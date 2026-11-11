//go:build linux

package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type nativeBackend struct{}

type linuxLinks interface {
	LinkByName(string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetUp(netlink.Link) error
	AddrList(netlink.Link, int) ([]netlink.Addr, error)
	AddrAdd(netlink.Link, *netlink.Addr) error
	AddrDel(netlink.Link, *netlink.Addr) error
	RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error)
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	Close()
}
type linuxWG interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
	Close() error
}
type linuxSession struct {
	mu      sync.Mutex
	links   linuxLinks
	wg      linuxWG
	link    netlink.Link
	desired Desired
	closed  bool
}

func (nativeBackend) Inspect(context.Context) (Snapshot, error) {
	return Snapshot{}, errors.New("Linux inspection requires an active daemon session; use status through local IPC")
}
func (nativeBackend) Start(ctx context.Context, desired Desired) (Session, error) {
	if err := validateLinuxDesired(desired); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	links, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open Linux networking control: %w", err)
	}
	if err := links.SetSocketTimeout(3 * time.Second); err != nil {
		links.Close()
		return nil, err
	}
	s, err := startLinux(ctx, desired, links, func() (linuxWG, error) { return wgctrl.New() })
	if err != nil {
		links.Close()
		return nil, err
	}
	return s, nil
}

func validateLinuxDesired(d Desired) error {
	if err := config.Validate(d.Config, "linux"); err != nil {
		return err
	}
	check := d.Config
	check.Interface.Name = d.InterfaceName
	if d.InterfaceName == "" {
		return errors.New("Linux interface name must be resolved before starting the backend")
	}
	if err := config.Validate(check, "linux"); err != nil {
		return err
	}
	if d.PrivateKey == [32]byte{} {
		return errors.New("WireGuard private key is required")
	}
	if d.OwnershipToken != "" {
		token, err := hex.DecodeString(d.OwnershipToken)
		if err != nil || len(token) != 32 || len(d.OwnershipToken) != 64 {
			return errors.New("invalid persisted Linux ownership token")
		}
	}
	own := wgtypes.Key(d.PrivateKey).PublicKey().String()
	for _, p := range d.Config.Peers {
		if p.PublicKey == own {
			return errors.New("a remote peer cannot use the local public key")
		}
	}
	return nil
}

func startLinux(ctx context.Context, d Desired, links linuxLinks, openWG func() (linuxWG, error)) (*linuxSession, error) {
	if err := validateLinuxDesired(d); err != nil {
		return nil, err
	}
	if existing, err := links.LinkByName(d.InterfaceName); err == nil {
		// The caller holds the protected state lock. Only a persisted random token,
		// never a network label or interface name, permits recovering its stale device.
		if d.OwnershipToken == "" || existing.Type() != "wireguard" || existing.Attrs().Alias != "peerimeter:"+d.OwnershipToken {
			return nil, errors.New("Linux interface already exists; refusing to take over an existing interface")
		}
		if _, _, err := planLinuxNetwork(links, existing, d); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := links.LinkDel(existing); err != nil {
			return nil, fmt.Errorf("remove stale owned Linux WireGuard interface: %w", err)
		}
	} else {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("check Linux interface availability: %w", err)
		}
	}
	if _, _, err := planLinuxNetwork(links, nil, d); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ownerToken := d.OwnershipToken
	if ownerToken == "" {
		token := make([]byte, 16)
		if _, err := rand.Read(token); err != nil {
			return nil, errors.New("generate Linux interface ownership token")
		}
		ownerToken = hex.EncodeToString(token)
	}
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: d.InterfaceName, MTU: 1420, Alias: "peerimeter:" + ownerToken}}
	if err := links.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("create native Linux WireGuard interface (requires CAP_NET_ADMIN and WireGuard kernel support): %w", err)
	}
	// LinkAdd fills Index, but refetch ensures the ownership attributes are real.
	actual, err := links.LinkByName(d.InterfaceName)
	if err != nil {
		_ = links.LinkDel(link)
		return nil, fmt.Errorf("inspect newly created Linux interface: %w", err)
	}
	if actual.Type() != "wireguard" || actual.Attrs().Alias != link.Attrs().Alias {
		return nil, errors.New("new Linux interface ownership could not be confirmed")
	}
	s := &linuxSession{links: links, link: actual}
	cleanup := func(cause error) (*linuxSession, error) {
		// Only delete if the index and random ownership alias still identify ours.
		closeErr := s.closeLocked()
		return nil, errors.Join(cause, closeErr)
	}
	s.wg, err = openWG() // The generic-netlink family may load only after LinkAdd.
	if err != nil {
		return cleanup(fmt.Errorf("open native WireGuard control: %w", err))
	}
	if err := links.LinkSetUp(actual); err != nil {
		return cleanup(fmt.Errorf("bring Linux WireGuard interface up: %w", err))
	}
	if err := s.reconcileLocked(ctx, d); err != nil {
		return cleanup(err)
	}
	return s, nil
}

func (s *linuxSession) ownedLink() (netlink.Link, error) {
	link, err := s.links.LinkByName(s.link.Attrs().Name)
	if err != nil {
		return nil, fmt.Errorf("owned Linux interface is unavailable: %w", err)
	}
	if link.Type() != "wireguard" || link.Attrs().Index != s.link.Attrs().Index || link.Attrs().Alias != s.link.Attrs().Alias {
		return nil, errors.New("Linux interface ownership changed; refusing to modify or remove it")
	}
	return link, nil
}

func cloneLinuxDesired(d Desired) Desired {
	d.Config.Interface.Address = append([]string(nil), d.Config.Interface.Address...)
	d.Config.Peers = append([]config.Peer(nil), d.Config.Peers...)
	for i := range d.Config.Peers {
		d.Config.Peers[i].AllowedIPs = append([]string(nil), d.Config.Peers[i].AllowedIPs...)
	}
	return d
}

func (s *linuxSession) Reconcile(ctx context.Context, d Desired) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("Linux WireGuard session is closed")
	}
	return s.reconcileLocked(ctx, d)
}

// Reconcile changes individual peers, addresses and routes. It never replaces
// the entire peer set or recreates the interface. A failed transaction attempts
// inverse changes in reverse order and reports any rollback failure explicitly.
func (s *linuxSession) reconcileLocked(ctx context.Context, d Desired) error {
	if err := validateLinuxDesired(d); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.InterfaceName != s.link.Attrs().Name {
		return errors.New("changing a running Linux interface name is unsupported")
	}
	if s.desired.Config.Network.ID != "" && d.Config.Network.ID != s.desired.Config.Network.ID {
		return errors.New("changing the running network identity is unsupported")
	}
	if s.desired.Config.Network.ID != "" && d.OwnershipToken != s.desired.OwnershipToken {
		return errors.New("changing the running interface ownership token is unsupported")
	}
	if _, err := s.ownedLink(); err != nil {
		return err
	}
	addrs, routes, err := planLinuxNetwork(s.links, s.link, d)
	if err != nil {
		return err
	}
	before, err := s.wg.Device(d.InterfaceName)
	if err != nil {
		return fmt.Errorf("read Linux WireGuard state before reconciliation: %w", err)
	}
	change := linuxWGDiff(s.desired, d, before)
	var undo []func() error
	rollback := func(cause error) error {
		var errs []error
		errs = append(errs, cause)
		for i := len(undo) - 1; i >= 0; i-- {
			if err := undo[i](); err != nil {
				errs = append(errs, fmt.Errorf("Linux reconciliation rollback failed: %w", err))
			}
		}
		return errors.Join(errs...)
	}
	currentAddrs, err := s.links.AddrList(s.link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	addrPresent := map[string]bool{}
	for _, a := range currentAddrs {
		addrPresent[linuxAddrKey(a)] = true
	}
	wantedAddrs := map[string]bool{}
	for _, a := range addrs {
		wantedAddrs[linuxAddrKey(a)] = true
		if addrPresent[linuxAddrKey(a)] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return rollback(err)
		}
		a := a
		if err := s.links.AddrAdd(s.link, &a); err != nil {
			return rollback(fmt.Errorf("add Linux tunnel address: %w", err))
		}
		undo = append(undo, func() error { return s.links.AddrDel(s.link, &a) })
	}
	wantedRoutes := map[string]bool{}
	for _, r := range routes {
		wantedRoutes[r.Dst.String()] = true
		exists, err := linuxRouteExists(s.links, r)
		if err != nil {
			return rollback(err)
		}
		if exists {
			continue
		}
		if err := ctx.Err(); err != nil {
			return rollback(err)
		}
		r := r
		if err := s.links.RouteAdd(&r); err != nil {
			return rollback(fmt.Errorf("add Linux peer route: %w", err))
		}
		undo = append(undo, func() error { return s.links.RouteDel(&r) })
	}
	if linuxHasWGChange(change) {
		reverse := linuxWGUndo(before, change)
		// Register first: ConfigureDevice can fail after applying part of a message.
		undo = append(undo, func() error { return s.wg.ConfigureDevice(d.InterfaceName, reverse) })
		if err := s.wg.ConfigureDevice(d.InterfaceName, change); err != nil {
			return rollback(fmt.Errorf("apply Linux WireGuard peer changes: %w", err))
		}
	}
	if err := ctx.Err(); err != nil {
		return rollback(err)
	}
	for _, r := range linuxRoutes(s.desired, s.link.Attrs().Index) {
		if wantedRoutes[r.Dst.String()] {
			continue
		}
		exists, err := linuxRouteExists(s.links, r)
		if err != nil {
			return rollback(err)
		}
		if !exists {
			continue
		}
		r := r
		if err := s.links.RouteDel(&r); err != nil {
			return rollback(fmt.Errorf("remove obsolete Linux peer route: %w", err))
		}
		undo = append(undo, func() error { return s.links.RouteAdd(&r) })
	}
	for _, a := range linuxAddresses(s.desired) {
		if wantedAddrs[linuxAddrKey(a)] || !addrPresent[linuxAddrKey(a)] {
			continue
		}
		a := a
		if err := s.links.AddrDel(s.link, &a); err != nil {
			return rollback(fmt.Errorf("remove obsolete Linux tunnel address: %w", err))
		}
		undo = append(undo, func() error { return s.links.AddrAdd(s.link, &a) })
	}
	s.desired = cloneLinuxDesired(d)
	return nil
}

func linuxAddresses(d Desired) []netlink.Addr {
	var result []netlink.Addr
	for _, raw := range d.Config.Interface.Address {
		ip, prefix, _ := net.ParseCIDR(raw)
		prefix.IP = ip
		result = append(result, netlink.Addr{IPNet: prefix, Flags: unix.IFA_F_NOPREFIXROUTE})
	}
	return result
}
func linuxAddrKey(a netlink.Addr) string {
	if a.IPNet == nil {
		return ""
	}
	return a.IPNet.String()
}
func linuxRoutes(d Desired, index int) []netlink.Route {
	var result []netlink.Route
	for _, p := range d.Config.Peers {
		for _, raw := range p.AllowedIPs {
			_, prefix, _ := net.ParseCIDR(raw)
			result = append(result, netlink.Route{LinkIndex: index, Dst: prefix, Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_STATIC, Scope: netlink.SCOPE_LINK})
		}
	}
	return result
}
func linuxRouteExists(links linuxLinks, want netlink.Route) (bool, error) {
	found, err := links.RouteListFiltered(netlink.FAMILY_ALL, &want, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, fmt.Errorf("inspect Linux route conflicts: %w", err)
	}
	if len(found) == 0 {
		return false, nil
	}
	for _, r := range found {
		if want.LinkIndex == 0 || r.LinkIndex != want.LinkIndex || r.Protocol != want.Protocol || r.Scope != want.Scope || r.Gw != nil || len(r.MultiPath) > 0 {
			return false, errors.New("a peer route already belongs to another Linux network configuration")
		}
	}
	return true, nil
}
func planLinuxNetwork(links linuxLinks, link netlink.Link, d Desired) ([]netlink.Addr, []netlink.Route, error) {
	index := 0
	if link != nil {
		index = link.Attrs().Index
	}
	addrs, routes := linuxAddresses(d), linuxRoutes(d, index)
	all, err := links.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect Linux address conflicts: %w", err)
	}
	for _, a := range addrs {
		for _, existing := range all {
			if existing.IPNet != nil && existing.LinkIndex != index && a.IP.Equal(existing.IP) {
				return nil, nil, errors.New("a tunnel address is already assigned to another Linux interface")
			}
		}
	}
	for _, r := range routes {
		if _, err := linuxRouteExists(links, r); err != nil {
			return nil, nil, err
		}
	}
	return addrs, routes, nil
}

func linuxWGDiff(previous, next Desired, actual *wgtypes.Device) wgtypes.Config {
	var result wgtypes.Config
	key := linuxPrivateKey(next.PrivateKey)
	if actual.PrivateKey != key {
		result.PrivateKey = &key
	}
	if actual.ListenPort != next.Config.Interface.ListenPort {
		v := next.Config.Interface.ListenPort
		result.ListenPort = &v
	}
	oldWanted := map[string]config.Peer{}
	for _, p := range previous.Config.Peers {
		oldWanted[p.PublicKey] = p
	}
	observed := map[string]wgtypes.Peer{}
	for _, p := range actual.Peers {
		observed[p.PublicKey.String()] = p
	}
	wanted := map[string]bool{}
	for _, p := range next.Config.Peers {
		wanted[p.PublicKey] = true
		key, _ := wgtypes.ParseKey(p.PublicKey)
		current, exists := observed[p.PublicKey]
		old, known := oldWanted[p.PublicKey]
		keepalive := time.Duration(p.PersistentKeepaliveSeconds) * time.Second
		change := wgtypes.PeerConfig{PublicKey: key}
		if !exists || !known || old.Endpoint != p.Endpoint {
			endpoint, _ := netip.ParseAddrPort(p.Endpoint)
			change.Endpoint = net.UDPAddrFromAddrPort(endpoint)
		}
		if !exists || current.PersistentKeepaliveInterval != keepalive {
			change.PersistentKeepaliveInterval = &keepalive
		}
		var allowed []net.IPNet
		for _, raw := range p.AllowedIPs {
			_, prefix, _ := net.ParseCIDR(raw)
			allowed = append(allowed, *prefix)
		}
		if !exists || !linuxSameAllowed(current.AllowedIPs, allowed) {
			change.ReplaceAllowedIPs = true
			change.AllowedIPs = allowed
		}
		if !exists || change.Endpoint != nil || change.PersistentKeepaliveInterval != nil || change.ReplaceAllowedIPs {
			result.Peers = append(result.Peers, change)
		}
	}
	for _, p := range actual.Peers {
		if !wanted[p.PublicKey.String()] {
			result.Peers = append(result.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	return result
}

// The kernel clamps X25519 keys on input. Compare the clamped representation
// to avoid resetting a valid tunnel when an operator supplied unclamped bytes.
func linuxPrivateKey(raw [32]byte) wgtypes.Key {
	key := wgtypes.Key(raw)
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key
}
func linuxSameAllowed(a, b []net.IPNet) bool {
	x, y := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		x[i] = a[i].String()
	}
	for i := range b {
		y[i] = b[i].String()
	}
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(x, y)
}
func linuxHasWGChange(c wgtypes.Config) bool {
	return c.PrivateKey != nil || c.ListenPort != nil || len(c.Peers) > 0
}
func linuxWGUndo(before *wgtypes.Device, change wgtypes.Config) wgtypes.Config {
	var result wgtypes.Config
	if change.PrivateKey != nil {
		key := before.PrivateKey
		result.PrivateKey = &key
	}
	if change.ListenPort != nil {
		port := before.ListenPort
		result.ListenPort = &port
	}
	peers := map[wgtypes.Key]wgtypes.Peer{}
	for _, p := range before.Peers {
		peers[p.PublicKey] = p
	}
	for _, changed := range change.Peers {
		p, exists := peers[changed.PublicKey]
		if !exists {
			result.Peers = append(result.Peers, wgtypes.PeerConfig{PublicKey: changed.PublicKey, Remove: true})
			continue
		}
		keepalive, key := p.PersistentKeepaliveInterval, p.PresharedKey
		result.Peers = append(result.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, PresharedKey: &key, Endpoint: p.Endpoint, PersistentKeepaliveInterval: &keepalive, ReplaceAllowedIPs: true, AllowedIPs: p.AllowedIPs})
	}
	return result
}

func (s *linuxSession) Snapshot(ctx context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if s.closed {
		return Snapshot{}, errors.New("Linux WireGuard session is closed")
	}
	link, err := s.ownedLink()
	if err != nil {
		return Snapshot{}, err
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return Snapshot{}, errors.New("Linux WireGuard interface is down")
	}
	if _, _, err := planLinuxNetwork(s.links, s.link, s.desired); err != nil {
		return Snapshot{}, err
	}
	for _, r := range linuxRoutes(s.desired, s.link.Attrs().Index) {
		exists, err := linuxRouteExists(s.links, r)
		if err != nil {
			return Snapshot{}, err
		}
		if !exists {
			return Snapshot{}, errors.New("a configured Linux peer route is missing")
		}
	}
	addrs, err := s.links.AddrList(s.link, netlink.FAMILY_ALL)
	if err != nil {
		return Snapshot{}, err
	}
	present := map[string]bool{}
	for _, a := range addrs {
		present[linuxAddrKey(a)] = true
	}
	for _, a := range linuxAddresses(s.desired) {
		if !present[linuxAddrKey(a)] {
			return Snapshot{}, errors.New("a configured Linux tunnel address is missing")
		}
	}
	device, err := s.wg.Device(s.link.Attrs().Name)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read native Linux WireGuard peer state: %w", err)
	}
	result := Snapshot{NetworkID: s.desired.Config.Network.ID, InterfaceName: s.link.Attrs().Name, State: "running", Peers: []PeerState{}}
	for _, p := range device.Peers {
		peer := PeerState{PublicKey: p.PublicKey.String(), LastHandshake: p.LastHandshakeTime}
		if p.ReceiveBytes > 0 {
			peer.ReceivedBytes = uint64(p.ReceiveBytes)
		}
		if p.TransmitBytes > 0 {
			peer.SentBytes = uint64(p.TransmitBytes)
		}
		if p.Endpoint != nil {
			peer.Endpoint = p.Endpoint.String()
		}
		result.Peers = append(result.Peers, peer)
	}
	sort.Slice(result.Peers, func(i, j int) bool { return result.Peers[i].PublicKey < result.Peers[j].PublicKey })
	return result, nil
}
func (s *linuxSession) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}
func (s *linuxSession) closeLocked() error {
	if s.closed {
		return nil
	}
	var result error
	link, err := s.ownedLink()
	var notFound netlink.LinkNotFoundError
	if err == nil {
		result = s.links.LinkDel(link)
	} else if !errors.As(err, &notFound) {
		result = err
	}
	if result != nil {
		return fmt.Errorf("remove owned Linux WireGuard interface: %w", result)
	}
	s.closed = true
	if s.wg != nil {
		result = s.wg.Close()
	}
	s.links.Close()
	// Erase the retained in-memory private key after native teardown.
	s.desired.PrivateKey = [32]byte{}
	return result
}
