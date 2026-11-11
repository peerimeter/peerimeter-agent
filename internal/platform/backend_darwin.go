//go:build darwin

package platform

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"golang.org/x/net/route"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type nativeBackend struct{}

type darwinDevice interface {
	IpcSet(string) error
	IpcGet() (string, error)
	Up() error
	Close()
}
type darwinRoute struct {
	prefix netip.Prefix
	index  int
}
type darwinOps struct {
	command   func(context.Context, string, ...string) error
	routes    func() ([]darwinRoute, error)
	addresses func(int, []string) error
}
type darwinSession struct {
	mu      sync.Mutex
	dev     darwinDevice
	name    string
	index   int
	desired Desired
	owned   map[netip.Prefix]bool
	ops     darwinOps
	closed  bool
}

func (nativeBackend) Start(ctx context.Context, d Desired) (Session, error) {
	if err := darwinValidate(d); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("macOS tunnel creation requires root privileges")
	}
	ops := darwinOps{command: darwinCommand, routes: darwinRoutes, addresses: darwinAddressConflicts}
	if err := darwinPreflight(ops, 0, d.Config, darwinDesiredRoutes(d.Config)); err != nil {
		return nil, err
	}
	t, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return nil, errors.New("cannot create native macOS utun interface")
	}
	name, err := t.Name()
	if err != nil {
		t.Close()
		return nil, errors.New("cannot identify native macOS utun interface")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Close()
		return nil, errors.New("cannot identify native macOS interface index")
	}
	// Keep the embedded backend silent: unfiltered upstream logs must not reach
	// product JSON output. Snapshot exposes only selected non-secret UAPI fields.
	dev := device.NewDevice(t, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	s := &darwinSession{dev: dev, name: name, index: iface.Index, desired: darwinCopy(d), owned: map[netip.Prefix]bool{}, ops: ops}
	fail := func(err error) (Session, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return nil, errors.Join(err, s.Close(cleanup))
	}
	if err := dev.IpcSet(darwinIPC(Desired{}, d)); err != nil {
		return fail(errors.New("cannot configure embedded WireGuard device"))
	}
	for _, raw := range d.Config.Interface.Address {
		p := netip.MustParsePrefix(raw)
		args := []string{name, "inet6", p.String(), "alias"}
		if p.Addr().Is4() {
			args = []string{name, "inet", p.Addr().String(), p.Addr().String(), "netmask", net.IP(net.CIDRMask(p.Bits(), 32)).String(), "alias"}
		}
		if err := ops.command(ctx, "/sbin/ifconfig", args...); err != nil {
			return fail(errors.New("cannot assign macOS tunnel address"))
		}
	}
	if err := ops.command(ctx, "/sbin/ifconfig", name, "up"); err != nil {
		return fail(errors.New("cannot enable macOS tunnel interface"))
	}
	for _, p := range darwinDesiredRoutes(d.Config) {
		if err := s.addRoute(ctx, p); err != nil {
			return fail(err)
		}
	}
	if err := dev.Up(); err != nil {
		return fail(errors.New("cannot activate embedded WireGuard UDP transport"))
	}
	return s, nil
}
func (nativeBackend) Inspect(context.Context) (Snapshot, error) {
	return Snapshot{}, errors.New("read macOS tunnel status through the running agent local IPC")
}

func darwinValidate(d Desired) error {
	if err := config.Validate(d.Config, "darwin"); err != nil {
		return err
	}
	if d.InterfaceName != "" {
		return errors.New("explicit interface names are supported only on Linux")
	}
	if d.PrivateKey == [32]byte{} {
		return errors.New("WireGuard private key must not be zero")
	}
	key, err := ecdh.X25519().NewPrivateKey(d.PrivateKey[:])
	if err != nil {
		return errors.New("invalid WireGuard private key")
	}
	own := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, p := range d.Config.Peers {
		if p.PublicKey == own {
			return errors.New("peer public key matches the local interface key")
		}
	}
	return nil
}
func darwinCopy(d Desired) Desired {
	d.Config.Interface.Address = slices.Clone(d.Config.Interface.Address)
	d.Config.Peers = slices.Clone(d.Config.Peers)
	for i := range d.Config.Peers {
		d.Config.Peers[i].AllowedIPs = slices.Clone(d.Config.Peers[i].AllowedIPs)
	}
	return d
}
func darwinDesiredRoutes(c config.Config) []netip.Prefix {
	var result []netip.Prefix
	for _, peer := range c.Peers {
		for _, raw := range peer.AllowedIPs {
			result = append(result, netip.MustParsePrefix(raw))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}
func darwinPreflight(ops darwinOps, index int, c config.Config, wanted []netip.Prefix) error {
	if err := ops.addresses(index, c.Interface.Address); err != nil {
		return err
	}
	routes, err := ops.routes()
	if err != nil {
		return errors.New("cannot inspect macOS routes before changing network state")
	}
	for _, want := range wanted {
		for _, existing := range routes {
			if existing.index == index && index != 0 {
				continue
			}
			// A default route is expected; any more specific overlapping route belongs
			// to another network and must never be replaced or shadowed implicitly.
			if existing.prefix.Bits() != 0 && existing.prefix.Overlaps(want) {
				return fmt.Errorf("macOS route %s conflicts with an existing network route", want)
			}
		}
	}
	return nil
}
func darwinAddressConflicts(index int, wanted []string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("cannot inspect local macOS interface addresses")
	}
	for _, iface := range interfaces {
		if iface.Index == index {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return errors.New("cannot inspect local macOS interface addresses")
		}
		for _, raw := range addresses {
			existing, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			for _, target := range wanted {
				if netip.MustParsePrefix(target).Overlaps(existing) {
					return errors.New("macOS tunnel address conflicts with another local interface")
				}
			}
		}
	}
	return nil
}
func darwinCommand(ctx context.Context, path string, args ...string) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	// Arguments contain only validated public addresses and an OS-assigned name.
	// Do not include command output in errors or log arbitrary native output.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("macOS network command %s failed", path)
	}
	return nil
}
func darwinRouteArgs(operation, name string, p netip.Prefix) []string {
	family := "-inet6"
	if p.Addr().Is4() {
		family = "-inet"
	}
	kind, target := "-net", p.String()
	if p.Bits() == p.Addr().BitLen() {
		kind, target = "-host", p.Addr().String()
	}
	return []string{"-n", operation, family, kind, target, "-interface", name}
}
func (s *darwinSession) addRoute(ctx context.Context, p netip.Prefix) error {
	if err := s.ops.command(ctx, "/sbin/route", darwinRouteArgs("add", s.name, p)...); err != nil {
		return fmt.Errorf("cannot add macOS tunnel route %s", p)
	}
	s.owned[p] = true
	return nil
}
func (s *darwinSession) removeRoute(ctx context.Context, p netip.Prefix) error {
	if !s.owned[p] {
		return nil
	}
	routes, err := s.ops.routes()
	if err != nil {
		return errors.New("cannot verify ownership of macOS tunnel route")
	}
	found := false
	for _, current := range routes {
		if current.prefix == p {
			if current.index != s.index {
				return errors.New("macOS tunnel route ownership changed; refusing to delete unrelated route")
			}
			found = true
		}
	}
	if found {
		if err := s.ops.command(ctx, "/sbin/route", darwinRouteArgs("delete", s.name, p)...); err != nil {
			return fmt.Errorf("cannot remove macOS tunnel route %s", p)
		}
	}
	delete(s.owned, p)
	return nil
}
func (s *darwinSession) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var errs []error
	for p := range s.owned {
		if err := s.removeRoute(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	s.dev.Close() // Closing the owned utun handle also removes connected routes.
	s.closed = true
	s.desired.PrivateKey = [32]byte{}
	return errors.Join(errs...)
}

func (s *darwinSession) Reconcile(ctx context.Context, d Desired) error {
	if err := darwinValidate(d); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("macOS WireGuard session is closed")
	}
	if d.Config.Network.ID != s.desired.Config.Network.ID {
		return errors.New("cannot change network identity of an active macOS tunnel")
	}
	before := slices.Clone(s.desired.Config.Interface.Address)
	after := slices.Clone(d.Config.Interface.Address)
	sort.Strings(before)
	sort.Strings(after)
	if !slices.Equal(before, after) {
		return errors.New("macOS local tunnel address changes require a deliberate agent restart")
	}
	wanted := darwinDesiredRoutes(d.Config)
	var add, remove []netip.Prefix
	for _, p := range wanted {
		if !s.owned[p] {
			add = append(add, p)
		}
	}
	for p := range s.owned {
		if !slices.Contains(wanted, p) {
			remove = append(remove, p)
		}
	}
	if err := darwinPreflight(s.ops, s.index, d.Config, add); err != nil {
		return err
	}
	var added, removed []netip.Prefix
	rollbackRoutes := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var errs []error
		for _, p := range removed {
			if err := s.addRoute(cleanup, p); err != nil {
				errs = append(errs, err)
			}
		}
		for _, p := range added {
			if err := s.removeRoute(cleanup, p); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for _, p := range add {
		if err := s.addRoute(ctx, p); err != nil {
			return errors.Join(err, rollbackRoutes())
		}
		added = append(added, p)
	}
	update := darwinIPC(s.desired, d)
	if update != "" {
		if err := s.dev.IpcSet(update); err != nil {
			restore := s.dev.IpcSet(darwinIPC(d, s.desired))
			if restore != nil {
				restore = errors.New("cannot restore previous embedded WireGuard configuration")
			}
			return errors.Join(errors.New("cannot reconcile embedded WireGuard configuration"), restore, rollbackRoutes())
		}
	}
	for _, p := range remove {
		if err := s.removeRoute(ctx, p); err != nil {
			restore := s.dev.IpcSet(darwinIPC(d, s.desired))
			if restore != nil {
				restore = errors.New("cannot restore previous embedded WireGuard configuration")
			}
			return errors.Join(err, restore, rollbackRoutes())
		}
		removed = append(removed, p)
	}
	s.desired = darwinCopy(d)
	return nil
}

// darwinIPC never replaces all peers: unchanged peers retain sessions, counters
// and WireGuard-authenticated roaming endpoints during ordinary reconciliation.
func darwinIPC(old, next Desired) string {
	var out strings.Builder
	if old.PrivateKey != next.PrivateKey {
		fmt.Fprintf(&out, "private_key=%x\n", next.PrivateKey)
	}
	if old.Config.Interface.ListenPort != next.Config.Interface.ListenPort {
		fmt.Fprintf(&out, "listen_port=%d\n", next.Config.Interface.ListenPort)
	}
	previous := map[string]config.Peer{}
	wanted := map[string]bool{}
	for _, p := range old.Config.Peers {
		previous[p.PublicKey] = p
	}
	for _, p := range next.Config.Peers {
		wanted[p.PublicKey] = true
	}
	hexKey := func(public string) string {
		raw, _ := base64.StdEncoding.DecodeString(public)
		return hex.EncodeToString(raw)
	}
	for _, p := range old.Config.Peers {
		if !wanted[p.PublicKey] {
			fmt.Fprintf(&out, "public_key=%s\nremove=true\n", hexKey(p.PublicKey))
		}
	}
	for _, p := range next.Config.Peers {
		prev, exists := previous[p.PublicKey]
		allowedChanged := !slices.Equal(prev.AllowedIPs, p.AllowedIPs)
		if exists && prev.Endpoint == p.Endpoint && prev.PersistentKeepaliveSeconds == p.PersistentKeepaliveSeconds && !allowedChanged {
			continue
		}
		fmt.Fprintf(&out, "public_key=%s\n", hexKey(p.PublicKey))
		if !exists || prev.Endpoint != p.Endpoint {
			fmt.Fprintf(&out, "endpoint=%s\n", p.Endpoint)
		}
		if !exists || prev.PersistentKeepaliveSeconds != p.PersistentKeepaliveSeconds {
			fmt.Fprintf(&out, "persistent_keepalive_interval=%d\n", p.PersistentKeepaliveSeconds)
		}
		if !exists || allowedChanged {
			out.WriteString("replace_allowed_ips=true\n")
			for _, prefix := range p.AllowedIPs {
				fmt.Fprintf(&out, "allowed_ip=%s\n", prefix)
			}
		}
	}
	return out.String()
}
func (s *darwinSession) Snapshot(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Snapshot{NetworkID: s.desired.Config.Network.ID, InterfaceName: s.name, State: "stopped", Peers: []PeerState{}}, nil
	}
	raw, err := s.dev.IpcGet()
	if err != nil {
		return Snapshot{}, errors.New("cannot read embedded WireGuard state")
	}
	peers, err := darwinPublicState(raw)
	if err != nil {
		return Snapshot{}, err
	}
	public, port, err := darwinPublicInterface(raw)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{NetworkName: s.desired.Config.Network.Name, PublicKey: public, ListenPort: port, NetworkID: s.desired.Config.Network.ID, InterfaceName: s.name, State: "running", Peers: peers}, nil
}
func darwinPublicState(raw string) ([]PeerState, error) {
	peers := []PeerState{}
	var peer *PeerState
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			data, err := hex.DecodeString(value)
			if err != nil || len(data) != 32 {
				return nil, errors.New("invalid public WireGuard state")
			}
			peers = append(peers, PeerState{PublicKey: base64.StdEncoding.EncodeToString(data)})
			peer = &peers[len(peers)-1]
		case "allowed_ip":
			if peer != nil {
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					return nil, errors.New("invalid public WireGuard route state")
				}
				peer.AllowedIPs = append(peer.AllowedIPs, prefix.String())
			}
		case "persistent_keepalive_interval":
			if peer != nil {
				seconds, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return nil, errors.New("invalid public WireGuard keepalive state")
				}
				peer.PersistentKeepaliveSeconds = int(seconds)
			}
		case "endpoint":
			if peer != nil {
				if _, err := netip.ParseAddrPort(value); err != nil {
					return nil, errors.New("invalid public WireGuard endpoint state")
				}
				peer.Endpoint = value
			}
		case "rx_bytes", "tx_bytes":
			if peer != nil {
				n, err := strconv.ParseUint(value, 10, 64)
				if err != nil {
					return nil, errors.New("invalid WireGuard traffic counter")
				}
				if key == "rx_bytes" {
					peer.ReceivedBytes = n
				} else {
					peer.SentBytes = n
				}
			}
		case "last_handshake_time_sec":
			if peer != nil {
				n, err := strconv.ParseInt(value, 10, 64)
				if err != nil || n < 0 {
					return nil, errors.New("invalid WireGuard handshake timestamp")
				}
				if n != 0 {
					peer.LastHandshake = time.Unix(n, 0)
				}
			}
		case "last_handshake_time_nsec":
			if peer != nil {
				n, err := strconv.ParseInt(value, 10, 64)
				if err != nil || n < 0 || n >= int64(time.Second) {
					return nil, errors.New("invalid WireGuard handshake timestamp")
				}
				if !peer.LastHandshake.IsZero() {
					peer.LastHandshake = peer.LastHandshake.Add(time.Duration(n))
				}
			}
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	return peers, nil
}
func darwinRoutes() ([]darwinRoute, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var result []darwinRoute
	for _, raw := range messages {
		m, ok := raw.(*route.RouteMessage)
		if !ok || len(m.Addrs) <= syscall.RTAX_DST {
			continue
		}
		var address netip.Addr
		switch dst := m.Addrs[syscall.RTAX_DST].(type) {
		case *route.Inet4Addr:
			address = netip.AddrFrom4(dst.IP)
		case *route.Inet6Addr:
			address = netip.AddrFrom16(dst.IP)
		default:
			continue
		}
		bits := 0
		if m.Flags&syscall.RTF_HOST != 0 {
			bits = address.BitLen()
		} else if len(m.Addrs) > syscall.RTAX_NETMASK && m.Addrs[syscall.RTAX_NETMASK] != nil {
			switch mask := m.Addrs[syscall.RTAX_NETMASK].(type) {
			case *route.Inet4Addr:
				bits, _ = net.IPMask(mask.IP[:]).Size()
			case *route.Inet6Addr:
				bits, _ = net.IPMask(mask.IP[:]).Size()
			default:
				continue
			}
		}
		result = append(result, darwinRoute{prefix: netip.PrefixFrom(address, bits).Masked(), index: m.Index})
	}
	return result, nil
}

func darwinPublicInterface(raw string) (string, int, error) {
	public := ""
	port := 0
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			break
		}
		switch key {
		case "private_key":
			bytes, err := hex.DecodeString(value)
			if err != nil || len(bytes) != 32 {
				return "", 0, errors.New("invalid embedded interface state")
			}
			key, err := ecdh.X25519().NewPrivateKey(bytes)
			if err != nil {
				return "", 0, errors.New("invalid embedded interface key state")
			}
			public = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		case "listen_port":
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return "", 0, errors.New("invalid embedded listen port state")
			}
			port = int(n)
		}
	}
	return public, port, nil
}
