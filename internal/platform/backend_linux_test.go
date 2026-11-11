//go:build linux

package platform

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeLinuxLinks struct {
	link                  netlink.Link
	addrs                 []netlink.Addr
	routes                []netlink.Route
	adds, dels, routeAdds int
	failRouteAt           int
	closed                bool
}

func (f *fakeLinuxLinks) LinkByName(name string) (netlink.Link, error) {
	if f.link == nil || f.link.Attrs().Name != name {
		return nil, netlink.LinkNotFoundError{}
	}
	return f.link, nil
}
func (f *fakeLinuxLinks) LinkAdd(link netlink.Link) error {
	f.adds++
	link.Attrs().Index = 42
	f.link = link
	return nil
}
func (f *fakeLinuxLinks) LinkDel(netlink.Link) error {
	f.dels++
	f.link = nil
	f.addrs = nil
	f.routes = nil
	return nil
}
func (f *fakeLinuxLinks) LinkSetUp(link netlink.Link) error {
	link.Attrs().Flags |= net.FlagUp
	return nil
}
func (f *fakeLinuxLinks) AddrList(link netlink.Link, _ int) ([]netlink.Addr, error) {
	var out []netlink.Addr
	for _, a := range f.addrs {
		if link == nil || a.LinkIndex == link.Attrs().Index {
			out = append(out, a)
		}
	}
	return out, nil
}
func (f *fakeLinuxLinks) AddrAdd(link netlink.Link, a *netlink.Addr) error {
	v := *a
	v.LinkIndex = link.Attrs().Index
	f.addrs = append(f.addrs, v)
	return nil
}
func (f *fakeLinuxLinks) AddrDel(_ netlink.Link, a *netlink.Addr) error {
	for i, x := range f.addrs {
		if linuxAddrKey(x) == linuxAddrKey(*a) {
			f.addrs = append(f.addrs[:i], f.addrs[i+1:]...)
			return nil
		}
	}
	return errors.New("address missing")
}
func (f *fakeLinuxLinks) RouteListFiltered(_ int, want *netlink.Route, _ uint64) ([]netlink.Route, error) {
	var out []netlink.Route
	for _, r := range f.routes {
		if r.Table == want.Table && r.Dst.String() == want.Dst.String() {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fakeLinuxLinks) RouteAdd(r *netlink.Route) error {
	f.routeAdds++
	if f.routeAdds == f.failRouteAt {
		return errors.New("injected route failure")
	}
	f.routes = append(f.routes, *r)
	return nil
}
func (f *fakeLinuxLinks) RouteDel(r *netlink.Route) error {
	for i, x := range f.routes {
		if x.Dst.String() == r.Dst.String() {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			return nil
		}
	}
	return errors.New("route missing")
}
func (f *fakeLinuxLinks) Close() { f.closed = true }

type fakeLinuxWG struct {
	device   wgtypes.Device
	changes  []wgtypes.Config
	failNext bool
	closed   bool
}

func (f *fakeLinuxWG) Device(string) (*wgtypes.Device, error) {
	v := f.device
	v.Peers = append([]wgtypes.Peer(nil), v.Peers...)
	return &v, nil
}
func (f *fakeLinuxWG) ConfigureDevice(_ string, c wgtypes.Config) error {
	f.changes = append(f.changes, c)
	if c.ReplacePeers {
		panic("full peer replacement resets unaffected peers")
	}
	if c.PrivateKey != nil {
		f.device.PrivateKey = *c.PrivateKey
	}
	if c.ListenPort != nil {
		f.device.ListenPort = *c.ListenPort
	}
	for _, change := range c.Peers {
		index := -1
		for i, p := range f.device.Peers {
			if p.PublicKey == change.PublicKey {
				index = i
				break
			}
		}
		if change.Remove {
			if index >= 0 {
				f.device.Peers = append(f.device.Peers[:index], f.device.Peers[index+1:]...)
			}
			continue
		}
		if index < 0 {
			f.device.Peers = append(f.device.Peers, wgtypes.Peer{PublicKey: change.PublicKey})
			index = len(f.device.Peers) - 1
		}
		p := &f.device.Peers[index]
		if change.Endpoint != nil {
			p.Endpoint = change.Endpoint
		}
		if change.PersistentKeepaliveInterval != nil {
			p.PersistentKeepaliveInterval = *change.PersistentKeepaliveInterval
		}
		if change.ReplaceAllowedIPs {
			p.AllowedIPs = append([]net.IPNet(nil), change.AllowedIPs...)
		}
	}
	if f.failNext {
		f.failNext = false
		return errors.New("injected partial WireGuard failure")
	}
	return nil
}
func (f *fakeLinuxWG) Close() error { f.closed = true; return nil }
func linuxTestDesired(t *testing.T) Desired {
	t.Helper()
	local, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	first, _ := wgtypes.GeneratePrivateKey()
	second, _ := wgtypes.GeneratePrivateKey()
	return Desired{InterfaceName: "pm-test", PrivateKey: [32]byte(local), Config: config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "network-test", Name: "test"}, Interface: config.Interface{PrivateKeyFile: "test.key", Address: []string{"10.80.0.1/32"}, ListenPort: 51820}, Peers: []config.Peer{{PublicKey: first.PublicKey().String(), AllowedIPs: []string{"10.80.0.2/32"}, Endpoint: "192.0.2.2:51820"}, {PublicKey: second.PublicKey().String(), AllowedIPs: []string{"10.80.0.3/32"}, Endpoint: "192.0.2.3:51820", PersistentKeepaliveSeconds: 25}}}}
}
func linuxTestSession(t *testing.T) (*linuxSession, *fakeLinuxLinks, *fakeLinuxWG, Desired) {
	t.Helper()
	d := linuxTestDesired(t)
	links := &fakeLinuxLinks{}
	wg := &fakeLinuxWG{}
	s, err := startLinux(context.Background(), d, links, func() (linuxWG, error) { return wg, nil })
	if err != nil {
		t.Fatal(err)
	}
	return s, links, wg, d
}
func TestLinuxStartSnapshotCleanup(t *testing.T) {
	s, links, wg, _ := linuxTestSession(t)
	snapshot, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != "running" || len(snapshot.Peers) != 2 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	for _, p := range snapshot.Peers {
		if !p.LastHandshake.IsZero() || p.SentBytes != 0 || p.ReceivedBytes != 0 {
			t.Fatal("invented handshake/traffic")
		}
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if links.dels != 1 || links.link != nil || len(links.routes) != 0 || len(links.addrs) != 0 || !wg.closed || !links.closed {
		t.Fatal("session resources leaked")
	}
}
func TestLinuxReconcilePreservesUntouchedPeersAndRoaming(t *testing.T) {
	s, _, wg, d := linuxTestSession(t)
	wg.device.Peers[0].Endpoint = &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345}
	wg.device.Peers[1].LastHandshakeTime = time.Unix(123, 0)
	wg.device.Peers[1].ReceiveBytes = 100
	previousCalls := len(wg.changes)
	if err := s.Reconcile(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(wg.changes) != previousCalls {
		t.Fatal("unchanged reconciliation reset WireGuard state")
	}
	changed := cloneLinuxDesired(d)
	changed.Config.Peers[0].Endpoint = "192.0.2.99:51822"
	if err := s.Reconcile(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	last := wg.changes[len(wg.changes)-1]
	if len(last.Peers) != 1 || last.Peers[0].PublicKey.String() != d.Config.Peers[0].PublicKey || last.PrivateKey != nil || last.ListenPort != nil || last.ReplacePeers {
		t.Fatal("endpoint change affected unrelated state")
	}
	if !wg.device.Peers[1].LastHandshakeTime.Equal(time.Unix(123, 0)) || wg.device.Peers[1].ReceiveBytes != 100 {
		t.Fatal("unaffected peer state reset")
	}
}
func TestLinuxRejectsResourceTakeover(t *testing.T) {
	d := linuxTestDesired(t)
	t.Run("interface", func(t *testing.T) {
		links := &fakeLinuxLinks{link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: d.InterfaceName}}}
		_, err := startLinux(context.Background(), d, links, nil)
		if err == nil || links.adds != 0 || links.dels != 0 {
			t.Fatal("existing interface takeover")
		}
	})
	t.Run("route", func(t *testing.T) {
		r := linuxRoutes(d, 7)[0]
		links := &fakeLinuxLinks{routes: []netlink.Route{r}}
		_, err := startLinux(context.Background(), d, links, nil)
		if err == nil || links.adds != 0 {
			t.Fatal("existing route takeover")
		}
	})
	t.Run("address", func(t *testing.T) {
		a := linuxAddresses(d)[0]
		a.LinkIndex = 7
		links := &fakeLinuxLinks{addrs: []netlink.Addr{a}}
		_, err := startLinux(context.Background(), d, links, nil)
		if err == nil || links.adds != 0 {
			t.Fatal("existing address takeover")
		}
	})
	t.Run("replacement", func(t *testing.T) {
		s, links, _, _ := linuxTestSession(t)
		links.link = &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: d.InterfaceName, Index: 42, Alias: "another-owner"}}
		if err := s.Close(context.Background()); err == nil || links.dels != 0 {
			t.Fatal("removed replacement interface")
		}
	})
}
func TestLinuxStartFailureRemovesOwnedResources(t *testing.T) {
	d := linuxTestDesired(t)
	links := &fakeLinuxLinks{failRouteAt: 2}
	wg := &fakeLinuxWG{}
	_, err := startLinux(context.Background(), d, links, func() (linuxWG, error) { return wg, nil })
	if err == nil || links.link != nil || len(links.addrs) != 0 || len(links.routes) != 0 || !wg.closed {
		t.Fatal("partial startup resources leaked")
	}
}
func TestLinuxReconcileFailureRollsBack(t *testing.T) {
	s, links, wg, d := linuxTestSession(t)
	before := wg.device.Peers[0].Endpoint.String()
	oldRoutes := append([]netlink.Route(nil), links.routes...)
	changed := cloneLinuxDesired(d)
	changed.Config.Peers[0].Endpoint = "192.0.2.77:50000"
	changed.Config.Peers[0].AllowedIPs = []string{"10.80.0.4/32"}
	wg.failNext = true
	if err := s.Reconcile(context.Background(), changed); err == nil {
		t.Fatal("ignored injected failure")
	}
	if wg.device.Peers[0].Endpoint.String() != before || !reflect.DeepEqual(oldRoutes, links.routes) || !reflect.DeepEqual(s.desired, d) {
		t.Fatal("failed change did not restore previous desired state")
	}
	if _, err := s.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestLinuxMissingRouteIsReportedAndRepaired(t *testing.T) {
	s, links, wg, d := linuxTestSession(t)
	links.routes = links.routes[1:]
	if _, err := s.Snapshot(context.Background()); err == nil {
		t.Fatal("reported healthy snapshot with missing route")
	}
	calls := len(wg.changes)
	if err := s.Reconcile(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(wg.changes) != calls || len(links.routes) != 2 {
		t.Fatal("route repair reset peer configuration")
	}
}
func TestLinuxInvalidDesiredNeverMutatesOS(t *testing.T) {
	d := linuxTestDesired(t)
	d.Config.Peers[0].PublicKey = wgtypes.Key(d.PrivateKey).PublicKey().String()
	links := &fakeLinuxLinks{}
	_, err := startLinux(context.Background(), d, links, nil)
	if err == nil || !strings.Contains(err.Error(), "local public key") || links.adds != 0 {
		t.Fatal("accepted self peer")
	}
}

func TestLinuxPersistedOwnershipRecoversOnlyItsStaleInterface(t *testing.T) {
	d := linuxTestDesired(t)
	d.OwnershipToken = strings.Repeat("a", 64)
	links := &fakeLinuxLinks{}
	_, err := startLinux(context.Background(), d, links, func() (linuxWG, error) { return &fakeLinuxWG{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	// Leave the first session unclosed to model a process killed without cleanup.
	recovered, err := startLinux(context.Background(), d, links, func() (linuxWG, error) { return &fakeLinuxWG{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if links.dels != 1 || links.adds != 2 {
		t.Fatal("owned stale interface was not recreated")
	}
	wrong := cloneLinuxDesired(d)
	wrong.OwnershipToken = strings.Repeat("b", 64)
	if _, err := startLinux(context.Background(), wrong, links, nil); err == nil {
		t.Fatal("another protected state took over an interface")
	}
	if links.dels != 1 {
		t.Fatal("foreign ownership caused deletion")
	}
	if err := recovered.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestLinuxUnclampedPrivateKeyDoesNotResetKernelState(t *testing.T) {
	d := linuxTestDesired(t)
	d.PrivateKey[0] |= 7
	d.PrivateKey[31] |= 128
	actual := &wgtypes.Device{PrivateKey: linuxPrivateKey(d.PrivateKey), ListenPort: d.Config.Interface.ListenPort}
	change := linuxWGDiff(Desired{}, d, actual)
	if change.PrivateKey != nil {
		t.Fatal("unclamped representation caused unnecessary private-key reset")
	}
}
