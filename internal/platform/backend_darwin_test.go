//go:build darwin

package platform

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/config"
)

func darwinFixture() Desired {
	var private [32]byte
	private[0] = 17
	var public [32]byte
	public[0] = 29
	return Desired{PrivateKey: private, Config: config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "test-network", Name: "test"}, Interface: config.Interface{PrivateKeyFile: "/secure/key", Address: []string{"10.203.0.1/32"}, ListenPort: 51820}, Peers: []config.Peer{{PublicKey: base64.StdEncoding.EncodeToString(public[:]), Endpoint: "127.0.0.1:51821", AllowedIPs: []string{"10.203.0.2/32"}}}}}
}
func TestDarwinPeerDiffKeepsUnchangedSessions(t *testing.T) {
	old := darwinFixture()
	next := darwinCopy(old)
	if got := darwinIPC(old, next); got != "" {
		t.Fatalf("unchanged config produced UAPI update: %q", got)
	}
	next.Config.Peers[0].PersistentKeepaliveSeconds = 25
	got := darwinIPC(old, next)
	if !strings.Contains(got, "persistent_keepalive_interval=25\n") || strings.Contains(got, "endpoint=") || strings.Contains(got, "replace_peers=") || strings.Contains(got, "private_key=") {
		t.Fatalf("keepalive change disturbed unrelated state: %q", got)
	}
	next = darwinCopy(old)
	next.Config.Peers[0].Endpoint = "127.0.0.1:51822"
	got = darwinIPC(old, next)
	if !strings.Contains(got, "endpoint=127.0.0.1:51822\n") || strings.Contains(got, "replace_allowed_ips=") {
		t.Fatalf("endpoint diff resets unaffected configuration: %q", got)
	}
	next = darwinCopy(old)
	next.Config.Peers = nil
	if !strings.Contains(darwinIPC(old, next), "remove=true\n") {
		t.Fatal("removed peer retained")
	}
	next = darwinCopy(old)
	next.Config.Peers[0].AllowedIPs = []string{"10.203.0.3/32"}
	if !strings.Contains(darwinIPC(old, next), "replace_allowed_ips=true\nallowed_ip=10.203.0.3/32\n") {
		t.Fatal("allowed IP change missing")
	}
}
func TestDarwinSnapshotNeverSerializesSecrets(t *testing.T) {
	public := strings.Repeat("ab", 32)
	raw := "private_key=" + strings.Repeat("12", 32) + "\npublic_key=" + public + "\npreshared_key=" + strings.Repeat("34", 32) + "\nendpoint=127.0.0.1:51821\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=123\nrx_bytes=44\ntx_bytes=55\n"
	peers, err := darwinPublicState(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(peers)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), strings.Repeat("12", 32)) || strings.Contains(string(encoded), strings.Repeat("34", 32)) {
		t.Fatal("secret leaked into status")
	}
	key, _ := hex.DecodeString(public)
	if len(peers) != 1 || peers[0].PublicKey != base64.StdEncoding.EncodeToString(key) || peers[0].ReceivedBytes != 44 || peers[0].SentBytes != 55 || peers[0].LastHandshake.Unix() != 1700000000 || peers[0].LastHandshake.Nanosecond() != 123 {
		t.Fatalf("incorrect public state: %+v", peers)
	}
	if _, err := darwinPublicState("public_key=" + public + "\nrx_bytes=private-secret\n"); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("malformed state not rejected safely")
	}
}
func TestDarwinRouteConflictPreflight(t *testing.T) {
	d := darwinFixture()
	want := netip.MustParsePrefix("10.203.0.2/32")
	ops := darwinOps{addresses: func(int, []string) error { return nil }, routes: func() ([]darwinRoute, error) {
		return []darwinRoute{{netip.MustParsePrefix("0.0.0.0/0"), 1}, {netip.MustParsePrefix("10.203.0.0/24"), 2}}, nil
	}}
	if err := darwinPreflight(ops, 7, d.Config, []netip.Prefix{want}); err == nil {
		t.Fatal("unrelated overlapping route accepted")
	}
	ops.routes = func() ([]darwinRoute, error) {
		return []darwinRoute{{netip.MustParsePrefix("0.0.0.0/0"), 1}, {want, 7}}, nil
	}
	if err := darwinPreflight(ops, 7, d.Config, []netip.Prefix{want}); err != nil {
		t.Fatal(err)
	}
	ops.addresses = func(int, []string) error { return errors.New("address conflict") }
	if err := darwinPreflight(ops, 7, d.Config, nil); err == nil {
		t.Fatal("address conflict accepted")
	}
}

type darwinFakeDevice struct {
	updates []string
	fail    bool
	closes  int
}

func (d *darwinFakeDevice) IpcSet(s string) error {
	d.updates = append(d.updates, s)
	if d.fail {
		d.fail = false
		return errors.New("private backend failure")
	}
	return nil
}
func (d *darwinFakeDevice) IpcGet() (string, error) { return "", nil }
func (d *darwinFakeDevice) Up() error               { return nil }
func (d *darwinFakeDevice) Close()                  { d.closes++ }
func TestDarwinReconcileRejectsAddressChangeBeforeMutation(t *testing.T) {
	old := darwinFixture()
	dev := &darwinFakeDevice{}
	session := darwinSession{dev: dev, desired: old, owned: map[netip.Prefix]bool{}}
	next := darwinCopy(old)
	next.Config.Interface.Address = []string{"10.203.1.1/32"}
	if err := session.Reconcile(context.Background(), next); err == nil {
		t.Fatal("live address change accepted")
	}
	if len(dev.updates) != 0 {
		t.Fatal("rejected configuration changed device state")
	}
}
func TestDarwinReconcileFailureRestoresExistingPeers(t *testing.T) {
	old := darwinFixture()
	dev := &darwinFakeDevice{fail: true}
	p := netip.MustParsePrefix("10.203.0.2/32")
	session := darwinSession{dev: dev, desired: darwinCopy(old), index: 7, owned: map[netip.Prefix]bool{p: true}, ops: darwinOps{addresses: func(int, []string) error { return nil }, routes: func() ([]darwinRoute, error) { return []darwinRoute{{p, 7}}, nil }}}
	next := darwinCopy(old)
	next.Config.Peers[0].Endpoint = "127.0.0.1:51822"
	err := session.Reconcile(context.Background(), next)
	if err == nil || strings.Contains(err.Error(), "private backend failure") {
		t.Fatal("backend failure was not safely reported")
	}
	if len(dev.updates) != 2 || !strings.Contains(dev.updates[1], "endpoint=127.0.0.1:51821\n") {
		t.Fatal("old endpoint not restored after failed update")
	}
	if session.desired.Config.Peers[0].Endpoint != old.Config.Peers[0].Endpoint {
		t.Fatal("failed desired state committed")
	}
}
func TestDarwinCloseNeverDeletesForeignRoute(t *testing.T) {
	p := netip.MustParsePrefix("10.203.0.2/32")
	dev := &darwinFakeDevice{}
	commands := 0
	s := darwinSession{dev: dev, index: 7, owned: map[netip.Prefix]bool{p: true}, ops: darwinOps{routes: func() ([]darwinRoute, error) { return []darwinRoute{{p, 9}}, nil }, command: func(context.Context, string, ...string) error { commands++; return nil }}}
	if err := s.Close(context.Background()); err == nil {
		t.Fatal("foreign ownership change not reported")
	}
	if commands != 0 || dev.closes != 1 {
		t.Fatal("foreign route modified or owned interface leaked")
	}
	if err := s.Close(context.Background()); err != nil || dev.closes != 1 {
		t.Fatal("close is not idempotent")
	}
}
