package platform

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
)

func windowsTestDesired() Desired {
	keyA, keyB := [32]byte{1}, [32]byte{2}
	return Desired{PrivateKey: [32]byte{3}, Config: config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "test-network", Name: "test"},
		Interface: config.Interface{PrivateKeyFile: "test.key", Address: []string{"10.203.0.1/32", "fd44::1/128"}, ListenPort: 51820},
		Peers: []config.Peer{
			{PublicKey: base64.StdEncoding.EncodeToString(keyA[:]), Endpoint: "192.0.2.2:51820", AllowedIPs: []string{"10.203.0.2/32"}, PersistentKeepaliveSeconds: 25},
			{PublicKey: base64.StdEncoding.EncodeToString(keyB[:]), Endpoint: "[2001:db8::2]:51821", AllowedIPs: []string{"fd44::2/128"}},
		}}}
}

func TestWindowsConfigurationInitial(t *testing.T) {
	desired := windowsTestDesired()
	builder, err := windowsConfiguration(nil, desired)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := builder.Interface()
	if cfg.Flags != driver.InterfaceHasPrivateKey|driver.InterfaceHasListenPort || cfg.PrivateKey != desired.PrivateKey || cfg.ListenPort != 51820 || cfg.PeerCount != 2 {
		t.Fatal("initial interface configuration is incorrect")
	}
	peerA := cfg.FirstPeer()
	peerB := peerA.NextPeer()
	if peerA.AllowedIPsCount != 1 || peerA.FirstAllowedIP().AddressFamily != windows.AF_INET || peerA.FirstAllowedIP().Cidr != 32 ||
		peerB.AllowedIPsCount != 1 || peerB.FirstAllowedIP().AddressFamily != windows.AF_INET6 || peerB.FirstAllowedIP().Cidr != 128 {
		t.Fatal("allowed IP address family or prefix translation is incorrect")
	}
	if peerB.Endpoint.AddrPort().String() != "[2001:db8::2]:51821" {
		t.Fatal("IPv6 endpoint translation is incorrect")
	}
}

func TestWindowsConfigurationNoOpAndEndpointDiff(t *testing.T) {
	before := windowsTestDesired()
	next := windowsTestDesired()
	builder, err := windowsConfiguration(&before, next)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := builder.Interface()
	if cfg.Flags != 0 || cfg.PeerCount != 0 {
		t.Fatal("identical desired state must not reset peers or interface")
	}
	next.Config.Peers[0].Endpoint = "192.0.2.22:51999"
	builder, err = windowsConfiguration(&before, next)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ = builder.Interface()
	if cfg.Flags != 0 || cfg.PeerCount != 1 {
		t.Fatal("endpoint update touched unrelated interface or peers")
	}
	peer := cfg.FirstPeer()
	if peer.Flags != driver.PeerHasPublicKey|driver.PeerHasEndpoint || peer.AllowedIPsCount != 0 || peer.Endpoint.AddrPort().String() != "192.0.2.22:51999" {
		t.Fatal("endpoint diff must preserve allowed IPs and keepalive")
	}
}

func TestWindowsConfigurationRemovalAndKeepaliveDisable(t *testing.T) {
	before := windowsTestDesired()
	next := windowsTestDesired()
	next.Config.Peers = next.Config.Peers[:1]
	next.Config.Peers[0].PersistentKeepaliveSeconds = 0
	builder, err := windowsConfiguration(&before, next)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := builder.Interface()
	if cfg.Flags != 0 || cfg.PeerCount != 2 {
		t.Fatal("expected keepalive update and one removal")
	}
	peer := cfg.FirstPeer()
	if peer.Flags != driver.PeerHasPublicKey|driver.PeerHasPersistentKeepalive || peer.PersistentKeepalive != 0 {
		t.Fatal("must explicitly send zero to disable keepalive")
	}
	if peer.NextPeer().Flags != driver.PeerHasPublicKey|driver.PeerRemove {
		t.Fatal("removed peer not deleted through incremental update")
	}
}

func TestWindowsConfigurationIdentityAndListenPortDiff(t *testing.T) {
	before := windowsTestDesired()
	next := windowsTestDesired()
	next.PrivateKey[0]++
	next.Config.Interface.ListenPort++
	builder, err := windowsConfiguration(&before, next)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := builder.Interface()
	if cfg.PeerCount != 0 || cfg.Flags != driver.InterfaceHasPrivateKey|driver.InterfaceHasListenPort || cfg.ListenPort != uint16(next.Config.Interface.ListenPort) || cfg.PrivateKey != next.PrivateKey {
		t.Fatal("local key/port change must not replace peers")
	}
}

func TestWindowsValidationPrecedesNativeChanges(t *testing.T) {
	desired := windowsTestDesired()
	desired.Config.Version = 99
	if _, err := (nativeBackend{}).Start(context.Background(), desired); err == nil {
		t.Fatal("invalid config must fail before driver load")
	}
	desired = windowsTestDesired()
	desired.PrivateKey = [32]byte{}
	if _, err := (nativeBackend{}).Start(context.Background(), desired); err == nil {
		t.Fatal("zero key must fail before driver load")
	}
}

func TestWindowsAdapterNameAndHandshake(t *testing.T) {
	if windowsAdapterName("a") != windowsAdapterName("a") || windowsAdapterName("a") == windowsAdapterName("b") {
		t.Fatal("native adapter name must be stable per network and distinguish IDs")
	}
	if !windowsHandshake(0).IsZero() {
		t.Fatal("missing handshake must not look like a real timestamp")
	}
	now := time.Date(2026, 11, 11, 1, 2, 3, 123456700, time.UTC)
	filetime := uint64(now.Unix())*10000000 + uint64(now.Nanosecond()/100) + 116444736000000000
	if got := windowsHandshake(filetime); !got.Equal(now) {
		t.Fatal("WireGuardNT FILETIME conversion is incorrect")
	}
}
