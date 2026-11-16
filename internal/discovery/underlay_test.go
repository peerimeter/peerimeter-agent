package discovery

import (
	"net"
	"net/netip"
	"testing"
)

func TestVirtualNameFilter(t *testing.T) {
	for _, name := range []string{"lo", "lo0", "utun3", "wg0", "wintun", "docker0", "br-abc", "vEthernet (Default Switch)"} {
		if !virtualName(name) {
			t.Errorf("virtual interface %q was not filtered", name)
		}
	}
	for _, name := range []string{"eth0", "en0", "Ethernet", "Wi-Fi"} {
		if virtualName(name) {
			t.Errorf("physical interface %q was filtered", name)
		}
	}
}

func TestInterfacePrefixAndAddressEligibility(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.50.12/24")
	prefix, ok := interfacePrefix(network)
	if !ok || prefix.String() != "192.168.50.0/24" {
		t.Fatalf("prefix = %v, ok = %t", prefix, ok)
	}
	for _, tc := range []struct {
		address string
		want    bool
	}{{"192.168.50.12", true}, {"fd00::2", true}, {"169.254.1.2", false}, {"127.0.0.1", false}, {"224.0.0.1", false}, {"0.0.0.0", false}} {
		if got := usableUnderlayAddress(netip.MustParseAddr(tc.address)); got != tc.want {
			t.Errorf("usableUnderlayAddress(%s) = %t, want %t", tc.address, got, tc.want)
		}
	}
}

func TestRouteSourceMustBelongToInterfaceAddress(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.20.10/24")
	if !ownsSourceAddress(prefix, netip.MustParseAddr("192.168.20.10")) {
		t.Fatal("interface's configured address was not matched")
	}
	if ownsSourceAddress(prefix, netip.MustParseAddr("192.168.20.15")) {
		t.Fatal("another address in the same subnet was incorrectly matched")
	}
}

func TestSelectEndpointUsesSharedLANPrefixThenPublicFallback(t *testing.T) {
	endpoint, ok := SelectEndpoint([]string{"192.168.20.15/24"}, []string{"192.168.20.28/24"}, 51821, "203.0.113.8:51821")
	if !ok || endpoint != "192.168.20.28:51821" {
		t.Fatalf("same-LAN endpoint = %q, %t", endpoint, ok)
	}
	endpoint, ok = SelectEndpoint([]string{"192.168.20.15/24"}, []string{"192.168.40.28/24"}, 51821, "8.8.8.8:51821")
	if !ok || endpoint != "8.8.8.8:51821" {
		t.Fatalf("public fallback = %q, %t", endpoint, ok)
	}
	if endpoint, ok = SelectEndpoint([]string{"192.168.20.15/24"}, []string{"192.168.40.28/24"}, 51821, ""); ok || endpoint != "" {
		t.Fatalf("accepted missing endpoint = %q, %t", endpoint, ok)
	}
}

func TestEndpointConflictsWithTunnelRoute(t *testing.T) {
	if !EndpointConflictsWithRoutes("192.168.1.20:51820", []string{"192.168.1.20/32"}) {
		t.Fatal("endpoint matching a tunnel route was not rejected")
	}
	if EndpointConflictsWithRoutes("192.168.1.21:51820", []string{"192.168.1.20/32"}) {
		t.Fatal("unrelated endpoint was marked as conflicting")
	}
}
