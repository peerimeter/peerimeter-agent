// Package discovery selects the system's primary physical underlay interface.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Underlay struct {
	Name      string   `json:"interface_name"`
	Addresses []string `json:"addresses"`
}

// PrimaryUnderlay asks the OS routing table which interface would carry an
// ordinary public IPv4/IPv6 packet, then reports only that interface's unicast
// addresses. UDP Dial selects a route but does not transmit a packet.
func PrimaryUnderlay(ctx context.Context) (Underlay, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	interfaces, err := net.Interfaces()
	if err != nil {
		return Underlay{}, errors.New("cannot enumerate network interfaces")
	}
	for _, target := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"} {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", target)
		if err != nil {
			continue
		}
		addr, _, err := net.SplitHostPort(conn.LocalAddr().String())
		_ = conn.Close()
		if err != nil {
			continue
		}
		source, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		source = source.Unmap()
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 || virtualName(iface.Name) {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			var result []string
			containsSource := false
			for _, raw := range addrs {
				prefix, ok := interfacePrefix(raw)
				if !ok || !usableUnderlayAddress(prefix.Addr()) {
					continue
				}
				result = append(result, prefix.String())
				if ownsSourceAddress(prefix, source) {
					containsSource = true
				}
			}
			if containsSource && len(result) > 0 {
				sort.Strings(result)
				return Underlay{Name: iface.Name, Addresses: result}, nil
			}
		}
	}
	return Underlay{}, fmt.Errorf("default route uses no eligible physical interface")
}

func ownsSourceAddress(prefix netip.Prefix, source netip.Addr) bool {
	return prefix.Addr().Unmap() == source.Unmap()
}

func interfacePrefix(raw net.Addr) (netip.Prefix, bool) {
	switch value := raw.(type) {
	case *net.IPNet:
		prefix, err := netip.ParsePrefix(value.String())
		return prefix, err == nil
	case *net.IPAddr:
		addr, err := netip.ParseAddr(value.IP.String())
		if err != nil {
			return netip.Prefix{}, false
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(addr, bits), true
	default:
		return netip.Prefix{}, false
	}
}

func usableUnderlayAddress(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast() && !addr.IsUnspecified() && !addr.Is4In6()
}

// SelectEndpoint prefers a peer's primary-interface address only when the
// reported interface CIDRs overlap. Otherwise it uses a validated public UDP
// endpoint if one is available.
func SelectEndpoint(local, peer []string, peerPort int, publicEndpoint string) (string, bool) {
	for _, localRaw := range local {
		localPrefix, err := netip.ParsePrefix(localRaw)
		if err != nil {
			continue
		}
		for _, peerRaw := range peer {
			peerPrefix, err := netip.ParsePrefix(peerRaw)
			if err == nil && localPrefix.Overlaps(peerPrefix) && peerPort > 0 && peerPort <= 65535 {
				return net.JoinHostPort(peerPrefix.Addr().String(), fmt.Sprint(peerPort)), true
			}
		}
	}
	endpoint, err := netip.ParseAddrPort(publicEndpoint)
	if err == nil && endpoint.Port() > 0 && endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLinkLocalUnicast() && endpoint.Addr().Zone() == "" {
		return endpoint.String(), true
	}
	return "", false
}

// EndpointConflictsWithRoutes reports whether the endpoint address would be
// routed through any WireGuard AllowedIPs prefix.
func EndpointConflictsWithRoutes(endpoint string, routes []string) bool {
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return false
	}
	for _, raw := range routes {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(address.Addr()) {
			return true
		}
	}
	return false
}

func virtualName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"lo", "utun", "tun", "tap", "wg", "wintun", "wireguard", "docker", "br-", "virbr", "veth", "vbox", "vmnet", "tailscale", "zerotier", "vEthernet"} {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}
