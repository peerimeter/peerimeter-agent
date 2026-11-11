// Package presentation renders only public agent state. The wgshow-style layout
// and unit formatting are adapted from zer0go/wgctrl-go/cmd/wgshow at 47ad6fc7;
// its MIT license and attribution are retained in third_party/wgshow.
package presentation

import (
	"fmt"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
)

func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
func PeerList(out io.Writer, snapshot platform.Snapshot, now time.Time, color bool) error {
	style := func(s, code string) string {
		s = safe(s)
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", style("interface", "1;32"), style(snapshot.InterfaceName, "32"))
	fmt.Fprintf(&b, "  network: %s", safe(snapshot.NetworkID))
	if snapshot.NetworkName != "" {
		fmt.Fprintf(&b, " (%s)", safe(snapshot.NetworkName))
	}
	b.WriteByte('\n')
	if snapshot.PublicKey != "" {
		fmt.Fprintf(&b, "  public key: %s\n", safe(snapshot.PublicKey))
	}
	fmt.Fprintf(&b, "  private key: (hidden)\n  listening port: %d\n", snapshot.ListenPort)
	peers := append([]platform.PeerState(nil), snapshot.Peers...)
	sort.SliceStable(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	if len(peers) == 0 {
		b.WriteString("\nNo peers configured.\n")
	}
	for _, p := range peers {
		endpoint := p.Endpoint
		if endpoint == "" {
			endpoint = "(not set)"
		}
		routes := strings.Join(p.AllowedIPs, ", ")
		if routes == "" {
			routes = "(none)"
		}
		fmt.Fprintf(&b, "\n%s: %s\n", style("peer", "1;33"), style(p.PublicKey, "33"))
		fmt.Fprintf(&b, "  endpoint: %s\n  allowed ips: %s\n  latest handshake: %s\n", safe(endpoint), safe(routes), HandshakeAge(p.LastHandshake, now))
		fmt.Fprintf(&b, "  transfer: %s received, %s sent\n", FormatBytes(p.ReceivedBytes), FormatBytes(p.SentBytes))
		keepalive := "off"
		if p.PersistentKeepaliveSeconds > 0 {
			keepalive = "every " + FormatDuration(time.Duration(p.PersistentKeepaliveSeconds)*time.Second)
		}
		fmt.Fprintf(&b, "  persistent keepalive: %s\n", keepalive)
	}
	_, err := io.WriteString(out, b.String())
	return err
}
func HandshakeAge(stamp, now time.Time) string {
	if stamp.IsZero() {
		return "never"
	}
	if stamp.After(now) {
		return "in the future (clock skew)"
	}
	age := now.Sub(stamp)
	if age < time.Second {
		return "just now"
	}
	return FormatDuration(age) + " ago"
}
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	seconds := int64(d / time.Second)
	units := []struct {
		n    int64
		name string
	}{{86400, "day"}, {3600, "hour"}, {60, "minute"}, {1, "second"}}
	parts := []string{}
	for _, unit := range units {
		n := seconds / unit.n
		seconds %= unit.n
		if n == 0 && unit.n != 1 {
			continue
		}
		name := unit.name
		if n != 1 {
			name += "s"
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, name))
	}
	return strings.Join(parts, ", ")
}
func FormatBytes(value uint64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	n := float64(value) / 1024
	unit := 0
	for n >= 1024 && unit < len(units)-1 {
		n /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", n, units[unit])
}
