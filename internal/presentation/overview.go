package presentation

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

// PeerOverview displays public identity, connection and observed activity in
// separate columns. Narrow terminals use two-column detail tables without
// dropping keys, endpoints or observed state.
func PeerOverview(out io.Writer, snapshot platform.Snapshot, now time.Time, color bool, width int) error {
	network := safe(snapshot.NetworkID)
	if snapshot.NetworkName != "" {
		network = safe(snapshot.NetworkName) + " (" + network + ")"
	}
	summary := [][]string{{"Network", network}, {"Interface", snapshot.InterfaceName}, {"Listen port", fmt.Sprint(snapshot.ListenPort)}, {"Peers", fmt.Sprint(len(snapshot.Peers))}}
	if snapshot.PublicKey != "" {
		summary = append(summary, []string{"Public key", snapshot.PublicKey})
	}
	if snapshot.State != "" {
		summary = append(summary, []string{"Agent state", snapshot.State})
	}
	if err := Table(out, []string{"Field", "Value"}, summary, color, width); err != nil {
		return err
	}
	peers := append([]platform.PeerState(nil), snapshot.Peers...)
	sort.SliceStable(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	if len(peers) == 0 {
		_, err := io.WriteString(out, "\nNo peers configured.\n")
		return err
	}
	if _, err := io.WriteString(out, "\n"); err != nil {
		return err
	}
	rows := make([][]string, 0, len(peers))
	for _, p := range peers {
		endpoint, routes := safe(p.Endpoint), safe(strings.Join(p.AllowedIPs, ", "))
		if endpoint == "" {
			endpoint = "not set"
		}
		if routes == "" {
			routes = "none"
		}
		keepalive := "off"
		if p.PersistentKeepaliveSeconds > 0 {
			keepalive = fmt.Sprintf("every %d seconds", p.PersistentKeepaliveSeconds)
		}
		if width < 70 {
			if err := Table(out, []string{"Peer field", "Value"}, [][]string{
				{"Public key", p.PublicKey}, {"Endpoint", endpoint}, {"Allowed IPs", routes}, {"Handshake", HandshakeAge(p.LastHandshake, now)},
				{"Received", FormatBytes(p.ReceivedBytes)}, {"Sent", FormatBytes(p.SentBytes)}, {"Keepalive", keepalive},
			}, color, width); err != nil {
				return err
			}
			continue
		}
		if width >= 120 {
			rows = append(rows, []string{safe(p.PublicKey), endpoint, routes, HandshakeAge(p.LastHandshake, now), FormatBytes(p.ReceivedBytes), FormatBytes(p.SentBytes), keepalive})
			continue
		}
		rows = append(rows, []string{
			safe(p.PublicKey),
			"Endpoint: " + endpoint + "\nAllowed IPs: " + routes + "\nKeepalive: " + keepalive,
			"Handshake: " + HandshakeAge(p.LastHandshake, now) + "\nReceived: " + FormatBytes(p.ReceivedBytes) + "\nSent: " + FormatBytes(p.SentBytes),
		})
	}
	if width < 70 {
		return nil
	}
	if width >= 120 {
		return Table(out, []string{"Public key", "Endpoint", "Allowed IPs", "Handshake", "Received", "Sent", "Keepalive"}, rows, color, width)
	}
	return Table(out, []string{"Public key", "Connection", "Activity"}, rows, color, width)
}

func StatusOverview(out io.Writer, snapshot platform.Snapshot, now time.Time, color bool, width int) error {
	return PeerOverview(out, snapshot, now, color, width)
}
