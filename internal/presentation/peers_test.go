package presentation

import (
	"bytes"
	"errors"
	"github.com/charmbracelet/lipgloss"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"math"
	"strings"
	"testing"
	"time"
)

func TestPeerListMissingAndClockStates(t *testing.T) {
	now := time.Unix(1730000000, 0)
	snapshot := platform.Snapshot{NetworkID: "net", NetworkName: "home", InterfaceName: "pm-home", PublicKey: "interface-public", ListenPort: 51820, Peers: []platform.PeerState{{PublicKey: "peer-public", ReceivedBytes: 1024, SentBytes: math.MaxUint64}}}
	var out bytes.Buffer
	if err := PeerList(&out, snapshot, now, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"interface: pm-home", "network: net (home)", "private key: (hidden)", "endpoint: (not set)", "allowed ips: (none)", "latest handshake: never", "1.0 KiB received", "16.0 EiB sent", "persistent keepalive: off"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("missing %q in %s", expected, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("plain output has ANSI")
	}
	snapshot.Peers[0].LastHandshake = now.Add(2 * time.Hour)
	snapshot.Peers[0].AllowedIPs = []string{"10.80.0.2/32"}
	snapshot.Peers[0].PersistentKeepaliveSeconds = 25
	out.Reset()
	if err := PeerList(&out, snapshot, now, true); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"\x1b[1;33m", "clock skew", "10.80.0.2/32", "every 25 seconds"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatal("missing colored/state field", expected)
		}
	}
	snapshot.Peers = nil
	out.Reset()
	if err := PeerList(&out, snapshot, now, false); err != nil || !strings.Contains(out.String(), "No peers configured") {
		t.Fatal("empty peer list not explicit")
	}
}
func TestUnits(t *testing.T) {
	for _, c := range []struct {
		value uint64
		want  string
	}{{0, "0 B"}, {1, "1 B"}, {1023, "1023 B"}, {1024, "1.0 KiB"}, {1 << 30, "1.0 GiB"}, {math.MaxUint64, "16.0 EiB"}} {
		if got := FormatBytes(c.value); got != c.want {
			t.Fatalf("%d: %s", c.value, got)
		}
	}
	for _, c := range []struct {
		d    time.Duration
		want string
	}{{0, "0 seconds"}, {time.Second, "1 second"}, {24*time.Hour + time.Hour + time.Minute + time.Second, "1 day, 1 hour, 1 minute, 1 second"}} {
		if got := FormatDuration(c.d); got != c.want {
			t.Fatal(got)
		}
	}
}
func TestHandshakeAge(t *testing.T) {
	now := time.Now()
	if HandshakeAge(time.Time{}, now) != "never" || HandshakeAge(now, now) != "just now" || HandshakeAge(now.Add(-time.Second), now) != "1 second ago" {
		t.Fatal("invalid handshake age")
	}
}
func TestTextControlInjectionRemoved(t *testing.T) {
	var out bytes.Buffer
	if err := PeerList(&out, platform.Snapshot{NetworkID: "net\nSECRET-CONTROL", InterfaceName: "name\x1b[31m"}, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "net\nSECRET") {
		t.Fatal("untrusted terminal controls preserved")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failure") }
func TestWriterFailure(t *testing.T) {
	if PeerList(failWriter{}, platform.Snapshot{}, time.Now(), false) == nil {
		t.Fatal("lost writer failure")
	}
}

func TestOverviewLayoutAndPublicValues(t *testing.T) {
	now := time.Unix(1730000000, 0)
	snapshot := platform.Snapshot{NetworkID: "mesh", InterfaceName: "pm-test", Peers: []platform.PeerState{
		{PublicKey: "zz-public", Endpoint: "[2001:db8::1]:51820", AllowedIPs: []string{"10.1.0.2/32"}, LastHandshake: now.Add(time.Hour)},
		{PublicKey: "aa-public", PersistentKeepaliveSeconds: 25, ReceivedBytes: 1024},
	}}
	for _, width := range []int{20, 40, 80, 160} {
		var out bytes.Buffer
		if err := PeerOverview(&out, snapshot, now, false, width); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "\x1b") {
			t.Fatal("ANSI in plain overview")
		}
		for _, line := range strings.Split(out.String(), "\n") {
			if lipgloss.Width(line) > width {
				t.Fatalf("width %d: %q", width, line)
			}
		}
		// Wrapping may split values on very narrow terminals; all text is preserved.
		// Read each rendered table column vertically to reconstruct wrapped values.
		columns := make([]strings.Builder, 7)
		for _, line := range strings.Split(out.String(), "\n") {
			cells := strings.Split(line, "│")
			if len(cells) < 3 {
				continue
			}
			for i, cell := range cells[1 : len(cells)-1] {
				if i < len(columns) {
					columns[i].WriteString(strings.Join(strings.Fields(cell), ""))
				}
			}
		}
		compact := ""
		for i := range columns {
			compact += columns[i].String() + "\n"
		}

		for _, value := range []string{"aa-public", "zz-public", "[2001:db8::1]:51820", "10.1.0.2/32", "clockskew", "1.0KiB", "every25seconds"} {
			if !strings.Contains(compact, value) {
				t.Fatalf("missing %s at width %d: %s", value, width, out.String())
			}
		}
		if strings.Index(compact, "aa-public") > strings.Index(compact, "zz-public") {
			t.Fatal("peers not sorted")
		}
	}
	var out bytes.Buffer
	if err := PeerOverview(&out, snapshot, now, true, 80); err != nil || !strings.Contains(out.String(), "\x1b[") {
		t.Fatal("missing color", err)
	}
	if PeerOverview(failWriter{}, snapshot, now, false, 80) == nil {
		t.Fatal("lost write failure")
	}
	out.Reset()
	if err := PeerOverview(&out, platform.Snapshot{NetworkID: "mesh\x1b[31m\ncontrol"}, now, false, 80); err != nil || strings.Contains(out.String(), "\x1b") {
		t.Fatal("unsafe output", err)
	}
	out.Reset()
	if err := PeerOverview(&out, platform.Snapshot{}, now, false, 80); err != nil || !strings.Contains(out.String(), "No peers configured.") {
		t.Fatal("missing empty state", err)
	}
}
