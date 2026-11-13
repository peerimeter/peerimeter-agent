package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

func TestStatusWatchJSONStreamsSnapshotsUntilCanceled(t *testing.T) {
	base := ""
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "pmwatch-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	runtimeDir := filepath.Join(dir, "runtime")
	closeServer, err := local.Serve(context.Background(), runtimeDir, local.Operations{
		Snapshot: func(context.Context) (platform.Snapshot, error) {
			return platform.Snapshot{NetworkID: "watch-test", InterfaceName: "pm-test", State: "running"}, nil
		},
		Reload: func(context.Context) error { return nil },
		Stop:   func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out, stderr bytes.Buffer
	code := execute(ctx, []string{"status", "--watch", "--interval", "10ms", "--runtime-dir", runtimeDir, "--json"}, &out, &stderr, platform.Native())
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("status watch returned %d: stdout=%s stderr=%s", code, out.String(), stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("watch should emit repeated snapshots, got %d: %s", len(lines), out.String())
	}
	for _, line := range lines {
		var snapshot platform.Snapshot
		if err := json.Unmarshal([]byte(line), &snapshot); err != nil || snapshot.NetworkID != "watch-test" {
			t.Fatalf("invalid watched JSON snapshot %q: %v", line, err)
		}
	}
}

func TestStatusIntervalRequiresWatch(t *testing.T) {
	code, _, stderr := invoke(t, "status", "--interval", "1s")
	if code == 0 || !strings.Contains(stderr, "--interval requires --watch") {
		t.Fatalf("expected interval validation error, got code=%d stderr=%q", code, stderr)
	}
}

func TestStatusWatchConsoleRequiresInteractiveTerminal(t *testing.T) {
	code, _, stderr := invoke(t, "status", "--watch", "--color", "never")
	if code == 0 || !strings.Contains(stderr, "use --json for a snapshot stream") {
		t.Fatalf("expected non-interactive watch guidance, got code=%d stderr=%q", code, stderr)
	}
}

func TestStatusWatchViewportScrollsToLaterPeers(t *testing.T) {
	model := statusWatchModel{
		interval: time.Second,
		width:    100,
		height:   10,
		updated:  time.Now(),
		snapshot: platform.Snapshot{NetworkID: "watch-test", InterfaceName: "pm-test", State: "running", Peers: []platform.PeerState{
			{PublicKey: "peer-a", AllowedIPs: []string{"10.0.0.1/32"}},
			{PublicKey: "peer-b", AllowedIPs: []string{"10.0.0.2/32"}},
			{PublicKey: "peer-c", AllowedIPs: []string{"10.0.0.3/32"}},
			{PublicKey: "peer-d", AllowedIPs: []string{"10.0.0.4/32"}},
			{PublicKey: "peer-e", AllowedIPs: []string{"10.0.0.5/32"}},
			{PublicKey: "peer-f", AllowedIPs: []string{"10.0.0.6/32"}},
		}},
	}
	if view := model.View(); !strings.Contains(view, "Network") || !strings.Contains(view, "q to quit") {
		t.Fatalf("initial view omitted status summary or footer: %s", view)
	}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnd})
	view := updated.(statusWatchModel).View()
	if !strings.Contains(view, "peer-f") || strings.Contains(view, "peer-a") {
		t.Fatalf("end key did not scroll to the last peer: %s", view)
	}
}
