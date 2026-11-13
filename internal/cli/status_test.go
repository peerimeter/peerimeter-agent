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
