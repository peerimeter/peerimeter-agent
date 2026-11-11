package local

import (
	"bytes"
	"context"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestExclusiveAndPersistedChoice(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	guard, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if other, err := Acquire(dir); err == nil {
		other.Close()
		t.Fatal("two managers accepted")
	}
	name, err := guard.InterfaceChoice("id-a", "production", "")
	if err != nil || name != "pm-production" {
		t.Fatalf("%s %v", name, err)
	}
	name, err = guard.InterfaceChoice("id-a", "renamed", "")
	if err != nil || name != "pm-production" {
		t.Fatal("persisted choice changed")
	}
	if _, err := guard.InterfaceChoice("id-a", "renamed", "wg-new"); err == nil {
		t.Fatal("implicit rename accepted")
	}
	if _, err := guard.InterfaceChoice("id-b", "other", ""); err == nil {
		t.Fatal("another network accepted")
	}
}
func TestLocalChannel(t *testing.T) {
	dir, err := os.MkdirTemp("", "pmipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	guard, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	ctx := context.Background()
	var reloaded atomic.Bool
	var stopped atomic.Bool
	closeServer, err := Serve(ctx, dir, Operations{Snapshot: func(context.Context) (platform.Snapshot, error) {
		return platform.Snapshot{NetworkID: "test", State: "running", Peers: []platform.PeerState{}}, nil
	}, Reload: func(context.Context) error { reloaded.Store(true); return nil }, Stop: func() { stopped.Store(true) }})
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	var out bytes.Buffer
	if err = Request(ctx, dir, "status", &out); err != nil || !bytes.Contains(out.Bytes(), []byte(`"state":"running"`)) {
		t.Fatalf("%s %v", out.String(), err)
	}
	out.Reset()
	if err = Request(ctx, dir, "reload", &out); err != nil || !reloaded.Load() {
		t.Fatal(err)
	}
	out.Reset()
	if err = Request(ctx, dir, "stop", &out); err != nil || !stopped.Load() {
		t.Fatal(err)
	}
}
