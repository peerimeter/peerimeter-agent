package local

import (
	"bytes"
	"context"
	"errors"
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
	guard, err := Acquire(filepath.Join(dir, "persistent"))
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

func TestExistingGuardNeverCreatesMissingStateAndBlocksLiveManager(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent-state")
	guard, err := TryAcquireExisting(missing)
	if err != nil || guard != nil {
		t.Fatal("absent state was not recognized")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("quiescence check created state directory")
	}
	dir := filepath.Join(t.TempDir(), "state")
	active, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := TryAcquireExisting(dir); err == nil {
		if second != nil {
			second.Close()
		}
		t.Fatal("live state owner was accepted as stopped")
	}
	active.Close()
	stopped, err := TryAcquireExisting(dir)
	if err != nil || stopped == nil {
		t.Fatalf("stopped state could not be locked: %v", err)
	}
	stopped.Close()
}

func TestProfileCallbackRunsOnlyAfterExclusiveRuntimeOwnership(t *testing.T) {
	dir, err := os.MkdirTemp("", "pmready-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	var callbacks atomic.Int32
	ops := Operations{BeforeServe: func() error { callbacks.Add(1); return nil }, Snapshot: func(context.Context) (platform.Snapshot, error) { return platform.Snapshot{State: "running"}, nil }, Reload: func(context.Context) error { return nil }, Stop: func() {}}
	closeServer, err := Serve(context.Background(), dir, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	if callbacks.Load() != 1 {
		t.Fatal("owned runtime did not reach inventory callback")
	}
	if second, err := Serve(context.Background(), dir, ops); err == nil {
		second()
		t.Fatal("second profile claimed an active runtime")
	}
	if callbacks.Load() != 1 {
		t.Fatal("failed runtime acquisition still changed profile ownership")
	}
	var status bytes.Buffer
	if err := Request(context.Background(), dir, "status", &status); err != nil {
		t.Fatal("failed competing listener disturbed active instance", err)
	}
}
func TestProfileCallbackFailureReleasesOnlyItsOwnedRuntime(t *testing.T) {
	dir, err := os.MkdirTemp("", "pmready-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	failure := errors.New("profile cannot claim runtime")
	if closeServer, err := Serve(context.Background(), dir, Operations{BeforeServe: func() error { return failure }}); !errors.Is(err, failure) || closeServer != nil {
		t.Fatal("profile callback failure was not returned before serving")
	}
	closeServer, err := Serve(context.Background(), dir, Operations{Snapshot: func(context.Context) (platform.Snapshot, error) { return platform.Snapshot{State: "running"}, nil }, Reload: func(context.Context) error { return nil }, Stop: func() {}})
	if err != nil {
		t.Fatal("failed callback leaked runtime ownership", err)
	}
	closeServer()
}

func TestRuntimeCloseCallbackRunsOnceAndErrorIsReported(t *testing.T) {
	dir, err := os.MkdirTemp("", "pmclose-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	failure := errors.New("runtime marker cleanup failed")
	var closed atomic.Int32
	closeServer, err := Serve(context.Background(), dir, Operations{OnClose: func() error { closed.Add(1); return failure }, Snapshot: func(context.Context) (platform.Snapshot, error) { return platform.Snapshot{State: "running"}, nil }, Reload: func(context.Context) error { return nil }, Stop: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	if err := closeServer(); !errors.Is(err, failure) {
		t.Fatalf("listener callback error was hidden by HTTP shutdown: %v", err)
	}
	if err := closeServer(); !errors.Is(err, failure) {
		t.Fatal("repeated close forgot original cleanup error")
	}
	if closed.Load() != 1 {
		t.Fatal("runtime cleanup callback ran more than once")
	}
}
