package cli

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/paths"
)

func TestDaemonSyncIntervalDefaultsToFiveMinutes(t *testing.T) {
	if defaultDaemonSyncInterval != 5*time.Minute {
		t.Fatalf("default sync interval = %s; want 5m", defaultDaemonSyncInterval)
	}
}

func TestDaemonSyncArgsTargetActiveNetworkAndCarryDirectoryOverrides(t *testing.T) {
	got := daemonSyncArgs(paths.Options{ConfigDir: "/config", StateDir: "/state", RuntimeDir: "/runtime"}, "network-1")
	want := []string{"sync", "--network-id", "network-1", "--config-dir", "/config", "--state-dir", "/state", "--runtime-dir", "/runtime"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("daemonSyncArgs() = %#v; want %#v", got, want)
	}
	localOnly := daemonSyncArgs(paths.Options{}, "")
	if !reflect.DeepEqual(localOnly, []string{"sync"}) {
		t.Fatalf("daemonSyncArgs() without a joined network = %#v; want local sync", localOnly)
	}
}

func TestPeriodicSyncRepeatsAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		runPeriodicSync(ctx, 10*time.Millisecond, func(context.Context) error {
			calls <- struct{}{}
			return errors.New("temporary failure")
		})
		close(done)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("periodic sync did not run")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("periodic sync did not stop after cancellation")
	}
}

func TestPeriodicSyncRunsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runPeriodicSync(ctx, time.Hour, func(context.Context) error {
			calls <- struct{}{}
			return nil
		})
		close(done)
	}()

	select {
	case <-calls:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("periodic sync did not run immediately")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("periodic sync did not stop after cancellation")
	}
}
