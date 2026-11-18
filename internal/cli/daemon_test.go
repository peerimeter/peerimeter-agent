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

func TestDaemonSyncArgsCarryDirectoryOverrides(t *testing.T) {
	got := daemonSyncArgs(paths.Options{ConfigDir: "/config", StateDir: "/state", RuntimeDir: "/runtime"})
	want := []string{"sync", "--config-dir", "/config", "--state-dir", "/state", "--runtime-dir", "/runtime"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("daemonSyncArgs() = %#v; want %#v", got, want)
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
