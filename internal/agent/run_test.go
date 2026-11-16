package agent

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

type fake struct {
	started            chan struct{}
	closed             bool
	startErr, closeErr error
	refreshDone        <-chan struct{}
}

func (f *fake) Start(context.Context, platform.Desired) (platform.Session, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	close(f.started)
	return f, nil
}
func (f *fake) Inspect(context.Context) (platform.Snapshot, error)  { return platform.Snapshot{}, nil }
func (f *fake) Reconcile(context.Context, platform.Desired) error   { return nil }
func (f *fake) Snapshot(context.Context) (platform.Snapshot, error) { return platform.Snapshot{}, nil }
func (f *fake) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.New("cleanup context already canceled")
	}
	if f.refreshDone != nil {
		select {
		case <-f.refreshDone:
		default:
			return errors.New("cleanup ran before refresh worker stopped")
		}
	}
	f.closed = true
	return f.closeErr
}

func TestManagedRefreshStopsBeforeSessionCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	refreshStarted := make(chan struct{})
	refreshDone := make(chan struct{})
	f := &fake{started: make(chan struct{}), refreshDone: refreshDone}
	dir, err := os.MkdirTemp("/tmp", "pm-agent-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	result := make(chan error, 1)
	go func() {
		result <- RunManagedWithRefresh(ctx, f, platform.Desired{Config: config.Config{Network: config.Network{ID: "net-a"}}}, dir, func(refreshCtx context.Context) (platform.Desired, error) {
			close(refreshStarted)
			<-refreshCtx.Done()
			close(refreshDone)
			return platform.Desired{}, refreshCtx.Err()
		}, "", "instance", nil, nil, time.Millisecond)
	}()
	<-f.started
	select {
	case <-refreshStarted:
	case err := <-result:
		t.Fatalf("managed run ended before refresh started: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("refresh worker did not start")
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !f.closed {
		t.Fatal("session was not closed")
	}
}
func TestCancellationCleansWithLiveContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fake{started: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, f, platform.Desired{}) }()
	<-f.started
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !f.closed {
		t.Fatal("missing cleanup")
	}
}
func TestErrorsPropagate(t *testing.T) {
	sentinel := errors.New("failure")
	for _, startup := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		f := &fake{started: make(chan struct{})}
		if startup {
			f.startErr = sentinel
			if err := Run(ctx, f, platform.Desired{}); !errors.Is(err, sentinel) {
				t.Fatalf("startup error lost: %v", err)
			}
			cancel()
			continue
		} else {
			f.closeErr = sentinel
		}
		done := make(chan error, 1)
		go func() { done <- Run(ctx, f, platform.Desired{}) }()
		if !startup {
			<-f.started
		}
		cancel()
		err := <-done
		if !errors.Is(err, sentinel) {
			t.Fatalf("error lost: %v", err)
		}
	}
}
