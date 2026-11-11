// Package agent separates foreground lifetime from platform/service management.
package agent

import (
	"context"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"log/slog"
	"sync"
	"time"
)

func Run(ctx context.Context, backend platform.Backend, desired platform.Desired) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := backend.Start(ctx, desired)
	if err != nil {
		return err
	}
	<-ctx.Done()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.Close(cleanup); err != nil {
		return errors.Join(errors.New("native tunnel cleanup failed"), err)
	}
	return nil
}

// RunManaged exposes only protected local control after the native tunnel starts.
// Reload validation happens before the backend touches OS state.
func RunManaged(ctx context.Context, backend platform.Backend, desired platform.Desired, dir string, reload func() (platform.Desired, error)) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	session, err := backend.Start(ctx, desired)
	if err != nil {
		return err
	}
	slog.Info("native tunnel started", "network_id", desired.Config.Network.ID)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		result = errors.Join(result, session.Close(cleanup))
	}()
	var mu sync.Mutex
	closeControl, err := local.Serve(ctx, dir, local.Operations{
		Snapshot: func(ctx context.Context) (platform.Snapshot, error) {
			mu.Lock()
			defer mu.Unlock()
			return session.Snapshot(ctx)
		},
		Reload: func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			next, err := reload()
			if err != nil {
				return err
			}
			if next.Config.Network.ID != desired.Config.Network.ID || next.InterfaceName != desired.InterfaceName {
				return errors.New("reload cannot change the local network identity or interface")
			}
			return session.Reconcile(ctx, next)
		},
		Stop: cancel,
	})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeControl()) }()
	<-ctx.Done()
	return nil
}
