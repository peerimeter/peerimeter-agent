// Package agent separates foreground lifetime from platform/service management.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
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
func RunManaged(ctx context.Context, backend platform.Backend, desired platform.Desired, dir string, reload func() (platform.Desired, error), operator, instanceID string, beforeServe, onClose func() error) (result error) {
	return RunManagedWithRefresh(ctx, backend, desired, dir, func(context.Context) (platform.Desired, error) { return reload() }, operator, instanceID, beforeServe, onClose, 0, "", nil)
}

// RunManagedWithRefresh periodically obtains desired state from reload while
// preserving the same local authenticated control surface as static mode.
func RunManagedWithRefresh(ctx context.Context, backend platform.Backend, desired platform.Desired, dir string, reload func(context.Context) (platform.Desired, error), operator, instanceID string, beforeServe, onClose func() error, interval time.Duration, configPath string, replaceConfig func([]byte) (func() error, error)) (result error) {
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
	currentDesired := desired
	reconcile := func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		next, err := reload(ctx)
		if err != nil {
			return err
		}
		if next.Config.Network.ID != desired.Config.Network.ID || next.InterfaceName != desired.InterfaceName {
			return errors.New("reload cannot change the local network identity or interface")
		}
		if err := session.Reconcile(ctx, next); err != nil {
			return err
		}
		currentDesired = next
		return nil
	}
	closeControl, err := local.Serve(ctx, dir, local.Operations{Operator: operator, InstanceID: instanceID, NetworkID: desired.Config.Network.ID, ConfigPath: configPath, BeforeListen: beforeServe, OnClose: onClose,
		Config: func() ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			return json.Marshal(currentDesired.Config)
		},
		ReplaceConfig: replaceConfig,
		Snapshot: func(ctx context.Context) (platform.Snapshot, error) {
			mu.Lock()
			defer mu.Unlock()
			snapshot, err := session.Snapshot(ctx)
			snapshot.InstanceID = instanceID
			return snapshot, err
		},
		Reload: func(ctx context.Context) error {
			return reconcile(ctx)
		},
		Stop: cancel,
	})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeControl()) }()
	var workers sync.WaitGroup
	defer workers.Wait()
	if interval > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					refreshCtx, done := context.WithTimeout(ctx, 10*time.Second)
					if err := reconcile(refreshCtx); err != nil && !errors.Is(err, context.Canceled) {
						slog.Warn("managed network refresh failed", "network_id", desired.Config.Network.ID, "error", err)
					}
					done()
				}
			}
		}()
	}
	<-ctx.Done()
	return nil
}
