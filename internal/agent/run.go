// Package agent separates foreground lifetime from platform/service management.
package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"gopkg.in/yaml.v3"
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
	publicKey := ""
	if public, err := secret.Public(desired.PrivateKey); err == nil {
		publicKey = base64.StdEncoding.EncodeToString(public[:])
	}
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
	reconcileLocked := func(ctx context.Context) error {
		next, err := reload(ctx)
		if err != nil {
			return err
		}
		if next.Config.Network.ID != desired.Config.Network.ID || next.InterfaceName != desired.InterfaceName {
			return errors.New("reload cannot change the local network identity or interface")
		}
		if next.PrivateKey != desired.PrivateKey {
			return errors.New("reload cannot change the local WireGuard key")
		}
		if err := session.Reconcile(ctx, next); err != nil {
			return err
		}
		currentDesired = next
		return nil
	}
	reconcile := func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		return reconcileLocked(ctx)
	}
	applyConfig := func(ctx context.Context, data []byte) error {
		if replaceConfig == nil {
			return errors.New("configuration updates are unavailable")
		}
		if len(data) > config.MaxSize {
			return errors.New("refreshed configuration exceeds the size limit")
		}
		mu.Lock()
		defer mu.Unlock()
		var next config.Config
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&next); err != nil {
			return errors.New("cannot decode refreshed configuration")
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return errors.New("refreshed configuration must contain one YAML document")
		}
		if err := config.Validate(next, runtime.GOOS); err != nil {
			return errors.Join(errors.New("refreshed configuration is invalid"), err)
		}
		unchanged := currentDesired.Config
		unchanged.Peers = next.Peers
		if !reflect.DeepEqual(next, unchanged) {
			return errors.New("sync may only update the peer list")
		}
		rollback, err := replaceConfig(data)
		if err != nil {
			return err
		}
		err = reconcileLocked(ctx)
		if err != nil && rollback != nil {
			err = errors.Join(err, rollback())
			recoveryCtx, cancelRecovery := context.WithTimeout(context.Background(), 10*time.Second)
			err = errors.Join(err, reconcileLocked(recoveryCtx))
			cancelRecovery()
		}
		return err
	}
	closeControl, err := local.Serve(ctx, dir, local.Operations{Operator: operator, InstanceID: instanceID, NetworkID: desired.Config.Network.ID, ConfigPath: configPath, PublicKey: publicKey, BeforeListen: beforeServe, OnClose: onClose,
		Config: func() ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			return json.Marshal(currentDesired.Config)
		},
		ApplyConfig: applyConfig,
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
