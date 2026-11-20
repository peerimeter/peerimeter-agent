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

// ManagedOptions groups the configuration and callbacks for managed runtime.
type ManagedOptions struct {
	Backend         platform.Backend
	Desired         platform.Desired
	Directory       string
	Reload          func(context.Context) (platform.Desired, error)
	Operator        string
	InstanceID      string
	BeforeServe     func() error
	OnClose         func() error
	RefreshInterval time.Duration
	ConfigPath      string
	ReplaceConfig   func([]byte) (func() error, error)
	Background      func(context.Context)
}

// RunManaged exposes only protected local control after the native tunnel starts.
// Reload validation happens before the backend touches OS state.
func RunManaged(ctx context.Context, options ManagedOptions) error {
	return RunManagedWithBackground(ctx, options)
}

// RunManagedWithRefresh periodically obtains desired state from reload while
// preserving the same local authenticated control surface as static mode.
func RunManagedWithRefresh(ctx context.Context, options ManagedOptions) error {
	return RunManagedWithBackground(ctx, options)
}

func RunManagedWithBackground(ctx context.Context, options ManagedOptions) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	backend, desired, dir := options.Backend, options.Desired, options.Directory
	reload, operator, instanceID := options.Reload, options.Operator, options.InstanceID
	beforeServe, onClose := options.BeforeServe, options.OnClose
	interval, configPath, replaceConfig := options.RefreshInterval, options.ConfigPath, options.ReplaceConfig
	background := options.Background
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
	runner := managedRunner{session: session, desired: desired, currentDesired: desired, reload: reload, replaceConfig: replaceConfig}
	publicKey := managedPublicKey(desired.PrivateKey)
	closeControl, err := local.Serve(ctx, dir, local.Operations{Operator: operator, InstanceID: instanceID, NetworkID: desired.Config.Network.ID, ConfigPath: configPath, PublicKey: publicKey, BeforeListen: beforeServe, OnClose: onClose,
		Config: func() ([]byte, error) {
			return runner.configJSON()
		},
		ApplyConfig: runner.applyConfig,
		Snapshot: func(ctx context.Context) (platform.Snapshot, error) {
			runner.mu.Lock()
			defer runner.mu.Unlock()
			snapshot, err := runner.session.Snapshot(ctx)
			snapshot.InstanceID = instanceID
			return snapshot, err
		},
		Reload: runner.reconcile,
		Stop:   cancel,
	})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeControl()) }()
	var workers sync.WaitGroup
	defer workers.Wait()
	if background != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			background(ctx)
		}()
	}
	if interval > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runner.runRefreshLoop(ctx, interval)
		}()
	}
	<-ctx.Done()
	return nil
}

type managedRunner struct {
	session        platform.Session
	desired        platform.Desired
	currentDesired platform.Desired
	reload         func(context.Context) (platform.Desired, error)
	replaceConfig  func([]byte) (func() error, error)
	mu             sync.Mutex
}

func (runner *managedRunner) reconcile(ctx context.Context) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.reconcileLocked(ctx)
}

func (runner *managedRunner) reconcileLocked(ctx context.Context) error {
	next, err := runner.reload(ctx)
	if err != nil {
		return err
	}
	if next.Config.Network.ID != runner.desired.Config.Network.ID || next.InterfaceName != runner.desired.InterfaceName {
		return errors.New("reload cannot change the local network identity or interface")
	}
	if next.PrivateKey != runner.desired.PrivateKey {
		return errors.New("reload cannot change the local WireGuard key")
	}
	if err := runner.session.Reconcile(ctx, next); err != nil {
		return err
	}
	runner.currentDesired = next
	return nil
}

func (runner *managedRunner) applyConfig(ctx context.Context, data []byte) error {
	if runner.replaceConfig == nil {
		return errors.New("configuration updates are unavailable")
	}
	if len(data) > config.MaxSize {
		return errors.New("refreshed configuration exceeds the size limit")
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	next, err := decodeRefreshedConfig(data)
	if err != nil {
		return err
	}
	if err := config.Validate(next, runtime.GOOS); err != nil {
		return errors.Join(errors.New("refreshed configuration is invalid"), err)
	}
	unchanged := runner.currentDesired.Config
	unchanged.Peers = next.Peers
	if !reflect.DeepEqual(next, unchanged) {
		return errors.New("sync may only update the peer list")
	}
	rollback, err := runner.replaceConfig(data)
	if err != nil {
		return err
	}
	err = runner.reconcileLocked(ctx)
	if err != nil && rollback != nil {
		err = errors.Join(err, rollback())
		recoveryCtx, cancelRecovery := context.WithTimeout(context.Background(), 10*time.Second)
		err = errors.Join(err, runner.reconcileLocked(recoveryCtx))
		cancelRecovery()
	}
	return err
}

func decodeRefreshedConfig(data []byte) (config.Config, error) {
	var next config.Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&next); err != nil {
		return config.Config{}, errors.New("cannot decode refreshed configuration")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return config.Config{}, errors.New("refreshed configuration must contain one YAML document")
	}
	return next, nil
}

func (runner *managedRunner) configJSON() ([]byte, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return json.Marshal(runner.currentDesired.Config)
}

func (runner *managedRunner) runRefreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := runner.reconcile(refreshCtx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Warn("managed network refresh failed", "network_id", runner.desired.Config.Network.ID, "error", err)
			}
			cancel()
		}
	}
}

func managedPublicKey(privateKey [32]byte) string {
	public, err := secret.Public(privateKey)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(public[:])
}
