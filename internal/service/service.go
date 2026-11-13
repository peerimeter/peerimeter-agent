// Package service manages native OS service registration separately from run.
package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

type Config struct{ ConfigPath, ConfigDirectory, StateDirectory, RuntimeDirectory, Operator string }

func normalized(cfg Config) (Config, error) {
	layout, err := paths.Resolve(paths.Options{ConfigDir: cfg.ConfigDirectory, StateDir: cfg.StateDirectory, RuntimeDir: cfg.RuntimeDirectory})
	if err != nil {
		return cfg, err
	}
	cfg.ConfigDirectory, cfg.StateDirectory, cfg.RuntimeDirectory = layout.ConfigDir, layout.StateDir, layout.RuntimeDir
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = filepath.Join(cfg.ConfigDirectory, "service.json")
	}
	return cfg, nil
}
func Manage(action string, cfg Config) error {
	if err := nativeRequireAdmin(); err != nil {
		return err
	}
	var err error
	cfg, err = normalized(cfg)
	if err != nil {
		return err
	}
	switch action {
	case "install", "migrate":
		if err := local.ValidateOperator(cfg.Operator); err != nil {
			return err
		}
		if !filepath.IsAbs(cfg.ConfigPath) || strings.ContainsAny(cfg.ConfigPath, "\x00\r\n") {
			return errors.New("service configuration path must be absolute without control characters")
		}
		for _, path := range []string{cfg.ConfigDirectory, cfg.StateDirectory, cfg.RuntimeDirectory} {
			if err := nativeValidateStatePath(path); err != nil {
				return err
			}
		}
		if action == "migrate" {
			return migrate(cfg, func(legacy Config) error { return RemoveOwned(context.Background(), currentExecutable(), legacy) }, func(next Config) error { return registerMigratedService(next) }, nativeSecureFiles)
		}
		if runtime.GOOS != "windows" && cfg.ConfigDirectory != cfg.StateDirectory {
			if _, err := os.Lstat(filepath.Join(cfg.StateDirectory, "service.json")); err == nil {
				return errors.New("legacy combined service layout requires explicit service migrate before installation")
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		return install(cfg, registerService, nativeSecureFiles)
	case "start", "stop", "uninstall":
		return nativeManage(action, cfg)
	default:
		return errors.New("service action must be install, migrate, start, stop or uninstall")
	}
}
func currentExecutable() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err == nil {
		return canonical
	}
	return path
}
func snapshotDirectory(cfg Config) string {
	if cfg.ConfigDirectory != "" {
		return cfg.ConfigDirectory
	}
	return cfg.StateDirectory
}
func registerService(cfg Config) error {
	if err := nativeManage("install", cfg); err != nil {
		return err
	}
	if err := recordProfile(cfg); err != nil {
		return errors.Join(err, nativeManage("uninstall", cfg))
	}
	return nil
}

// provision snapshots operator-supplied data before a privileged service uses it.
// It never changes the original files and refuses to overwrite installed secrets.
func provision(cfg *Config, secure func(...string) error) (copied bool, resultError error) {
	if err := validateConfigOwnership(*cfg); err != nil {
		return false, err
	}
	desired, err := config.Load(cfg.ConfigPath)
	if err != nil {
		return false, err
	}
	key, err := secret.Load(desired.Interface.PrivateKeyFile)
	if err != nil {
		return false, err
	}
	public, err := secret.Public(key)
	if err != nil {
		return false, err
	}
	for _, peer := range desired.Peers {
		if peer.PublicKey == base64.StdEncoding.EncodeToString(public[:]) {
			return false, errors.New("peer public key matches the local interface key")
		}
	}
	directory := snapshotDirectory(*cfg)
	if _, err := os.Lstat(directory); err == nil {
		// Existing configuration directories may belong to another installed
		// profile. Validate them without rewriting their ACL before ownership and
		// contents have been verified below.
		if err := installstate.CheckDirectory(directory); err != nil {
			return false, fmt.Errorf("cannot validate protected service configuration directory %s: %w", directory, err)
		}
	} else if os.IsNotExist(err) {
		if err := local.PrepareDirectory(directory); err != nil {
			return false, err
		}
	} else {
		return false, fmt.Errorf("cannot inspect service configuration directory %s: %w", directory, err)
	}
	destination := filepath.Join(directory, "service.json")
	keyPath := filepath.Join(directory, "service.key")
	if _, err := os.Lstat(destination); err == nil {
		if err := installstate.CheckPrivateFile(destination); err != nil {
			return false, fmt.Errorf("existing protected service configuration %s is not secure: %w", destination, err)
		}
		installed, err := config.Load(destination)
		if err != nil {
			return false, err
		}
		// Reinstall must reuse exactly the same protected desired state and key.
		expected := desired
		expected.Interface.PrivateKeyFile = keyPath
		if !reflect.DeepEqual(installed, expected) {
			return false, errors.New("existing protected service configuration differs; use the installed configuration or make an explicit migration")
		}
		if err := installstate.CheckPrivateFile(keyPath); err != nil {
			return false, fmt.Errorf("existing protected service key %s is not secure: %w", keyPath, err)
		}
		oldKey, err := secret.Load(keyPath)
		if err != nil {
			return false, err
		}
		if oldKey != key {
			return false, errors.New("existing protected service key differs; refusing to overwrite it")
		}
		cfg.ConfigPath = destination
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, errors.New("cannot inspect installed service configuration")
	}
	if err := secret.WriteNew(keyPath, key); err != nil {
		return false, err
	}
	success := false
	jsonCreated := false
	defer func() {
		if !success {
			owned := *cfg
			owned.ConfigPath = destination
			resultError = errors.Join(resultError, rollbackSnapshotFiles(owned, jsonCreated))
		}
	}()
	desired.Interface.PrivateKeyFile = keyPath
	data, err := json.MarshalIndent(desired, "", "  ")
	if err != nil {
		return false, errors.New("cannot encode protected service configuration")
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return false, errors.New("cannot create protected service configuration")
	}
	jsonCreated = true
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return false, errors.New("cannot write protected service configuration")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return false, err
	}
	if err = f.Close(); err != nil {
		return false, err
	}
	if err := secureSnapshot(*cfg, destination, keyPath, secure); err != nil {
		return false, err
	}
	cfg.ConfigPath = destination
	success = true
	return true, nil
}

// install is separated from OS registration so partial-registration failures and
// safe secret-preserving retry can be tested without a privileged service manager.
func install(cfg Config, register func(Config) error, secure func(...string) error) error {
	startup, err := captureServiceStartup()
	if err != nil {
		return err
	}
	defer startup.Close()
	guard, err := local.Acquire(cfg.StateDirectory)
	if err != nil {
		return err
	}
	defer guard.Close()
	if err := startup.Check(); err != nil {
		return err
	}
	// Record planned paths while removal is still excluded by the startup
	// lease. Service ownership is claimed only after native registration succeeds.
	if err := startup.RegisterProfile(installstate.Profile{ConfigDir: snapshotDirectory(cfg), StateDir: cfg.StateDirectory, RuntimeDir: serviceRuntime(cfg), Service: false}); err != nil {
		return err
	}
	// Provision and claim configuration while the startup lease still excludes
	// removal. Intent alone must never authorize deleting another profile's keys.
	created, err := provision(&cfg, secure)
	if err != nil {
		return err
	}
	if err := startup.RegisterProfile(installstate.Profile{ConfigDir: snapshotDirectory(cfg), StateDir: cfg.StateDirectory, RuntimeDir: serviceRuntime(cfg), ClaimConfig: true}); err != nil {
		if created {
			return errors.Join(err, rollbackSnapshots(cfg))
		}
		return err
	}
	// Native registration obtains its own registry lock. Retain persistent state
	// ownership while releasing the short lease before that separate operation.
	if err := startup.Close(); err != nil {
		if created {
			return errors.Join(err, rollbackSnapshots(cfg))
		}
		return err
	}
	if err := register(cfg); err != nil {
		if created {
			return errors.Join(err, rollbackSnapshots(cfg))
		}
		return err
	}
	return nil
}

func secureSnapshot(cfg Config, destination, key string, secure func(...string) error) error {
	files := []string{cfg.StateDirectory, snapshotDirectory(cfg), destination, key}
	if runtime.GOOS == "windows" {
		files = append(files, filepath.Join(cfg.StateDirectory, "agent.lock"))
	}
	return secure(files...)
}

// migrate keeps the durable identity in place. It removes old snapshots only
// after replacement registration succeeds; failed attempts retain recoverable
// legacy credentials and never overwrite a conflicting destination.
func migrate(cfg Config, unregister func(Config) error, register func(Config) error, secure func(...string) error) error {
	if runtime.GOOS == "windows" {
		return errors.New("Windows retains its existing storage layout; no Unix layout migration is required")
	}
	startup, err := captureServiceStartup()
	if err != nil {
		return err
	}
	defer startup.Close()
	legacyJSON := filepath.Join(cfg.StateDirectory, "service.json")
	legacyKey := filepath.Join(cfg.StateDirectory, "service.key")
	if snapshotDirectory(cfg) == cfg.StateDirectory || cfg.RuntimeDirectory == cfg.StateDirectory {
		return errors.New("migration requires separate config, persistent state and runtime directories")
	}
	if err := validateLegacySnapshot(legacyJSON); err != nil {
		return err
	}
	legacy, err := config.Load(legacyJSON)
	if err != nil {
		return err
	}
	expected, err := filepath.EvalSymlinks(legacyKey)
	if err != nil {
		return errors.New("legacy service key is unavailable")
	}
	actual, err := filepath.EvalSymlinks(legacy.Interface.PrivateKeyFile)
	if err != nil || actual != expected {
		return errors.New("legacy service configuration must reference its protected installed service.key")
	}
	if _, err := secret.Load(legacyKey); err != nil {
		return err
	}
	// Validate target ownership and conflicts before stopping a working service.
	if err := validateConfigOwnership(cfg); err != nil {
		return err
	}
	for _, name := range []string{"service.json", "service.key"} {
		if _, err := os.Lstat(filepath.Join(snapshotDirectory(cfg), name)); err == nil {
			return errors.New("migration destination already contains service configuration or keys; refusing to overwrite")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	old := cfg
	old.ConfigDirectory = cfg.StateDirectory
	old.ConfigPath = legacyJSON
	old.RuntimeDirectory = cfg.StateDirectory
	if err := validateConfigOwnership(old); err != nil {
		return err
	}
	if err := startup.Check(); err != nil {
		return err
	}
	// Stop must not wait on a supervisor process whose own startup needs this
	// installation lease. No state is changed before the inventory gate passes.
	if err := startup.Close(); err != nil {
		return err
	}
	if err := unregister(old); err != nil {
		return err
	}
	// Reacquire the startup lease across state acquisition after supervisor stop;
	// the original captured ID still detects removal/replacement during the gap.
	lease, err := captureServiceStartup()
	if err != nil {
		return err
	}
	defer lease.Close()
	if err := startup.Check(); err != nil {
		return err
	}
	guard, err := acquireMigrationState(context.Background(), cfg.StateDirectory)
	if err != nil {
		return err
	}
	defer guard.Close()
	if err := startup.Check(); err != nil {
		return err
	}
	// Only after native registration ownership was verified and the old
	// supervisor stopped may this installation adopt the protected legacy data.
	if err := planAndClaimLegacy(lease, old); err != nil {
		return err
	}
	cfg.ConfigPath = legacyJSON
	created, err := provision(&cfg, secure)
	if err != nil {
		return err
	}
	if err := lease.ClaimMigrationConfig(installstate.Profile{ConfigDir: snapshotDirectory(cfg), StateDir: cfg.StateDirectory, RuntimeDir: serviceRuntime(cfg)}); err != nil {
		if created {
			return errors.Join(err, rollbackSnapshots(cfg))
		}
		return err
	}
	if err := lease.Close(); err != nil {
		if created {
			return errors.Join(err, rollbackSnapshots(cfg))
		}
		return err
	}
	if err := register(cfg); err != nil {
		if created {
			return errors.Join(err, rollbackSnapshots(cfg))
		}
		return err
	}
	// A held directory lock plus a compatibility lock proves no old manager still
	// owns the legacy lock inode. Persistent network/ownership files are untouched.
	var cleanup []error
	for _, path := range []string{legacyJSON, legacyKey, filepath.Join(cfg.StateDirectory, "agent.lock")} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cleanup = append(cleanup, err)
		}
	}
	if len(cleanup) == 0 {
		if err := releaseConfigMarker(cfg, cfg.StateDirectory); err != nil {
			cleanup = append(cleanup, err)
		}
	}
	if len(cleanup) != 0 {
		return errors.Join(append([]error{errors.New("new service installed but legacy snapshot cleanup is incomplete")}, cleanup...)...)
	}
	return nil
}

func serviceRuntime(cfg Config) string {
	if cfg.RuntimeDirectory != "" {
		return cfg.RuntimeDirectory
	}
	return cfg.StateDirectory
}

type profilePlanner interface {
	RegisterProfile(installstate.Profile) error
}

func planAndClaimLegacy(startup profilePlanner, legacy Config) error {
	planned := installstate.Profile{ConfigDir: legacy.ConfigDirectory, StateDir: legacy.StateDirectory, RuntimeDir: legacy.RuntimeDirectory}
	if err := startup.RegisterProfile(planned); err != nil {
		return err
	}
	planned.ClaimConfig = true
	return startup.RegisterProfile(planned)
}

// Native supervisor removal can return before the old process releases its
// kernel lock (notably launchd bootout). Wait for proof instead of unlinking or
// bypassing the live legacy lock; malformed paths fail immediately.
func acquireMigrationState(ctx context.Context, directory string) (*local.Guard, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		guard, err := local.TryAcquireExisting(directory)
		if err == nil {
			if guard == nil {
				return nil, errors.New("legacy persistent state disappeared during supervisor shutdown")
			}
			return guard, nil
		}
		if !errors.Is(err, local.ErrBusy) {
			return nil, err
		}
		select {
		case <-bounded.Done():
			return nil, errors.Join(errors.New("legacy manager shutdown was not established; migration data was preserved"), bounded.Err(), err)
		case <-ticker.C:
		}
	}
}
