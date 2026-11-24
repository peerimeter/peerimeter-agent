// Package service manages native OS service registration separately from run.
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/keycheck"
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
		cfg.ConfigPath = filepath.Join(cfg.ConfigDirectory, "service.yaml")
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
	case "install":
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
		return install(cfg, registerService, nativeSecureFiles)
	case "start", "stop", "uninstall":
		return nativeManage(action, cfg)
	default:
		return errors.New("service action must be install, start, stop or uninstall")
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
	key, err := keycheck.LoadAndVerifyInterfaceKey(desired)
	if err != nil {
		return false, err
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
	destination := filepath.Join(directory, "service.yaml")
	keyPath := filepath.Join(directory, "service.key")
	if _, err := os.Lstat(destination); err == nil {
		if err := verifyExistingServiceSnapshot(destination, keyPath, desired, key); err != nil {
			return false, err
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
	configCreated := false
	defer func() {
		if !success {
			owned := *cfg
			owned.ConfigPath = destination
			resultError = errors.Join(resultError, rollbackSnapshotFiles(owned, configCreated))
		}
	}()
	desired.Interface.PrivateKeyFile = keyPath
	data, err := config.MarshalYAML(desired)
	if err != nil {
		return false, errors.New("cannot encode protected service configuration")
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return false, errors.New("cannot create protected service configuration")
	}
	configCreated = true
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

func verifyExistingServiceSnapshot(destination, keyPath string, desired config.Config, key [32]byte) error {
	if err := installstate.CheckPrivateFile(destination); err != nil {
		return fmt.Errorf("existing protected service configuration %s is not secure: %w", destination, err)
	}
	installed, err := config.Load(destination)
	if err != nil {
		return err
	}
	// Reinstall must reuse exactly the same protected desired state and key.
	expected := desired
	expected.Interface.PrivateKeyFile = keyPath
	if !reflect.DeepEqual(installed, expected) {
		return errors.New("existing protected service configuration differs; use the installed configuration or reinstall it explicitly")
	}
	if err := installstate.CheckPrivateFile(keyPath); err != nil {
		return fmt.Errorf("existing protected service key %s is not secure: %w", keyPath, err)
	}
	oldKey, err := secret.Load(keyPath)
	if err != nil {
		return err
	}
	if oldKey != key {
		return errors.New("existing protected service key differs; refusing to overwrite it")
	}
	return nil
}

// install is separated from OS registration so partial-registration failures and
// safe secret-preserving retry can be tested without a privileged service manager.
func install(cfg Config, register func(Config) error, secure func(...string) error) error {
	startup, err := captureServiceStartup()
	if err != nil {
		return err
	}
	defer startup.Close()
	guard, err := local.AcquireForService(cfg.StateDirectory)
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
		return rollbackIfCreated(err, created, cfg)
	}
	// Native registration obtains its own registry lock. Retain persistent state
	// ownership while releasing the short lease before that separate operation.
	if err := startup.Close(); err != nil {
		return rollbackIfCreated(err, created, cfg)
	}
	if err := register(cfg); err != nil {
		return rollbackIfCreated(err, created, cfg)
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

func rollbackIfCreated(err error, created bool, cfg Config) error {
	if !created {
		return err
	}
	return errors.Join(err, rollbackSnapshots(cfg))
}

func serviceRuntime(cfg Config) string {
	if cfg.RuntimeDirectory != "" {
		return cfg.RuntimeDirectory
	}
	return cfg.StateDirectory
}
