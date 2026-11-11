// Package service manages native OS service registration separately from run.
package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

type Config struct{ ConfigPath, StateDirectory, Operator string }

func Manage(action string, cfg Config) error {
	if err := nativeRequireAdmin(); err != nil {
		return err
	}
	switch action {
	case "install":
		if err := local.ValidateOperator(cfg.Operator); err != nil {
			return err
		}
		if !filepath.IsAbs(cfg.ConfigPath) || !filepath.IsAbs(cfg.StateDirectory) {
			return errors.New("service install requires absolute config and state directory paths")
		}
		if strings.ContainsAny(cfg.ConfigPath+cfg.StateDirectory, "\x00\r\n") {
			return errors.New("invalid service configuration path")
		}
		if err := nativeValidateStatePath(cfg.StateDirectory); err != nil {
			return err
		}
		return install(cfg, func(cfg Config) error { return nativeManage("install", cfg) }, nativeSecureFiles)
	case "start", "stop", "uninstall":
	default:
		return errors.New("service action must be install, start, stop or uninstall")
	}
	return nativeManage(action, cfg)
}

// provision snapshots operator-supplied data before a privileged service uses it.
// It never changes the original files and refuses to overwrite installed secrets.
func provision(cfg *Config, secure func(...string) error) (bool, error) {
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
	guard, err := local.Acquire(cfg.StateDirectory)
	if err != nil {
		return false, err
	}
	defer guard.Close()
	destination := filepath.Join(cfg.StateDirectory, "service.json")
	keyPath := filepath.Join(cfg.StateDirectory, "service.key")
	if _, err := os.Lstat(destination); err == nil {
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
		oldKey, err := secret.Load(keyPath)
		if err != nil {
			return false, err
		}
		if oldKey != key {
			return false, errors.New("existing protected service key differs; refusing to overwrite it")
		}
		if err := secure(cfg.StateDirectory, destination, keyPath, filepath.Join(cfg.StateDirectory, "agent.lock")); err != nil {
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
	defer func() {
		if !success {
			_ = os.Remove(keyPath)
			_ = os.Remove(destination)
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
	if err := secure(cfg.StateDirectory, destination, keyPath, filepath.Join(cfg.StateDirectory, "agent.lock")); err != nil {
		return false, err
	}
	cfg.ConfigPath = destination
	success = true
	return true, nil
}

// install is separated from OS registration so partial-registration failures and
// safe secret-preserving retry can be tested without a privileged service manager.
func install(cfg Config, register func(Config) error, secure func(...string) error) error {
	created, err := provision(&cfg, secure)
	if err != nil {
		return err
	}
	if err := register(cfg); err != nil {
		if created {
			return errors.Join(err, os.Remove(cfg.ConfigPath), os.Remove(filepath.Join(cfg.StateDirectory, "service.key")))
		}
		return err
	}
	return nil
}
