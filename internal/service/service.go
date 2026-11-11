// Package service manages native OS service registration separately from run.
package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

type Config struct{ ConfigPath, StateDirectory string }

func Manage(action string, cfg Config) error {
	if err := nativeRequireAdmin(); err != nil {
		return err
	}
	switch action {
	case "install":
		if !filepath.IsAbs(cfg.ConfigPath) || !filepath.IsAbs(cfg.StateDirectory) {
			return errors.New("service install requires absolute config and state directory paths")
		}
		if strings.ContainsAny(cfg.ConfigPath+cfg.StateDirectory, "\x00\r\n") {
			return errors.New("invalid service configuration path")
		}
		if err := provision(&cfg); err != nil {
			return err
		}
	case "start", "stop", "uninstall":
	default:
		return errors.New("service action must be install, start, stop or uninstall")
	}
	return nativeManage(action, cfg)
}

// provision snapshots operator-supplied data before a privileged service uses it.
// It never changes the original files and refuses to overwrite installed secrets.
func provision(cfg *Config) error {
	desired, err := config.Load(cfg.ConfigPath)
	if err != nil {
		return err
	}
	key, err := secret.Load(desired.Interface.PrivateKeyFile)
	if err != nil {
		return err
	}
	public, err := secret.Public(key)
	if err != nil {
		return err
	}
	for _, peer := range desired.Peers {
		if peer.PublicKey == base64.StdEncoding.EncodeToString(public[:]) {
			return errors.New("peer public key matches the local interface key")
		}
	}
	guard, err := local.Acquire(cfg.StateDirectory)
	if err != nil {
		return err
	}
	defer guard.Close()
	destination := filepath.Join(cfg.StateDirectory, "service.json")
	keyPath := filepath.Join(cfg.StateDirectory, "service.key")
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return errors.New("protected service configuration already exists; preserve it and manage the existing service")
	}
	if err := secret.WriteNew(keyPath, key); err != nil {
		return err
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
		return errors.New("cannot encode protected service configuration")
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create protected service configuration")
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return errors.New("cannot write protected service configuration")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := nativeSecureFiles(cfg.StateDirectory, destination, keyPath, filepath.Join(cfg.StateDirectory, "agent.lock")); err != nil {
		return err
	}
	cfg.ConfigPath = destination
	success = true
	return nil
}
