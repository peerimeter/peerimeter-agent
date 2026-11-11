package service

import (
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"path/filepath"
)

func recordProfile(cfg Config) error {
	executable := currentExecutable()
	if executable == "" {
		return errors.New("cannot identify service installation for inventory")
	}
	return installstate.RegisterProfile(filepath.Dir(executable), installstate.Profile{ConfigDir: snapshotDirectory(cfg), StateDir: cfg.StateDirectory, RuntimeDir: serviceRuntime(cfg), Service: true})
}

func registerMigratedService(cfg Config) error {
	if err := nativeManage("install", cfg); err != nil {
		return err
	}
	executable := currentExecutable()
	old := installstate.Profile{ConfigDir: cfg.StateDirectory, StateDir: cfg.StateDirectory, RuntimeDir: cfg.StateDirectory, Service: true}
	next := installstate.Profile{ConfigDir: snapshotDirectory(cfg), StateDir: cfg.StateDirectory, RuntimeDir: serviceRuntime(cfg), Service: true}
	if err := installstate.MigrateProfile(filepath.Dir(executable), old, next); err != nil {
		return errors.Join(err, nativeManage("uninstall", cfg))
	}
	return nil
}

func captureServiceStartup() (*installstate.Startup, error) {
	executable := currentExecutable()
	if executable == "" {
		return nil, errors.New("cannot identify service installation during startup")
	}
	return installstate.CaptureStartup(filepath.Dir(executable))
}
