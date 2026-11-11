package service

import (
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"os"
	"path/filepath"
)

func recordProfile(cfg Config) error {
	executable := currentExecutable()
	if executable == "" {
		return errors.New("cannot identify service installation for inventory")
	}
	return installstate.RegisterProfile(filepath.Dir(executable), installstate.Profile{ConfigDir: snapshotDirectory(cfg), StateDir: cfg.StateDirectory, RuntimeDir: serviceRuntime(cfg), Service: true, ClaimConfig: true})
}

func registerMigratedService(cfg Config) error {
	if err := nativeManage("install", cfg); err != nil {
		return err
	}
	executable := currentExecutable()
	old := installstate.Profile{ConfigDir: cfg.StateDirectory, StateDir: cfg.StateDirectory, RuntimeDir: cfg.StateDirectory, Service: true}
	next := installstate.Profile{ConfigDir: snapshotDirectory(cfg), StateDir: cfg.StateDirectory, RuntimeDir: serviceRuntime(cfg), Service: true, ClaimConfig: true}
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

func validateConfigOwnership(cfg Config) error {
	executable := currentExecutable()
	if executable == "" {
		return errors.New("cannot identify configuration ownership for installation")
	}
	return installstate.ValidateConfigClaim(filepath.Dir(executable), cfg.StateDirectory, snapshotDirectory(cfg))
}

// A different profile can adopt identical, validated copies before our marker
// claim wins. Never roll back files after that profile owns the config marker.
func rollbackSnapshots(cfg Config) error { return rollbackSnapshotFiles(cfg, true) }
func rollbackSnapshotFiles(cfg Config, removeJSON bool) error {
	if err := validateConfigOwnership(cfg); err != nil {
		return errors.Join(errors.New("configuration cleanup deferred because ownership changed"), err)
	}
	files := []string{filepath.Join(snapshotDirectory(cfg), "service.key")}
	if removeJSON {
		files = append(files, cfg.ConfigPath)
	}
	var failures []error
	for _, path := range files {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 {
		if err := releaseConfigMarker(cfg, snapshotDirectory(cfg)); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
func releaseConfigMarker(cfg Config, directory string) error {
	executable := currentExecutable()
	if executable == "" {
		return errors.New("cannot identify configuration marker owner")
	}
	return installstate.ReleaseConfig(filepath.Dir(executable), cfg.StateDirectory, directory)
}
