package installstate

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Startup remembers whether this process began as a registered installation.
// Its short lease spans persistent-state acquisition, so uninstall cannot mark
// removal and delete the state directory before a queued starter acquires it.
// Close the lease before RegisterProfile (which obtains its own inventory lock).
type Startup struct {
	dir, id, executable string
	registered          bool
	lease               io.Closer
}

func CaptureStartup(dir string) (*Startup, error) {
	canonical, err := Canonical(dir)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	startup := &Startup{dir: canonical, executable: exe}
	inv, err := Load(canonical)
	if os.IsNotExist(err) {
		if err := startup.Check(); err != nil {
			return nil, err
		}
		return startup, nil
	}
	if err != nil {
		return nil, err
	}
	lease, err := Lock(canonical)
	if err != nil {
		return nil, err
	}
	startup.lease = lease
	inv, err = Load(canonical)
	if err != nil {
		lease.Close()
		return nil, err
	}
	startup.registered = true
	startup.id = inv.ID
	if err := startup.Check(); err != nil {
		lease.Close()
		return nil, err
	}
	return startup, nil
}
func (s *Startup) Check() error {
	info, err := os.Stat(s.executable)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("agent executable is no longer installed; startup refused")
	}
	if !s.registered {
		return nil
	}
	inv, err := Load(s.dir)
	if err != nil {
		return errors.New("installation inventory disappeared during startup; refusing to recreate removed installation state")
	}
	if inv.ID != s.id || inv.Removing {
		return errors.New("installation is being removed or replaced; agent startup is disabled")
	}
	return nil
}
func (s *Startup) Close() error {
	if s.lease == nil {
		return nil
	}
	lease := s.lease
	s.lease = nil
	return lease.Close()
}

// MarkRemoving requires the caller to hold Lock(inv.InstallDir). It is durable
// until program files are gone and the manifest is removed last. Dry-run must
// never call it. A failed removal remains retryable, but cannot start a manager.
func MarkRemoving(inv Inventory) error { inv.Removing = true; return save(inv) }

// ExecutableDirectory is a convenience for service/installer internal callers.
func ExecutableDirectory() string {
	exe, e := os.Executable()
	if e != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// RegisterProfile records planned state while the startup lease is still held.
// Call after obtaining the persistent guard and before creating identity files;
// then Close the lease before the later runtime-claim callback.
func (s *Startup) RegisterProfile(p Profile) error {
	if err := s.Check(); err != nil {
		return err
	}
	if !s.registered {
		if _, err := os.Lstat(filepath.Join(p.StateDir, MarkerFilename)); err == nil {
			return errors.New("persistent state belongs to an installed agent; source builds cannot adopt it")
		} else if !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if s.lease == nil {
		return errors.New("startup inventory lease is already closed")
	}
	return registerProfileLocked(s.dir, p)
}

// ClaimMigrationConfig authorizes provisional snapshots without switching the
// active profile paths before native service registration succeeds. Recording
// the pending target also makes a crash before MigrateProfile fully removable.
func (s *Startup) ClaimMigrationConfig(next Profile) error {
	if err := s.Check(); err != nil {
		return err
	}
	if !s.registered {
		return ValidateConfigClaim(s.dir, next.StateDir, next.ConfigDir)
	}
	if s.lease == nil {
		return errors.New("migration configuration claim requires the startup lease")
	}
	inv, err := Load(s.dir)
	if err != nil {
		return err
	}
	state, err := Canonical(next.StateDir)
	if err != nil {
		return err
	}
	cfg, err := Canonical(next.ConfigDir)
	if err != nil {
		return err
	}
	run, err := Canonical(next.RuntimeDir)
	if err != nil {
		return err
	}
	for i, p := range inv.Profiles {
		if p.StateDir != state {
			continue
		}
		candidate := p
		candidate.ConfigDir = cfg
		if err := ValidateConfigClaim(s.dir, state, cfg); err != nil {
			return err
		}
		inv.Profiles[i].PendingConfigDir = cfg
		inv.Profiles[i].PendingRuntimeDir = run
		if err := save(inv); err != nil {
			return err
		}
		if err := claimConfig(inv, candidate); err != nil {
			return err
		}
		return nil
	}
	return errors.New("migration requires a planned legacy persistent-state profile")
}
