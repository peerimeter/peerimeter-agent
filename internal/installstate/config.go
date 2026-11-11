package installstate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const ConfigMarkerFilename = ".peerimeter-agent.config"

// ValidateConfigClaim performs no writes. Service provisioning calls it before reading/reusing/creating snapshots.
// Exclusive marker creation plus owner-checked rollback resolves competing claims.
func ValidateConfigClaim(dir, stateDir, configDir string) error {
	target, err := Canonical(configDir)
	if err != nil {
		return err
	}
	data, markerErr := readPrivate(filepath.Join(target, ConfigMarkerFilename))
	if os.IsNotExist(markerErr) {
		return nil
	}
	if markerErr != nil {
		return markerErr
	}
	inv, err := Load(dir)
	if os.IsNotExist(err) {
		return errors.New("configuration belongs to an installed agent; use that installation to manage it")
	}
	if err != nil {
		return err
	}
	stateDir, err = Canonical(stateDir)
	if err != nil {
		return err
	}
	for _, p := range inv.Profiles {
		if p.StateDir == stateDir {
			var got runtimeMarker
			if json.Unmarshal(data, &got) == nil && got == expectedRuntime(inv, p) {
				return nil
			}
			return errors.New("configuration directory belongs to another installation profile")
		}
	}
	return errors.New("configuration marker has no matching planned installation profile")
}
func claimConfig(inv Inventory, p Profile) error {
	if p.ConfigDir == "" {
		return errors.New("managed configuration directory is required")
	}
	if err := ValidateConfigClaim(inv.InstallDir, p.StateDir, p.ConfigDir); err != nil {
		return err
	}
	for _, name := range []string{"service.json", "service.key"} {
		if err := CheckFile(filepath.Join(p.ConfigDir, name)); err != nil {
			return errors.New("protected configuration snapshots must be provisioned before claiming ownership")
		}
	}
	expected := expectedRuntime(inv, p)
	path := filepath.Join(p.ConfigDir, ConfigMarkerFilename)
	before, err := readPrivate(path)
	if err == nil {
		var got runtimeMarker
		if json.Unmarshal(before, &got) == nil && got == expected {
			return nil
		}
		return errors.New("configuration ownership changed during provisioning")
	}
	if !os.IsNotExist(err) {
		return err
	}
	data, _ := json.Marshal(expected)
	// Exclusive creation selects one configuration owner across installations.
	// A losing provisioner must verify this marker before rolling back snapshots.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("configuration ownership was claimed by another operation")
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if err := protect(path); err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	success = true
	return nil
}
func VerifyConfig(inv Inventory, p Profile) (bool, error) {
	return VerifyConfigDirectory(inv, p, p.ConfigDir)
}
func VerifyConfigDirectory(inv Inventory, p Profile, dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	data, err := readPrivate(filepath.Join(dir, ConfigMarkerFilename))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		if p.ConfigOwned {
			return false, err
		}
		return false, nil
	}
	var got runtimeMarker
	return json.Unmarshal(data, &got) == nil && got == expectedRuntime(inv, p), nil
}

// ReleaseConfig drops only a matching marker after its protected snapshots have
// been removed. Migration uses it for legacy combined-directory cleanup.
func ReleaseConfig(dir, stateDir, configDir string) error {
	inv, err := Load(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stateDir, err = Canonical(stateDir)
	if err != nil {
		return err
	}
	configDir, err = Canonical(configDir)
	if err != nil {
		return err
	}
	for _, p := range inv.Profiles {
		if p.StateDir != stateDir {
			continue
		}
		owned, e := VerifyConfigDirectory(inv, p, configDir)
		if e != nil {
			return e
		}
		if !owned {
			return nil
		}
		for _, name := range []string{"service.json", "service.key"} {
			if _, e := os.Lstat(filepath.Join(configDir, name)); !os.IsNotExist(e) {
				return errors.New("legacy configuration snapshots remain; ownership marker was preserved")
			}
		}
		if e := os.Remove(filepath.Join(configDir, ConfigMarkerFilename)); e != nil && !os.IsNotExist(e) {
			return e
		}
		entries, e := os.ReadDir(configDir)
		if e == nil && len(entries) == 0 {
			return os.Remove(configDir)
		}
		return e
	}
	return nil
}
