package installstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type runtimeMarker struct {
	Version    int    `json:"version"`
	InstallID  string `json:"installation_id"`
	ProfileID  string `json:"profile_id"`
	InstanceID string `json:"instance_id"`
}

func InstanceID(state string) string {
	path, err := Canonical(state)
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}
func expectedRuntime(inv Inventory, p Profile) runtimeMarker {
	return runtimeMarker{1, inv.ID, p.ID, InstanceID(p.StateDir)}
}
func claimRuntime(inv Inventory, p Profile) error {
	path := filepath.Join(p.RuntimeDir, RuntimeMarkerFilename)
	data, err := readPrivate(path)
	expected := expectedRuntime(inv, p)
	if err == nil {
		var got runtimeMarker
		if json.Unmarshal(data, &got) != nil || got != expected {
			return errors.New("runtime directory belongs to another installation profile")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(p.RuntimeDir, "control.sock")); !os.IsNotExist(err) {
		return errors.New("runtime socket has no verifiable profile ownership; refusing to take it over")
	}
	data, _ = json.Marshal(expected)
	return WritePrivate(path, append(data, '\n'))
}

// VerifyRuntime never claims a path. A planned profile without a matching
// marker does not own the socket/directory, even if it names the same path.
func VerifyRuntime(inv Inventory, p Profile) (bool, error) {
	data, err := readPrivate(filepath.Join(p.RuntimeDir, RuntimeMarkerFilename))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		if p.RuntimeOwned {
			return false, err
		}
		return false, nil
	}
	var got runtimeMarker
	if json.Unmarshal(data, &got) == nil && got == expectedRuntime(inv, p) {
		return true, nil
	}
	// The path may have been deliberately reused after this profile stopped.
	// A different marker never authorizes stopping or deleting that new runtime.
	return false, nil
}

func validateSourceRuntime(p Profile) error {
	data, err := readPrivate(filepath.Join(p.RuntimeDir, RuntimeMarkerFilename))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var got runtimeMarker
	if json.Unmarshal(data, &got) != nil || got.InstanceID != InstanceID(p.StateDir) {
		return errors.New("runtime directory is bound to another persistent-state instance")
	}
	return nil
}

// ReleaseRuntime is called after the owned listener closes and while its runtime
// guard remains held. It does not mutate the installation inventory or acquire
// its lock: full uninstall can be holding that lock while requesting shutdown.
func ReleaseRuntime(dir, stateDir, runtimeDir string) error {
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
	runtimeDir, err = Canonical(runtimeDir)
	if err != nil {
		return err
	}
	var selected *Profile
	for i := range inv.Profiles {
		if inv.Profiles[i].StateDir == stateDir && inv.Profiles[i].RuntimeDir == runtimeDir {
			selected = &inv.Profiles[i]
			break
		}
	}
	if selected == nil {
		return nil
	}
	owned, err := VerifyRuntime(inv, *selected)
	if err != nil {
		return err
	}
	if !owned {
		return nil
	}
	if _, err := os.Lstat(filepath.Join(runtimeDir, "control.sock")); !os.IsNotExist(err) {
		return errors.New("owned runtime socket remains after close; ownership marker was preserved")
	}
	if err := os.Remove(filepath.Join(runtimeDir, RuntimeMarkerFilename)); err != nil && !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(runtimeDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return os.Remove(runtimeDir)
	}
	return nil
}
