package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/selfupdate"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

const updateManifestName = ".peerimeter-agent.update.json"

type helperManifest struct {
	Version   string                  `json:"version"`
	InstallID string                  `json:"installation_id"`
	Hashes    map[string]string       `json:"hashes"`
	Snapshot  updateInventorySnapshot `json:"inventory_snapshot"`
}

func scheduleWindowsUpdate(inv installstate.Inventory, files map[string][]byte, tag string, profile *installstate.Profile, out io.Writer, jsonOutput bool) error {
	dir, err := os.MkdirTemp(inv.LockDir, ".peerimeter-update-")
	if err != nil {
		return restartServiceAfterFailure(profile, fmt.Errorf("create update staging directory under recorded lock directory: %w", err))
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	hashes := make(map[string]string, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
		mode := os.FileMode(0600)
		if name == "peerimeter-agent.exe" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			cleanup()
			return restartServiceAfterFailure(profile, err)
		}
	}
	manifest, err := json.Marshal(helperManifest{Version: tag, InstallID: inv.ID, Hashes: hashes, Snapshot: snapshotUpdateInventory(inv)})
	if err != nil {
		cleanup()
		return restartServiceAfterFailure(profile, err)
	}
	if err := installstate.WritePrivate(filepath.Join(dir, updateManifestName), append(manifest, '\n')); err != nil {
		cleanup()
		return restartServiceAfterFailure(profile, err)
	}
	helper := filepath.Join(dir, "peerimeter-agent.exe")
	cmd := exec.Command(helper, "__update-helper", inv.InstallDir, dir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cleanup()
		return restartServiceAfterFailure(profile, fmt.Errorf("start Windows update helper: %w", err))
	}
	_ = cmd.Process.Release()
	return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "scheduled", PreviousVersion: Version, UpdatedVersion: tag})
}

func runWindowsUpdateHelper(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return errors.New("invalid update helper arguments")
	}
	installDir, err := installstate.Canonical(args[0])
	if err != nil {
		return err
	}
	transactionDir, err := installstate.Canonical(args[1])
	if err != nil {
		return err
	}
	inv, err := installstate.Load(installDir)
	if err != nil {
		return err
	}
	profile, _ := serviceProfileForHelper(inv.Profiles, nil)
	serviceRestartAttempted := false
	if profile != nil {
		defer func() {
			if !serviceRestartAttempted {
				_ = startManagedService(*profile)
			}
		}()
	}
	updateLock, err := acquireWindowsUpdateLock(ctx, inv, 45*time.Second)
	if err != nil {
		return err
	}
	defer updateLock.Close()
	if !pathWithin(inv.LockDir, transactionDir) {
		return errors.New("update transaction is outside the recorded lock directory")
	}
	if err := installstate.CheckDirectory(transactionDir); err != nil {
		return err
	}
	defer func() { _ = scheduleWindowsCleanup(transactionDir) }()
	manifestPath := filepath.Join(transactionDir, updateManifestName)
	if err := installstate.CheckPrivateFile(manifestPath); err != nil {
		return err
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest helperManifest
	if json.Unmarshal(data, &manifest) != nil {
		return errors.New("update helper manifest is invalid")
	}
	if manifest.InstallID != inv.ID || manifest.Snapshot.ID != inv.ID || manifest.Snapshot.InstallDir != inv.InstallDir || manifest.Snapshot.LockDir != inv.LockDir {
		return errors.New("update helper manifest is invalid")
	}
	// The service was stopped using the profile set recorded before the release
	// fetch. Prefer that profile for cleanup if another service profile was
	// registered while the helper was being staged.
	profile, multipleServiceProfiles := serviceProfileForHelper(inv.Profiles, manifest.Snapshot.Profiles)
	if !manifest.Snapshot.matches(inv) {
		return errors.New("update helper manifest is invalid")
	}
	if multipleServiceProfiles {
		return errors.New("multiple service profiles are unsupported")
	}
	if _, ok := parseReleaseVersion(manifest.Version); !ok {
		return errors.New("update helper version is invalid")
	}
	if manifest.Version != Version {
		return errors.New("update helper executable does not match the staged release version")
	}
	if inv.Removing {
		return errors.New("installation is being removed")
	}
	files := make(map[string][]byte, len(manifest.Hashes))
	for name, want := range manifest.Hashes {
		if !knownFileName(inv, name) {
			return errors.New("update helper manifest contains an unowned file")
		}
		path := filepath.Join(transactionDir, name)
		if err := installstate.CheckFile(path); err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			return errors.New("staged update file failed its checksum check")
		}
		files[name] = b
	}
	if len(files) != len(inv.Files) {
		return errors.New("update helper package is incomplete")
	}
	for _, owned := range inv.Files {
		if owned.Name != "wireguard.dll" {
			continue
		}
		installed, err := os.ReadFile(installstate.ResourcePath(inv, owned))
		if err != nil {
			return err
		}
		if !bytes.Equal(installed, files[owned.Name]) {
			return errors.New("staged update attempted to replace the pinned WireGuardNT DLL")
		}
	}
	var newHashes map[string]string
	var rollback func() error
	var commit func() error
	lock, err := installstate.Lock(installDir)
	if err != nil {
		return err
	}
	inv, err = installstate.Load(installDir)
	if err != nil {
		_ = lock.Close()
		return err
	}
	if inv.Removing {
		_ = lock.Close()
		return errors.New("installation is being removed")
	}
	if err := selfupdate.RecoverLocked(inv); err != nil {
		_ = lock.Close()
		return err
	}
	inv, err = installstate.Load(installDir)
	if err != nil {
		_ = lock.Close()
		return err
	}
	if !manifest.Snapshot.matches(inv) {
		_ = lock.Close()
		return errors.New("installation profiles or files changed while the release was being fetched; retry self-update")
	}
	var lastErr error
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		newHashes, rollback, commit, lastErr = selfupdate.Apply(inv, files)
		if lastErr == nil {
			if err := installstate.UpdateProgramHashesLocked(inv, newHashes); err != nil {
				restoreErr := rollback()
				_ = lock.Close()
				return errors.Join(fmt.Errorf("record updated program hashes: %w", err), restoreErr)
			}
			break
		}
		if recoverErr := selfupdate.RecoverLocked(inv); recoverErr != nil {
			_ = lock.Close()
			return errors.Join(lastErr, recoverErr)
		}
		if verifyErr := verifyInstalledFiles(inv); verifyErr != nil {
			_ = lock.Close()
			return errors.Join(lastErr, verifyErr)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		_ = lock.Close()
		if profile != nil {
			serviceRestartAttempted = true
			_ = startManagedService(*profile)
		}
		return fmt.Errorf("Windows update helper could not replace installed files: %w", lastErr)
	}
	if err := lock.Close(); err != nil {
		return helperRollback(installDir, rollback, profileValue(profile), err)
	}
	if profile != nil {
		serviceRestartAttempted = true
		if err := startManagedService(*profile); err != nil {
			return helperRollback(installDir, rollback, *profile, err)
		}
		if err := waitForService(ctx, profile.RuntimeDir); err != nil {
			if stopErr := service.Manage("stop", service.Config{ConfigDirectory: profile.ConfigDir, StateDirectory: profile.StateDir, RuntimeDirectory: profile.RuntimeDir}); stopErr != nil {
				return errors.Join(fmt.Errorf("updated Windows service did not become ready: %w", err), fmt.Errorf("could not stop updated service; rollback is pending a later update recovery: %w", stopErr))
			}
			return helperRollback(installDir, rollback, *profile, err)
		}
	} else if err := verifyUpdatedBinary(ctx, filepath.Join(installDir, "peerimeter-agent.exe"), manifest.Version); err != nil {
		return helperRollback(installDir, rollback, installstate.Profile{}, err)
	}
	if err := commit(); err != nil {
		return err
	}
	return nil
}

func serviceProfileForHelper(current, beforeUpdate []installstate.Profile) (*installstate.Profile, bool) {
	profile := func(profiles []installstate.Profile) *installstate.Profile {
		for i := range profiles {
			if profiles[i].Service {
				selected := profiles[i]
				return &selected
			}
		}
		return nil
	}
	selected := profile(beforeUpdate)
	if selected == nil {
		selected = profile(current)
	}
	serviceCount := 0
	for _, p := range current {
		if p.Service {
			serviceCount++
		}
	}
	return selected, serviceCount > 1
}

func profileValue(profile *installstate.Profile) installstate.Profile {
	if profile == nil {
		return installstate.Profile{}
	}
	return *profile
}

func helperRollback(dir string, rollback func() error, profile installstate.Profile, cause error) error {
	lock, lockErr := installstate.Lock(dir)
	if lockErr != nil {
		return errors.Join(cause, fmt.Errorf("automatic rollback was incomplete: %w", lockErr))
	}
	err := errors.Join(rollback(), lock.Close())
	if profile.Service {
		err = errors.Join(err, startManagedService(profile), waitForService(context.Background(), profile.RuntimeDir))
	}
	return errors.Join(cause, err)
}

func acquireWindowsUpdateLock(ctx context.Context, inv installstate.Inventory, timeout time.Duration) (io.Closer, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		lock, err := selfupdate.LockUpdate(inv)
		if err == nil {
			return lock, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("wait for update ownership lock: %w", err)
		case <-ticker.C:
		}
	}
}

func knownFileName(inv installstate.Inventory, name string) bool {
	for _, f := range inv.Files {
		if f.Name == name {
			return true
		}
	}
	return false
}

func pathWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func scheduleWindowsCleanup(dir string) error {
	quoted := strings.ReplaceAll(dir, "'", "''")
	script := "Start-Sleep -Seconds 2; Remove-Item -LiteralPath '" + quoted + "' -Recurse -Force"
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Start()
}
