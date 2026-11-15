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
	"github.com/peerimeter/peerimeter-agent/internal/local"
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
	dir, err := installstate.CreatePrivateTempDir(inv.LockDir, ".peerimeter-update-")
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

func scheduleWindowsRecovery(inv installstate.Inventory) error {
	dir, err := installstate.CreatePrivateTempDir(inv.LockDir, ".peerimeter-recovery-")
	if err != nil {
		return fmt.Errorf("create protected Windows recovery helper directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	executable, err := os.Executable()
	if err != nil {
		cleanup()
		return err
	}
	source, err := os.Open(executable)
	if err != nil {
		cleanup()
		return err
	}
	helperPath := filepath.Join(dir, "peerimeter-agent.exe")
	help, err := os.OpenFile(helperPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		_ = source.Close()
		cleanup()
		return err
	}
	_, copyErr := io.Copy(help, source)
	closeSourceErr := source.Close()
	syncErr := help.Sync()
	closeHelperErr := help.Close()
	if err := errors.Join(copyErr, closeSourceErr, syncErr, closeHelperErr); err != nil {
		cleanup()
		return err
	}
	if err := installstate.CheckFile(helperPath); err != nil {
		cleanup()
		return fmt.Errorf("verify protected Windows recovery helper: %w", err)
	}
	cmd := exec.Command(helperPath, "__recover-helper", inv.InstallDir, dir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cleanup()
		return fmt.Errorf("start Windows recovery helper: %w", err)
	}
	_ = cmd.Process.Release()
	return nil
}

func runWindowsRecoveryHelper(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return errors.New("invalid recovery helper arguments")
	}
	installDir, err := installstate.Canonical(args[0])
	if err != nil {
		return err
	}
	helperDir, err := installstate.Canonical(args[1])
	if err != nil {
		return err
	}
	inv, err := installstate.Load(installDir)
	if err != nil {
		return err
	}
	updateLock, err := acquireWindowsUpdateLock(ctx, inv, 45*time.Second)
	if err != nil {
		return err
	}
	defer updateLock.Close()
	inv, err = installstate.Load(installDir)
	if err != nil {
		return err
	}
	if !pathWithin(inv.LockDir, helperDir) || installstate.CheckDirectory(helperDir) != nil {
		return errors.New("recovery helper is outside the protected installation lock directory")
	}
	defer func() { _ = scheduleWindowsCleanup(helperDir) }()
	journalPath := filepath.Join(inv.LockDir, selfupdate.JournalFilename)
	if _, err := os.Lstat(journalPath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	} else if err := installstate.CheckPrivateFile(journalPath); err != nil {
		return err
	}
	var profile *installstate.Profile
	for i := range inv.Profiles {
		p := &inv.Profiles[i]
		if p.Service {
			if profile != nil {
				return errors.New("multiple service profiles prevent safe update recovery")
			}
			profile = p
			continue
		}
		for _, dir := range []string{p.StateDir, p.RuntimeDir} {
			guard, guardErr := local.TryAcquireExisting(dir)
			if guardErr != nil {
				return errors.New("stop active agent profiles before update recovery")
			}
			if guard != nil {
				_ = guard.Close()
			}
		}
	}
	if profile != nil {
		if err := service.Manage("stop", service.Config{ConfigDirectory: profile.ConfigDir, StateDirectory: profile.StateDir, RuntimeDirectory: profile.RuntimeDir}); err != nil {
			return fmt.Errorf("stop service before update recovery: %w", err)
		}
	}
	lock, err := installstate.Lock(installDir)
	if err != nil {
		return err
	}
	var recoveryErr error
	profileCheckFailed := false
	transactionDeadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(transactionDeadline) {
		if err := ctx.Err(); err != nil {
			recoveryErr = err
			break
		}
		current, loadErr := installstate.Load(installDir)
		if loadErr != nil {
			recoveryErr = loadErr
			break
		}
		if recoveryErr = ensureNoActiveUpdateProfiles(current); recoveryErr != nil {
			profileCheckFailed = true
			break
		}
		recoveryErr = selfupdate.RecoverLocked(current)
		if recoveryErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			recoveryErr = ctx.Err()
			break
		case <-time.After(250 * time.Millisecond):
		}
	}
	if profileCheckFailed {
		return restartServiceAfterRecoveryAbort(ctx, profile, lock, recoveryErr, startManagedService, waitForService)
	}
	if err := errors.Join(recoveryErr, lock.Close()); err != nil {
		return err
	}
	if profile != nil {
		if err := startManagedService(*profile); err != nil {
			return err
		}
		if err := waitForService(ctx, profile.RuntimeDir); err != nil {
			return err
		}
	}
	return nil
}

func restartServiceAfterRecoveryAbort(ctx context.Context, profile *installstate.Profile, lock io.Closer, cause error, start func(installstate.Profile) error, wait func(context.Context, string) error) error {
	closeErr := lock.Close()
	if profile == nil {
		return errors.Join(cause, closeErr)
	}
	restartErr := start(*profile)
	if restartErr == nil {
		restartErr = wait(ctx, profile.RuntimeDir)
	}
	return errors.Join(cause, closeErr, restartErr)
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
	profile, _ := serviceProfileForHelper(inv.Profiles, nil, false)
	updateLock, err := acquireWindowsUpdateLock(ctx, inv, 45*time.Second)
	if err != nil {
		return err
	}
	defer updateLock.Close()
	serviceRestartAttempted := false
	defer func() {
		if !serviceRestartAttempted && profile != nil {
			_ = startManagedService(*profile)
		}
	}()
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
	profile, multipleServiceProfiles := serviceProfileForHelper(inv.Profiles, manifest.Snapshot.Profiles, true)
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
	if err := ensureNoActiveUpdateProfiles(inv); err != nil {
		_ = lock.Close()
		return fmt.Errorf("stop active agent profiles before update recovery: %w", err)
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
		if recoverErr := ensureNoActiveUpdateProfiles(inv); recoverErr != nil {
			_ = lock.Close()
			return errors.Join(lastErr, fmt.Errorf("stop active agent profiles before update recovery: %w", recoverErr))
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
			if stopErr := service.Manage("stop", service.Config{ConfigDirectory: profile.ConfigDir, StateDirectory: profile.StateDir, RuntimeDirectory: profile.RuntimeDir}); stopErr != nil {
				return errors.Join(fmt.Errorf("start updated Windows service: %w", err), fmt.Errorf("could not stop partially started service; rollback is pending a later update recovery: %w", stopErr))
			}
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

func serviceProfileForHelper(current, beforeUpdate []installstate.Profile, preferSnapshot bool) (*installstate.Profile, bool) {
	profile := func(profiles []installstate.Profile) *installstate.Profile {
		for i := range profiles {
			if profiles[i].Service {
				selected := profiles[i]
				return &selected
			}
		}
		return nil
	}
	selected := profile(current)
	if preferSnapshot {
		selected = profile(beforeUpdate)
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
	inv, err := installstate.Load(dir)
	if err == nil {
		err = ensureNoActiveUpdateProfiles(inv)
	}
	if err != nil {
		_ = lock.Close()
		return errors.Join(cause, fmt.Errorf("automatic rollback is pending because an agent profile may still be running: %w", err))
	}
	err = errors.Join(rollback(), lock.Close())
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
