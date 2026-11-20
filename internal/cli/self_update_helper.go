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

const updateManifestName = ".update.json"
const updateResultSuffix = ".result.json"

type windowsUpdateResult struct {
	State          string `json:"state"`
	HelperReady    bool   `json:"helper_ready,omitempty"`
	UpdatedVersion string `json:"updated_version,omitempty"`
	Message        string `json:"message,omitempty"`
}

// TODO(next major): remove fallback for update manifests staged by older agents.
const legacyUpdateManifestName = ".peerimeter-agent.update.json"

type helperManifest struct {
	Version   string                  `json:"version"`
	InstallID string                  `json:"installation_id"`
	Hashes    map[string]string       `json:"hashes"`
	Snapshot  updateInventorySnapshot `json:"inventory_snapshot"`
}

func scheduleWindowsUpdate(inv installstate.Inventory, files map[string][]byte, tag string, profile *installstate.Profile, out io.Writer, jsonOutput bool) error {
	dir, err := installstate.CreatePrivateTempDir(inv.LockDir, ".peerimeter-update-")
	if err != nil {
		return restartManagedServiceAfterFailure(profile, fmt.Errorf("create update staging directory under recorded lock directory: %w", err))
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
			return restartManagedServiceAfterFailure(profile, err)
		}
	}
	manifest, err := json.Marshal(helperManifest{Version: tag, InstallID: inv.ID, Hashes: hashes, Snapshot: snapshotUpdateInventory(inv)})
	if err != nil {
		cleanup()
		return restartManagedServiceAfterFailure(profile, err)
	}
	if err := installstate.WritePrivate(filepath.Join(dir, updateManifestName), append(manifest, '\n')); err != nil {
		cleanup()
		return restartManagedServiceAfterFailure(profile, err)
	}
	resultPath := dir + updateResultSuffix
	pending, _ := json.Marshal(windowsUpdateResult{State: "pending"})
	if err := installstate.WritePrivate(resultPath, append(pending, '\n')); err != nil {
		cleanup()
		return restartManagedServiceAfterFailure(profile, fmt.Errorf("create Windows update result file: %w", err))
	}
	helper := filepath.Join(dir, "peerimeter-agent.exe")
	cmd := exec.Command(helper, "__update-helper", inv.InstallDir, dir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.Dir = inv.LockDir
	cmd.SysProcAttr = updateHelperProcessAttributes()
	if err := cmd.Start(); err != nil {
		cleanup()
		return restartManagedServiceAfterFailure(profile, fmt.Errorf("start Windows update helper: %w", err))
	}
	ready := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var response windowsUpdateResult
		if data, readErr := os.ReadFile(resultPath); readErr == nil && json.Unmarshal(data, &response) == nil {
			if response.HelperReady {
				ready = true
				break
			}
			if response.State == "failed" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return restartManagedServiceAfterFailure(profile, fmt.Errorf("Windows update helper could not initialize; inspect %s", resultPath))
	}
	_ = cmd.Process.Release()
	return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "scheduled", PreviousVersion: Version, UpdatedVersion: tag, ResultFile: resultPath}, false)
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
	profile, err := findAndCheckActiveProfiles(inv.Profiles, func(error) error {
		return errors.New("stop active agent profiles before update recovery")
	})
	if errors.Is(err, errMultipleServiceProfiles) {
		return errors.New("multiple service profiles prevent safe update recovery")
	}
	if err != nil {
		return err
	}
	if profile != nil {
		if err := service.Manage("stop", profileServiceConfig(*profile)); err != nil {
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

func runWindowsUpdateHelper(ctx context.Context, args []string) (resultErr error) {
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
	resultPath := transactionDir + updateResultSuffix
	updatedVersion := ""
	defer func() {
		state := "updated"
		message := ""
		if resultErr != nil {
			state = "failed"
			message = resultErr.Error()
		}
		data, marshalErr := json.Marshal(windowsUpdateResult{State: state, UpdatedVersion: updatedVersion, Message: message})
		if marshalErr == nil {
			resultErr = errors.Join(resultErr, installstate.WritePrivate(resultPath, append(data, '\n')))
		}
	}()
	inv, err := installstate.Load(installDir)
	if err != nil {
		return err
	}
	profile, _ := serviceProfileForHelper(inv.Profiles, nil, false)
	serviceRestartAttempted := false
	defer func() {
		if !serviceRestartAttempted && profile != nil {
			resultErr = errors.Join(resultErr, startManagedService(*profile))
		}
	}()
	// Acknowledge process startup before waiting for the parent to release its
	// update lock. The parent releases that lock after it receives this signal.
	ready, err := json.Marshal(windowsUpdateResult{State: "pending", HelperReady: true})
	if err != nil {
		return err
	}
	if err := installstate.WritePrivate(resultPath, append(ready, '\n')); err != nil {
		return fmt.Errorf("confirm Windows update helper startup: %w", err)
	}
	// The parent already stopped the service before scheduling this helper.
	// A bounded handoff lets the helper report failure and restart the service.
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
	if _, err := os.Lstat(manifestPath); os.IsNotExist(err) {
		// TODO(next major): remove fallback for the previous update manifest name.
		manifestPath = filepath.Join(transactionDir, legacyUpdateManifestName)
	} else if err != nil {
		return err
	}
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
	updatedVersion = manifest.Version
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
		profileValue := *profile
		serviceConfig := profileServiceConfig(profileValue)
		err := startAndWaitForUpdatedService(
			func() error { return startManagedService(profileValue) },
			func() error { return waitForService(ctx, profileValue.RuntimeDir) },
			func() error { return service.Manage("stop", serviceConfig) },
			"start updated Windows service",
			"updated Windows service did not become ready",
		)
		if err != nil {
			if rollbackMustWaitForRecovery(err) {
				return err
			}
			return helperRollback(installDir, rollback, profileValue, err)
		}
	} else if err := verifyUpdatedBinary(ctx, filepath.Join(installDir, "peerimeter-agent.exe"), manifest.Version); err != nil {
		return helperRollback(installDir, rollback, installstate.Profile{}, err)
	}
	if err := commit(); err != nil {
		return err
	}
	resultErr = nil
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
	err := restoreUpdateFiles(nil, dir, rollback)
	if profile.Service {
		err = errors.Join(err, startManagedService(profile), waitForService(context.Background(), profile.RuntimeDir))
	}
	return errors.Join(cause, err)
}

func acquireWindowsUpdateLock(ctx context.Context, inv installstate.Inventory, timeout time.Duration) (io.Closer, error) {
	var deadline <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}
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
		case <-deadline:
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
