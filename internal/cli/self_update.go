package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/diagnostic"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/selfupdate"
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
)

func newSelfUpdateCommand(app *application) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "self-update",
		Short: "Update this installed agent to the latest stable release",
		Long:  "Checks for the latest stable release, displays the current and new versions, asks before updating unless --yes is set, verifies SHA256SUMS, and replaces only program files recorded by this installation.",
		Args:  noArguments,
		RunE: app.handle(func(cmd *cobra.Command) error {
			return selfUpdate(cmd.Context(), app.out, app.promptOut, app.in, app.jsonOutput, yes, app.color)
		}),
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Update without asking for confirmation")
	return cmd
}

type selfUpdateResult struct {
	State           string   `json:"state"`
	PreviousVersion string   `json:"previous_version,omitempty"`
	UpdatedVersion  string   `json:"updated_version,omitempty"`
	Files           []string `json:"files,omitempty"`
}

func selfUpdate(ctx context.Context, out, promptOut io.Writer, in io.Reader, jsonOutput, yes bool, colorMode string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	installDir, err := installstate.Canonical(filepath.Dir(exe))
	if err != nil {
		return err
	}
	return selfUpdateAt(ctx, out, jsonOutput, installDir, Version, runtime.GOOS, runtime.GOARCH, selfUpdateDeps{
		latest: latestStableReleaseTag,
		fetch:  selfupdate.Fetch, verify: verifyUpdatedBinary, manage: service.Manage, wait: waitForService,
		yes: yes, progress: newSelfUpdateProgress(promptOut, colorMode),
		confirm: func(current, latest string) (bool, error) {
			return confirmSelfUpdate(in, promptOut, current, latest)
		},
	})
}

func latestStableReleaseTag(ctx context.Context) (string, error) {
	release, err := latestReleaseAt(ctx, latestReleaseURL, http.DefaultClient)
	if err != nil {
		return "", fmt.Errorf("check latest release before self-update: %w", err)
	}
	return release.TagName, nil
}

func confirmSelfUpdate(in io.Reader, promptOut io.Writer, current, latest string) (bool, error) {
	if _, err := fmt.Fprintf(promptOut, "Update Peerimeter Agent from %s to %s? [y/N]: ", current, latest); err != nil {
		return false, err
	}
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read update confirmation: %w", err)
	}
	answer = strings.TrimSpace(answer)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}

type updateFetcher func(context.Context, *http.Client, string, string) (string, map[string][]byte, error)
type updateReleaseChecker func(context.Context) (string, error)
type updateBinaryVerifier func(context.Context, string, string) error
type updateServiceManager func(string, service.Config) error
type updateServiceWaiter func(context.Context, string) error

type selfUpdateDeps struct {
	latest   updateReleaseChecker
	fetch    updateFetcher
	verify   updateBinaryVerifier
	manage   updateServiceManager
	wait     updateServiceWaiter
	yes      bool
	confirm  func(string, string) (bool, error)
	progress *selfUpdateProgress
}

// selfUpdateAt keeps release retrieval and binary execution injectable so the
// complete inventory-to-replacement flow can be exercised without network or
// service side effects.
func selfUpdateAt(ctx context.Context, out io.Writer, jsonOutput bool, installDir, currentVersion, goos, goarch string, deps selfUpdateDeps) error {
	defer deps.progress.stop()
	inv, err := runSelfUpdateStep(deps.progress, "Validating installation inventory", func() (installstate.Inventory, error) {
		return installstate.Load(installDir)
	})
	if err != nil {
		return fmt.Errorf("self-update requires a valid installation inventory: %w", err)
	}
	if inv.Removing {
		return errors.New("this installation is being removed")
	}
	updateLock, err := runSelfUpdateStep(deps.progress, "Checking update and uninstall locks", func() (io.Closer, error) {
		return selfupdate.LockUpdate(inv)
	})
	if err != nil {
		return fmt.Errorf("another update or uninstall is already using this installation: %w", err)
	}
	defer updateLock.Close()
	recovered, err := runSelfUpdateStep(deps.progress, "Checking for interrupted update recovery", func() (bool, error) {
		return recoverInterruptedUpdate(installDir, inv, goos)
	})
	if err != nil {
		return err
	}
	if recovered {
		state := "recovered"
		if goos == "windows" {
			state = "recovery_scheduled"
		}
		return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: state, PreviousVersion: Version})
	}
	inv, err = runSelfUpdateStep(deps.progress, "Reloading installation inventory", func() (installstate.Inventory, error) {
		return installstate.Load(installDir)
	})
	if err != nil {
		return err
	}
	if err := runSelfUpdateAction(deps.progress, "Verifying installed program files", func() error {
		return verifyInstalledFiles(inv)
	}); err != nil {
		return err
	}
	latestTag, err := runSelfUpdateStep(deps.progress, "Checking the latest stable release", func() (string, error) {
		return deps.latest(ctx)
	})
	if err != nil {
		return err
	}
	latest, ok := parseReleaseVersion(latestTag)
	current, currentOK := parseReleaseVersion(currentVersion)
	if !ok || !currentOK {
		deps.progress.stop()
		return fmt.Errorf("cannot compare agent version %q with release %q", currentVersion, latestTag)
	}
	upToDate := compareVersion(latest, current) <= 0
	if upToDate {
		deps.progress.stop(selfUpdateProgressUpToDate)
	} else {
		deps.progress.stop(selfUpdateProgressUpdateAvailable)
	}
	if !jsonOutput {
		if _, err := fmt.Fprintf(out, "Current version: %s\nLatest version: %s\n", currentVersion, latestTag); err != nil {
			return err
		}
	}
	if upToDate {
		return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "up_to_date", PreviousVersion: currentVersion, UpdatedVersion: latestTag})
	}
	if !deps.yes {
		if deps.confirm == nil {
			return errors.New("self-update confirmation is unavailable; rerun with --yes")
		}
		confirmed, err := deps.confirm(currentVersion, latestTag)
		if err != nil {
			return err
		}
		if !confirmed {
			return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "cancelled", PreviousVersion: currentVersion, UpdatedVersion: latestTag})
		}
	}
	updateSnapshot := inv
	updateSnapshot.Files = slices.Clone(inv.Files)
	updateSnapshot.Profiles = slices.Clone(inv.Profiles)
	type fetchedRelease struct {
		tag   string
		files map[string][]byte
	}
	fetched, err := runSelfUpdateStep(deps.progress, fmt.Sprintf("Downloading and verifying %s for %s/%s", latestTag, goos, goarch), func() (fetchedRelease, error) {
		tag, files, err := deps.fetch(ctx, nil, goos, goarch)
		return fetchedRelease{tag: tag, files: files}, err
	})
	if err != nil {
		return err
	}
	tag, files := fetched.tag, fetched.files
	if tag != latestTag {
		return fmt.Errorf("latest release changed from %s to %s while preparing the update; run self-update again", latestTag, tag)
	}
	for _, owned := range inv.Files {
		if _, ok := files[owned.Name]; !ok {
			return fmt.Errorf("release package is missing inventoried program file %q", owned.Name)
		}
	}
	if goos == "windows" {
		// WireGuardNT is an independently pinned, Authenticode-verified runtime
		// dependency. Do not change it as part of an agent-only update.
		for _, owned := range inv.Files {
			if owned.Name == "wireguard.dll" {
				old, err := os.ReadFile(installstate.ResourcePath(inv, owned))
				if err != nil {
					return err
				}
				if !bytes.Equal(old, files[owned.Name]) {
					return errors.New("release contains a different WireGuardNT DLL; install it through the verified installer")
				}
			}
		}
	}
	var managedService *installstate.Profile
	serviceConfig := func(p *installstate.Profile) service.Config {
		return service.Config{ConfigDirectory: p.ConfigDir, StateDirectory: p.StateDir, RuntimeDirectory: p.RuntimeDir}
	}
	restartAfterFailure := func(profile *installstate.Profile, cause error) error {
		if profile == nil {
			return cause
		}
		if err := deps.manage("start", serviceConfig(profile)); err != nil {
			return errors.Join(cause, fmt.Errorf("restart installed service after update failure: %w", err))
		}
		if err := deps.wait(context.Background(), profile.RuntimeDir); err != nil {
			return errors.Join(cause, fmt.Errorf("verify service after update failure: %w", err))
		}
		return cause
	}
	if err := runSelfUpdateAction(deps.progress, "Checking that agent profiles are stopped", func() error {
		for i := range inv.Profiles {
			p := &inv.Profiles[i]
			if p.Service {
				if managedService != nil {
					return errors.New("installation has multiple service profiles; self-update cannot select one safely")
				}
				managedService = p
				continue
			}
			for _, dir := range []string{p.StateDir, p.RuntimeDir} {
				guard, err := local.TryAcquireExisting(dir)
				if err != nil {
					return selfUpdateProfileLockError(err)
				}
				if guard != nil {
					_ = guard.Close()
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if managedService != nil {
		if err := runSelfUpdateAction(deps.progress, "Stopping the managed agent service", func() error {
			return deps.manage("stop", serviceConfig(managedService))
		}); err != nil {
			return restartAfterFailure(managedService, fmt.Errorf("stop installed service before update: %w", err))
		}
		if err := runSelfUpdateAction(deps.progress, "Waiting for the stopped agent to release its locks", func() error {
			return waitForProfileStopped(ctx, *managedService)
		}); err != nil {
			return restartAfterFailure(managedService, fmt.Errorf("wait for installed service to stop: %w", err))
		}
	}
	if goos == "windows" {
		return runSelfUpdateAction(deps.progress, "Scheduling Windows file replacement", func() error {
			return scheduleWindowsUpdate(inv, files, tag, managedService, out, jsonOutput)
		})
	}
	lock, err := runSelfUpdateStep(deps.progress, "Locking installation for replacement", func() (io.Closer, error) {
		return installstate.Lock(installDir)
	})
	if err != nil {
		return restartAfterFailure(managedService, err)
	}
	inv, err = runSelfUpdateStep(deps.progress, "Rechecking installation inventory", func() (installstate.Inventory, error) {
		return installstate.Load(installDir)
	})
	if err != nil {
		_ = lock.Close()
		return restartAfterFailure(managedService, err)
	}
	if inv.Removing {
		_ = lock.Close()
		return restartAfterFailure(managedService, errors.New("this installation is being removed"))
	}
	if !sameUpdateSnapshot(updateSnapshot, inv) {
		_ = lock.Close()
		return restartAfterFailure(managedService, errors.New("installation profiles or files changed while the release was being fetched; retry self-update"))
	}
	for _, profile := range inv.Profiles {
		for _, dir := range []string{profile.StateDir, profile.RuntimeDir} {
			guard, guardErr := local.TryAcquireExisting(dir)
			if guardErr != nil {
				_ = lock.Close()
				return restartAfterFailure(managedService, selfUpdateProfileLockError(guardErr))
			}
			if guard != nil {
				_ = guard.Close()
			}
		}
	}
	if err := verifyInstalledFiles(inv); err != nil {
		_ = lock.Close()
		return restartAfterFailure(managedService, err)
	}
	type appliedUpdate struct {
		hashes   map[string]string
		rollback func() error
		commit   func() error
	}
	applied, err := runSelfUpdateStep(deps.progress, "Replacing inventoried program files", func() (appliedUpdate, error) {
		hashes, rollback, commit, err := selfupdate.Apply(inv, files)
		return appliedUpdate{hashes: hashes, rollback: rollback, commit: commit}, err
	})
	if err != nil {
		_ = lock.Close()
		return restartAfterFailure(managedService, err)
	}
	newHashes, rollback, commit := applied.hashes, applied.rollback, applied.commit
	if err := runSelfUpdateAction(deps.progress, "Recording updated program file checksums", func() error {
		return installstate.UpdateProgramHashesLocked(inv, newHashes)
	}); err != nil {
		restoreErr := rollback()
		_ = lock.Close()
		cause := errors.Join(fmt.Errorf("record updated program hashes: %w", err), restoreErr)
		return restartAfterFailure(managedService, cause)
	}
	if err := lock.Close(); err != nil {
		return rollbackInstalledUpdate(deps.progress, installDir, rollback, profileValue(managedService), err, deps.manage, deps.wait)
	}
	if managedService != nil {
		if err := runSelfUpdateAction(deps.progress, "Starting the updated agent service", func() error {
			return deps.manage("start", serviceConfig(managedService))
		}); err != nil {
			if stopErr := deps.manage("stop", serviceConfig(managedService)); stopErr != nil {
				return errors.Join(fmt.Errorf("restart updated service: %w", err), fmt.Errorf("could not stop partially started service; rollback is pending a later update recovery: %w", stopErr))
			}
			return rollbackInstalledUpdate(deps.progress, installDir, rollback, *managedService, fmt.Errorf("restart updated service: %w", err), deps.manage, deps.wait)
		}
		if err := runSelfUpdateAction(deps.progress, "Waiting for the updated service to become ready", func() error {
			return deps.wait(ctx, managedService.RuntimeDir)
		}); err != nil {
			if stopErr := deps.manage("stop", serviceConfig(managedService)); stopErr != nil {
				return errors.Join(fmt.Errorf("updated service did not become ready: %w", err), fmt.Errorf("could not stop updated service; rollback is pending a later update recovery: %w", stopErr))
			}
			return rollbackInstalledUpdate(deps.progress, installDir, rollback, *managedService, fmt.Errorf("updated service did not become ready: %w", err), deps.manage, deps.wait)
		}
	} else if err := runSelfUpdateAction(deps.progress, "Verifying the updated agent binary", func() error {
		return deps.verify(ctx, filepath.Join(installDir, binaryNameFor(goos)), tag)
	}); err != nil {
		return rollbackInstalledUpdate(deps.progress, installDir, rollback, installstate.Profile{}, err, deps.manage, deps.wait)
	}
	if err := runSelfUpdateAction(deps.progress, "Finalizing update and removing rollback backup", func() error {
		return commit()
	}); err != nil {
		return fmt.Errorf("update succeeded but backup cleanup needs attention: %w", err)
	}
	filesUpdated := make([]string, 0, len(inv.Files))
	for _, f := range inv.Files {
		filesUpdated = append(filesUpdated, f.Name)
	}
	deps.progress.stop(selfUpdateProgressUpdateSucceeded)
	return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "updated", PreviousVersion: currentVersion, UpdatedVersion: tag, Files: filesUpdated})
}

func selfUpdateProfileLockError(err error) error {
	if errors.Is(err, local.ErrBusy) {
		return diagnostic.Wrap(fmt.Errorf("an agent process started while the release was being fetched; retry self-update: %w", err))
	}
	return diagnostic.Wrap(fmt.Errorf("cannot verify whether an agent profile is stopped: %w", err))
}

func sameUpdateSnapshot(a, b installstate.Inventory) bool {
	return snapshotUpdateInventory(a).matches(b)
}

func waitForProfileStopped(parent context.Context, profile installstate.Profile) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		busy := false
		for _, dir := range []string{profile.StateDir, profile.RuntimeDir} {
			guard, err := local.TryAcquireExisting(dir)
			if errors.Is(err, local.ErrBusy) {
				busy = true
				continue
			}
			if err != nil {
				return fmt.Errorf("cannot inspect stopped agent profile: %w", err)
			}
			if guard != nil {
				if err := guard.Close(); err != nil {
					return fmt.Errorf("release stopped agent profile lock: %w", err)
				}
			}
		}
		if !busy {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped service still owns an agent profile lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type updateInventorySnapshot struct {
	ID, InstallDir, DataDir, DocDir, LockDir string
	Files                                    []installstate.File
	Profiles                                 []installstate.Profile
}

func snapshotUpdateInventory(inv installstate.Inventory) updateInventorySnapshot {
	return updateInventorySnapshot{
		ID: inv.ID, InstallDir: inv.InstallDir, DataDir: inv.DataDir, DocDir: inv.DocDir, LockDir: inv.LockDir,
		Files: slices.Clone(inv.Files), Profiles: slices.Clone(inv.Profiles),
	}
}

func (s updateInventorySnapshot) matches(inv installstate.Inventory) bool {
	return s.ID == inv.ID && s.InstallDir == inv.InstallDir && s.DataDir == inv.DataDir && s.DocDir == inv.DocDir && s.LockDir == inv.LockDir && slices.Equal(s.Files, inv.Files) && slices.Equal(s.Profiles, inv.Profiles)
}

func recoverInterruptedUpdate(installDir string, inv installstate.Inventory, goos string) (bool, error) {
	_, found, err := selfupdate.FindJournal(inv)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	if goos == "windows" {
		return true, scheduleWindowsRecovery(inv)
	}
	var profile *installstate.Profile
	for i := range inv.Profiles {
		p := &inv.Profiles[i]
		if p.Service {
			if profile != nil {
				return false, errors.New("multiple service profiles prevent safe update recovery")
			}
			profile = p
			continue
		}
		guard, guardErr := local.TryAcquireExisting(p.RuntimeDir)
		if guardErr != nil {
			return false, errors.New("stop active agent profiles before update recovery")
		}
		if guard != nil {
			_ = guard.Close()
		}
	}
	if profile != nil {
		if err := service.Manage("stop", service.Config{ConfigDirectory: profile.ConfigDir, StateDirectory: profile.StateDir, RuntimeDirectory: profile.RuntimeDir}); err != nil {
			return false, fmt.Errorf("stop service before update recovery: %w", err)
		}
	}
	lock, err := installstate.Lock(installDir)
	if err != nil {
		return false, restartServiceAfterFailure(profile, err)
	}
	current, err := installstate.Load(installDir)
	if err == nil {
		err = ensureNoActiveUpdateProfiles(current)
	}
	if err == nil {
		err = selfupdate.RecoverLocked(current)
	}
	err = errors.Join(err, lock.Close())
	err = restartServiceAfterFailure(profile, err)
	return err == nil, err
}

func newUpdateHelperCommand(app *application) *cobra.Command {
	return &cobra.Command{
		Use:    "__update-helper <install-dir> <transaction-dir>",
		Short:  "Complete a Windows self-update file replacement",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			app.ran = true
			if runtime.GOOS != "windows" {
				return errors.New("update helper is only available on Windows")
			}
			return runWindowsUpdateHelper(cmd.Context(), args)
		},
	}
}

func newUpdateRecoveryHelperCommand(app *application) *cobra.Command {
	return &cobra.Command{
		Use:    "__recover-helper <install-dir> <helper-dir>",
		Short:  "Recover an interrupted Windows self-update",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			app.ran = true
			if runtime.GOOS != "windows" {
				return errors.New("update recovery helper is only available on Windows")
			}
			return runWindowsRecoveryHelper(cmd.Context(), args)
		},
	}
}

func binaryNameFor(goos string) string {
	if goos == "windows" {
		return "peerimeter-agent.exe"
	}
	return "peerimeter-agent"
}

func verifyInstalledFiles(inv installstate.Inventory) error {
	for _, owned := range inv.Files {
		path := installstate.ResourcePath(inv, owned)
		digest, err := installstate.Hash(path)
		if err != nil {
			return fmt.Errorf("verify installed %s: %w", owned.Name, err)
		}
		if digest != owned.SHA256 {
			return fmt.Errorf("installed %s was modified; refusing self-update", owned.Name)
		}
	}
	return nil
}

func startManagedService(p installstate.Profile) error {
	return service.Manage("start", service.Config{ConfigDirectory: p.ConfigDir, StateDirectory: p.StateDir, RuntimeDirectory: p.RuntimeDir})
}

func restartServiceAfterFailure(profile *installstate.Profile, cause error) error {
	if profile == nil {
		return cause
	}
	if err := startManagedService(*profile); err != nil {
		return errors.Join(cause, fmt.Errorf("restart installed service after update failure: %w", err))
	}
	if err := waitForService(context.Background(), profile.RuntimeDir); err != nil {
		return errors.Join(cause, fmt.Errorf("verify service after update failure: %w", err))
	}
	return cause
}

func waitForService(parent context.Context, runtimeDir string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := local.Request(ctx, runtimeDir, "status", io.Discard); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func verifyUpdatedBinary(ctx context.Context, path, expectedVersion string) error {
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(check, path, "version", "--json").Output()
	if err != nil {
		return fmt.Errorf("updated binary did not start: %w", err)
	}
	var result struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output, &result); err != nil || result.Version != expectedVersion {
		return errors.New("updated binary returned an unexpected version")
	}
	return nil
}

func rollbackInstalledUpdate(progress *selfUpdateProgress, dir string, rollback func() error, p installstate.Profile, cause error, manage updateServiceManager, wait updateServiceWaiter) error {
	lock, err := runSelfUpdateStep(progress, "Locking installation to roll back", func() (io.Closer, error) {
		return installstate.Lock(dir)
	})
	if err != nil {
		return errors.Join(cause, fmt.Errorf("automatic rollback was incomplete: %w", err))
	}
	inv, err := runSelfUpdateStep(progress, "Checking installation before rollback", func() (installstate.Inventory, error) {
		return installstate.Load(dir)
	})
	if err == nil {
		err = ensureNoActiveUpdateProfiles(inv)
	}
	if err != nil {
		_ = lock.Close()
		return errors.Join(cause, fmt.Errorf("automatic rollback is pending because an agent profile may still be running: %w", err))
	}
	rollbackErr := runSelfUpdateAction(progress, "Restoring previous program files and inventory", func() error {
		return errors.Join(rollback(), lock.Close())
	})
	if p.Service {
		rollbackErr = errors.Join(rollbackErr, runSelfUpdateAction(progress, "Restarting the previous service version", func() error {
			return errors.Join(manage("start", service.Config{ConfigDirectory: p.ConfigDir, StateDirectory: p.StateDir, RuntimeDirectory: p.RuntimeDir}), wait(context.Background(), p.RuntimeDir))
		}))
	}
	if rollbackErr != nil {
		return errors.Join(cause, fmt.Errorf("automatic rollback was incomplete: %w", rollbackErr))
	}
	return fmt.Errorf("%w; previous program files were restored", cause)
}

func ensureNoActiveUpdateProfiles(inv installstate.Inventory) error {
	for _, profile := range inv.Profiles {
		for _, dir := range []string{profile.StateDir, profile.RuntimeDir} {
			guard, err := local.TryAcquireExisting(dir)
			if err != nil {
				return fmt.Errorf("cannot safely update while an agent profile is active: %w", err)
			}
			if guard != nil {
				_ = guard.Close()
			}
		}
	}
	return nil
}

func writeSelfUpdateResult(out io.Writer, jsonOutput bool, result selfUpdateResult) error {
	if jsonOutput {
		return json.NewEncoder(out).Encode(result)
	}
	if result.State == "up_to_date" {
		_, err := fmt.Fprintf(out, "Peerimeter Agent is already up to date (%s).\n", result.PreviousVersion)
		return err
	}
	if result.State == "cancelled" {
		_, err := fmt.Fprintln(out, "Update cancelled.")
		return err
	}
	if result.State == "scheduled" {
		_, err := fmt.Fprintf(out, "Windows update helper started for %s. It will finish replacing the agent in the background.\n", result.UpdatedVersion)
		return err
	}
	if result.State == "recovered" {
		_, err := fmt.Fprintln(out, "Recovered the previous installation after an interrupted update. Run `peerimeter-agent self-update` again to retry.")
		return err
	}
	if result.State == "recovery_scheduled" {
		_, err := fmt.Fprintln(out, "Windows recovery helper started. It will restore the previous installation after this command exits.")
		return err
	}
	_, err := fmt.Fprintf(out, "Updated Peerimeter Agent %s → %s.\n", result.PreviousVersion, result.UpdatedVersion)
	return err
}
