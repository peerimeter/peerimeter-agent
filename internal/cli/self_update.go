package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/selfupdate"
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
)

func newSelfUpdateCommand(app *application) *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update this installed agent to the latest stable release",
		Long:  "Downloads the latest stable release, verifies SHA256SUMS, and replaces only program files recorded by this installation.",
		Args:  noArguments,
		RunE:  app.handle(func(cmd *cobra.Command) error { return selfUpdate(cmd.Context(), app.out, app.jsonOutput) }),
	}
}

type selfUpdateResult struct {
	State           string   `json:"state"`
	PreviousVersion string   `json:"previous_version,omitempty"`
	UpdatedVersion  string   `json:"updated_version,omitempty"`
	Files           []string `json:"files,omitempty"`
}

func selfUpdate(ctx context.Context, out io.Writer, jsonOutput bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	installDir, err := installstate.Canonical(filepath.Dir(exe))
	if err != nil {
		return err
	}
	inv, err := installstate.Load(installDir)
	if err != nil {
		return fmt.Errorf("self-update requires a valid installation inventory: %w", err)
	}
	if inv.Removing {
		return errors.New("this installation is being removed")
	}
	recovered, err := recoverInterruptedUpdate(installDir, inv)
	if err != nil {
		return err
	}
	if recovered {
		return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "recovered", PreviousVersion: Version})
	}
	inv, err = installstate.Load(installDir)
	if err != nil {
		return err
	}
	if err := verifyInstalledFiles(inv); err != nil {
		return err
	}
	tag, files, err := selfupdate.Fetch(ctx, nil, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	latest, ok := parseReleaseVersion(tag)
	current, currentOK := parseReleaseVersion(Version)
	if !ok || !currentOK {
		return fmt.Errorf("cannot compare agent version %q with release %q", Version, tag)
	}
	if compareVersion(latest, current) <= 0 {
		return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "up_to_date", PreviousVersion: Version, UpdatedVersion: tag})
	}
	for _, owned := range inv.Files {
		if _, ok := files[owned.Name]; !ok {
			return fmt.Errorf("release package is missing inventoried program file %q", owned.Name)
		}
	}
	if runtime.GOOS == "windows" {
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
	for i := range inv.Profiles {
		p := &inv.Profiles[i]
		if p.Service {
			if managedService != nil {
				return errors.New("installation has multiple service profiles; self-update cannot select one safely")
			}
			managedService = p
			continue
		}
		guard, err := local.TryAcquireExisting(p.RuntimeDir)
		if err != nil {
			return errors.New("an agent process is using an installed profile; stop it before updating")
		}
		if guard != nil {
			_ = guard.Close()
		}
	}
	if managedService != nil {
		if err := service.Manage("stop", service.Config{ConfigDirectory: managedService.ConfigDir, StateDirectory: managedService.StateDir, RuntimeDirectory: managedService.RuntimeDir}); err != nil {
			return restartServiceAfterFailure(managedService, fmt.Errorf("stop installed service before update: %w", err))
		}
	}
	if runtime.GOOS == "windows" {
		return scheduleWindowsUpdate(inv, files, tag, managedService, out, jsonOutput)
	}
	lock, err := installstate.Lock(installDir)
	if err != nil {
		return restartServiceAfterFailure(managedService, err)
	}
	inv, err = installstate.Load(installDir)
	if err != nil {
		_ = lock.Close()
		return restartServiceAfterFailure(managedService, err)
	}
	if inv.Removing {
		_ = lock.Close()
		return restartServiceAfterFailure(managedService, errors.New("this installation is being removed"))
	}
	if err := verifyInstalledFiles(inv); err != nil {
		_ = lock.Close()
		return restartServiceAfterFailure(managedService, err)
	}
	oldHashes := make(map[string]string, len(inv.Files))
	for _, f := range inv.Files {
		oldHashes[f.Name] = f.SHA256
	}
	newHashes, rollback, commit, err := selfupdate.Apply(inv, files)
	if err != nil {
		_ = lock.Close()
		return restartServiceAfterFailure(managedService, err)
	}
	if err := installstate.UpdateProgramHashesLocked(inv, newHashes); err != nil {
		restoreErr := rollback()
		_ = lock.Close()
		cause := errors.Join(fmt.Errorf("record updated program hashes: %w", err), restoreErr)
		return restartServiceAfterFailure(managedService, cause)
	}
	if err := lock.Close(); err != nil {
		return rollbackInstalledUpdate(installDir, oldHashes, inv, rollback, profileValue(managedService), err)
	}
	if managedService != nil {
		if err := startManagedService(*managedService); err != nil {
			return rollbackInstalledUpdate(installDir, oldHashes, inv, rollback, *managedService, fmt.Errorf("restart updated service: %w", err))
		}
		if err := waitForService(ctx, managedService.RuntimeDir); err != nil {
			_ = service.Manage("stop", service.Config{ConfigDirectory: managedService.ConfigDir, StateDirectory: managedService.StateDir, RuntimeDirectory: managedService.RuntimeDir})
			return rollbackInstalledUpdate(installDir, oldHashes, inv, rollback, *managedService, fmt.Errorf("updated service did not become ready: %w", err))
		}
	} else if err := verifyUpdatedBinary(ctx, filepath.Join(installDir, binaryName()), tag); err != nil {
		return rollbackInstalledUpdate(installDir, oldHashes, inv, rollback, installstate.Profile{}, err)
	}
	if err := commit(); err != nil {
		return fmt.Errorf("update succeeded but backup cleanup needs attention: %w", err)
	}
	filesUpdated := make([]string, 0, len(inv.Files))
	for _, f := range inv.Files {
		filesUpdated = append(filesUpdated, f.Name)
	}
	return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "updated", PreviousVersion: Version, UpdatedVersion: tag, Files: filesUpdated})
}

func recoverInterruptedUpdate(installDir string, inv installstate.Inventory) (bool, error) {
	_, err := os.Lstat(filepath.Join(inv.LockDir, selfupdate.JournalFilename))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
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
		err = selfupdate.RecoverLocked(current)
	}
	err = errors.Join(err, lock.Close())
	err = restartServiceAfterFailure(profile, err)
	return err == nil, err
}

func newUpdateHelperCommand(app *application) *cobra.Command {
	return &cobra.Command{
		Use:    "__update-helper <install-dir> <transaction-dir>",
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

func binaryName() string {
	if runtime.GOOS == "windows" {
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

func rollbackInstalledUpdate(dir string, oldHashes map[string]string, inv installstate.Inventory, rollback func() error, p installstate.Profile, cause error) error {
	rollbackErr := rollback()
	lock, err := installstate.Lock(dir)
	if err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
	} else {
		current, loadErr := installstate.Load(dir)
		if loadErr == nil {
			loadErr = installstate.UpdateProgramHashesLocked(current, oldHashes)
		}
		rollbackErr = errors.Join(rollbackErr, loadErr, lock.Close())
	}
	if p.Service {
		rollbackErr = errors.Join(rollbackErr, startManagedService(p), waitForService(context.Background(), p.RuntimeDir))
	}
	if rollbackErr != nil {
		return errors.Join(cause, fmt.Errorf("automatic rollback was incomplete: %w", rollbackErr))
	}
	return fmt.Errorf("%w; previous program files were restored", cause)
}

func writeSelfUpdateResult(out io.Writer, jsonOutput bool, result selfUpdateResult) error {
	if jsonOutput {
		return json.NewEncoder(out).Encode(result)
	}
	if result.State == "up_to_date" {
		_, err := fmt.Fprintf(out, "Peerimeter Agent is already up to date (%s).\n", result.PreviousVersion)
		return err
	}
	if result.State == "scheduled" {
		_, err := fmt.Fprintf(out, "Windows update helper started for %s. It will finish replacing the agent in the background.\n", result.UpdatedVersion)
		return err
	}
	if result.State == "recovered" {
		_, err := fmt.Fprintln(out, "Recovered the previous installation after an interrupted update. Run `peerimeter-agent update` again to retry.")
		return err
	}
	_, err := fmt.Fprintf(out, "Updated Peerimeter Agent %s → %s.\n", result.PreviousVersion, result.UpdatedVersion)
	return err
}
