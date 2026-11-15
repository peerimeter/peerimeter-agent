package cli

import (
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
	return selfUpdateAt(ctx, out, jsonOutput, installDir, Version, runtime.GOOS, runtime.GOARCH, selfUpdateDeps{
		fetch: selfupdate.Fetch, verify: verifyUpdatedBinary, manage: service.Manage, wait: waitForService,
	})
}

type updateFetcher func(context.Context, *http.Client, string, string) (string, map[string][]byte, error)
type updateBinaryVerifier func(context.Context, string, string) error
type updateServiceManager func(string, service.Config) error
type updateServiceWaiter func(context.Context, string) error

type selfUpdateDeps struct {
	fetch  updateFetcher
	verify updateBinaryVerifier
	manage updateServiceManager
	wait   updateServiceWaiter
}

// selfUpdateAt keeps release retrieval and binary execution injectable so the
// complete inventory-to-replacement flow can be exercised without network or
// service side effects.
func selfUpdateAt(ctx context.Context, out io.Writer, jsonOutput bool, installDir, currentVersion, goos, goarch string, deps selfUpdateDeps) error {
	inv, err := installstate.Load(installDir)
	if err != nil {
		return fmt.Errorf("self-update requires a valid installation inventory: %w", err)
	}
	if inv.Removing {
		return errors.New("this installation is being removed")
	}
	updateLock, err := selfupdate.LockUpdate(inv)
	if err != nil {
		return fmt.Errorf("another update or uninstall is already using this installation: %w", err)
	}
	defer updateLock.Close()
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
	tag, files, err := deps.fetch(ctx, nil, goos, goarch)
	if err != nil {
		return err
	}
	latest, ok := parseReleaseVersion(tag)
	current, currentOK := parseReleaseVersion(currentVersion)
	if !ok || !currentOK {
		return fmt.Errorf("cannot compare agent version %q with release %q", currentVersion, tag)
	}
	if compareVersion(latest, current) <= 0 {
		return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "up_to_date", PreviousVersion: currentVersion, UpdatedVersion: tag})
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
		if err := deps.manage("stop", serviceConfig(managedService)); err != nil {
			return restartAfterFailure(managedService, fmt.Errorf("stop installed service before update: %w", err))
		}
	}
	if goos == "windows" {
		return scheduleWindowsUpdate(inv, files, tag, managedService, out, jsonOutput)
	}
	lock, err := installstate.Lock(installDir)
	if err != nil {
		return restartAfterFailure(managedService, err)
	}
	inv, err = installstate.Load(installDir)
	if err != nil {
		_ = lock.Close()
		return restartAfterFailure(managedService, err)
	}
	if inv.Removing {
		_ = lock.Close()
		return restartAfterFailure(managedService, errors.New("this installation is being removed"))
	}
	if err := verifyInstalledFiles(inv); err != nil {
		_ = lock.Close()
		return restartAfterFailure(managedService, err)
	}
	newHashes, rollback, commit, err := selfupdate.Apply(inv, files)
	if err != nil {
		_ = lock.Close()
		return restartAfterFailure(managedService, err)
	}
	if err := installstate.UpdateProgramHashesLocked(inv, newHashes); err != nil {
		restoreErr := rollback()
		_ = lock.Close()
		cause := errors.Join(fmt.Errorf("record updated program hashes: %w", err), restoreErr)
		return restartAfterFailure(managedService, cause)
	}
	if err := lock.Close(); err != nil {
		return rollbackInstalledUpdate(installDir, rollback, profileValue(managedService), err, deps.manage, deps.wait)
	}
	if managedService != nil {
		if err := deps.manage("start", serviceConfig(managedService)); err != nil {
			return rollbackInstalledUpdate(installDir, rollback, *managedService, fmt.Errorf("restart updated service: %w", err), deps.manage, deps.wait)
		}
		if err := deps.wait(ctx, managedService.RuntimeDir); err != nil {
			_ = deps.manage("stop", serviceConfig(managedService))
			return rollbackInstalledUpdate(installDir, rollback, *managedService, fmt.Errorf("updated service did not become ready: %w", err), deps.manage, deps.wait)
		}
	} else if err := deps.verify(ctx, filepath.Join(installDir, binaryNameFor(goos)), tag); err != nil {
		return rollbackInstalledUpdate(installDir, rollback, installstate.Profile{}, err, deps.manage, deps.wait)
	}
	if err := commit(); err != nil {
		return fmt.Errorf("update succeeded but backup cleanup needs attention: %w", err)
	}
	filesUpdated := make([]string, 0, len(inv.Files))
	for _, f := range inv.Files {
		filesUpdated = append(filesUpdated, f.Name)
	}
	return writeSelfUpdateResult(out, jsonOutput, selfUpdateResult{State: "updated", PreviousVersion: currentVersion, UpdatedVersion: tag, Files: filesUpdated})
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

func rollbackInstalledUpdate(dir string, rollback func() error, p installstate.Profile, cause error, manage updateServiceManager, wait updateServiceWaiter) error {
	lock, err := installstate.Lock(dir)
	if err != nil {
		return errors.Join(cause, fmt.Errorf("automatic rollback was incomplete: %w", err))
	}
	rollbackErr := errors.Join(rollback(), lock.Close())
	if p.Service {
		rollbackErr = errors.Join(rollbackErr, manage("start", service.Config{ConfigDirectory: p.ConfigDir, StateDirectory: p.StateDir, RuntimeDirectory: p.RuntimeDir}), wait(context.Background(), p.RuntimeDir))
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
