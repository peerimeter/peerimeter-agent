// Package uninstall removes only resources recorded by a verified installer.
// Registration-only service uninstall remains a separate operation.
package uninstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/selfupdate"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

type Options struct {
	InstallDir, ConfigDir, StateDir, RuntimeDir string
	DataDir, DocDir, LockDir                    string
	DryRun, Purge                               bool
}
type removalFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Marker bool   `json:"marker,omitempty"`
}
type removalPlan struct {
	Version           int                    `json:"version"`
	InstallID         string                 `json:"installation_id"`
	InstallDir        string                 `json:"install_dir"`
	ParentPID         int                    `json:"parent_pid"`
	Inventory         string                 `json:"inventory"`
	Lock              string                 `json:"lock"`
	UpdateLock        string                 `json:"update_lock,omitempty"`
	DataLock          string                 `json:"data_lock,omitempty"`
	LegacyLock        string                 `json:"legacy_lock,omitempty"`
	LegacyDataLock    string                 `json:"legacy_data_lock,omitempty"`
	LegacyUpdateLock  string                 `json:"legacy_update_lock,omitempty"`
	LegacyInventories []string               `json:"legacy_inventories,omitempty"`
	Files             []removalFile          `json:"files"`
	Directories       []string               `json:"directories"`
	PurgeDirs         []string               `json:"purge_directories,omitempty"`
	Profiles          []installstate.Profile `json:"profiles"`
	ResultFile        string                 `json:"result_file"`
}
type report struct {
	State      string   `json:"state"`
	Paths      []string `json:"paths,omitempty"`
	Services   []string `json:"services,omitempty"`
	Remaining  []string `json:"remaining,omitempty"`
	ResultFile string   `json:"result_file,omitempty"`
	Message    string   `json:"message,omitempty"`
}

func resources(p installstate.Profile) []removalFile {
	var files []removalFile
	if p.LegacyConfigOwned && p.LegacyConfigDir != "" && p.LegacyConfigDir != p.ConfigDir {
		for _, name := range []string{"service.yaml", "service.json", "service.key"} {
			files = append(files, removalFile{Path: filepath.Join(p.LegacyConfigDir, name)})
		}
	}
	if p.PendingConfigOwned && p.PendingConfigDir != "" && p.PendingConfigDir != p.ConfigDir {
		for _, name := range []string{"service.yaml", "service.json", "service.key"} {
			files = append(files, removalFile{Path: filepath.Join(p.PendingConfigDir, name)})
		}
		files = append(files, removalFile{Path: filepath.Join(p.PendingConfigDir, installstate.ConfigMarkerFilename), Marker: true}, removalFile{Path: filepath.Join(p.PendingConfigDir, installstate.LegacyConfigMarkerFilename), Marker: true})
	}
	if p.ConfigOwned && p.ConfigDir != "" {
		for _, name := range []string{"service.yaml", "service.json", "service.key"} {
			files = append(files, removalFile{Path: filepath.Join(p.ConfigDir, name)})
		}
	}
	if p.ConfigOwned {
		files = append(files, removalFile{Path: filepath.Join(p.ConfigDir, installstate.ConfigMarkerFilename), Marker: true}, removalFile{Path: filepath.Join(p.ConfigDir, installstate.LegacyConfigMarkerFilename), Marker: true})
	}
	if p.LegacyConfigOwned && p.LegacyConfigDir != p.ConfigDir {
		files = append(files, removalFile{Path: filepath.Join(p.LegacyConfigDir, installstate.ConfigMarkerFilename), Marker: true}, removalFile{Path: filepath.Join(p.LegacyConfigDir, installstate.LegacyConfigMarkerFilename), Marker: true})
	}
	// TODO(next major): remove network.json from owned cleanup after migration support expires.
	for _, name := range []string{"network.yaml", "network.json", "ownership", "agent.lock"} {
		files = append(files, removalFile{Path: filepath.Join(p.StateDir, name)})
	}
	if p.RuntimeOwned {
		files = append(files, removalFile{Path: filepath.Join(p.RuntimeDir, "control.sock")}, removalFile{Path: filepath.Join(p.RuntimeDir, installstate.RuntimeMarkerFilename), Marker: true}, removalFile{Path: filepath.Join(p.RuntimeDir, installstate.LegacyRuntimeMarkerFilename), Marker: true})
	}
	files = append(files, removalFile{Path: filepath.Join(p.StateDir, installstate.MarkerFilename), Marker: true}, removalFile{Path: filepath.Join(p.StateDir, installstate.LegacyMarkerFilename), Marker: true})
	return files
}
func makePlan(inv installstate.Inventory, purge bool) removalPlan {
	inventoryName := installstate.Filename
	if name, err := installstate.ExistingInventoryFilename(inv.DataDir); err == nil {
		inventoryName = name
	}
	p := removalPlan{Version: 1, InstallID: inv.ID, InstallDir: inv.InstallDir, ParentPID: os.Getpid(), Inventory: filepath.Join(inv.DataDir, inventoryName), Lock: filepath.Join(inv.LockDir, installstate.LockFilename), UpdateLock: filepath.Join(inv.LockDir, selfupdate.UpdateLockFilename), LegacyLock: filepath.Join(inv.LockDir, installstate.LegacyLockFilename), LegacyUpdateLock: filepath.Join(inv.LockDir, selfupdate.LegacyUpdateLockFilename), LegacyInventories: []string{filepath.Join(inv.DataDir, installstate.LegacyYAMLFilename), filepath.Join(inv.DataDir, installstate.LegacyJSONFilename)}, Profiles: inv.Profiles}
	if inv.DataDir != inv.LockDir {
		p.DataLock = filepath.Join(inv.DataDir, installstate.LockFilename)
		p.LegacyDataLock = filepath.Join(inv.DataDir, installstate.LegacyLockFilename)
	}
	seen := map[string]bool{}
	dirs := map[string]bool{inv.InstallDir: true, inv.DocDir: true, inv.DataDir: true, inv.LockDir: true}
	for _, profile := range inv.Profiles {
		for _, f := range resources(profile) {
			if !seen[f.Path] {
				p.Files = append(p.Files, f)
				seen[f.Path] = true
			}
		}
		ownedDirs := []string{profile.StateDir}
		if profile.PendingConfigOwned {
			ownedDirs = append(ownedDirs, profile.PendingConfigDir)
		}
		if profile.ConfigOwned {
			ownedDirs = append(ownedDirs, profile.ConfigDir)
		}
		if profile.LegacyConfigOwned {
			ownedDirs = append(ownedDirs, profile.LegacyConfigDir)
		}
		if profile.RuntimeOwned {
			ownedDirs = append(ownedDirs, profile.RuntimeDir)
		}
		for _, d := range ownedDirs {
			if d != "" {
				dirs[d] = true
			}
		}
		if purge {
			purgeDirs := []string{profile.StateDir}
			if profile.ConfigOwned {
				purgeDirs = append(purgeDirs, profile.ConfigDir)
			}
			if profile.LegacyConfigOwned {
				purgeDirs = append(purgeDirs, profile.LegacyConfigDir)
			}
			if profile.PendingConfigOwned {
				purgeDirs = append(purgeDirs, profile.PendingConfigDir)
			}
			if profile.RuntimeOwned {
				purgeDirs = append(purgeDirs, profile.RuntimeDir)
			}
			for _, d := range purgeDirs {
				if d != "" && !contains(p.PurgeDirs, d) {
					p.PurgeDirs = append(p.PurgeDirs, d)
				}
			}
		}
	}
	for _, f := range inv.Files {
		path := installstate.ResourcePath(inv, f)
		if !seen[path] {
			p.Files = append(p.Files, removalFile{Path: path, SHA256: f.SHA256})
			seen[path] = true
		}
	}
	// Keep discovery metadata until every managed resource is gone, so a
	// partial removal can load the same inventory and resume safely.
	p.Files = append(p.Files, removalFile{Path: filepath.Join(inv.InstallDir, installstate.ReferenceFilename), Marker: true}, removalFile{Path: filepath.Join(inv.InstallDir, installstate.LegacyReferenceFilename), Marker: true})
	for d := range dirs {
		p.Directories = append(p.Directories, d)
	}
	sort.Strings(p.PurgeDirs)
	sort.Slice(p.Directories, func(i, j int) bool { return len(p.Directories[i]) > len(p.Directories[j]) })
	return p
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func purgeRootContains(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func validatePurgeRoots(inv installstate.Inventory, plan removalPlan) error {
	for _, root := range plan.PurgeDirs {
		for _, protected := range []struct{ name, path string }{{"installation", inv.InstallDir}, {"installation data", inv.DataDir}, {"installation lock", inv.LockDir}} {
			if purgeRootContains(root, protected.path) {
				return fmt.Errorf("purge directory %s contains the %s directory %s; refusing to delete installation metadata", root, protected.name, protected.path)
			}
		}
	}
	return nil
}

func plannedMarkersForRoot(root string, files []removalFile) map[string]bool {
	markers := make(map[string]bool)
	for _, file := range files {
		if file.Marker && filepath.Dir(file.Path) == root {
			markers[file.Path] = true
		}
	}
	return markers
}

func validateOverrides(opts Options, inv installstate.Inventory) error {
	for _, item := range []struct {
		value string
		pick  func(installstate.Profile) string
	}{{opts.ConfigDir, func(p installstate.Profile) string { return p.ConfigDir }}, {opts.StateDir, func(p installstate.Profile) string { return p.StateDir }}, {opts.RuntimeDir, func(p installstate.Profile) string { return p.RuntimeDir }}} {
		if item.value == "" {
			continue
		}
		value, err := installstate.Canonical(item.value)
		if err != nil {
			return err
		}
		found := false
		for _, p := range inv.Profiles {
			if item.pick(p) == value {
				found = true
				break
			}
		}
		if !found {
			return errors.New("directory override is not recorded by this installation; refusing to remove untracked resources")
		}
	}
	for _, item := range []struct{ value, recorded string }{{opts.DataDir, inv.DataDir}, {opts.DocDir, inv.DocDir}, {opts.LockDir, inv.LockDir}} {
		if item.value == "" {
			continue
		}
		canonical, err := installstate.Canonical(item.value)
		if err != nil || canonical != item.recorded {
			return errors.New("installation resource directory does not match the recorded installation")
		}
	}
	return nil
}
func verifyProfile(inv installstate.Inventory, p installstate.Profile) error {
	err := installstate.VerifyProfile(inv, p)
	if err == nil {
		return nil
	}
	// A previous removal can finish a profile before failing on another file.
	// Missing markers are accepted only when every other tracked leaf is absent.
	for _, name := range []string{installstate.MarkerFilename, installstate.LegacyMarkerFilename} {
		if _, e := os.Lstat(filepath.Join(p.StateDir, name)); !os.IsNotExist(e) {
			return err
		}
	}
	for _, f := range resources(p) {
		if f.Marker {
			continue
		}
		if _, e := os.Lstat(f.Path); !os.IsNotExist(e) {
			return err
		}
	}
	return nil
}
func preflight(inv installstate.Inventory, p removalPlan) error {
	if err := validatePurgeRoots(inv, p); err != nil {
		return err
	}
	for _, dir := range []string{inv.InstallDir, inv.DocDir, inv.DataDir, inv.LockDir} {
		if err := installstate.CheckDirectoryWithPolicy(dir, inv.AllowInsecureInstallDir); err != nil {
			return err
		}
	}
	for _, profile := range inv.Profiles {
		if _, err := installstate.VerifyRuntime(inv, profile); err != nil {
			return err
		}
		if err := verifyProfile(inv, profile); err != nil {
			return err
		}
		ownedDirs := []string{profile.StateDir}
		if profile.PendingConfigOwned {
			ownedDirs = append(ownedDirs, profile.PendingConfigDir)
		}
		if profile.ConfigOwned {
			ownedDirs = append(ownedDirs, profile.ConfigDir)
		}
		if profile.LegacyConfigOwned {
			ownedDirs = append(ownedDirs, profile.LegacyConfigDir)
		}
		if profile.RuntimeOwned {
			ownedDirs = append(ownedDirs, profile.RuntimeDir)
		}
		for _, dir := range ownedDirs {
			if dir != "" {
				if err := installstate.CheckDirectoryWithPolicy(dir, inv.AllowInsecureInstallDir); err != nil {
					return err
				}
			}
		}
	}
	for _, f := range p.Files {
		info, err := os.Lstat(f.Path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot inspect owned resource %s: %w", f.Path, err)
		}
		if info.Mode()&os.ModeSocket != 0 && filepath.Base(f.Path) == "control.sock" {
			continue
		}
		if err := installstate.CheckFile(f.Path); err != nil {
			return fmt.Errorf("owned resource %s is not safe to remove: %w", f.Path, err)
		}
		if f.SHA256 != "" {
			hash, err := installstate.Hash(f.Path)
			if err != nil {
				return err
			}
			if hash != f.SHA256 {
				return fmt.Errorf("installed file changed: %s; restore the inventoried file or rerun the verified installer before removal", f.Path)
			}
		}
	}
	return nil
}
func serviceConfig(p installstate.Profile) service.Config {
	configPath := filepath.Join(p.ConfigDir, "service.yaml")
	if _, err := os.Lstat(configPath); os.IsNotExist(err) {
		legacyPath := filepath.Join(p.ConfigDir, "service.json")
		if _, legacyErr := os.Lstat(legacyPath); legacyErr == nil {
			configPath = legacyPath
		}
	}
	return service.Config{ConfigPath: configPath, ConfigDirectory: p.ConfigDir, StateDirectory: p.StateDir, RuntimeDirectory: p.RuntimeDir}
}
func removeServices(ctx context.Context, exe string, profiles []installstate.Profile) error {
	var failed []installstate.Profile
	var problems []error
	removed := false
	candidates := append([]installstate.Profile{}, profiles...)
	for _, p := range profiles {
		if p.Service && p.PendingConfigOwned && p.PendingConfigDir != "" {
			pending := p
			pending.ConfigDir = p.PendingConfigDir
			if p.PendingRuntimeDir != "" {
				pending.RuntimeDir = p.PendingRuntimeDir
			}
			candidates = append(candidates, pending)
		}
	}
	for _, p := range candidates {
		if !p.Service {
			continue
		}
		if err := service.RemoveOwned(ctx, exe, serviceConfig(p)); err != nil {
			failed = append(failed, p)
			problems = append(problems, err)
		} else {
			removed = true
		}
	}
	if len(failed) > 0 && removed {
		problems = nil
		for _, p := range failed {
			if err := service.RemoveOwned(ctx, exe, serviceConfig(p)); err != nil {
				problems = append(problems, err)
			}
		}
	}
	return errors.Join(problems...)
}
func acquireStopped(ctx context.Context, inv installstate.Inventory, p installstate.Profile) (*local.Guard, error) {
	// A failed/missing IPC endpoint never counts as shutdown proof. Only the
	// exclusive persistent-state lock below can establish that the manager ended.
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ownedRuntime, verifyErr := installstate.VerifyRuntime(inv, p)
		if verifyErr != nil {
			return nil, verifyErr
		}
		if ownedRuntime {
			var status bytes.Buffer
			requestCtx, cancel := context.WithTimeout(ctx, time.Second)
			statusErr := local.Request(requestCtx, p.RuntimeDir, "identity", &status)
			cancel()
			if statusErr == nil {
				var identity struct {
					InstanceID string `json:"instance_id"`
				}
				if json.Unmarshal(status.Bytes(), &identity) != nil || identity.InstanceID != local.InstanceID(p.StateDir) {
					return nil, errors.New("control channel belongs to another persistent-state instance; it was not stopped")
				}
				requestCtx, cancel = context.WithTimeout(ctx, time.Second)
				_ = local.Request(requestCtx, p.RuntimeDir, "stop", io.Discard)
				cancel()
			}
		}
		guard, err := local.TryAcquireExisting(p.StateDir)
		if err == nil {
			return guard, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("manager shutdown could not be established for %s; managed files were preserved", p.StateDir)
		case <-ticker.C:
		}
	}
}

type registrationProbe func(context.Context, string) (bool, error)

func Execute(ctx context.Context, opts Options, out io.Writer) error {
	return executeWithRegistrationProbe(ctx, opts, out, service.HasOwnedRegistration)
}
func executeWithRegistrationProbe(ctx context.Context, opts Options, out io.Writer, probe registrationProbe) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := opts.InstallDir
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		dir = filepath.Dir(exe)
	}
	dir, err := installstate.Canonical(dir)
	if err != nil {
		return err
	}
	inv, err := installstate.Load(dir)
	if os.IsNotExist(err) {
		for _, name := range append(append(installstate.ProgramNames(), installstate.Filename, installstate.LegacyYAMLFilename, installstate.LegacyJSONFilename), installstate.ReferenceFilename, installstate.LegacyReferenceFilename) {
			if _, e := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(e) {
				return errors.New("installation inventory is absent; existing files are untracked and were preserved")
			}
		}
		return json.NewEncoder(out).Encode(report{State: "already_absent"})
	}
	if err != nil {
		return err
	}
	if _, found, err := selfupdate.FindJournal(inv); err != nil {
		return err
	} else if found {
		return errors.New("an interrupted self-update must be recovered with `peerimeter-agent self-update` before uninstall")
	}
	if err := validateOverrides(opts, inv); err != nil {
		return err
	}
	for i, p := range inv.Profiles {
		owned, e := installstate.VerifyRuntime(inv, p)
		if e != nil {
			return e
		}
		inv.Profiles[i].RuntimeOwned = owned
		configOwned, configErr := installstate.VerifyConfig(inv, p)
		if configErr != nil {
			return configErr
		}
		inv.Profiles[i].ConfigOwned = configOwned
		legacyOwned, legacyErr := installstate.VerifyConfigDirectory(inv, p, p.LegacyConfigDir)
		if legacyErr != nil {
			return legacyErr
		}
		inv.Profiles[i].LegacyConfigOwned = legacyOwned
		pendingOwned, pendingErr := installstate.VerifyConfigDirectory(inv, p, p.PendingConfigDir)
		if pendingErr != nil {
			return pendingErr
		}
		inv.Profiles[i].PendingConfigOwned = pendingOwned
	}
	plan := makePlan(inv, opts.Purge)
	if err := preflight(inv, plan); err != nil {
		return err
	}
	// Refuse an untracked native registration before any tombstone or lock-file
	// mutation, so legacy service migration remains available after refusal.
	if !hasTrackedService(inv.Profiles) {
		if err := requireNoOwnedRegistration(ctx, registrationExecutable(dir), probe); err != nil {
			return err
		}
	}
	if opts.DryRun {
		r := report{State: "dry_run", Message: "Deletes the installed identity, configuration, credentials and inventoried program files; original source files are preserved."}
		for _, f := range plan.Files {
			r.Paths = append(r.Paths, f.Path)
		}
		r.Paths = append(r.Paths, plan.Lock, plan.LegacyLock, plan.Inventory)
		r.Paths = append(r.Paths, plan.UpdateLock, plan.LegacyUpdateLock)
		r.Paths = append(r.Paths, plan.LegacyInventories...)
		if opts.Purge {
			r.Message = "In addition to the tracked install files, deletes every file and nested directory inside the recorded state, config and runtime directories."
			for _, dir := range plan.PurgeDirs {
				paths, err := listTree(dir)
				if err != nil {
					return err
				}
				for _, path := range paths {
					if !contains(r.Paths, path) {
						r.Paths = append(r.Paths, path)
					}
				}
			}
		}
		if plan.DataLock != "" {
			r.Paths = append(r.Paths, plan.DataLock, plan.LegacyDataLock)
		}
		for _, p := range inv.Profiles {
			if p.Service {
				r.Services = append(r.Services, "owned agent service registration")
			}
		}
		return json.NewEncoder(out).Encode(r)
	}
	updateLock, err := selfupdate.LockUpdate(inv)
	if err != nil {
		return fmt.Errorf("self-update is using this installation: %w", err)
	}
	updateLockHeld := true
	defer func() {
		if updateLockHeld {
			_ = updateLock.Close()
		}
	}()
	lock, err := installstate.Lock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	reread, err := installstate.Load(dir)
	if err != nil {
		return err
	}
	if reread.ID != inv.ID {
		return errors.New("installation inventory changed before removal")
	}
	if _, found, err := selfupdate.FindJournal(reread); err != nil {
		return err
	} else if found {
		return errors.New("an interrupted self-update must be recovered with `peerimeter-agent self-update` before uninstall")
	}
	inv = reread
	for i, p := range inv.Profiles {
		owned, e := installstate.VerifyRuntime(inv, p)
		if e != nil {
			return e
		}
		inv.Profiles[i].RuntimeOwned = owned
		configOwned, configErr := installstate.VerifyConfig(inv, p)
		if configErr != nil {
			return configErr
		}
		inv.Profiles[i].ConfigOwned = configOwned
		legacyOwned, legacyErr := installstate.VerifyConfigDirectory(inv, p, p.LegacyConfigDir)
		if legacyErr != nil {
			return legacyErr
		}
		inv.Profiles[i].LegacyConfigOwned = legacyOwned
		pendingOwned, pendingErr := installstate.VerifyConfigDirectory(inv, p, p.PendingConfigDir)
		if pendingErr != nil {
			return pendingErr
		}
		inv.Profiles[i].PendingConfigOwned = pendingOwned
	}
	plan = makePlan(inv, opts.Purge)
	if err := preflight(inv, plan); err != nil {
		return err
	}
	exeName := "peerimeter-agent"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	if !hasTrackedService(inv.Profiles) {
		if err := requireNoOwnedRegistration(ctx, filepath.Join(dir, exeName), probe); err != nil {
			return err
		}
	}
	if err := installstate.MarkRemoving(inv); err != nil {
		return err
	}
	if err := removeServices(ctx, filepath.Join(dir, exeName), inv.Profiles); err != nil {
		return fmt.Errorf("owned service registration could not be removed: %w", err)
	}
	var guards []*local.Guard
	defer func() {
		for _, g := range guards {
			_ = g.Close()
		}
	}()
	for _, p := range inv.Profiles {
		guard, err := acquireStopped(ctx, inv, p)
		if err != nil {
			return err
		}
		if guard != nil {
			guards = append(guards, guard)
		}
	}
	// Native supervisor removal can return before its process exits. In
	// particular, launchd may still report a booted-out label during that
	// interval. Establish process shutdown through every profile lock before
	// treating a remaining registration as orphaned or cleaning its tunnel.
	if err := requireNoOwnedRegistration(ctx, filepath.Join(dir, exeName), probe); err != nil {
		return err
	}
	for _, p := range inv.Profiles {
		if err := verifyProfile(inv, p); err != nil {
			return err
		}
		if err := cleanupOwnedNetwork(ctx, p); err != nil {
			return err
		}
	}
	for i, p := range inv.Profiles {
		owned, e := installstate.VerifyRuntime(inv, p)
		if e != nil {
			return e
		}
		inv.Profiles[i].RuntimeOwned = owned
		configOwned, configErr := installstate.VerifyConfig(inv, p)
		if configErr != nil {
			return configErr
		}
		inv.Profiles[i].ConfigOwned = configOwned
		legacyOwned, legacyErr := installstate.VerifyConfigDirectory(inv, p, p.LegacyConfigDir)
		if legacyErr != nil {
			return legacyErr
		}
		inv.Profiles[i].LegacyConfigOwned = legacyOwned
		pendingOwned, pendingErr := installstate.VerifyConfigDirectory(inv, p, p.PendingConfigDir)
		if pendingErr != nil {
			return pendingErr
		}
		inv.Profiles[i].PendingConfigOwned = pendingOwned
	}
	plan = makePlan(inv, opts.Purge)
	if runtime.GOOS != "windows" {
		held := map[string]bool{}
		for _, p := range inv.Profiles {
			held[p.StateDir] = true
		}
		for _, p := range inv.Profiles {
			if !p.RuntimeOwned || held[p.RuntimeDir] {
				continue
			}
			guard, e := local.TryAcquireExisting(p.RuntimeDir)
			stillOwned, verifyErr := installstate.VerifyRuntime(inv, p)
			if verifyErr != nil {
				if guard != nil {
					guard.Close()
				}
				return verifyErr
			}
			if !stillOwned {
				if guard != nil {
					guard.Close()
				}
				for i, profile := range inv.Profiles {
					if profile.ID == p.ID {
						inv.Profiles[i].RuntimeOwned = false
					}
				}
				continue
			}
			if e != nil {
				return fmt.Errorf("runtime remains in use; unrelated listener was preserved: %w", e)
			}
			if guard != nil {
				guards = append(guards, guard)
			}
			held[p.RuntimeDir] = true
		}
	}
	plan = makePlan(inv, opts.Purge)
	if runtime.GOOS == "windows" {
		result, err := scheduleRemoval(plan)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report{State: "pending", ResultFile: result, Message: "The bounded removal helper runs after this process exits. Read the result file to confirm completion; remaining paths indicate a retry is required."})
	}
	removedFiles := make([]string, 0, len(plan.Files)+3)
	// Retain profile markers and inventory until all other removals succeed, so
	// partial failure remains verifiable and a later invocation can safely retry.
	for _, f := range plan.Files {
		if f.Marker {
			continue
		}
		removed, err := removeLeaf(f)
		if err != nil {
			return fmt.Errorf("partial uninstall; remaining resource %s: %w", f.Path, err)
		}
		if removed {
			removedFiles = append(removedFiles, f.Path)
		}
	}
	if opts.Purge {
		for _, dir := range plan.PurgeDirs {
			purged, err := removeDirectoryContents(dir, plannedMarkersForRoot(dir, plan.Files))
			if err != nil {
				return fmt.Errorf("partial uninstall; cannot purge %s: %w", dir, err)
			}
			removedFiles = append(removedFiles, purged...)
		}
	}
	for _, f := range plan.Files {
		if !f.Marker {
			continue
		}
		removed, err := removeLeaf(f)
		if err != nil {
			return fmt.Errorf("partial uninstall; profile marker remains %s: %w", f.Path, err)
		}
		if removed {
			removedFiles = append(removedFiles, f.Path)
		}
	}
	if err := lock.Close(); err != nil {
		return err
	}
	if removed, err := removeTracked(plan.Lock); err != nil {
		return err
	} else if removed {
		removedFiles = append(removedFiles, plan.Lock)
	}
	if removed, err := removeTracked(plan.LegacyLock); err != nil {
		return err
	} else if removed {
		removedFiles = append(removedFiles, plan.LegacyLock)
	}
	if plan.DataLock != "" {
		if removed, err := removeTracked(plan.DataLock); err != nil {
			return err
		} else if removed {
			removedFiles = append(removedFiles, plan.DataLock)
		}
		if removed, err := removeTracked(plan.LegacyDataLock); err != nil {
			return err
		} else if removed {
			removedFiles = append(removedFiles, plan.LegacyDataLock)
		}
	}
	if removed, err := removeTracked(plan.Inventory); err != nil {
		return err
	} else if removed {
		removedFiles = append(removedFiles, plan.Inventory)
	}
	for _, inventory := range plan.LegacyInventories {
		if removed, err := removeTracked(inventory); err != nil {
			return err
		} else if removed {
			removedFiles = append(removedFiles, inventory)
		}
	}
	if err := updateLock.Close(); err != nil {
		return err
	}
	updateLockHeld = false
	if removed, err := removeTracked(plan.UpdateLock); err != nil {
		return err
	} else if removed {
		removedFiles = append(removedFiles, plan.UpdateLock)
	}
	if removed, err := removeTracked(plan.LegacyUpdateLock); err != nil {
		return err
	} else if removed {
		removedFiles = append(removedFiles, plan.LegacyUpdateLock)
	}
	for _, d := range plan.Directories {
		if err := removeEmptyDirectory(d); err != nil {
			return err
		}
	}
	sort.Strings(removedFiles)
	return json.NewEncoder(out).Encode(report{State: "removed", Paths: removedFiles})
}
func removeTracked(path string) (bool, error) {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
func removeLeaf(f removalFile) (bool, error) {
	info, err := os.Lstat(f.Path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSocket == 0 {
		if err := installstate.CheckFile(f.Path); err != nil {
			return false, err
		}
	}
	if f.SHA256 != "" {
		hash, e := installstate.Hash(f.Path)
		if e != nil {
			return false, e
		}
		if hash != f.SHA256 {
			return false, errors.New("program file changed during removal")
		}
	}
	if err := os.Remove(f.Path); err != nil {
		return false, err
	}
	return true, nil
}
func removeEmptyDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("owned resource directory changed type")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return nil
	}
	return os.Remove(path)
}

func listTree(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if path != root {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

func removeDirectoryContents(root string, markers map[string]bool) ([]string, error) {
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("purge target changed type or became a symbolic link")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, entry := range entries {
		// Keep only markers scheduled for the normal marker-removal phase.
		path := filepath.Join(root, entry.Name())
		if markers[path] {
			continue
		}
		paths, err := listTree(path)
		if err != nil {
			return nil, err
		}
		removed = append(removed, path)
		removed = append(removed, paths...)
		if err := os.RemoveAll(path); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func requireNoOwnedRegistration(ctx context.Context, executable string, probe registrationProbe) error {
	owned, err := probe(ctx, executable)
	if err != nil {
		return fmt.Errorf("incomplete uninstall: native registration could not be verified; managed data and program files were preserved: %w", err)
	}
	if owned {
		return errors.New("incomplete uninstall: an untracked native service still references this executable; migrate its legacy profile or remove its registration before retrying; managed data and program files were preserved")
	}
	return nil
}

func hasTrackedService(profiles []installstate.Profile) bool {
	for _, profile := range profiles {
		if profile.Service {
			return true
		}
	}
	return false
}
func registrationExecutable(dir string) string {
	name := "peerimeter-agent"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}
