// Package uninstall removes only resources recorded by a verified installer.
// Registration-only service uninstall remains a separate operation.
package uninstall

import (
	"bufio"
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
	DryRun, Purge, Yes                          bool
	ConfirmIn                                   io.Reader
	ConfirmOut                                  io.Writer
	Confirm                                     func(string) (bool, error)
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
	PurgeContents     map[string][]string    `json:"purge_contents,omitempty"`
	PurgePreserve     []string               `json:"purge_preserve,omitempty"`
	Profiles          []installstate.Profile `json:"profiles"`
	ResultFile        string                 `json:"result_file"`
}
type report struct {
	State      string   `json:"state"`
	Paths      []string `json:"paths,omitempty"`
	Services   []string `json:"services,omitempty"`
	Remaining  []string `json:"remaining,omitempty"`
	Refused    []string `json:"refused,omitempty"`
	ResultFile string   `json:"result_file,omitempty"`
	Message    string   `json:"message,omitempty"`
}

func resources(p installstate.Profile) []removalFile {
	var files []removalFile
	if p.LegacyConfigOwned && p.LegacyConfigDir != "" && p.LegacyConfigDir != p.ConfigDir {
		files = append(files, serviceSnapshotFiles(p.LegacyConfigDir)...)
	}
	if p.PendingConfigOwned && p.PendingConfigDir != "" && p.PendingConfigDir != p.ConfigDir {
		files = append(files, serviceSnapshotFiles(p.PendingConfigDir)...)
		files = append(files, markerFiles(p.PendingConfigDir, installstate.ConfigMarkerFilename, installstate.LegacyConfigMarkerFilename)...)
	}
	if p.ConfigOwned && p.ConfigDir != "" {
		files = append(files, serviceSnapshotFiles(p.ConfigDir)...)
	}
	if p.ConfigOwned {
		files = append(files, markerFiles(p.ConfigDir, installstate.ConfigMarkerFilename, installstate.LegacyConfigMarkerFilename)...)
	}
	if p.LegacyConfigOwned && p.LegacyConfigDir != p.ConfigDir {
		files = append(files, markerFiles(p.LegacyConfigDir, installstate.ConfigMarkerFilename, installstate.LegacyConfigMarkerFilename)...)
	}
	for _, name := range []string{"network.yaml", "network.json", "ownership", "agent.lock"} {
		files = append(files, removalFile{Path: filepath.Join(p.StateDir, name)})
	}
	if p.RuntimeOwned {
		files = append(files, removalFile{Path: filepath.Join(p.RuntimeDir, "control.sock")}, removalFile{Path: filepath.Join(p.RuntimeDir, installstate.RuntimeMarkerFilename), Marker: true}, removalFile{Path: filepath.Join(p.RuntimeDir, installstate.LegacyRuntimeMarkerFilename), Marker: true})
	}
	files = append(files, removalFile{Path: filepath.Join(p.StateDir, installstate.MarkerFilename), Marker: true}, removalFile{Path: filepath.Join(p.StateDir, installstate.LegacyMarkerFilename), Marker: true})
	return files
}

func serviceSnapshotFiles(dir string) []removalFile {
	var files []removalFile
	for _, name := range []string{"service.yaml", "service.json", "service.key"} {
		files = append(files, removalFile{Path: filepath.Join(dir, name)})
	}
	return files
}

func markerFiles(dir, current, legacy string) []removalFile {
	return []removalFile{
		{Path: filepath.Join(dir, current), Marker: true},
		{Path: filepath.Join(dir, legacy), Marker: true},
	}
}

func ownedProfileDirs(profile installstate.Profile) []string {
	dirs := []string{profile.StateDir}
	if profile.PendingConfigOwned {
		dirs = append(dirs, profile.PendingConfigDir)
	}
	if profile.ConfigOwned {
		dirs = append(dirs, profile.ConfigDir)
	}
	if profile.LegacyConfigOwned {
		dirs = append(dirs, profile.LegacyConfigDir)
	}
	if profile.RuntimeOwned {
		dirs = append(dirs, profile.RuntimeDir)
	}
	return dirs
}

func collectPlannedPaths(plan removalPlan, purge bool) ([]string, map[string][]string, error) {
	paths := make([]string, 0, len(plan.Files)+len(plan.Directories)+len(plan.PurgeDirs))
	seen := make(map[string]bool)
	add := func(path string) {
		if path != "" && !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}
	for _, file := range plan.Files {
		add(file.Path)
	}
	for _, dir := range plan.Directories {
		add(dir)
	}
	for _, path := range []string{plan.Lock, plan.LegacyLock, plan.Inventory, plan.UpdateLock, plan.LegacyUpdateLock, plan.DataLock, plan.LegacyDataLock} {
		add(path)
	}
	for _, path := range plan.LegacyInventories {
		add(path)
	}
	purgeContents := make(map[string][]string)
	if purge {
		for _, root := range plan.PurgeDirs {
			contents, err := listTree(root)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot list purge contents of %s: %w", root, err)
			}
			purgeContents[root] = contents
			for _, path := range contents {
				add(path)
			}
		}
	}
	return paths, purgeContents, nil
}

func reportAlreadyAbsentOrUntracked(dir string, out io.Writer) error {
	programNames := installstate.ProgramNames()
	if runtime.GOOS == "windows" {
		// TODO(next major): remove legacy pma.exe detection with inventory compatibility.
		programNames = append(programNames, "pma.exe")
	}
	for _, name := range append(append(programNames, installstate.Filename, installstate.LegacyYAMLFilename, installstate.LegacyJSONFilename), installstate.ReferenceFilename, installstate.LegacyReferenceFilename) {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return errors.New("installation inventory is absent; existing files are untracked and were preserved")
		}
	}
	return json.NewEncoder(out).Encode(report{State: "already_absent"})
}

func writeDryRunReport(opts Options, plan removalPlan, inv installstate.Inventory, out io.Writer) error {
	r := report{State: "dry_run", Message: "Deletes the installed identity, configuration, credentials and inventoried program files; original source files are preserved."}
	if opts.Purge {
		r.Message = "In addition to the tracked install files, deletes every file and nested directory inside the recorded state, config and runtime directories."
	}
	paths, _, err := collectPlannedPaths(plan, opts.Purge)
	if err != nil {
		return err
	}
	r.Paths = paths
	for _, profile := range inv.Profiles {
		if profile.Service {
			r.Services = append(r.Services, "owned agent service registration")
		}
	}
	return json.NewEncoder(out).Encode(r)
}

func confirmUninstall(opts Options, plan removalPlan) (map[string][]string, error) {
	if opts.ConfirmIn == nil || opts.ConfirmOut == nil {
		return nil, errors.New("uninstall requires confirmation; use --yes to confirm non-interactively")
	}
	preview, purgeContents, err := collectPlannedPaths(plan, opts.Purge)
	if err != nil {
		return nil, err
	}
	writeLine := func(line string) error {
		_, err := fmt.Fprintln(opts.ConfirmOut, line)
		return err
	}
	if err := writeLine("The following files and directories will be removed:"); err != nil {
		return nil, fmt.Errorf("cannot display uninstall preview: %w", err)
	}
	for _, path := range preview {
		if err := writeLine("  " + path); err != nil {
			return nil, fmt.Errorf("cannot display uninstall preview: %w", err)
		}
	}
	if !opts.Purge {
		if err := writeLine("Non-empty directories are preserved unless --purge is enabled."); err != nil {
			return nil, fmt.Errorf("cannot display uninstall preview: %w", err)
		}
	}
	confirmed := false
	if opts.Confirm != nil {
		confirmed, err = opts.Confirm("Continue with uninstall?")
		if err != nil {
			return nil, fmt.Errorf("cannot confirm uninstall: %w", err)
		}
	} else {
		if _, err := fmt.Fprint(opts.ConfirmOut, "Continue? [y/N] "); err != nil {
			return nil, fmt.Errorf("cannot display uninstall confirmation prompt: %w", err)
		}
		answer, readErr := bufio.NewReader(opts.ConfirmIn).ReadString('\n')
		answer = strings.TrimSpace(answer)
		confirmed = (readErr == nil || errors.Is(readErr, io.EOF)) && (answer == "y" || answer == "Y" || answer == "yes" || answer == "YES")
	}
	if !confirmed {
		return nil, errors.New("uninstall cancelled")
	}
	return purgeContents, nil
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
	if root := windowsInstallerResourceRoot(inv); root != "" {
		// Remove empty containers from the verified default ProgramData layout.
		// The helper checks each directory is empty before deleting it.
		dirs[root] = true
		dirs[filepath.Dir(root)] = true
		dirs[filepath.Dir(filepath.Dir(root))] = true
	}
	for _, profile := range inv.Profiles {
		managedDir := filepath.Join(profile.StateDir, "managed")
		dirs[managedDir] = true
		if purge && profile.ConfigDir != "" {
			dirs[profile.ConfigDir] = true
		}
		for _, f := range resources(profile) {
			if !seen[f.Path] {
				p.Files = append(p.Files, f)
				seen[f.Path] = true
			}
		}
		for _, d := range ownedProfileDirs(profile) {
			if d != "" {
				dirs[d] = true
			}
		}
		if purge {
			if profile.ConfigDir != "" && !contains(p.PurgeDirs, profile.ConfigDir) {
				p.PurgeDirs = append(p.PurgeDirs, profile.ConfigDir)
			}
			if managedDir != "" && !contains(p.PurgeDirs, managedDir) {
				p.PurgeDirs = append(p.PurgeDirs, managedDir)
			}
			for _, d := range ownedProfileDirs(profile) {
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
	for _, path := range finalizationResources(p) {
		for _, root := range p.PurgeDirs {
			if filepath.Dir(path) == root {
				p.PurgePreserve = append(p.PurgePreserve, path)
			}
		}
	}
	sort.Strings(p.PurgePreserve)
	return p
}

func finalizationResources(plan removalPlan) []string {
	return append([]string{
		plan.Lock,
		plan.LegacyLock,
		plan.DataLock,
		plan.LegacyDataLock,
		plan.UpdateLock,
		plan.LegacyUpdateLock,
		plan.Inventory,
	}, plan.LegacyInventories...)
}

func windowsInstallerResourceRoot(inv installstate.Inventory) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	base, err := installstate.Canonical(filepath.Join(programData, "Peerimeter", "Installations"))
	if err != nil {
		return ""
	}
	root := filepath.Dir(inv.DataDir)
	expectedRoot, err := installstate.Canonical(root)
	if err != nil || !strings.EqualFold(filepath.Dir(expectedRoot), base) {
		return ""
	}
	state, err := installstate.Canonical(filepath.Join(root, "State"))
	if err != nil || !strings.EqualFold(inv.DataDir, state) {
		return ""
	}
	doc, err := installstate.Canonical(filepath.Join(root, "Documentation"))
	if err != nil || !strings.EqualFold(inv.DocDir, doc) {
		return ""
	}
	locks, err := installstate.Canonical(filepath.Join(root, "Locks"))
	if err != nil || !strings.EqualFold(inv.LockDir, locks) {
		return ""
	}
	return expectedRoot
}

type confirmedProfile struct {
	ID, ConfigDir, LegacyConfigDir, PendingConfigDir, PendingRuntimeDir string
	StateDir, RuntimeDir                                                string
	Service                                                             bool
}

func samePathSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, path := range a {
		seen[path]++
	}
	for _, path := range b {
		if seen[path] == 0 {
			return false
		}
		seen[path]--
	}
	return true
}

func sameConfirmedPlan(a, b removalPlan) bool {
	if len(a.Files) != len(b.Files) || !samePathSet(a.Directories, b.Directories) || !samePathSet(a.PurgeDirs, b.PurgeDirs) || !samePathSet(a.PurgePreserve, b.PurgePreserve) || len(a.Profiles) != len(b.Profiles) {
		return false
	}
	files := make(map[string]removalFile, len(a.Files))
	for _, file := range a.Files {
		files[file.Path] = file
	}
	for _, file := range b.Files {
		if files[file.Path] != file {
			return false
		}
	}
	profiles := make(map[confirmedProfile]int, len(a.Profiles))
	for _, p := range a.Profiles {
		profiles[profileForConfirmation(p)]++
	}
	for _, p := range b.Profiles {
		profile := profileForConfirmation(p)
		if profiles[profile] == 0 {
			return false
		}
		profiles[profile]--
	}
	return true
}

func profileForConfirmation(p installstate.Profile) confirmedProfile {
	return confirmedProfile{p.ID, p.ConfigDir, p.LegacyConfigDir, p.PendingConfigDir, p.PendingRuntimeDir, p.StateDir, p.RuntimeDir, p.Service}
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
				// Exact metadata directories are safe purge roots because their
				// inventory and lock files stay protected until finalization.
				if root == protected.path && protected.name != "installation" {
					continue
				}
				return fmt.Errorf("purge directory %s contains the %s directory %s; refusing to delete installation metadata", root, protected.name, protected.path)
			}
		}
	}
	return nil
}

func verifyProfileOwnership(inv *installstate.Inventory) error {
	for i, profile := range inv.Profiles {
		runtimeOwned, err := installstate.VerifyRuntime(*inv, profile)
		if err != nil {
			return err
		}
		configOwned, err := installstate.VerifyConfig(*inv, profile)
		if err != nil {
			return err
		}
		legacyConfigOwned, err := installstate.VerifyConfigDirectory(*inv, profile, profile.LegacyConfigDir)
		if err != nil {
			return err
		}
		pendingConfigOwned, err := installstate.VerifyConfigDirectory(*inv, profile, profile.PendingConfigDir)
		if err != nil {
			return err
		}
		inv.Profiles[i].RuntimeOwned = runtimeOwned
		inv.Profiles[i].ConfigOwned = configOwned
		inv.Profiles[i].LegacyConfigOwned = legacyConfigOwned
		inv.Profiles[i].PendingConfigOwned = pendingConfigOwned
	}
	return nil
}

func plannedMarkersForRoot(root string, plan removalPlan) map[string]bool {
	markers := make(map[string]bool)
	for _, file := range plan.Files {
		if file.Marker && filepath.Dir(file.Path) == root {
			markers[file.Path] = true
		}
	}
	for _, path := range plan.PurgePreserve {
		if filepath.Dir(path) == root {
			markers[path] = true
		}
	}
	return markers
}

func purgeContentsWithoutPreserved(root string, contents []string, plan removalPlan) []string {
	preserved := plannedMarkersForRoot(root, removalPlan{PurgePreserve: plan.PurgePreserve})
	filtered := make([]string, 0, len(contents))
	for _, path := range contents {
		if !preserved[path] {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func approvePreservedPurgePaths(root string, contents []string, plan removalPlan) []string {
	approved := append([]string(nil), contents...)
	for _, path := range plan.PurgePreserve {
		if filepath.Dir(path) == root && !contains(approved, path) {
			approved = append(approved, path)
		}
	}
	return approved
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
		for _, dir := range ownedProfileDirs(profile) {
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

func acquireRuntimeOwnershipGuards(ctx context.Context, inv installstate.Inventory, guards *[]*local.Guard) error {
	for _, profile := range inv.Profiles {
		guard, err := acquireStopped(ctx, inv, profile)
		if err != nil {
			return err
		}
		if guard != nil {
			*guards = append(*guards, guard)
		}
	}
	return nil
}

type registrationProbe func(context.Context, string) (bool, error)

func Execute(ctx context.Context, opts Options, out io.Writer) error {
	return executeWithRegistrationProbeAndFinalizer(ctx, opts, out, service.HasOwnedRegistration, removeTracked)
}
func executeWithRegistrationProbe(ctx context.Context, opts Options, out io.Writer, probe registrationProbe) error {
	return executeWithRegistrationProbeAndFinalizer(ctx, opts, out, probe, removeTracked)
}
func executeWithRegistrationProbeAndFinalizer(ctx context.Context, opts Options, out io.Writer, probe registrationProbe, remove trackedFileRemover) error {
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
		return reportAlreadyAbsentOrUntracked(dir, out)
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
	if err := verifyProfileOwnership(&inv); err != nil {
		return err
	}
	plan := makePlan(inv, opts.Purge)
	if err := preflight(inv, plan); err != nil {
		return err
	}
	confirmedPlan := plan
	// Refuse an untracked native registration before any tombstone or lock-file
	// mutation, so legacy service migration remains available after refusal.
	if !hasTrackedService(inv.Profiles) {
		if err := requireNoOwnedRegistration(ctx, registrationExecutable(dir), probe); err != nil {
			return err
		}
	}
	if opts.DryRun {
		return writeDryRunReport(opts, plan, inv, out)
	}
	confirmedPlanPurgeContents := make(map[string][]string)
	if !opts.Yes {
		confirmedPlanPurgeContents, err = confirmUninstall(opts, plan)
		if err != nil {
			return err
		}
	}
	if opts.Purge && opts.Yes {
		for _, root := range plan.PurgeDirs {
			paths, err := listTree(root)
			if err != nil {
				return fmt.Errorf("cannot list purge contents of %s: %w", root, err)
			}
			confirmedPlanPurgeContents[root] = paths
		}
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
	inv, plan, err = reverifyPlanUnderLock(dir, inv, confirmedPlan, opts.Purge, confirmedPlanPurgeContents)
	if err != nil {
		return err
	}
	if err := preflight(inv, plan); err != nil {
		return err
	}
	exe := registrationExecutable(dir)
	if !hasTrackedService(inv.Profiles) {
		if err := requireNoOwnedRegistration(ctx, exe, probe); err != nil {
			return err
		}
	}
	if err := installstate.MarkRemoving(inv); err != nil {
		return err
	}
	if err := removeServices(ctx, exe, inv.Profiles); err != nil {
		return fmt.Errorf("owned service registration could not be removed: %w", err)
	}
	var guards []*local.Guard
	defer func() {
		for _, g := range guards {
			_ = g.Close()
		}
	}()
	if err := acquireRuntimeOwnershipGuards(ctx, inv, &guards); err != nil {
		return err
	}
	// Native supervisor removal can return before its process exits. In
	// particular, launchd may still report a booted-out label during that
	// interval. Establish process shutdown through every profile lock before
	// treating a remaining registration as orphaned or cleaning its tunnel.
	if err := requireNoOwnedRegistration(ctx, exe, probe); err != nil {
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
	if err := verifyProfileOwnership(&inv); err != nil {
		return err
	}
	plan = makePlan(inv, opts.Purge)
	if runtime.GOOS != "windows" {
		if err := acquireUnixRuntimeDirectoryGuards(&inv, &guards); err != nil {
			return err
		}
	}
	plan = makePlan(inv, opts.Purge)
	if runtime.GOOS == "windows" {
		plan.PurgeContents = confirmedPlanPurgeContents
		result, err := scheduleRemoval(plan)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report{State: "pending", ResultFile: result, Message: "The bounded removal helper runs after this process exits. Read the result file to confirm completion; remaining paths indicate a retry is required."})
	}
	return executeUnixRemoval(plan, inv, opts.Purge, confirmedPlanPurgeContents, lock, updateLock, &updateLockHeld, remove, out)
}

func acquireUnixRuntimeDirectoryGuards(inv *installstate.Inventory, guards *[]*local.Guard) error {
	held := make(map[string]bool, len(inv.Profiles))
	for _, profile := range inv.Profiles {
		held[profile.StateDir] = true
	}
	for _, profile := range inv.Profiles {
		if !profile.RuntimeOwned || held[profile.RuntimeDir] {
			continue
		}
		guard, lockErr := local.TryAcquireExisting(profile.RuntimeDir)
		stillOwned, verifyErr := installstate.VerifyRuntime(*inv, profile)
		if verifyErr != nil {
			closeGuard(guard)
			return verifyErr
		}
		if !stillOwned {
			closeGuard(guard)
			clearRuntimeOwnership(inv, profile.ID)
			continue
		}
		if lockErr != nil {
			return fmt.Errorf("runtime remains in use; unrelated listener was preserved: %w", lockErr)
		}
		if guard != nil {
			*guards = append(*guards, guard)
		}
		held[profile.RuntimeDir] = true
	}
	return nil
}

func closeGuard(guard *local.Guard) {
	if guard != nil {
		_ = guard.Close()
	}
}

func clearRuntimeOwnership(inv *installstate.Inventory, profileID string) {
	for index := range inv.Profiles {
		if inv.Profiles[index].ID == profileID {
			inv.Profiles[index].RuntimeOwned = false
		}
	}
}

func reverifyPlanUnderLock(dir string, initialInv installstate.Inventory, confirmedPlan removalPlan, purge bool, confirmedPurgeContents map[string][]string) (installstate.Inventory, removalPlan, error) {
	inv, err := installstate.Load(dir)
	if err != nil {
		return installstate.Inventory{}, removalPlan{}, err
	}
	if inv.ID != initialInv.ID {
		return installstate.Inventory{}, removalPlan{}, errors.New("installation inventory changed before removal")
	}
	if _, found, err := selfupdate.FindJournal(inv); err != nil {
		return installstate.Inventory{}, removalPlan{}, err
	} else if found {
		return installstate.Inventory{}, removalPlan{}, errors.New("an interrupted self-update must be recovered with `peerimeter-agent self-update` before uninstall")
	}
	if err := verifyProfileOwnership(&inv); err != nil {
		return installstate.Inventory{}, removalPlan{}, err
	}
	plan := makePlan(inv, purge)
	if !sameConfirmedPlan(confirmedPlan, plan) {
		return installstate.Inventory{}, removalPlan{}, errors.New("installation profiles or removal resources changed before removal")
	}
	if purge {
		for _, root := range plan.PurgeDirs {
			current, err := listTree(root)
			if err != nil {
				return installstate.Inventory{}, removalPlan{}, fmt.Errorf("cannot recheck purge contents of %s: %w", root, err)
			}
			if !samePathSet(purgeContentsWithoutPreserved(root, confirmedPurgeContents[root], plan), purgeContentsWithoutPreserved(root, current, plan)) {
				return installstate.Inventory{}, removalPlan{}, errors.New("purge contents changed after confirmation; review the updated contents and retry uninstall")
			}
		}
	}
	return inv, plan, nil
}

func executeUnixRemoval(plan removalPlan, inv installstate.Inventory, purge bool, purgeContents map[string][]string, lock, updateLock io.Closer, updateLockHeld *bool, remove trackedFileRemover, out io.Writer) error {
	removedFiles := make([]string, 0, len(plan.Files)+3)
	// Retain profile markers and inventory until all other removals succeed, so
	// partial failure remains verifiable and a later invocation can safely retry.
	programFiles := append([]removalFile(nil), plan.Files...)
	sort.SliceStable(programFiles, func(i, j int) bool {
		return isCommandAlias(programFiles[i].Path) && !isCommandAlias(programFiles[j].Path)
	})
	for _, f := range programFiles {
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
	if purge {
		for _, dir := range plan.PurgeDirs {
			purged, err := removeDirectoryContents(dir, plannedMarkersForRoot(dir, plan), approvePreservedPurgePaths(dir, purgeContents[dir], plan))
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
		if isInstallationReference(f.Path, inv.InstallDir) {
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
	if err := updateLock.Close(); err != nil {
		return err
	}
	*updateLockHeld = false
	finalizedFiles, err := removeFinalizationResources(plan, inv.InstallDir, remove)
	if err != nil {
		return err
	}
	removedFiles = append(removedFiles, finalizedFiles...)
	for _, d := range plan.Directories {
		if err := removeEmptyDirectory(d); err != nil {
			return err
		}
	}
	sort.Strings(removedFiles)
	return json.NewEncoder(out).Encode(report{State: "removed", Paths: removedFiles})
}

func isCommandAlias(path string) bool {
	name := filepath.Base(path)
	return name == "pma" || name == "pma.exe" || name == "pma.cmd"
}

func isInstallationReference(path, installDir string) bool {
	return path == filepath.Join(installDir, installstate.ReferenceFilename) || path == filepath.Join(installDir, installstate.LegacyReferenceFilename)
}

type trackedFileRemover func(string) (bool, error)

func removeFinalizationResources(plan removalPlan, installDir string, remove trackedFileRemover) ([]string, error) {
	inventoryData, err := os.ReadFile(plan.Inventory)
	if err != nil {
		return nil, fmt.Errorf("read uninstall inventory before finalization: %w", err)
	}
	paths := finalizationResources(plan)
	paths = append(paths, filepath.Join(installDir, installstate.ReferenceFilename), filepath.Join(installDir, installstate.LegacyReferenceFilename))
	var removed []string
	inventoryRemoved := false
	for _, path := range paths {
		if path == "" {
			continue
		}
		wasRemoved, err := remove(path)
		if err != nil {
			if inventoryRemoved && isInstallationReference(path, installDir) {
				restoreErr := installstate.WritePrivate(plan.Inventory, inventoryData)
				if restoreErr != nil {
					return removed, errors.Join(fmt.Errorf("remove uninstall metadata %s: %w", path, err), fmt.Errorf("restore inventory for uninstall retry: %w", restoreErr))
				}
			}
			return removed, fmt.Errorf("remove uninstall metadata %s: %w", path, err)
		}
		if wasRemoved {
			removed = append(removed, path)
			if path == plan.Inventory {
				inventoryRemoved = true
			}
		}
	}
	return removed, nil
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
