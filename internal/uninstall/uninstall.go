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
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

type Options struct {
	InstallDir, ConfigDir, StateDir, RuntimeDir string
	DryRun                                      bool
}
type removalFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Marker bool   `json:"marker,omitempty"`
}
type removalPlan struct {
	Version     int                    `json:"version"`
	InstallID   string                 `json:"installation_id"`
	ParentPID   int                    `json:"parent_pid"`
	Inventory   string                 `json:"inventory"`
	Lock        string                 `json:"lock"`
	Files       []removalFile          `json:"files"`
	Directories []string               `json:"directories"`
	Profiles    []installstate.Profile `json:"profiles"`
	ResultFile  string                 `json:"result_file"`
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
	if p.LegacyConfigDir != "" && p.LegacyConfigDir != p.ConfigDir {
		for _, name := range []string{"service.json", "service.key"} {
			files = append(files, removalFile{Path: filepath.Join(p.LegacyConfigDir, name)})
		}
	}
	if p.ConfigDir != "" {
		for _, name := range []string{"service.json", "service.key"} {
			files = append(files, removalFile{Path: filepath.Join(p.ConfigDir, name)})
		}
	}
	for _, name := range []string{"network.json", "ownership", "agent.lock"} {
		files = append(files, removalFile{Path: filepath.Join(p.StateDir, name)})
	}
	if p.RuntimeOwned {
		files = append(files, removalFile{Path: filepath.Join(p.RuntimeDir, "control.sock")}, removalFile{Path: filepath.Join(p.RuntimeDir, installstate.RuntimeMarkerFilename), Marker: true})
	}
	files = append(files, removalFile{Path: filepath.Join(p.StateDir, installstate.MarkerFilename), Marker: true})
	return files
}
func makePlan(inv installstate.Inventory) removalPlan {
	p := removalPlan{Version: 1, InstallID: inv.ID, ParentPID: os.Getpid(), Inventory: filepath.Join(inv.InstallDir, installstate.Filename), Lock: filepath.Join(inv.InstallDir, installstate.LockFilename), Profiles: inv.Profiles}
	seen := map[string]bool{}
	dirs := map[string]bool{inv.InstallDir: true}
	for _, profile := range inv.Profiles {
		for _, f := range resources(profile) {
			if !seen[f.Path] {
				p.Files = append(p.Files, f)
				seen[f.Path] = true
			}
		}
		ownedDirs := []string{profile.ConfigDir, profile.LegacyConfigDir, profile.StateDir}
		if profile.RuntimeOwned {
			ownedDirs = append(ownedDirs, profile.RuntimeDir)
		}
		for _, d := range ownedDirs {
			if d != "" {
				dirs[d] = true
			}
		}
	}
	for _, f := range inv.Files {
		path := filepath.Join(inv.InstallDir, f.Name)
		if !seen[path] {
			p.Files = append(p.Files, removalFile{Path: path, SHA256: f.SHA256})
			seen[path] = true
		}
	}
	for d := range dirs {
		p.Directories = append(p.Directories, d)
	}
	sort.Slice(p.Directories, func(i, j int) bool { return len(p.Directories[i]) > len(p.Directories[j]) })
	return p
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
	return nil
}
func verifyProfile(inv installstate.Inventory, p installstate.Profile) error {
	err := installstate.VerifyProfile(inv, p)
	if err == nil {
		return nil
	}
	// A previous removal can finish a profile before failing on another file.
	// Missing markers are accepted only when every other tracked leaf is absent.
	if _, e := os.Lstat(filepath.Join(p.StateDir, installstate.MarkerFilename)); !os.IsNotExist(e) {
		return err
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
	for _, profile := range inv.Profiles {
		if _, err := installstate.VerifyRuntime(inv, profile); err != nil {
			return err
		}
		if err := verifyProfile(inv, profile); err != nil {
			return err
		}
		ownedDirs := []string{profile.ConfigDir, profile.LegacyConfigDir, profile.StateDir}
		if profile.RuntimeOwned {
			ownedDirs = append(ownedDirs, profile.RuntimeDir)
		}
		for _, dir := range ownedDirs {
			if dir != "" {
				if err := installstate.CheckDirectory(dir); err != nil {
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
	return service.Config{ConfigPath: filepath.Join(p.ConfigDir, "service.json"), ConfigDirectory: p.ConfigDir, StateDirectory: p.StateDir, RuntimeDirectory: p.RuntimeDir}
}
func removeServices(ctx context.Context, exe string, profiles []installstate.Profile) error {
	var failed []installstate.Profile
	var problems []error
	removed := false
	for _, p := range profiles {
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

func Execute(ctx context.Context, opts Options, out io.Writer) error {
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
		for _, name := range append(installstate.ProgramNames(), installstate.Filename) {
			if _, e := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(e) {
				return errors.New("installation inventory is absent; existing files are untracked and were preserved")
			}
		}
		return json.NewEncoder(out).Encode(report{State: "already_absent"})
	}
	if err != nil {
		return err
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
	}
	plan := makePlan(inv)
	if err := preflight(inv, plan); err != nil {
		return err
	}
	if opts.DryRun {
		r := report{State: "dry_run", Message: "Deletes the installed identity, configuration, credentials and inventoried program files; original source files are preserved."}
		for _, f := range plan.Files {
			r.Paths = append(r.Paths, f.Path)
		}
		r.Paths = append(r.Paths, plan.Lock, plan.Inventory)
		for _, p := range inv.Profiles {
			if p.Service {
				r.Services = append(r.Services, "owned agent service registration")
			}
		}
		return json.NewEncoder(out).Encode(r)
	}
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
	inv = reread
	for i, p := range inv.Profiles {
		owned, e := installstate.VerifyRuntime(inv, p)
		if e != nil {
			return e
		}
		inv.Profiles[i].RuntimeOwned = owned
	}
	plan = makePlan(inv)
	if err := preflight(inv, plan); err != nil {
		return err
	}
	exeName := "peerimeter-agent"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
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
	}
	plan = makePlan(inv)
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
	plan = makePlan(inv)
	if runtime.GOOS == "windows" {
		result, err := scheduleRemoval(plan)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report{State: "pending", ResultFile: result, Message: "The bounded removal helper runs after this process exits. Read the result file to confirm completion; remaining paths indicate a retry is required."})
	}
	// Retain profile markers and inventory until all other removals succeed, so
	// partial failure remains verifiable and a later invocation can safely retry.
	for _, f := range plan.Files {
		if f.Marker {
			continue
		}
		if err := removeLeaf(f); err != nil {
			return fmt.Errorf("partial uninstall; remaining resource %s: %w", f.Path, err)
		}
	}
	for _, f := range plan.Files {
		if !f.Marker {
			continue
		}
		if err := removeLeaf(f); err != nil {
			return fmt.Errorf("partial uninstall; profile marker remains %s: %w", f.Path, err)
		}
	}
	if err := lock.Close(); err != nil {
		return err
	}
	if err := removeAbsentOK(plan.Lock); err != nil {
		return err
	}
	if err := removeAbsentOK(plan.Inventory); err != nil {
		return err
	}
	for _, d := range plan.Directories {
		if err := removeEmptyDirectory(d); err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(report{State: "removed"})
}
func removeAbsentOK(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func removeLeaf(f removalFile) error {
	info, err := os.Lstat(f.Path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		if err := installstate.CheckFile(f.Path); err != nil {
			return err
		}
	}
	if f.SHA256 != "" {
		hash, e := installstate.Hash(f.Path)
		if e != nil {
			return e
		}
		if hash != f.SHA256 {
			return errors.New("program file changed during removal")
		}
	}
	return os.Remove(f.Path)
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
