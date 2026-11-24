//go:build linux || darwin

package uninstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/selfupdate"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func prepareUninstall(t *testing.T) (string, installstate.Profile) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "pm-uninstall-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "installation")
	p := installstate.Profile{ConfigDir: filepath.Join(base, "config"), StateDir: filepath.Join(base, "state"), RuntimeDir: filepath.Join(base, "runtime")}
	for _, d := range []string{dir, p.ConfigDir, p.StateDir, p.RuntimeDir} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range installstate.ProgramNames() {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.Register(dir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(p.ConfigDir, "service.yaml"), filepath.Join(p.ConfigDir, "service.key"), filepath.Join(p.StateDir, "network.yaml")} {
		if err := os.WriteFile(path, []byte("private fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.RegisterProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	claimed := p
	claimed.ClaimConfig = true
	if err := installstate.RegisterProfile(dir, claimed); err != nil {
		t.Fatal(err)
	}
	return dir, p
}

func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = canonicalRoot
	out := map[string]string{}
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		s, e := os.Lstat(p)
		if e != nil {
			return e
		}
		v := s.Mode().String() + s.ModTime().String()
		if s.Mode().IsRegular() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			h := sha256.Sum256(b)
			v += hex.EncodeToString(h[:])
		}
		out[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestDryRunIsReadOnlyAndListsManagedIdentity(t *testing.T) {
	dir, p := prepareUninstall(t)
	if err := os.Remove(filepath.Join(dir, installstate.LockFilename)); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, filepath.Dir(dir))
	var out bytes.Buffer
	if err := Execute(context.Background(), Options{InstallDir: dir, DryRun: true}, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshotTree(t, filepath.Dir(dir))) {
		t.Fatal("dry-run changed filesystem metadata or contents")
	}
	var result report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.State != "dry_run" {
		t.Fatal("invalid dry-run report")
	}
	found := false
	for _, path := range result.Paths {
		canonicalConfig, _ := installstate.Canonical(p.ConfigDir)
		if path == filepath.Join(canonicalConfig, "service.key") {
			found = true
		}
	}
	if !found {
		t.Fatal("dry-run omitted installed private key")
	}
}

func TestUninstallListsFilesAndRequiresConfirmation(t *testing.T) {
	dir, p := prepareUninstall(t)
	var prompt bytes.Buffer
	err := Execute(context.Background(), Options{InstallDir: dir, ConfirmIn: strings.NewReader("n\n"), ConfirmOut: &prompt}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "uninstall cancelled") {
		t.Fatalf("uninstall without affirmative confirmation returned %v", err)
	}
	if !strings.Contains(prompt.String(), filepath.Join(p.ConfigDir, "service.key")) {
		t.Fatal("confirmation prompt omitted the installed private key")
	}
	canonicalConfig, err := installstate.Canonical(p.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	foundDirectory := false
	for _, line := range strings.Split(prompt.String(), "\n") {
		if line == "  "+canonicalConfig {
			foundDirectory = true
		}
	}
	if !foundDirectory {
		t.Fatal("confirmation prompt omitted a directory removal candidate")
	}
	if _, err := os.Stat(filepath.Join(p.ConfigDir, "service.key")); err != nil {
		t.Fatalf("cancelled uninstall removed a file: %v", err)
	}
}

type callbackReader struct {
	callback func()
	used     bool
}

func (r *callbackReader) Read(p []byte) (int, error) {
	if r.used {
		return 0, io.EOF
	}
	r.used = true
	r.callback()
	return copy(p, "y\n"), nil
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestConfirmationWriteFailurePreservesInstallation(t *testing.T) {
	dir, p := prepareUninstall(t)
	err := Execute(context.Background(), Options{InstallDir: dir, ConfirmIn: strings.NewReader("y\n"), ConfirmOut: failedWriter{}}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot display uninstall preview") {
		t.Fatalf("confirmation output failure returned %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.ConfigDir, "service.key")); err != nil {
		t.Fatalf("preview output failure removed an installed file: %v", err)
	}
}

func TestUninstallRejectsProfileChangesDuringConfirmation(t *testing.T) {
	dir, _ := prepareUninstall(t)
	newState := filepath.Join(t.TempDir(), "new-state")
	newRuntime := filepath.Join(t.TempDir(), "new-runtime")
	for _, path := range []string{newState, newRuntime} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var registrationErr error
	reader := &callbackReader{callback: func() {
		registrationErr = installstate.RegisterProfile(dir, installstate.Profile{StateDir: newState, RuntimeDir: newRuntime})
	}}
	err := Execute(context.Background(), Options{InstallDir: dir, ConfirmIn: reader, ConfirmOut: &bytes.Buffer{}}, &bytes.Buffer{})
	if registrationErr != nil {
		t.Fatalf("register concurrent profile: %v", registrationErr)
	}
	if err == nil || !strings.Contains(err.Error(), "changed before removal") {
		t.Fatalf("uninstall accepted profiles different from the confirmed plan: %v", err)
	}
	if _, err := os.Stat(newState); err != nil {
		t.Fatalf("uninstall removed the newly registered profile: %v", err)
	}
}

func TestPurgeRejectsContentsAddedAfterConfirmation(t *testing.T) {
	dir, profile := prepareUninstall(t)
	added := filepath.Join(profile.StateDir, "appeared-after-preview.txt")
	reader := &callbackReader{callback: func() {
		if err := os.WriteFile(added, []byte("keep"), 0600); err != nil {
			t.Errorf("add unapproved purge file: %v", err)
		}
	}}
	err := Execute(context.Background(), Options{InstallDir: dir, Purge: true, ConfirmIn: reader, ConfirmOut: &bytes.Buffer{}}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "purge contents changed after confirmation") {
		t.Fatalf("uninstall accepted changed purge contents: %v", err)
	}
	if _, err := os.Stat(added); err != nil {
		t.Fatalf("unapproved file was removed: %v", err)
	}
}

func TestPurgeDoesNotRecursivelyDeleteUnapprovedChild(t *testing.T) {
	rootPath := t.TempDir()
	purgeDir := filepath.Join(rootPath, "cache")
	if err := os.Mkdir(purgeDir, 0700); err != nil {
		t.Fatal(err)
	}
	approvedFile := filepath.Join(purgeDir, "approved.txt")
	unapprovedFile := filepath.Join(purgeDir, "appeared-later.txt")
	for _, path := range []string{approvedFile, unapprovedFile} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	removed := []string{}
	approved := map[string]bool{purgeDir: true, approvedFile: true}
	err = removeApprovedTree(root, "cache", rootPath, approved, true, &removed)
	if err == nil || !strings.Contains(err.Error(), "purge contents changed after confirmation") {
		t.Fatalf("purge accepted an unapproved child: %v", err)
	}
	if _, err := os.Stat(unapprovedFile); err != nil {
		t.Fatalf("unapproved child was removed: %v", err)
	}
}

func TestFinalizationFailureKeepsReferenceForRetry(t *testing.T) {
	root := t.TempDir()
	installDir := filepath.Join(root, "install")
	dataDir := filepath.Join(root, "data")
	lockDir := filepath.Join(root, "locks")
	for _, dir := range []string{installDir, dataDir, lockDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	plan := removalPlan{
		Lock: filepath.Join(lockDir, "install.lock"), DataLock: filepath.Join(dataDir, "install.lock"),
		Inventory: filepath.Join(dataDir, installstate.Filename),
	}
	reference := filepath.Join(installDir, installstate.ReferenceFilename)
	for _, path := range []string{plan.Lock, plan.DataLock, plan.Inventory, reference} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	failure := errors.New("simulated inventory removal failure")
	removeInventoryFailure := func(path string) (bool, error) {
		if path == plan.Inventory {
			return false, failure
		}
		return removeTracked(path)
	}
	if _, err := removeFinalizationResources(plan, installDir, removeInventoryFailure); !errors.Is(err, failure) {
		t.Fatalf("finalization returned %v, want injected failure", err)
	}
	for _, path := range []string{plan.Inventory, reference} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("failed finalization removed retry metadata %s: %v", path, err)
		}
	}
	if _, err := removeFinalizationResources(plan, installDir, removeTracked); err != nil {
		t.Fatalf("retry finalization: %v", err)
	}
	if _, err := os.Lstat(reference); !os.IsNotExist(err) {
		t.Fatalf("retry retained reference: %v", err)
	}
}

func TestPurgeDryRunListsAndRemovalDeletesNestedTrackedData(t *testing.T) {
	dir, profile := prepareUninstall(t)
	stateFile := filepath.Join(profile.StateDir, "managed", "network", "cache.json")
	stateConfigMarker := filepath.Join(profile.StateDir, installstate.ConfigMarkerFilename)
	configFile := filepath.Join(profile.ConfigDir, "extra", "old.yaml")
	configLock := filepath.Join(profile.ConfigDir, "agent.lock")
	for _, path := range []string{stateFile, stateConfigMarker, configFile, configLock} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("remove me"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var dryRun bytes.Buffer
	if err := Execute(context.Background(), Options{InstallDir: dir, DryRun: true, Purge: true}, &dryRun); err != nil {
		t.Fatal(err)
	}
	var preview report
	if err := json.Unmarshal(dryRun.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{stateFile, stateConfigMarker, configFile, configLock} {
		canonical, err := installstate.Canonical(expected)
		if err != nil {
			t.Fatal(err)
		}
		if !contains(preview.Paths, canonical) {
			t.Fatalf("purge dry-run omitted %s: %v", expected, preview.Paths)
		}
		if _, err := os.Stat(expected); err != nil {
			t.Fatalf("dry-run removed %s: %v", expected, err)
		}
	}
	var out bytes.Buffer
	probe := func(context.Context, string) (bool, error) { return false, nil }
	if err := executeWithRegistrationProbe(context.Background(), Options{InstallDir: dir, Purge: true, Yes: true}, &out, probe); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stateFile, stateConfigMarker, configFile, configLock} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("purge left %s behind: %v", path, err)
		}
	}
	var result report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.State != "removed" {
		t.Fatalf("purge result = %s, %v", out.String(), err)
	}
}

func TestPurgePreservesOnlyScheduledMarkersUntilMarkerPhase(t *testing.T) {
	root := t.TempDir()
	markers := []string{installstate.MarkerFilename}
	untrackedMarkers := []string{installstate.ConfigMarkerFilename, installstate.RuntimeMarkerFilename}
	for _, name := range append(append(markers, untrackedMarkers...), "agent.lock", "untracked.txt") {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	planned := []removalFile{{Path: filepath.Join(root, installstate.MarkerFilename), Marker: true}}
	if _, err := removeDirectoryContents(root, plannedMarkersForRoot(root, removalPlan{Files: planned})); err != nil {
		t.Fatal(err)
	}
	for _, name := range markers {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			t.Fatalf("purge removed ownership marker %s before marker phase: %v", name, err)
		}
	}
	for _, name := range append(untrackedMarkers, "agent.lock", "untracked.txt") {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("purge retained untracked entry %s: %v", name, err)
		}
	}
}

func TestPurgeDoesNotFollowSymlinkRootsOrEntries(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "purge")
	target := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(target, "keep.txt")
	if err := os.WriteFile(outsideFile, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "outside-link")); err != nil {
		t.Fatal(err)
	}
	removed, err := removeDirectoryContents(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "outside-link")); !os.IsNotExist(err) {
		t.Fatalf("purge retained child symlink: %v", err)
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("purge followed child symlink and removed its target: %v", err)
	}
	if len(removed) != 1 || removed[0] != filepath.Join(root, "outside-link") {
		t.Fatalf("removed paths = %v, want only the child symlink", removed)
	}

	linkRoot := filepath.Join(base, "root-link")
	if err := os.Symlink(target, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := removeDirectoryContents(linkRoot, nil); err == nil {
		t.Fatal("purge accepted a symlink root")
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("purge through symlink root removed its target: %v", err)
	}
}

func TestPurgeRejectsRootsContainingInstallationMetadata(t *testing.T) {
	for _, protected := range []string{"install", "data", "locks"} {
		root := filepath.Join(string(filepath.Separator), "tmp", "peerimeter-purge-test")
		inv := installstate.Inventory{InstallDir: filepath.Join(root, "install"), DataDir: filepath.Join(root, "data"), LockDir: filepath.Join(root, "locks")}
		if protected == "install" {
			inv.InstallDir = filepath.Join(root, "state", "install")
		} else if protected == "data" {
			inv.DataDir = filepath.Join(root, "state", "inventory")
		} else {
			inv.LockDir = filepath.Join(root, "state", "locks")
		}
		plan := removalPlan{PurgeDirs: []string{filepath.Join(root, "state")}}
		err := validatePurgeRoots(inv, plan)
		protectedPath := map[string]string{"install": inv.InstallDir, "data": inv.DataDir, "locks": inv.LockDir}[protected]
		if err == nil || !strings.Contains(err.Error(), protectedPath) {
			t.Fatalf("purge root was not rejected for nested %s directory: %v", protected, err)
		}
	}
}

func TestPurgeAllowsExactInstallationDataAndLockDirectories(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "tmp", "peerimeter-purge-test")
	for _, protected := range []string{"data", "locks"} {
		inv := installstate.Inventory{InstallDir: filepath.Join(root, "install"), DataDir: filepath.Join(root, "data"), LockDir: filepath.Join(root, "locks")}
		protectedPath := map[string]string{"data": inv.DataDir, "locks": inv.LockDir}[protected]
		if err := validatePurgeRoots(inv, removalPlan{PurgeDirs: []string{protectedPath}}); err != nil {
			t.Fatalf("purge rejected exact %s directory: %v", protected, err)
		}
	}
}

func TestPurgeRemovesManagedJoinFilesWhenStateIsInstallationData(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "pm-uninstall-shared-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	installDir := filepath.Join(base, "install")
	docDir := filepath.Join(base, "doc")
	dataDir := filepath.Join(base, "state")
	configDir := filepath.Join(base, "config")
	runtimeDir := filepath.Join(base, "runtime")
	for _, dir := range []string{installDir, docDir, dataDir, configDir, runtimeDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range installstate.ProgramNames() {
		programDir := installDir
		if name == "peerimeter-agent.NOTICES.txt" {
			programDir = docDir
		}
		if err := os.WriteFile(filepath.Join(programDir, name), []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.RegisterWithDirectories(installDir, docDir, dataDir, dataDir, false); err != nil {
		t.Fatal(err)
	}
	profile := installstate.Profile{ConfigDir: configDir, StateDir: dataDir, RuntimeDir: runtimeDir}
	for _, path := range []string{filepath.Join(configDir, "service.yaml"), filepath.Join(configDir, "service.key")} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	managedDir := filepath.Join(dataDir, "managed")
	if err := os.Mkdir(managedDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(managedDir, "network-a.token"),
		filepath.Join(managedDir, "network-a.yaml"),
		filepath.Join(configDir, "network-a.yaml"),
		filepath.Join(configDir, "network-a.key"),
	} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.RegisterProfile(installDir, profile); err != nil {
		t.Fatal(err)
	}
	profile.ClaimConfig = true
	if err := installstate.RegisterProfile(installDir, profile); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := Execute(context.Background(), Options{InstallDir: installDir, Purge: true, Yes: true}, &output); err != nil {
		t.Fatalf("purge uninstall failed: %v", err)
	}
	for _, path := range []string{installDir, dataDir, configDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("purge retained %s: %v", path, err)
		}
	}
}

func TestUninstallRefusesPendingSelfUpdateRecovery(t *testing.T) {
	dir, _ := prepareUninstall(t)
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inv.LockDir, selfupdate.JournalFilename)
	if err := os.WriteFile(path, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = Execute(context.Background(), Options{InstallDir: dir, Yes: true}, &out)
	if err == nil || !strings.Contains(err.Error(), "recovered with `peerimeter-agent self-update`") {
		t.Fatalf("uninstall did not preserve pending recovery files: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pending journal was removed: %v", err)
	}
}

func TestUninstallRefusesActiveSelfUpdate(t *testing.T) {
	dir, _ := prepareUninstall(t)
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	updateLock, err := selfupdate.LockUpdate(inv)
	if err != nil {
		t.Fatal(err)
	}
	defer updateLock.Close()
	if err := Execute(context.Background(), Options{InstallDir: dir, Yes: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "self-update is using this installation") {
		t.Fatalf("uninstall did not respect active update ownership: %v", err)
	}
	current, err := installstate.Load(dir)
	if err != nil || current.Removing {
		t.Fatalf("busy updater caused installation removal: inv=%+v err=%v", current, err)
	}
}
func TestFullRemovalPreservesUnrelatedAndSupportsRetry(t *testing.T) {
	dir, p := prepareUninstall(t)
	legacyNetworkPath := filepath.Join(p.StateDir, "network.json")
	if err := os.WriteFile(legacyNetworkPath, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	var untouched []string
	for _, d := range []string{dir, p.ConfigDir, p.StateDir, p.RuntimeDir} {
		path := filepath.Join(d, "unrelated.txt")
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		untouched = append(untouched, path)
	}
	notice := filepath.Join(dir, "peerimeter-agent.NOTICES.txt")
	if err := os.WriteFile(notice, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, filepath.Dir(dir))
	if err := Execute(context.Background(), Options{InstallDir: dir, Yes: true}, &bytes.Buffer{}); err == nil {
		t.Fatal("changed program file was removed")
	}
	if !reflect.DeepEqual(before, snapshotTree(t, filepath.Dir(dir))) {
		t.Fatal("failed preflight mutated the live installation")
	}
	// Missing already-removed package members are safe on partial-failure retry.
	if err := os.Remove(notice); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Execute(context.Background(), Options{InstallDir: dir, Yes: true}, &out); err != nil {
		t.Fatal(err)
	}
	var result report
	_ = json.Unmarshal(out.Bytes(), &result)
	if result.State != "removed" {
		t.Fatal("full removal did not report success")
	}
	for _, path := range untouched {
		b, e := os.ReadFile(path)
		if e != nil || string(b) != "preserve" {
			t.Fatal("unrelated custom-parent content was removed")
		}
	}
	for _, path := range []string{filepath.Join(p.ConfigDir, "service.key"), filepath.Join(p.ConfigDir, "service.yaml"), filepath.Join(p.StateDir, "network.yaml"), filepath.Join(p.StateDir, installstate.MarkerFilename), filepath.Join(dir, installstate.Filename)} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatalf("owned file remained: %s", path)
		}
	}
	if data, err := os.ReadFile(legacyNetworkPath); err != nil || string(data) != "preserve" {
		t.Fatalf("legacy network state was not preserved: %q, %v", data, err)
	}
	out.Reset()
	if err := Execute(context.Background(), Options{InstallDir: dir, Yes: true}, &out); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(out.Bytes(), &result)
	if result.State != "already_absent" {
		t.Fatal("repeated removal was not idempotent")
	}
}
func TestLivePersistentGuardPreventsDeletion(t *testing.T) {
	dir, p := prepareUninstall(t)
	guard, err := local.Acquire(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	before := snapshotTree(t, filepath.Dir(dir))
	canonicalDir, err := installstate.Canonical(dir)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	updateLockPath := filepath.Join(inv.LockDir, selfupdate.UpdateLockFilename)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	executeErr := executeWithRegistrationProbe(ctx, Options{InstallDir: dir, Yes: true}, &bytes.Buffer{}, func(context.Context, string) (bool, error) {
		return false, nil
	})
	if executeErr == nil {
		t.Fatal("uninstall bypassed a live manager state lock")
	}
	after := snapshotTree(t, filepath.Dir(dir))
	delete(before, filepath.Join(canonicalDir, installstate.Filename))
	delete(after, filepath.Join(canonicalDir, installstate.Filename))
	delete(before, updateLockPath)
	delete(after, updateLockPath)
	delete(before, canonicalDir)
	delete(after, canonicalDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("live lock refusal deleted or changed managed data")
	}
	inv, e := installstate.Load(dir)
	if e != nil || !inv.Removing {
		t.Fatalf("incomplete removal must durably prevent a new manager startup: removing=%v load_err=%v execute_err=%v", inv.Removing, e, executeErr)
	}
}
func TestUntrackedOverrideAndSymlinkRefused(t *testing.T) {
	dir, p := prepareUninstall(t)
	outside := t.TempDir()
	if err := Execute(context.Background(), Options{InstallDir: dir, ConfigDir: outside, DryRun: true}, &bytes.Buffer{}); err == nil {
		t.Fatal("untracked directory override accepted")
	}
	key := filepath.Join(p.ConfigDir, "service.key")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(outside, "operator-original.key")
	if err := os.WriteFile(source, []byte("private source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, key); err != nil {
		t.Fatal(err)
	}
	if err := Execute(context.Background(), Options{InstallDir: dir, Yes: true}, &bytes.Buffer{}); err == nil {
		t.Fatal("symlink resource was followed during removal")
	}
	b, e := os.ReadFile(source)
	if e != nil || string(b) != "private source" {
		t.Fatal("operator original key was removed")
	}
}

func TestOwnedDaemonStopsEvenWhenNetworkSnapshotFails(t *testing.T) {
	dir, p := prepareUninstall(t)
	guard, err := local.Acquire(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	var calls atomic.Int32
	stop := make(chan struct{})
	var once sync.Once
	claim := p
	claim.ClaimRuntime = true
	closeControl, err := local.Serve(context.Background(), p.RuntimeDir, local.Operations{
		InstanceID:   local.InstanceID(p.StateDir),
		BeforeListen: func() error { return installstate.RegisterProfile(dir, claim) },
		OnClose:      func() error { return installstate.ReleaseRuntime(dir, p.StateDir, p.RuntimeDir) },
		Snapshot: func(context.Context) (platform.Snapshot, error) {
			calls.Add(1)
			return platform.Snapshot{}, errors.New("native interface drift")
		},
		Reload: func(context.Context) error { return nil }, Stop: func() { once.Do(func() { close(stop) }) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeControl()
	done := make(chan error, 1)
	go func() {
		<-stop
		closeErr := closeControl()
		lockErr := guard.Close()
		done <- errors.Join(closeErr, lockErr)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Execute(ctx, Options{InstallDir: dir, Yes: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("uninstall depended on mutable network health instead of authenticated instance identity")
	}
}

func TestFailedForeignConfigIntentDoesNotDeleteInstalledCredentials(t *testing.T) {
	owner, pa := prepareUninstall(t)
	base, err := os.MkdirTemp("/tmp", "pm-cfg-alias-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	program := filepath.Join(base, "program")
	state := filepath.Join(base, "state")
	run := filepath.Join(base, "runtime")
	for _, dir := range []string{program, state, run} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range installstate.ProgramNames() {
		if err := os.WriteFile(filepath.Join(program, name), []byte("second program"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.Register(program); err != nil {
		t.Fatal(err)
	}
	planned := installstate.Profile{ConfigDir: pa.ConfigDir, StateDir: state, RuntimeDir: run}
	if err := installstate.RegisterProfile(program, planned); err != nil {
		t.Fatal(err)
	}
	if err := installstate.ValidateConfigClaim(program, state, pa.ConfigDir); err == nil {
		t.Fatal("foreign configuration provision was authorized")
	}
	before := snapshotTree(t, pa.ConfigDir)
	if err := Execute(context.Background(), Options{InstallDir: program, Yes: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshotTree(t, pa.ConfigDir)) {
		t.Fatal("failed alias installation removed another installation's credentials")
	}
	if _, err := installstate.Load(owner); err != nil {
		t.Fatal("another installation's registry was removed")
	}
}

func TestUntrackedNativeRegistrationBlocksProgramAndIdentityDeletion(t *testing.T) {
	dir, p := prepareUninstall(t)
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	inv.Profiles = nil // Legacy upgrade / registration succeeded before profile save.
	data, _ := json.Marshal(inv)
	if err := installstate.WritePrivate(filepath.Join(dir, installstate.Filename), data); err != nil {
		t.Fatal(err)
	}
	originalManifest, err := os.ReadFile(filepath.Join(dir, installstate.Filename))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	calls := 0
	probe := func(ctx context.Context, executable string) (bool, error) {
		calls++
		canonical, _ := installstate.Canonical(dir)
		if executable != filepath.Join(canonical, "peerimeter-agent") {
			t.Fatal("registration probe checked another installation")
		}
		return true, nil
	}
	err = executeWithRegistrationProbe(context.Background(), Options{InstallDir: dir, Yes: true}, &out, probe)
	if err == nil || !strings.Contains(err.Error(), "untracked native service") {
		t.Fatalf("untracked registration was not reported incomplete: %v", err)
	}
	if calls != 1 || bytes.Contains(out.Bytes(), []byte(`"state":"removed"`)) {
		t.Fatal("untracked service was ignored or removal was falsely reported")
	}
	for _, path := range []string{filepath.Join(dir, "peerimeter-agent"), filepath.Join(dir, "peerimeter-agent.NOTICES.txt"), filepath.Join(p.ConfigDir, "service.yaml"), filepath.Join(p.ConfigDir, "service.key"), filepath.Join(p.StateDir, "network.yaml")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("registration guard deleted preserved resource %s", path)
		}
	}
	pending, err := installstate.Load(dir)
	if err != nil || pending.Removing {
		t.Fatal("read-only untracked-service refusal blocked later uninstall retry")
	}
	after, _ := os.ReadFile(filepath.Join(dir, installstate.Filename))
	if !bytes.Equal(after, originalManifest) {
		t.Fatal("untracked-registration refusal changed inventory bytes")
	}
}
func TestForeignRegistrationDoesNotBlockRemovalAndInspectionFailureDoes(t *testing.T) {
	for _, inspectionError := range []bool{true, false} {
		dir, _ := prepareUninstall(t)
		failure := errors.New("native service query denied")
		probe := func(context.Context, string) (bool, error) {
			if inspectionError {
				return false, failure
			}
			return false, nil
		}
		err := executeWithRegistrationProbe(context.Background(), Options{InstallDir: dir, Yes: true}, &bytes.Buffer{}, probe)
		if inspectionError {
			if !errors.Is(err, failure) {
				t.Fatal("inspection failure was ignored")
			}
			if _, err := os.Stat(filepath.Join(dir, "peerimeter-agent")); err != nil {
				t.Fatal("failed inspection deleted executable")
			}
		} else if err != nil {
			t.Fatal("foreign executable registration blocked unrelated installation cleanup", err)
		}
	}
}
