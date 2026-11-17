package installstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestPrivateFileDisappearedDuringInspection(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".runtime")
	wrappedENOENT := fmt.Errorf("cannot verify extended permissions: %w", syscall.ENOENT)
	if !privateFileDisappeared(path, wrappedENOENT) {
		t.Fatal("wrapped ENOENT after the inspected file disappeared should be retried")
	}
	if privateFileDisappeared(path, &os.PathError{Op: "lstat", Path: path, Err: syscall.ENOENT}) {
		t.Fatal("an initial Lstat miss must remain a not-exist result")
	}
	if err := os.WriteFile(path, []byte("marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if privateFileDisappeared(path, wrappedENOENT) {
		t.Fatal("must not retry when the inspected path exists again")
	}
	if privateFileDisappeared(path, errors.New("unrelated inspection failure")) {
		t.Fatal("must not retry unrelated inspection failures")
	}
}

func TestCheckDirectoryRejectsWritableAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode-bit trust check")
	}
	parent := filepath.Join(t.TempDir(), "writable-parent")
	child := filepath.Join(parent, "trusted-child")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0707); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(child); err == nil {
		t.Fatal("trusted child directory accepted an attacker-writable ancestor")
	}
}

func TestCreatePrivateTempDirProtectsChildren(t *testing.T) {
	parent := t.TempDir()
	dir, err := CreatePrivateTempDir(parent, ".private-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := CheckDirectory(dir); err != nil {
		t.Fatalf("private temporary directory failed trust check: %v", err)
	}
	file := filepath.Join(dir, "child")
	if err := os.WriteFile(file, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(file); err != nil {
		t.Fatalf("private child inherited an unsafe ACL: %v", err)
	}
}

func fixtureInstall(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "installed agent")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range ProgramNames() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("public fixture program "+name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Register(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}
func fixtureProfile(t *testing.T) Profile {
	t.Helper()
	root := t.TempDir()
	p := Profile{ConfigDir: filepath.Join(root, "configuration"), StateDir: filepath.Join(root, "persistent state"), RuntimeDir: filepath.Join(root, "runtime")}
	for _, d := range []string{p.ConfigDir, p.StateDir, p.RuntimeDir} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return p
}
func TestInventoryUpgradeAndProfileMerge(t *testing.T) {
	dir := fixtureInstall(t)
	initial, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := fixtureProfile(t)
	foreground := p
	foreground.ConfigDir = ""
	if err := RegisterProfile(dir, foreground); err != nil {
		t.Fatal(err)
	}
	p.Service = true
	if err := RegisterProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	if err := RegisterProfile(dir, foreground); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ProgramNames()[0]), []byte("verified next package"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := Register(dir); err != nil {
		t.Fatal(err)
	}
	after, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	canonicalConfig, _ := Canonical(p.ConfigDir)
	if after.ID != initial.ID || len(after.Profiles) != 1 || after.Profiles[0].ConfigDir != canonicalConfig || !after.Profiles[0].Service {
		t.Fatal("upgrade or foreground registration lost installation/profile ownership")
	}
	if err := VerifyProfile(after, after.Profiles[0]); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationUpgradePreservesStoredInsecureDirectoryPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode-bit trust check")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "install")
	docDir := filepath.Join(root, "docs")
	dataDir := filepath.Join(root, "state")
	lockDir := filepath.Join(root, "locks")
	for _, path := range []string{dir, docDir, dataDir, lockDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range ProgramNames() {
		resourceDir, mode := dir, os.FileMode(0755)
		if name == "peerimeter-agent.NOTICES.txt" {
			resourceDir, mode = docDir, 0644
		}
		if err := os.WriteFile(filepath.Join(resourceDir, name), []byte("public fixture program "+name), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := RegisterWithDirectories(dir, docDir, dataDir, lockDir, false); err != nil {
		t.Fatal(err)
	}
	inv, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	inv.AllowInsecureInstallDir = true
	if err := save(inv); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, docDir, dataDir, lockDir} {
		if err := os.Chmod(path, 0770); err != nil {
			t.Fatal(err)
		}
	}

	if err := RegisterWithDirectories(dir, docDir, dataDir, lockDir, false); err != nil {
		t.Fatalf("upgrade rejected directories allowed by stored policy: %v", err)
	}
	upgraded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !upgraded.AllowInsecureInstallDir {
		t.Fatal("upgrade lost the stored insecure-directory policy")
	}
}

func TestUpdateProgramHashesPreservesProfileAndDirectories(t *testing.T) {
	dir := fixtureInstall(t)
	p := fixtureProfile(t)
	p.Service = true
	if err := RegisterProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	before, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make(map[string]string, len(before.Files))
	for _, f := range before.Files {
		hashes[f.Name] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	if err := UpdateProgramHashesLocked(before, hashes); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before.ID != after.ID || before.InstallDir != after.InstallDir || before.DataDir != after.DataDir || before.DocDir != after.DocDir || before.LockDir != after.LockDir || len(before.Profiles) != len(after.Profiles) || before.Profiles[0] != after.Profiles[0] {
		t.Fatal("program hash update changed installation identity, directories or profile")
	}
	for _, f := range after.Files {
		if f.SHA256 != hashes[f.Name] {
			t.Fatalf("hash for %s was not updated", f.Name)
		}
	}
}
func TestForeignProfileAndChangedLayoutRefused(t *testing.T) {
	first, second := fixtureInstall(t), fixtureInstall(t)
	p := fixtureProfile(t)
	if err := RegisterProfile(first, p); err != nil {
		t.Fatal(err)
	}
	if err := RegisterProfile(second, p); err == nil {
		t.Fatal("another installation took over persistent profile")
	}
	p.RuntimeDir = filepath.Join(t.TempDir(), "new runtime")
	if err := os.Mkdir(p.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RegisterProfile(first, p); err == nil {
		t.Fatal("implicit runtime migration accepted")
	}
}
func TestExplicitLegacyMigrationPreservesMarkerAndOldResources(t *testing.T) {
	dir := fixtureInstall(t)
	p := fixtureProfile(t)
	p.ConfigDir = p.StateDir
	p.RuntimeDir = p.StateDir
	p.Service = true
	if err := RegisterProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	before, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := fixtureProfile(t)
	next.StateDir = p.StateDir
	next.Service = true
	if err := MigrateProfile(dir, p, next); err != nil {
		t.Fatal(err)
	}
	after, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	oldCanonical, _ := Canonical(p.StateDir)
	if after.Profiles[0].ID != before.Profiles[0].ID || after.Profiles[0].LegacyConfigDir != oldCanonical {
		t.Fatal("migration lost stable ownership or legacy snapshot inventory")
	}
	if err := VerifyProfile(after, after.Profiles[0]); err != nil {
		t.Fatal(err)
	}
}
func TestSourceBuildRegistrationDoesNotCreateInventory(t *testing.T) {
	dir := t.TempDir()
	p := fixtureProfile(t)
	if err := RegisterProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, Filename)); !os.IsNotExist(err) {
		t.Fatal("source build registration created inventory")
	}
	if _, err := os.Lstat(filepath.Join(p.StateDir, MarkerFilename)); !os.IsNotExist(err) {
		t.Fatal("source build registration claimed unrelated state")
	}
}

func TestStartupLeaseAndRemovalGate(t *testing.T) {
	dir := fixtureInstall(t)
	p := fixtureProfile(t)
	if err := RegisterProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	startup, err := CaptureStartup(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer startup.Close()
	if other, err := Lock(dir); err == nil {
		other.Close()
		t.Fatal("startup lease did not exclude removal before state acquisition")
	}
	if err := startup.Check(); err != nil {
		t.Fatal(err)
	}
	if err := startup.Close(); err != nil {
		t.Fatal(err)
	}
	inv, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkRemoving(inv); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	if err := startup.Check(); err == nil {
		t.Fatal("captured installed process ignored durable removal gate")
	}
	if err := RegisterProfile(dir, p); err == nil {
		t.Fatal("new runtime registered during full removal")
	}
	if _, err := CaptureStartup(dir); err == nil {
		t.Fatal("new startup acquired a removal-gated installation")
	}
	if err := os.Remove(filepath.Join(dir, Filename)); err != nil {
		t.Fatal(err)
	}
	if err := startup.Check(); err == nil {
		t.Fatal("already-loaded installed process fell back to source mode after inventory deletion")
	}
}
func TestRuntimeClaimCannotTakeAnotherProfile(t *testing.T) {
	a, b := fixtureInstall(t), fixtureInstall(t)
	pa, pb := fixtureProfile(t), fixtureProfile(t)
	pb.RuntimeDir = pa.RuntimeDir
	if err := RegisterProfile(a, pa); err != nil {
		t.Fatal(err)
	}
	pa.ClaimRuntime = true
	if err := RegisterProfile(a, pa); err != nil {
		t.Fatal(err)
	}
	if err := RegisterProfile(b, pb); err != nil {
		t.Fatal(err)
	}
	pb.ClaimRuntime = true
	if err := RegisterProfile(b, pb); err == nil {
		t.Fatal("another profile took over the runtime marker")
	}
	ia, _ := Load(a)
	ib, _ := Load(b)
	if owned, e := VerifyRuntime(ia, ia.Profiles[0]); e != nil || !owned {
		t.Fatal("first profile lost runtime ownership")
	}
	if owned, e := VerifyRuntime(ib, ib.Profiles[0]); e != nil || owned {
		t.Fatal("planned second profile claimed the first runtime")
	}
	if ib.Profiles[0].RuntimeOwned {
		t.Fatal("failed runtime claim was persisted as owned")
	}
}

func TestUnregisteredSourceCannotAdoptInstalledState(t *testing.T) {
	installed := fixtureInstall(t)
	p := fixtureProfile(t)
	if err := RegisterProfile(installed, p); err != nil {
		t.Fatal(err)
	}
	sourceDir := t.TempDir()
	source, err := CaptureStartup(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	before, err := os.ReadFile(filepath.Join(p.StateDir, MarkerFilename))
	if err != nil {
		t.Fatal(err)
	}
	if err := source.RegisterProfile(Profile{StateDir: p.StateDir, RuntimeDir: p.RuntimeDir}); err == nil {
		t.Fatal("source build adopted installed ownership state")
	}
	after, err := os.ReadFile(filepath.Join(p.StateDir, MarkerFilename))
	if err != nil || string(before) != string(after) {
		t.Fatal("source build changed another installation's state")
	}
}
func TestConfigOwnershipCannotBeClaimedByPlannedForeignProfile(t *testing.T) {
	a, b := fixtureInstall(t), fixtureInstall(t)
	pa, pb := fixtureProfile(t), fixtureProfile(t)
	pb.ConfigDir = pa.ConfigDir
	for _, name := range []string{"service.yaml", "service.key"} {
		if err := os.WriteFile(filepath.Join(pa.ConfigDir, name), []byte("private installed snapshot"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RegisterProfile(a, pa); err != nil {
		t.Fatal(err)
	}
	pa.ClaimConfig = true
	if err := RegisterProfile(a, pa); err != nil {
		t.Fatal(err)
	}
	if err := RegisterProfile(b, pb); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfigClaim(b, pb.StateDir, pb.ConfigDir); err == nil {
		t.Fatal("foreign config passed pre-provision validation")
	}
	pb.ClaimConfig = true
	if err := RegisterProfile(b, pb); err == nil {
		t.Fatal("foreign planned profile claimed config")
	}
	ia, _ := Load(a)
	ib, _ := Load(b)
	if owned, e := VerifyConfig(ia, ia.Profiles[0]); e != nil || !owned {
		t.Fatal("first installation lost config ownership")
	}
	if owned, e := VerifyConfig(ib, ib.Profiles[0]); e != nil || owned {
		t.Fatal("second planned installation owns foreign config")
	}
}

func TestMigrationClaimTracksProvisionalConfigWithoutChangingActivePaths(t *testing.T) {
	dir := fixtureInstall(t)
	old := fixtureProfile(t)
	if err := RegisterProfile(dir, old); err != nil {
		t.Fatal(err)
	}
	before, _ := Load(dir)
	next := fixtureProfile(t)
	next.StateDir = old.StateDir
	for _, name := range []string{"service.yaml", "service.key"} {
		if err := os.WriteFile(filepath.Join(next.ConfigDir, name), []byte("private migrated snapshot"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	startup, err := CaptureStartup(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer startup.Close()
	if err := startup.ClaimMigrationConfig(next); err != nil {
		t.Fatal(err)
	}
	after, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := after.Profiles[0]
	cfg, _ := Canonical(next.ConfigDir)
	runtime, _ := Canonical(next.RuntimeDir)
	if p.ID != before.Profiles[0].ID || p.ConfigDir != before.Profiles[0].ConfigDir || p.RuntimeDir != before.Profiles[0].RuntimeDir || p.PendingConfigDir != cfg || p.PendingRuntimeDir != runtime {
		t.Fatal("provisional claim changed the active profile or lost its pending target")
	}
	if owned, err := VerifyConfigDirectory(after, p, p.PendingConfigDir); err != nil || !owned {
		t.Fatalf("pending config is not bound to the existing profile: %v", err)
	}
	if err := MarkRemoving(after); err != nil {
		t.Fatal(err)
	}
	if err := startup.Close(); err != nil {
		t.Fatal(err)
	}
	next.ClaimConfig = true
	if err := MigrateProfile(dir, old, next); err == nil {
		t.Fatal("migration changed a removing installation")
	}
}
