package installstate

import (
	"os"
	"path/filepath"
	"testing"
)

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
	for _, name := range []string{"service.json", "service.key"} {
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
	for _, name := range []string{"service.json", "service.key"} {
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
