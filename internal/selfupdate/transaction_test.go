package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
)

func TestApplyUpdatesOnlyInventoryFilesAndCanRollback(t *testing.T) {
	dir := t.TempDir()
	profileData := filepath.Join(dir, "service.key")
	oldFiles := make(map[string]string)
	newFiles := make(map[string][]byte)
	for _, name := range installstate.ProgramNames() {
		oldFiles[name] = "old " + name
		newFiles[name] = []byte("new " + name)
	}
	for name, data := range oldFiles {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(profileData, []byte("must remain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installstate.Register(dir); err != nil {
		t.Fatal(err)
	}
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	updateLock, err := LockUpdate(inv)
	if err != nil {
		t.Fatal(err)
	}
	defer updateLock.Close()
	lock, err := installstate.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	hashes, rollback, commit, err := Apply(inv, newFiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != len(inv.Files) {
		t.Fatalf("hashes=%v", hashes)
	}
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	wantFiles := map[string]string{profileData: "must remain"}
	for name, data := range oldFiles {
		wantFiles[filepath.Join(dir, name)] = data
	}
	for path, want := range wantFiles {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	_, rollback, commit, err = Apply(inv, newFiles)
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if err := rollback(); err == nil {
		t.Fatal("rollback succeeded after committed backups were removed")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAndRollbackPreservesInventoryWithPmaSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows installs pma.exe as a binary copy")
	}
	dir := t.TempDir()
	for _, name := range installstate.ProgramNames() {
		path := filepath.Join(dir, name)
		if name == "pma" {
			if err := os.Symlink("peerimeter-agent", path); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, []byte("old "+name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.Register(dir); err != nil {
		t.Fatal(err)
	}
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(inv.Files))
	for _, file := range inv.Files {
		files[file.Name] = []byte("new " + file.Name)
	}
	_, rollback, _, err := Apply(inv, files)
	if err != nil {
		t.Fatal(err)
	}
	aliasPath := filepath.Join(dir, "pma")
	aliasInfo, err := os.Lstat(aliasPath)
	if err != nil || aliasInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Apply replaced pma symlink: info=%v err=%v", aliasInfo, err)
	}
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	aliasInfo, err = os.Lstat(aliasPath)
	if err != nil || aliasInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rollback replaced pma symlink: info=%v err=%v", aliasInfo, err)
	}
	for _, file := range inv.Files {
		path := installstate.ResourcePath(inv, file)
		digest, err := installstate.Hash(path)
		if err != nil || digest != file.SHA256 {
			t.Fatalf("rollback left stale inventory hash for %s: %s %v", file.Name, digest, err)
		}
	}
}

func TestApplyRefusesModifiedInstalledFile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range installstate.ProgramNames() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("original"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.Register(dir); err != nil {
		t.Fatal(err)
	}
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	updateLock, err := LockUpdate(inv)
	if err != nil {
		t.Fatal(err)
	}
	defer updateLock.Close()
	path := filepath.Join(dir, installstate.ProgramNames()[0])
	if err := os.WriteFile(path, []byte("modified"), 0700); err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	for _, f := range inv.Files {
		files[f.Name] = []byte("replacement")
	}
	lock, err := installstate.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, _, _, err := Apply(inv, files); err == nil {
		t.Fatal("modified installation was overwritten")
	}
}

func TestApplyRefusesWritableProgramDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory mode bits are not available on Windows")
	}
	dir := t.TempDir()
	for _, name := range installstate.ProgramNames() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("original"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.Register(dir); err != nil {
		t.Fatal(err)
	}
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm()&0020 == 0 {
		t.Skip("filesystem does not preserve group-write mode bits")
	}
	files := make(map[string][]byte, len(inv.Files))
	for _, file := range inv.Files {
		files[file.Name] = []byte("replacement")
	}
	if _, _, _, err := Apply(inv, files); err == nil {
		t.Fatal("updated files in a group-writable program directory")
	}
}

func TestRecoverLockedRestoresInterruptedUpdate(t *testing.T) {
	dir := t.TempDir()
	files := make(map[string][]byte)
	for _, name := range installstate.ProgramNames() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("previous "+name), 0700); err != nil {
			t.Fatal(err)
		}
		files[name] = []byte("updated " + name)
	}
	if err := installstate.Register(dir); err != nil {
		t.Fatal(err)
	}
	inv, err := installstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	updateLock, err := LockUpdate(inv)
	if err != nil {
		t.Fatal(err)
	}
	defer updateLock.Close()
	lock, err := installstate.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Apply(inv, files); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = installstate.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	current, err := installstate.Load(dir)
	if err == nil {
		err = RecoverLocked(current)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyOldFiles(dir, files); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, JournalFilename)); !os.IsNotExist(err) {
		t.Fatal("recovery journal was not removed")
	}
}

func verifyOldFiles(dir string, updated map[string][]byte) error {
	for name := range updated {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if string(data) != "previous "+name {
			return errors.New("recovery did not restore previous program file")
		}
	}
	return nil
}
