package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
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
	path := filepath.Join(dir, installstate.ProgramNames()[0])
	if err := os.WriteFile(path, []byte("modified"), 0700); err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	for _, f := range inv.Files {
		files[f.Name] = []byte("replacement")
	}
	if _, _, _, err := Apply(inv, files); err == nil {
		t.Fatal("modified installation was overwritten")
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
	if _, _, _, err := Apply(inv, files); err != nil {
		t.Fatal(err)
	}
	lock, err := installstate.Lock(dir)
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
