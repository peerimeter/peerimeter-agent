//go:build linux || darwin

package secret

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPOSIXPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	if err := WriteNew(path, mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("creation permissions are not 0600: %v", err)
	}
	for _, mode := range []os.FileMode{0644, 0640, 0604, 0620, 0601} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted insecure mode %o", mode)
		}
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("read-only private file must be accepted: %v", err)
	}
}

func TestPOSIXSymlinkAndFIFORefused(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "private.key")
	if err := WriteNew(key, mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink.key")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symbolic link accepted")
	}
	fifo := filepath.Join(dir, "fifo.key")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(fifo); err == nil {
		t.Fatal("FIFO accepted")
	}
}
