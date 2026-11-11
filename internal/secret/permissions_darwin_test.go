package secret

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDarwinExtendedACLRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	if err := WriteNew(path, mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	// macOS NFSv4-style ACLs can grant Everyone read independently of the
	// POSIX group mask; chmod 600 alone must never establish key privacy.
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read", path).CombinedOutput(); err != nil {
		t.Fatalf("set test ACL: %v: %s", err, out)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted private key with extended ACL read grant")
	}
	if out, err := exec.Command("/bin/chmod", "-N", path).CombinedOutput(); err != nil {
		t.Fatalf("remove test ACL: %v: %s", err, out)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("ACL removal should restore access: %v", err)
	}
}

func TestDarwinInheritedACLRefusesCreation(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read,file_inherit,directory_inherit", dir).CombinedOutput(); err != nil {
		t.Fatalf("set inherited test ACL: %v: %s", err, out)
	}
	path := filepath.Join(dir, "private.key")
	if err := WriteNew(path, mustGenerate(t)); err == nil {
		t.Fatal("wrote a key into a directory granting inherited read access")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed key creation left a file behind")
	}
}
