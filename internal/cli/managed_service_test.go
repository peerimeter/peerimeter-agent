package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

func TestSyncConfigPathMatchesRunningAgent(t *testing.T) {
	runtimePath := filepath.Join(t.TempDir(), "active.yaml")
	if err := os.WriteFile(runtimePath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	runtimePath, err = filepath.EvalSymlinks(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := syncConfigPath("", runtimePath)
	if err != nil || got != runtimePath {
		t.Fatalf("syncConfigPath() = %q, %v; want %q", got, err, runtimePath)
	}
	got, err = syncConfigPath(runtimePath, runtimePath)
	if err != nil || got != runtimePath {
		t.Fatalf("syncConfigPath(explicit active path) = %q, %v", got, err)
	}
	otherPath := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(otherPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := syncConfigPath(otherPath, runtimePath); err == nil {
		t.Fatal("syncConfigPath accepted a file other than the running agent's configuration")
	}
	if _, err := syncConfigPath("", ""); err == nil {
		t.Fatal("syncConfigPath accepted an unknown running configuration path")
	}
}

func TestWriteConfigFileUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pulled.yaml")
	if err := writeConfigFile(path, []byte("version: 1\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigFile(path, []byte("version: 1\nname: updated\n")); err != nil {
		t.Fatalf("replace existing config: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "version: 1\nname: updated\n" {
		t.Fatalf("pulled file = %q, %v", data, err)
	}
	if mode := mustStat(t, path).Mode().Perm(); runtime.GOOS != "windows" && mode != 0600 {
		t.Fatalf("file permissions = %04o, want 0600", mode)
	}
	if _, err := secret.ReadProtectedText(path, 1<<20); err != nil {
		t.Fatalf("pulled file failed protected ACL/permission validation: %v", err)
	}
}

func TestPrivateConfigTempFileIsProtectedBeforeWrite(t *testing.T) {
	f, path, err := createPrivateConfigTempFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	defer f.Close()
	if err := secret.VerifyProtectedFile(f); err != nil {
		t.Fatalf("temporary file is not private before writing: %v", err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
