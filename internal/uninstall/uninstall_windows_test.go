//go:build windows

package uninstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallPreservesUntrackedLegacyPmaExe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pma.exe")
	if err := os.WriteFile(path, []byte("untracked legacy executable"), 0600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	err := Execute(context.Background(), Options{InstallDir: dir}, &output)
	if err == nil || !strings.Contains(err.Error(), "existing files are untracked and were preserved") {
		t.Fatalf("untracked legacy executable was not reported as preserved: %v", err)
	}
	if contents, err := os.ReadFile(path); err != nil || string(contents) != "untracked legacy executable" {
		t.Fatalf("untracked legacy executable changed: %q %v", contents, err)
	}
}
