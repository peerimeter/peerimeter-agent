//go:build windows

package uninstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallIgnoresUntrackedLegacyPmaExe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pma.exe")
	if err := os.WriteFile(path, []byte("untracked legacy executable"), 0600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := Execute(context.Background(), Options{InstallDir: dir}, &output); err != nil {
		t.Fatalf("uninstall considered an unsupported legacy executable: %v", err)
	}
	if contents, err := os.ReadFile(path); err != nil || string(contents) != "untracked legacy executable" {
		t.Fatalf("untracked legacy executable changed: %q %v", contents, err)
	}
}
