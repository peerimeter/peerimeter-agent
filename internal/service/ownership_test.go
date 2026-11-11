package service

import (
	"path/filepath"
	"testing"
)

func TestServiceRemovalRequiresMatchingInstallationAndLayout(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "agent")
	cfg := Config{ConfigDirectory: filepath.Join(root, "cfg"), StateDirectory: filepath.Join(root, "state"), RuntimeDirectory: filepath.Join(root, "runtime")}
	cfg.ConfigPath = filepath.Join(cfg.ConfigDirectory, "service.json")
	args := []string{exe, "run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", cfg.RuntimeDirectory, "--config-dir", cfg.ConfigDirectory, "--operator", "nobody"}
	if err := verifyServiceArguments(args, exe, cfg); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 3, 5, 7, 9} {
		changed := append([]string{}, args...)
		changed[index] = filepath.Join(root, "another-installation")
		if err := verifyServiceArguments(changed, exe, cfg); err == nil {
			t.Fatalf("foreign registration argument %d accepted", index)
		}
	}
	duplicated := append(append([]string{}, args...), "--state-dir", cfg.StateDirectory)
	if err := verifyServiceArguments(duplicated, exe, cfg); err == nil {
		t.Fatal("ambiguous state registration accepted")
	}
	legacy := cfg
	legacy.ConfigDirectory = cfg.StateDirectory
	legacy.ConfigPath = filepath.Join(cfg.StateDirectory, "service.json")
	legacy.RuntimeDirectory = cfg.StateDirectory
	legacyArgs := []string{exe, "run", "--config", legacy.ConfigPath, "--state-dir", legacy.StateDirectory}
	if err := verifyServiceArguments(legacyArgs, exe, legacy); err != nil {
		t.Fatal("legacy registration cannot be explicitly migrated", err)
	}
	legacy.RuntimeDirectory = cfg.RuntimeDirectory
	if err := verifyServiceArguments(legacyArgs, exe, legacy); err == nil {
		t.Fatal("legacy registration mistaken for separate runtime layout")
	}
}
