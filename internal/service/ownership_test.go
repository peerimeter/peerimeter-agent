package service

import (
	"path/filepath"
	"testing"
)

func TestServiceRemovalRequiresMatchingInstallationAndLayout(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "agent")
	cfg := Config{ConfigDirectory: filepath.Join(root, "cfg"), StateDirectory: filepath.Join(root, "state"), RuntimeDirectory: filepath.Join(root, "runtime")}
	cfg.ConfigPath = filepath.Join(cfg.ConfigDirectory, "service.yaml")
	for _, command := range []string{"run", "daemon"} {
		args := []string{exe, command, "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", cfg.RuntimeDirectory, "--config-dir", cfg.ConfigDirectory, "--operator", "nobody"}
		if err := verifyServiceArguments(args, exe, cfg); err != nil {
			t.Fatalf("%s registration rejected: %v", command, err)
		}
	}
	args := []string{exe, "run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", cfg.RuntimeDirectory, "--config-dir", cfg.ConfigDirectory, "--operator", "nobody"}
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
	withoutRuntime := []string{exe, "run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--config-dir", cfg.ConfigDirectory}
	if err := verifyServiceArguments(withoutRuntime, exe, cfg); err == nil {
		t.Fatal("registration without runtime directory accepted")
	}
	withoutConfig := []string{exe, "run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", cfg.RuntimeDirectory}
	if err := verifyServiceArguments(withoutConfig, exe, cfg); err == nil {
		t.Fatal("registration without configuration directory accepted")
	}
}
