//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxServiceUnitPreservesLiteralPaths(t *testing.T) {
	data, err := linuxServiceUnit(`/opt/Peerimeter Agent/agent"$x%y\z`, Config{ConfigPath: `/var/lib/peerimeter/config with spaces.json`, StateDirectory: `/var/lib/peerimeter/$state%id`})
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	for _, part := range []string{`ExecStart="/opt/Peerimeter Agent/agent\"$$x%%y\\z" run --config "/var/lib/peerimeter/config with spaces.json" --state-dir "/var/lib/peerimeter/$$state%%id"`, "Restart=on-failure", "WantedBy=multi-user.target", "User=root", "KillSignal=SIGTERM", "UMask=0077"} {
		if !strings.Contains(unit, part) {
			t.Fatalf("missing safe systemd setting %q", part)
		}
	}
	if strings.Contains(unit, "/bin/sh") {
		t.Fatal("service used shell expansion")
	}
}
func TestLinuxServiceRejectsDirectiveInjection(t *testing.T) {
	for _, path := range []string{"relative", "/path\nExecStart=/bad", "/path\rBad=1", "/path\x00bad"} {
		if _, err := linuxServiceUnit(path, Config{ConfigPath: "/config.json", StateDirectory: "/state"}); err == nil {
			t.Fatal("accepted unsafe executable path")
		}
		if _, err := linuxServiceUnit("/agent", Config{ConfigPath: path, StateDirectory: "/state"}); err == nil {
			t.Fatal("accepted unsafe config path")
		}
	}
}
func TestLinuxServiceOwnershipAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peerimeter-agent.service")
	if err := os.WriteFile(path, []byte("[Service]\nExecStart=/unrelated\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readLinuxService(path); err == nil {
		t.Fatal("accepted unrelated service")
	}
	contents, err := linuxServiceUnit("/agent", Config{ConfigPath: "/config.json", StateDirectory: "/state"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLinuxService(path, contents); err != nil {
		t.Fatal(err)
	}
	if _, err := readLinuxService(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.service")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readLinuxService(link); err == nil {
		t.Fatal("accepted symlinked service path")
	}
}

func TestLinuxServiceOperatorIsExplicitAndSafelyQuoted(t *testing.T) {
	cfg := Config{ConfigPath: "/config.json", StateDirectory: "/state"}
	without, err := linuxServiceUnit("/agent", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(without), "--operator") {
		t.Fatal("service implicitly delegated operator access")
	}
	cfg.Operator = "nobody"
	with, err := linuxServiceUnit("/agent", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(with), `--operator "nobody"`) {
		t.Fatal("service did not persist explicit operator")
	}
	cfg.Operator = `operator"$x%y`
	quoted, err := linuxServiceUnit("/agent", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(quoted), `--operator "operator\"$$x%%y"`) {
		t.Fatal("operator was not safely quoted")
	}
	for _, bad := range []string{"nobody\nExecStart=/bad", "nobody\x00bad", " nobody"} {
		cfg.Operator = bad
		if _, err := linuxServiceUnit("/agent", cfg); err == nil {
			t.Fatal("accepted unsafe operator identity")
		}
	}
}
