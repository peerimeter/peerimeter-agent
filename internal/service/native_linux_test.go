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

func TestLinuxInstallNeverReplacesAnotherPeerimeterUnit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peerimeter-agent.service")
	a, err := linuxServiceUnit("/opt/install-a/peerimeter-agent", Config{ConfigPath: "/etc/install-a/service.json", ConfigDirectory: "/etc/install-a", StateDirectory: "/var/lib/install-a", RuntimeDirectory: "/run/install-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := linuxServiceUnit("/opt/install-b/peerimeter-agent", Config{ConfigPath: "/etc/install-b/service.json", ConfigDirectory: "/etc/install-b", StateDirectory: "/var/lib/install-b", RuntimeDirectory: "/run/install-b"})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists, err := installLinuxService(path, a); err != nil || exists {
		t.Fatalf("initial installation failed: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installLinuxService(path, b); err == nil {
		t.Fatal("installation B replaced installation A's owned service")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(a) {
		t.Fatal("rejected registration changed the active service unit")
	}
	if _, exists, err := installLinuxService(path, a); err != nil || !exists {
		t.Fatalf("identical registration cannot be reused: %v", err)
	}
	identical, err := os.Stat(path)
	if err != nil || !os.SameFile(before, identical) {
		t.Fatal("identical installation needlessly rewrote the service unit")
	}
}

func TestLinuxReadOnlyRegistrationMatchesExactExecutable(t *testing.T) {
	executable := `/opt/Peerimeter Agent/bin/peerimeter-agent$literal%name`
	unit, err := linuxServiceUnit(executable, Config{ConfigPath: "/etc/peerimeter/service.json", StateDirectory: "/var/lib/peerimeter-agent", RuntimeDirectory: "/run/peerimeter-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if owned, err := linuxRegistrationUsesExecutable(unit, executable); err != nil || !owned {
		t.Fatalf("own pre-inventory registration was not found: %v", err)
	}
	if owned, err := linuxRegistrationUsesExecutable(unit, executable+"-other"); err != nil || owned {
		t.Fatal("foreign executable matched service ownership")
	}
	if owned, err := linuxRegistrationUsesExecutable([]byte("ExecStart=\"unterminated\n"), executable); err == nil || owned {
		t.Fatal("ambiguous executable inspection did not fail closed")
	}
}

func TestLinuxReadOnlyProbeRejectsUnsupportedUnquotedEscapes(t *testing.T) {
	for _, command := range []string{`/opt/Peerimeter\x20Agent/peerimeter-agent run`, `/opt/%n/peerimeter-agent run`, `/opt/$INSTALL/peerimeter-agent run`} {
		if owned, err := linuxRegistrationUsesExecutable([]byte("ExecStart="+command+"\n"), "/opt/Peerimeter Agent/peerimeter-agent"); err == nil || owned {
			t.Fatal("ambiguous unquoted executable was classified as safely foreign")
		}
	}
}
