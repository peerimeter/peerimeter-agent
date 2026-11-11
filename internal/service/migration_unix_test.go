//go:build linux || darwin

package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

func migrationFixture(t *testing.T) (Config, [32]byte, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	originalKey, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sourceKey := filepath.Join(root, "operator.key")
	if err := secret.WriteNew(sourceKey, originalKey); err != nil {
		t.Fatal(err)
	}
	other, _ := secret.Generate()
	public, _ := secret.Public(other)
	cfg := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "migration-network", Name: "migration"}, Interface: config.Interface{PrivateKeyFile: sourceKey, Address: []string{"10.203.0.1/32"}, ListenPort: 51820}, Peers: []config.Peer{{PublicKey: base64.StdEncoding.EncodeToString(public[:]), AllowedIPs: []string{"10.203.0.2/32"}, Endpoint: "127.0.0.1:51821"}}}
	data, _ := json.Marshal(cfg)
	source := filepath.Join(root, "operator.json")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(root, "old combined state")
	if err := install(Config{ConfigPath: source, ConfigDirectory: legacy, StateDirectory: legacy, RuntimeDirectory: legacy}, func(Config) error { return nil }, func(...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	preserved := map[string][]byte{"network.json": []byte(`{"network_id":"migration-network","interface_name":"wg-persisted"}`), "ownership": []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")}
	for name, data := range preserved {
		if err := os.WriteFile(filepath.Join(legacy, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(legacy, "agent.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	return Config{ConfigDirectory: filepath.Join(root, "new config with spaces"), StateDirectory: legacy, RuntimeDirectory: filepath.Join(root, "new runtime with spaces")}, originalKey, preserved
}
func TestUnixMigrationPreservesKeyAndDurableIdentity(t *testing.T) {
	cfg, key, preserved := migrationFixture(t)
	unregistered, registered := false, false
	unregister := func(old Config) error {
		unregistered = true
		if old.ConfigPath != filepath.Join(cfg.StateDirectory, "service.json") || old.RuntimeDirectory != cfg.StateDirectory {
			t.Fatal("incorrect legacy registration identity")
		}
		return nil
	}
	register := func(next Config) error {
		registered = true
		if !unregistered {
			t.Fatal("old registration still active")
		}
		if filepath.Dir(next.ConfigPath) != cfg.ConfigDirectory {
			t.Fatal("snapshots stayed in state directory")
		}
		loaded, err := config.Load(next.ConfigPath)
		if err != nil {
			return err
		}
		newKey, err := secret.Load(loaded.Interface.PrivateKeyFile)
		if err != nil {
			return err
		}
		if newKey != key {
			t.Fatal("migration rotated identity key")
		}
		return nil
	}
	if err := migrate(cfg, unregister, register, func(...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !registered {
		t.Fatal("new service not registered")
	}
	for name, before := range preserved {
		after, err := os.ReadFile(filepath.Join(cfg.StateDirectory, name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("durable %s changed", name)
		}
	}
	for _, name := range []string{"service.json", "service.key", "agent.lock"} {
		if _, err := os.Lstat(filepath.Join(cfg.StateDirectory, name)); !os.IsNotExist(err) {
			t.Fatalf("legacy %s not removed", name)
		}
	}
	for _, name := range []string{"operator.json", "operator.key"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(cfg.StateDirectory), name)); err != nil {
			t.Fatal("operator original was moved or removed")
		}
	}
}
func TestUnixMigrationConflictsPreserveWorkingLegacyRegistration(t *testing.T) {
	cfg, key, _ := migrationFixture(t)
	if err := os.Mkdir(cfg.ConfigDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cfg.ConfigDirectory, "service.key")
	if err := os.WriteFile(target, []byte("unrelated target"), 0600); err != nil {
		t.Fatal(err)
	}
	touched := false
	err := migrate(cfg, func(Config) error { touched = true; return nil }, func(Config) error { touched = true; return nil }, func(...string) error { return nil })
	if err == nil || touched {
		t.Fatal("migration stopped working service before rejecting a destination conflict")
	}
	after, _ := os.ReadFile(target)
	if string(after) != "unrelated target" {
		t.Fatal("destination overwritten")
	}
	legacy, err := secret.Load(filepath.Join(cfg.StateDirectory, "service.key"))
	if err != nil || legacy != key {
		t.Fatal("conflicting migration changed legacy key")
	}
}
func TestUnixMigrationRegistrationFailureRetainsRecoverableLegacy(t *testing.T) {
	cfg, key, _ := migrationFixture(t)
	failure := errors.New("new registration failed")
	err := migrate(cfg, func(Config) error { return nil }, func(Config) error { return failure }, func(...string) error { return nil })
	if !errors.Is(err, failure) {
		t.Fatalf("wrong registration failure: %v", err)
	}
	oldKey, err := secret.Load(filepath.Join(cfg.StateDirectory, "service.key"))
	if err != nil || oldKey != key {
		t.Fatal("failed registration removed legacy credentials")
	}
	for _, name := range []string{"service.json", "service.key"} {
		if _, err := os.Stat(filepath.Join(cfg.ConfigDirectory, name)); !os.IsNotExist(err) {
			t.Fatal("failed registration left conflicting new snapshots")
		}
	}
}
