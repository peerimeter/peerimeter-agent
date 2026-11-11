package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallFailureRetryAndPreservedReinstall(t *testing.T) {
	dir := t.TempDir()
	key, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "original.key")
	if err := secret.WriteNew(keyPath, key); err != nil {
		t.Fatal(err)
	}
	peerKey, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := secret.Public(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	desired := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "service-test", Name: "test"}, Interface: config.Interface{PrivateKeyFile: keyPath, Address: []string{"10.203.0.1/32"}, ListenPort: 51820}, Peers: []config.Peer{{PublicKey: base64.StdEncoding.EncodeToString(pub[:]), AllowedIPs: []string{"10.203.0.2/32"}, Endpoint: "127.0.0.1:51821"}}}
	data, _ := json.Marshal(desired)
	source := filepath.Join(dir, "original.json")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ConfigPath: source, StateDirectory: filepath.Join(dir, "state")}
	// Native ACL hardening is covered by actual platform integration; this fake
	// keeps the registration-transaction test runnable without administrator rights.
	secure := func(...string) error { return nil }
	failure := errors.New("registration failed")
	if err := install(cfg, func(Config) error { return failure }, secure); !errors.Is(err, failure) {
		t.Fatalf("wrong failure: %v", err)
	}
	for _, name := range []string{"service.json", "service.key"} {
		if _, err := os.Lstat(filepath.Join(cfg.StateDirectory, name)); !os.IsNotExist(err) {
			t.Fatal("failed registration left installed secrets")
		}
	}
	register := func(installed Config) error {
		if installed.ConfigPath == source {
			t.Fatal("service uses unprotected source")
		}
		loaded, err := config.Load(installed.ConfigPath)
		if err != nil {
			return err
		}
		copied, err := secret.Load(loaded.Interface.PrivateKeyFile)
		if err != nil {
			return err
		}
		if copied != key {
			t.Fatal("wrong copied key")
		}
		return nil
	}
	if err := install(cfg, register, secure); err != nil {
		t.Fatal(err)
	}
	originalSnapshot, err := os.ReadFile(filepath.Join(cfg.StateDirectory, "service.key"))
	if err != nil {
		t.Fatal(err)
	}
	// Successful uninstall intentionally keeps both snapshots; registering again
	// against identical protected desired state must succeed without rewriting keys.
	if err := install(cfg, register, secure); err != nil {
		t.Fatalf("reinstall failed: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(cfg.StateDirectory, "service.key"))
	if string(after) != string(originalSnapshot) {
		t.Fatal("reinstall replaced private key")
	}
	desired.Interface.ListenPort++
	data, _ = json.Marshal(desired)
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := install(cfg, register, secure); err == nil {
		t.Fatal("different configuration silently replaced snapshots")
	}
	after, _ = os.ReadFile(filepath.Join(cfg.StateDirectory, "service.key"))
	if string(after) != string(originalSnapshot) {
		t.Fatal("rejected reinstall altered keys")
	}
}
