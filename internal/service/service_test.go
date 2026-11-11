package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
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

func TestConcurrentInstallKeepsSnapshotsLockedThroughRegistration(t *testing.T) {
	dir := t.TempDir()
	key, _ := secret.Generate()
	keyPath := filepath.Join(dir, "key")
	if err := secret.WriteNew(keyPath, key); err != nil {
		t.Fatal(err)
	}
	other, _ := secret.Generate()
	pub, _ := secret.Public(other)
	desired := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "race-test", Name: "test"}, Interface: config.Interface{PrivateKeyFile: keyPath, Address: []string{"10.203.0.1/32"}, ListenPort: 51820}, Peers: []config.Peer{{PublicKey: base64.StdEncoding.EncodeToString(pub[:]), AllowedIPs: []string{"10.203.0.2/32"}, Endpoint: "127.0.0.1:51821"}}}
	data, _ := json.Marshal(desired)
	source := filepath.Join(dir, "source.json")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ConfigPath: source, StateDirectory: filepath.Join(dir, "state")}
	entered, finish := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	secure := func(...string) error { return nil }
	go func() { done <- install(cfg, func(Config) error { close(entered); <-finish; return nil }, secure) }()
	<-entered
	called := false
	err := install(cfg, func(Config) error { called = true; return errors.New("unexpected second registration") }, secure)
	close(finish)
	firstErr := <-done
	if err == nil || called {
		t.Fatal("concurrent installer reached registration while snapshots could be rolled back")
	}
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	for _, name := range []string{"service.json", "service.key"} {
		if _, err := os.Stat(filepath.Join(cfg.StateDirectory, name)); err != nil {
			t.Fatalf("successful registration lost %s: %v", name, err)
		}
	}
	if err := install(cfg, func(Config) error { return nil }, secure); err != nil {
		t.Fatal("state lock was not released after registration", err)
	}
}

func TestForeignConfigMarkerPreventsSnapshotAdoptionBeforeRegistration(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "installation-a-config")
	key, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(configDir, "service.key")
	if err := secret.WriteNew(keyPath, key); err != nil {
		t.Fatal(err)
	}
	peer, _ := secret.Generate()
	public, _ := secret.Public(peer)
	sourceConfig := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "shared-config", Name: "shared"}, Interface: config.Interface{PrivateKeyFile: keyPath, Address: []string{"10.203.0.1/32"}, ListenPort: 51820}, Peers: []config.Peer{{PublicKey: base64.StdEncoding.EncodeToString(public[:]), AllowedIPs: []string{"10.203.0.2/32"}, Endpoint: "127.0.0.1:51821"}}}
	data, _ := json.Marshal(sourceConfig)
	jsonPath := filepath.Join(configDir, "service.json")
	if err := os.WriteFile(jsonPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	// A source build cannot adopt any config marker from an installed agent.
	marker := filepath.Join(configDir, installstate.ConfigMarkerFilename)
	if err := os.WriteFile(marker, []byte(`{"version":1,"installation_id":"installation-a"}`), 0600); err != nil {
		t.Fatal(err)
	}
	beforeKey, _ := os.ReadFile(keyPath)
	beforeJSON, _ := os.ReadFile(jsonPath)
	beforeMarker, _ := os.ReadFile(marker)
	called := false
	err = install(Config{ConfigPath: jsonPath, ConfigDirectory: configDir, StateDirectory: filepath.Join(root, "installation-b-state"), RuntimeDirectory: filepath.Join(root, "installation-b-runtime")}, func(Config) error { called = true; return nil }, func(...string) error { t.Fatal("foreign configuration ACL or ownership changed"); return nil })
	if err == nil || called {
		t.Fatal("foreign marked config was adopted or registered")
	}
	for path, before := range map[string][]byte{keyPath: beforeKey, jsonPath: beforeJSON, marker: beforeMarker} {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatal("failed installation changed another installation's configuration")
		}
	}
}

func TestSnapshotFailureDoesNotDeleteAnotherConfigurationClaim(t *testing.T) {
	root := t.TempDir()
	key, _ := secret.Generate()
	sourceKey := filepath.Join(root, "operator.key")
	if err := secret.WriteNew(sourceKey, key); err != nil {
		t.Fatal(err)
	}
	peer, _ := secret.Generate()
	public, _ := secret.Public(peer)
	cfg := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "rollback-claim", Name: "rollback"}, Interface: config.Interface{PrivateKeyFile: sourceKey, Address: []string{"10.203.0.1/32"}, ListenPort: 51820}, Peers: []config.Peer{{PublicKey: base64.StdEncoding.EncodeToString(public[:]), AllowedIPs: []string{"10.203.0.2/32"}, Endpoint: "127.0.0.1:51821"}}}
	source := filepath.Join(root, "operator.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "config")
	failure := errors.New("secure snapshot failed")
	err := install(Config{ConfigPath: source, ConfigDirectory: target, StateDirectory: filepath.Join(root, "state"), RuntimeDirectory: filepath.Join(root, "runtime")}, func(Config) error { t.Fatal("failed provisioning reached registration"); return nil }, func(...string) error {
		// Simulate another operation winning the exclusive ownership marker after
		// validating the same complete snapshots, before this operation rolls back.
		if err := os.WriteFile(filepath.Join(target, installstate.ConfigMarkerFilename), []byte(`{"version":1,"installation_id":"other-winner"}`), 0600); err != nil {
			t.Fatal(err)
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("snapshot failure was lost: %v", err)
	}
	for _, name := range []string{"service.json", "service.key", installstate.ConfigMarkerFilename} {
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			t.Fatalf("rollback deleted foreign claimed %s", name)
		}
	}
	if _, err := secret.Load(sourceKey); err != nil {
		t.Fatal("operator original key was changed")
	}
}
