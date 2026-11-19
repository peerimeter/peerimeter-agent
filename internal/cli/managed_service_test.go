package cli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

func TestManagedServiceMigrationIsSavedOnlyWhenRequested(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "managed")
	if err := os.MkdirAll(managedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(managedDir, "mesh.token")
	if err := writeConfigFile(tokenPath, []byte("secret-key\n")); err != nil {
		t.Fatal(err)
	}

	metadataPath := filepath.Join(managedDir, "mesh.yaml")
	_, saveMigration, err := managedServiceClient(serviceConfigOptions{
		networkID: "mesh", nodeID: "node-1", apiURL: "http://localhost:8080",
	}, paths.Layout{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(metadataPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("migration metadata exists before API success: stat error = %v", err)
	}
	if err := saveMigration(); err != nil {
		t.Fatal(err)
	}
	metadata, err := readManagedNetworkMetadata(stateDir, "mesh")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.APIURL != "http://localhost:8080" || metadata.NodeID != "node-1" {
		t.Fatalf("saved migration metadata = %+v", metadata)
	}
}

func TestManagedNetworkMetadataMigratesLegacyJSONToYAML(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "managed")
	if err := os.MkdirAll(managedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(managedDir, "home-test.json")
	legacy := `{"version":1,"api_url":"https://api.example","network_id":"home-test","node_id":"node-1"}` + "\n"
	if err := writeConfigFile(legacyPath, []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	metadata, err := readManagedNetworkMetadata(stateDir, "home-test")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.NetworkID != "home-test" || metadata.NodeID != "node-1" {
		t.Fatalf("migrated metadata = %+v", metadata)
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy JSON metadata remains: %v", err)
	}
	yamlPath := filepath.Join(managedDir, "home-test.yaml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "version: 1\n") || strings.Contains(string(data), "{") {
		t.Fatalf("metadata was not saved as YAML: %s", data)
	}
}

func TestShouldFallbackToLocalSync(t *testing.T) {
	for _, tc := range []struct {
		name        string
		metadata    managedNetworkMetadata
		metadataErr error
		nodeID      string
		apiURL      string
		want        bool
	}{
		{name: "missing metadata uses local reload", metadataErr: errors.New("missing"), want: true},
		{name: "empty saved node uses local reload", metadata: managedNetworkMetadata{}, want: true},
		{name: "explicit node completes metadata", metadata: managedNetworkMetadata{}, nodeID: "node-1"},
		{name: "API URL opts into migration", metadataErr: errors.New("missing"), nodeID: "node-1", apiURL: "http://localhost:8080"},
		{name: "complete metadata uses service", metadata: managedNetworkMetadata{NodeID: "node-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFallbackToLocalSync(tc.metadata, tc.metadataErr, tc.nodeID, tc.apiURL); got != tc.want {
				t.Fatalf("shouldFallbackToLocalSync() = %t, want %t", got, tc.want)
			}
		})
	}
}

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
