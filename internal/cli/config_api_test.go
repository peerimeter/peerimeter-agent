package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateConfigSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts serviceConfigOptions
		ok   bool
	}{
		{name: "network", opts: serviceConfigOptions{kind: "network", networkID: "mesh", file: "network.json"}, ok: true},
		{name: "node", opts: serviceConfigOptions{kind: "node", networkID: "mesh", nodeID: "node-1", file: "node.json"}, ok: true},
		{name: "unknown kind", opts: serviceConfigOptions{kind: "other", networkID: "mesh", file: "config.json"}},
		{name: "missing network", opts: serviceConfigOptions{kind: "network", file: "config.json"}},
		{name: "node requires node ID", opts: serviceConfigOptions{kind: "node", networkID: "mesh", file: "config.json"}},
		{name: "network rejects node ID", opts: serviceConfigOptions{kind: "network", networkID: "mesh", nodeID: "node-1", file: "config.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfigSelection(tc.opts)
			if (err == nil) != tc.ok {
				t.Fatalf("validateConfigSelection() error = %v", err)
			}
		})
	}
}

func TestWriteConfigFileUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pulled.json")
	if err := writeConfigFile(path, []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigFile(path, []byte(`{"version":1,"name":"updated"}`)); err != nil {
		t.Fatalf("replace existing config: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"version":1,"name":"updated"}` {
		t.Fatalf("pulled file = %q, %v", data, err)
	}
	if mode := mustStat(t, path).Mode().Perm(); runtime.GOOS != "windows" && mode != 0600 {
		t.Fatalf("file permissions = %04o, want 0600", mode)
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
