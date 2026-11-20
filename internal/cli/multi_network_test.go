package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

func TestDiscoverManagedConfigsWithoutServiceYAML(t *testing.T) {
	root := t.TempDir()
	layout := paths.Layout{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), RuntimeDir: filepath.Join(root, "runtime")}
	if err := os.MkdirAll(layout.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"network-a", "network-b"} {
		writeManagedConfigFixture(t, layout, id, 51820+i, []string{configAddress(i)})
	}
	configs, err := discoverManagedConfigs(layout)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 || configs[0].networkID != "network-a" || configs[1].networkID != "network-b" {
		t.Fatalf("discoverManagedConfigs() = %#v; want both sorted registered networks", configs)
	}
	if configs[0].path == configs[1].path || configs[0].path != filepath.Join(layout.ConfigDir, "network-a.yaml") {
		t.Fatalf("config paths = %q, %q; want per-network YAML paths", configs[0].path, configs[1].path)
	}
}

func TestNetworkProfilesHaveDistinctStateAndRuntime(t *testing.T) {
	base := paths.Layout{ConfigDir: "/config", StateDir: "/state", RuntimeDir: "/runtime"}
	a := networkLayout(base, "network-a")
	b := networkLayout(base, "network-b")
	if a.StateDir == b.StateDir || a.RuntimeDir == b.RuntimeDir || a.ConfigDir != b.ConfigDir {
		t.Fatalf("network layouts are not isolated: %#v %#v", a, b)
	}
}

func TestValidateNetworkConflictsRejectsDuplicatePortsAndRoutes(t *testing.T) {
	a := managedConfig{networkID: "network-a", config: config.Config{Network: config.Network{ID: "network-a", Name: "first"}, Interface: config.Interface{ListenPort: 51820}, Peers: []config.Peer{{AllowedIPs: []string{"10.80.0.2/32"}}}}}
	b := managedConfig{networkID: "network-b", config: config.Config{Network: config.Network{ID: "network-b", Name: "second"}, Interface: config.Interface{ListenPort: 51820}, Peers: []config.Peer{{AllowedIPs: []string{"10.80.0.3/32"}}}}}
	if err := validateNetworkConflicts([]managedConfig{a, b}); err == nil {
		t.Fatal("duplicate listen ports were accepted")
	}
	b.config.Interface.ListenPort++
	b.config.Peers[0].AllowedIPs = []string{"10.80.0.2/32"}
	if err := validateNetworkConflicts([]managedConfig{a, b}); err == nil {
		t.Fatal("overlapping peer routes were accepted")
	}
}

func TestAllocateListenPortPreservesExistingAndFindsNextFree(t *testing.T) {
	root := t.TempDir()
	layout := paths.Layout{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), RuntimeDir: filepath.Join(root, "runtime")}
	if err := os.MkdirAll(layout.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeManagedConfigFixture(t, layout, "network-a", 51820, []string{configAddress(0)})
	writeManagedConfigFixture(t, layout, "network-b", 51821, []string{configAddress(1)})
	port, err := allocateListenPort(layout.ConfigDir, layout.StateDir, "network-c")
	if err != nil || port != 51822 {
		t.Fatalf("allocateListenPort() = %d, %v; want 51822", port, err)
	}
	port, err = allocateListenPort(layout.ConfigDir, layout.StateDir, "network-a")
	if err != nil || port != 51820 {
		t.Fatalf("allocateListenPort() existing = %d, %v; want 51820", port, err)
	}
}

func TestStatusAndStopDefaultToEveryConfiguredNetwork(t *testing.T) {
	tempDir := os.TempDir()
	if runtime.GOOS != "windows" {
		tempDir = "/tmp"
	}
	root, err := os.MkdirTemp(tempDir, "pma-multi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	layout := paths.Layout{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), RuntimeDir: filepath.Join(root, "runtime")}
	if err := os.MkdirAll(layout.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	var stopped [2]atomic.Int32
	var closers []func() error
	for i, id := range []string{"network-a", "network-b"} {
		writeManagedConfigFixture(t, layout, id, 51820+i, []string{configAddress(i)})
		runtimeDir := networkLayout(layout, id).RuntimeDir
		index := i
		closeServer, err := local.Serve(context.Background(), runtimeDir, local.Operations{
			Snapshot: func(context.Context) (platform.Snapshot, error) {
				return platform.Snapshot{NetworkID: id, InterfaceName: "pm-" + id, Peers: []platform.PeerState{}}, nil
			},
			Stop: func() { stopped[index].Add(1) },
		})
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, closeServer)
	}
	t.Cleanup(func() {
		for _, closeServer := range closers {
			_ = closeServer()
		}
	})
	code, output, stderr := invoke(t, "status", "--config-dir", layout.ConfigDir, "--state-dir", layout.StateDir, "--runtime-dir", layout.RuntimeDir, "--json")
	var result networkSnapshots
	if code != 0 || stderr != "" || json.Unmarshal([]byte(output), &result) != nil || len(result.Networks) != 2 {
		t.Fatalf("all-network status = %d %q %q; want two snapshots", code, output, stderr)
	}
	code, output, stderr = invoke(t, "status", "--config-dir", layout.ConfigDir, "--state-dir", layout.StateDir, "--runtime-dir", layout.RuntimeDir, "--network", "network-b", "--json")
	var selected platform.Snapshot
	if code != 0 || stderr != "" || json.Unmarshal([]byte(output), &selected) != nil || selected.NetworkID != "network-b" {
		t.Fatalf("selected-network status = %d %q %q; want network-b snapshot", code, output, stderr)
	}
	code, output, stderr = invoke(t, "stop", "--config-dir", layout.ConfigDir, "--state-dir", layout.StateDir, "--runtime-dir", layout.RuntimeDir, "--network", "network-b")
	if code != 0 || stderr != "" || stopped[0].Load() != 0 || stopped[1].Load() != 1 {
		t.Fatalf("selected-network stop = %d %q %q; stopped callbacks = %d, %d", code, output, stderr, stopped[0].Load(), stopped[1].Load())
	}
	code, output, stderr = invoke(t, "stop", "--config-dir", layout.ConfigDir, "--state-dir", layout.StateDir, "--runtime-dir", layout.RuntimeDir)
	if code != 0 || stderr != "" || !strings.Contains(output, "Network count") || stopped[0].Load() != 1 || stopped[1].Load() != 2 {
		t.Fatalf("all-network stop = %d %q %q; stopped callbacks = %d, %d", code, output, stderr, stopped[0].Load(), stopped[1].Load())
	}
}

func writeManagedConfigFixture(t *testing.T, layout paths.Layout, id string, port int, addresses []string) {
	t.Helper()
	tokenDir := filepath.Join(layout.StateDir, "managed")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenDir, id+".token"), []byte("token"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: id, Name: id}, Interface: config.Interface{PrivateKeyFile: filepath.Join(layout.ConfigDir, id+".key"), Address: addresses, ListenPort: port}}
	data, err := config.MarshalYAML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.ConfigDir, id+".yaml"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func configAddress(index int) string {
	return []string{"10.80.0.1/32", "10.80.0.2/32"}[index%2]
}
