package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultLayouts(t *testing.T) {
	for target, want := range map[string]Layout{"linux": {"/etc/peerimeter", "/var/lib/peerimeter-agent", "/run/peerimeter-agent"}, "darwin": {"/etc/peerimeter", "/Library/Application Support/Peerimeter", "/var/run/peerimeter-agent"}} {
		if target == runtime.GOOS && os.Geteuid() != 0 {
			home, err := os.UserHomeDir()
			config := os.Getenv("XDG_CONFIG_HOME")
			if !filepath.IsAbs(config) && err == nil && home != "" {
				config = filepath.Join(home, ".config")
			}
			state := os.Getenv("XDG_STATE_HOME")
			if !filepath.IsAbs(state) && err == nil && home != "" {
				state = filepath.Join(home, ".local", "state")
			}
			if filepath.IsAbs(config) && filepath.IsAbs(state) {
				runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
				if filepath.IsAbs(runtimeDir) {
					runtimeDir = filepath.Join(runtimeDir, "peerimeter-agent")
				} else {
					runtimeDir = filepath.Join(state, "peerimeter-agent", "run")
				}
				configDir := filepath.Join(config, "peerimeter-agent")
				stateDir := filepath.Join(state, "peerimeter-agent")
				if configDir == stateDir {
					configDir = filepath.Join(configDir, "config")
				}
				want = Layout{configDir, stateDir, runtimeDir}
			}
		}
		got, err := ResolveForOS(Options{}, target)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v", target, got, err)
		}
	}
}
func TestCustomLayoutAndWindowsCombinedLayout(t *testing.T) {
	root := t.TempDir()
	opts := Options{filepath.Join(root, "config space"), filepath.Join(root, "state space"), filepath.Join(root, "runtime space")}
	layout, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if layout.ConfigDir != opts.ConfigDir || layout.StateDir != opts.StateDir || layout.RuntimeDir != opts.RuntimeDir {
		t.Fatal("custom layout changed")
	}
	windows, err := ResolveForOS(Options{StateDir: opts.StateDir}, "windows")
	if err != nil || windows.ConfigDir != opts.StateDir || windows.RuntimeDir != opts.StateDir {
		t.Fatal("Windows custom combined layout changed")
	}
	if runtime.GOOS != "windows" {
		if _, err := Resolve(Options{ConfigDir: opts.StateDir, StateDir: opts.StateDir, RuntimeDir: opts.RuntimeDir}); err == nil {
			t.Fatal("combined Unix layout accepted")
		}
	}
	if _, err := Resolve(Options{ConfigDir: "relative"}); err == nil {
		t.Fatal("relative directory accepted")
	}
}
