package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultLayouts(t *testing.T) {
	for os, want := range map[string]Layout{"linux": {"/etc/peerimeter", "/var/lib/peerimeter-agent", "/run/peerimeter-agent"}, "darwin": {"/etc/peerimeter", "/Library/Application Support/Peerimeter", "/var/run/peerimeter-agent"}} {
		got, err := ResolveForOS(Options{}, os)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v", os, got, err)
		}
	}
}
func TestCustomLayoutAndWindowsCombinedCompatibility(t *testing.T) {
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
