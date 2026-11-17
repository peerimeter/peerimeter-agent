// Package paths resolves the administrator-selected installation layout without
// creating or moving any files. Foreground --config remains a direct reference.
package paths

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

type Options struct{ ConfigDir, StateDir, RuntimeDir string }
type Layout struct{ ConfigDir, StateDir, RuntimeDir string }

func Resolve(options Options) (Layout, error) { return ResolveForOS(options, runtime.GOOS) }
func ResolveForOS(options Options, target string) (Layout, error) {
	var result Layout
	switch target {
	case "linux":
		result = unixDefaults("linux", "/etc/peerimeter", "/var/lib/peerimeter-agent", "/run/peerimeter-agent")
	case "darwin":
		result = unixDefaults("darwin", "/etc/peerimeter", "/Library/Application Support/Peerimeter", "/var/run/peerimeter-agent")
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		state := options.StateDir
		if state == "" {
			state = filepath.Join(base, "Peerimeter")
			if runtime.GOOS != "windows" {
				state = strings.TrimRight(base, `\/`) + `\Peerimeter`
			}
		}
		result = Layout{state, state, state}
	default:
		return Layout{}, errors.New("unsupported platform for agent directories")
	}
	if options.ConfigDir != "" {
		result.ConfigDir = options.ConfigDir
	}
	if options.StateDir != "" {
		result.StateDir = options.StateDir
	}
	if options.RuntimeDir != "" {
		result.RuntimeDir = options.RuntimeDir
	}
	for _, value := range []string{result.ConfigDir, result.StateDir, result.RuntimeDir} {
		// ResolveForOS tests Windows defaults on Unix without interpreting a drive as
		// a Unix relative path; native Resolve always uses filepath.IsAbs directly.
		absolute := filepath.IsAbs(value)
		if target != "windows" {
			absolute = strings.HasPrefix(value, "/")
		}
		if target == "windows" && len(value) >= 3 && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
			absolute = true
		}
		if !absolute || strings.ContainsAny(value, "\x00\r\n") {
			return Layout{}, errors.New("config, state and runtime directories must be absolute paths without control characters")
		}
	}
	clean := filepath.Clean
	if target != "windows" {
		clean = path.Clean
	}
	result.ConfigDir = clean(result.ConfigDir)
	result.StateDir = clean(result.StateDir)
	result.RuntimeDir = clean(result.RuntimeDir)
	if target != "windows" && (result.ConfigDir == result.StateDir || result.ConfigDir == result.RuntimeDir || result.StateDir == result.RuntimeDir) {
		return Layout{}, errors.New("Unix config, state and runtime directories must be distinct")
	}
	return result, nil
}

func unixDefaults(target, rootConfig, rootState, rootRuntime string) Layout {
	if runtime.GOOS != target || os.Geteuid() == 0 {
		return Layout{rootConfig, rootState, rootRuntime}
	}
	config := absoluteEnvironmentPath("XDG_CONFIG_HOME")
	state := absoluteEnvironmentPath("XDG_STATE_HOME")
	runtimeDir := absoluteEnvironmentPath("XDG_RUNTIME_DIR")
	var home string
	if config == "" || state == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil || home == "" || !filepath.IsAbs(home) {
			return Layout{rootConfig, rootState, rootRuntime}
		}
	}
	if config == "" {
		config = filepath.Join(home, ".config")
	}
	if state == "" {
		state = filepath.Join(home, ".local", "state")
	}
	if runtimeDir == "" {
		runtimeDir = filepath.Join(state, "peerimeter-agent", "run")
	} else {
		runtimeDir = filepath.Join(runtimeDir, "peerimeter-agent")
	}
	configDir := filepath.Join(config, "peerimeter-agent")
	stateDir := filepath.Join(state, "peerimeter-agent")
	if configDir == stateDir {
		configDir = filepath.Join(configDir, "config")
	}
	if runtimeDir == configDir || runtimeDir == stateDir {
		runtimeDir = filepath.Join(runtimeDir, "run")
	}
	return Layout{configDir, stateDir, runtimeDir}
}

func absoluteEnvironmentPath(name string) string {
	value := os.Getenv(name)
	if !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Clean(value)
}
