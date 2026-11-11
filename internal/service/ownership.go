package service

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
)

func equalServicePath(left, right string) bool {
	a, err := filepath.EvalSymlinks(left)
	if err != nil {
		a = filepath.Clean(left)
	}
	b, err := filepath.EvalSymlinks(right)
	if err != nil {
		b = filepath.Clean(right)
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
func verifyServiceArguments(args []string, executable string, cfg Config) error {
	if len(args) < 2 || !equalServicePath(args[0], executable) || args[1] != "run" {
		return errors.New("registered service executable belongs to another installation")
	}
	flags := map[string]string{}
	for i := 2; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return errors.New("registered service has invalid arguments")
		}
		key := args[i]
		switch key {
		case "--config", "--state-dir", "--runtime-dir", "--config-dir", "--operator":
		default:
			return errors.New("registered service has unexpected arguments")
		}
		if _, exists := flags[key]; exists {
			return errors.New("registered service has ambiguous arguments")
		}
		flags[key] = args[i+1]
	}
	expectedConfig := cfg.ConfigPath
	if expectedConfig == "" {
		expectedConfig = filepath.Join(snapshotDirectory(cfg), "service.json")
	}
	if !equalServicePath(flags["--config"], expectedConfig) || !equalServicePath(flags["--state-dir"], cfg.StateDirectory) {
		return errors.New("registered service configuration or state belongs to another installation")
	}
	if value, exists := flags["--runtime-dir"]; exists {
		if !equalServicePath(value, serviceRuntime(cfg)) {
			return errors.New("registered service runtime belongs to another installation")
		}
	} else if serviceRuntime(cfg) != cfg.StateDirectory {
		return errors.New("registered service uses a legacy runtime directory; explicit migration is required")
	}
	if value, exists := flags["--config-dir"]; exists && !equalServicePath(value, snapshotDirectory(cfg)) {
		return errors.New("registered service configuration directory belongs to another installation")
	}
	return nil
}
