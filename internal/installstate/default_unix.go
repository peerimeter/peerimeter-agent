//go:build linux || darwin

package installstate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func defaultInstallDataDir(_ string) (string, error) {
	if os.Geteuid() == 0 {
		if runtime.GOOS == "darwin" {
			return "/Library/Application Support/Peerimeter Installer/State", nil
		}
		return "/var/lib/peerimeter-agent-install", nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base != "" {
		if !filepath.IsAbs(base) {
			return "", errors.New("XDG_STATE_HOME must be absolute")
		}
		return filepath.Join(base, "peerimeter-agent"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return "", errors.New("cannot determine current user's home directory for installation state")
	}
	return filepath.Join(home, ".local", "state", "peerimeter-agent"), nil
}
