//go:build linux || darwin

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// acquireLegacyManagerLock is used only while migrating an existing combined
// service layout. Runtime agent ownership uses the current directory lock.
func acquireLegacyManagerLock(stateDir string) (*os.File, error) {
	path := filepath.Join(stateDir, "agent.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect legacy manager lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), "legacy-agent-lock")
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("legacy manager lock is not a regular private file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("legacy agent is still using persistent state; stop it before migrating")
		}
		return nil, fmt.Errorf("acquire legacy manager migration lock: %w", err)
	}
	return file, nil
}
