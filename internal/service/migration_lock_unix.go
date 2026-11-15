//go:build linux || darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

var errLegacyManagerBusy = errors.New("legacy agent is still using persistent state")

// acquireLegacyManagerLock is used only while migrating an existing combined
// service layout. Runtime agent ownership uses the current directory lock.
func acquireLegacyManagerLock(ctx context.Context, stateDir string) (*os.File, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		file, err := tryAcquireLegacyManagerLock(stateDir)
		if err == nil || !errors.Is(err, errLegacyManagerBusy) {
			return file, err
		}
		select {
		case <-bounded.Done():
			return nil, errors.Join(fmt.Errorf("legacy manager shutdown was not established; migration data was preserved: %w", err), bounded.Err())
		case <-ticker.C:
		}
	}
}

func tryAcquireLegacyManagerLock(stateDir string) (*os.File, error) {
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
			return nil, fmt.Errorf("%w; stop it before migrating", errLegacyManagerBusy)
		}
		return nil, fmt.Errorf("acquire legacy manager migration lock: %w", err)
	}
	return file, nil
}
