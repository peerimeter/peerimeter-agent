//go:build linux || darwin

package local

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
)

func prepareDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create protected agent state directory")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private (chmod 700) and not a symbolic link")
	}
	var stat unix.Stat_t
	if unix.Stat(dir, &stat) != nil || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("state directory must belong to the current effective user")
	}
	return nil
}
func openLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open agent lock")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(fd)
		return nil, errors.New("another agent already owns this state directory")
	}
	return os.NewFile(uintptr(fd), "agent-lock"), nil
}
func listen(dir string) (net.Listener, error) {
	path := filepath.Join(dir, "control.sock")
	st, err := os.Lstat(path)
	if err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("control socket path is occupied by another resource")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("cannot create local control socket (check permissions/path length)")
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
func dial(ctx context.Context, dir string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", filepath.Join(dir, "control.sock"))
}
