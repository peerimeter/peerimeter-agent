//go:build linux || darwin

package service

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func nativeRequireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("system service management requires root privileges")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	for path := exe; ; path = filepath.Dir(path) {
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Uid != 0 {
			return errors.New("system service executable and parent directories must be root-owned")
		}
		// A root-owned sticky temporary parent is safe when the private child itself
		// is root-owned; arbitrary writable installation directories are not.
		if st.Mode&0022 != 0 && !(st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&unix.S_ISVTX != 0) {
			return errors.New("system service executable path must not be writable by other users")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	return nil
}
