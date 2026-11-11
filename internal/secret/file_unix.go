//go:build linux || darwin

package secret

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openProtected(path string) (*os.File, error) {
	// O_NONBLOCK avoids hanging on a FIFO before its type can be checked.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open private key: unavailable or symbolic link")
	}
	f := os.NewFile(uintptr(fd), "private-key")
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, errors.New("inspect private key: metadata unavailable")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("private key: require a regular file without hard links")
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		f.Close()
		return nil, errors.New("private key: require current-user ownership and no group or other permissions (chmod 600)")
	}
	if err := checkExtendedPermissions(fd); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func createProtected(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("create private key: destination exists or is unavailable")
	}
	f := os.NewFile(uintptr(fd), "private-key")
	// A newly created macOS file may inherit an ACL independent of mode 0600.
	// Reject it before writing any key material.
	if err := checkExtendedPermissions(fd); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return f, nil
}
