//go:build linux || darwin

package installstate

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
)

var runTrustedUID atomic.Int64

// TrustSudoUserForRun allows only a root run process to use resources owned by
// the invoking sudo user. Other commands never enable this exception.
func TrustSudoUserForRun() {
	if os.Geteuid() != 0 {
		return
	}
	uid, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err == nil && uid > 0 {
		runTrustedUID.Store(int64(uid) + 1)
	}
}

func trustedRunOwner(uid uint32) bool {
	allowed := runTrustedUID.Load()
	return allowed > 0 && uint32(allowed-1) == uid
}

func preserveRunOwner(file *os.File, existing os.FileInfo) error {
	if existing == nil || os.Geteuid() != 0 {
		return nil
	}
	st, ok := existing.Sys().(*syscall.Stat_t)
	if !ok || !trustedRunOwner(st.Uid) {
		return nil
	}
	if err := file.Chown(int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	return file.Chmod(0600)
}

func isReparse(os.FileInfo) bool { return false }
func trustedSystemAlias(path string, info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return runtime.GOOS == "darwin" && ok && st.Uid == 0 && (path == "/etc" || path == "/var" || path == "/tmp")
}
func checkTrust(path string, info os.FileInfo, directory bool) error {
	return checkTrustWithPolicy(path, info, directory, false)
}
func checkTrustWithPolicy(path string, info os.FileInfo, directory, allowInsecureDirectory bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify installation resource ownership")
	}
	uid := uint32(os.Geteuid())
	if st.Uid != uid && st.Uid != 0 && !(uid == 0 && trustedRunOwner(st.Uid)) {
		return errors.New("installation resource is owned by another user")
	}
	if uid == 0 && st.Uid != 0 && !trustedRunOwner(st.Uid) {
		return errors.New("privileged removal requires root-owned installation resources")
	}
	if !directory && st.Nlink != 1 {
		return errors.New("installation files must not have hard links")
	}
	sticky := directory && st.Uid == 0 && info.Mode()&os.ModeSticky != 0
	if info.Mode().Perm()&0022 != 0 && !sticky && !(directory && allowInsecureDirectory) {
		return errors.New("installation resource grants group or other write access")
	}
	return checkExtendedTrust(path, false, directory)
}
func checkPrivate(path string, info os.FileInfo) error {
	if err := checkTrust(path, info, false); err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("installation inventory/profile must have private permissions")
	}
	return checkExtendedTrust(path, true, false)
}
func protect(path string) error {
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	return checkExtendedTrust(path, true, false)
}

func protectCreatedTemp(path string) error {
	return checkExtendedTrust(path, true, false)
}
func lockInventory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "installation-lock")
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("installation lock is not regular")
	}
	if err := checkPrivate(path, info); err != nil {
		f.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another installation inventory operation is running")
	}
	return f, nil
}
