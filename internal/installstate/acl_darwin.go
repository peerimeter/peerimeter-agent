package installstate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

// Darwin ACL grants are independent of chmod mode bits. Query the same file
// descriptor using the Apple fstat64_extended/kauth_filesec ABI (Libc/sys/statx_np.c,
// xnu/bsd/sys/kauth.h). Deny-only and public read/search ACLs on parent directories
// are safe; write/security/ownership grants are rejected without guessing UUIDs.
func checkExtendedTrust(path string, private, directory bool) error {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return fmt.Errorf("cannot verify macOS installation extended permissions for %s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	var buf [4096]byte
	size := uint64(len(buf))
	_, _, e := syscall.Syscall6(syscall.SYS_FSTAT64_EXTENDED, uintptr(fd), uintptr(unsafe.Pointer(&st)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
	if e != 0 {
		return fmt.Errorf("cannot verify macOS installation extended permissions for %s: %w", path, e)
	}
	if size == 0 {
		return nil
	}
	if size < 44 || size > uint64(len(buf)) || binary.NativeEndian.Uint32(buf[0:4]) != 0x012cc16d {
		return errors.New("unrecognized macOS installation security metadata")
	}
	count := binary.NativeEndian.Uint32(buf[36:40])
	if count == ^uint32(0) {
		return nil
	}
	if count > 128 || 44+uint64(count)*24 > size {
		return errors.New("invalid macOS installation ACL size")
	}
	const writeRights = uint32(1<<2 | 1<<4 | 1<<5 | 1<<6 | 1<<8 | 1<<10 | 1<<12 | 1<<13 | 1<<25)
	for i := uint32(0); i < count; i++ {
		off := 44 + i*24
		kind := binary.NativeEndian.Uint32(buf[off+16:off+20]) & 0xf
		rights := binary.NativeEndian.Uint32(buf[off+20 : off+24])
		if kind == 2 {
			continue
		}
		if kind != 1 {
			return errors.New("unsupported macOS installation ACL entry")
		}
		if rights != 0 && (private || rights&writeRights != 0) {
			return errors.New("macOS installation resource has an extended access grant; remove it with chmod -N")
		}
	}
	return nil
}
