package secret

import (
	"encoding/binary"
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// checkExtendedPermissions fails closed on macOS extended ACLs: unlike Linux
// POSIX ACLs, these can grant read access independently of the mode's group mask.
//
// Apple Libc's acl_get_fd calls fstat64_extended to read kauth_filesec from the
// open descriptor. x/sys does not expose this operation, so use the same Darwin
// syscall. Primary ABI sources:
// https://github.com/apple-oss-distributions/Libc/blob/main/sys/statx_np.c
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kauth.h
// The 44-byte
// kauth_filesec header has magic at byte 0 and ACL entry count at byte 36; any
// nonempty ACL necessarily needs more than the header and is rejected without
// parsing its identities or permissions. An unavailable security query is never
// treated as proof that the file has no ACL.
func checkExtendedPermissions(fd int) error {
	var st unix.Stat_t
	var security [44]byte
	size := uint64(len(security))
	_, _, errno := syscall.Syscall6(syscall.SYS_FSTAT64_EXTENDED,
		uintptr(fd), uintptr(unsafe.Pointer(&st)), uintptr(unsafe.Pointer(&security[0])),
		uintptr(unsafe.Pointer(&size)), 0, 0)
	runtime.KeepAlive(&st)
	runtime.KeepAlive(&security)
	if errno != 0 {
		return errors.New("private key: macOS extended permissions cannot be verified")
	}
	if size == 0 {
		return nil
	}
	if size > uint64(len(security)) {
		return errors.New("private key: remove macOS extended ACLs (chmod -N)")
	}
	if size != uint64(len(security)) || binary.NativeEndian.Uint32(security[0:4]) != 0x012cc16d {
		return errors.New("private key: unrecognized macOS security metadata")
	}
	count := binary.NativeEndian.Uint32(security[36:40])
	if count != 0 && count != ^uint32(0) {
		return errors.New("private key: remove macOS extended ACLs (chmod -N)")
	}
	return nil
}
