package installstate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Linux's POSIX ACL mask is reflected in group mode bits checked by checkTrust.
func checkExtendedTrust(string, bool, bool) error { return nil }

func checkAncestorACL(path string) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		size, err := unix.Getxattr(path, name, nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot inspect installation ancestor ACL: %w", err)
		}
		if size > 1<<16 {
			return errors.New("installation ancestor ACL is oversized")
		}
		data := make([]byte, size)
		read, err := unix.Getxattr(path, name, data)
		if err != nil {
			return fmt.Errorf("cannot inspect installation ancestor ACL: %w", err)
		}
		if read != size || len(data) < 4 || binary.LittleEndian.Uint32(data[:4]) != 2 || (len(data)-4)%8 != 0 {
			return errors.New("installation ancestor has an invalid POSIX ACL")
		}
		for offset := 4; offset < len(data); offset += 8 {
			tag := binary.LittleEndian.Uint16(data[offset : offset+2])
			id := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
			if !allowedAncestorACLEntry(tag, id) {
				return errors.New("installation ancestor has named ACL entries")
			}
		}
	}
	return nil
}

func allowedAncestorACLEntry(tag uint16, id uint32) bool {
	switch tag {
	case 0x02: // ACL_USER
		// An ACL entry for the installing user cannot grant access to another
		// principal, even when the runner's temporary directory has one.
		return id == uint32(os.Geteuid())
	case 0x08: // ACL_GROUP
		// Group ACL entries are safe only for a verified private primary group.
		return id == uint32(os.Getegid()) && hasPrivatePrimaryGroup(uint32(os.Geteuid()), id)
	case 0x01, 0x04, 0x10, 0x20: // ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER
		return true
	default:
		return false
	}
}
