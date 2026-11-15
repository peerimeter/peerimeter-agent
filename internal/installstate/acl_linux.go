package installstate

import (
	"encoding/binary"
	"errors"
	"fmt"

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
			if tag == 0x02 || tag == 0x08 { // ACL_USER or ACL_GROUP
				return errors.New("installation ancestor has named ACL entries")
			}
		}
	}
	return nil
}
