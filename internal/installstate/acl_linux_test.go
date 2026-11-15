//go:build linux

package installstate

import (
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckAncestorACLRejectsNamedUserAndGroupEntries(t *testing.T) {
	dir := t.TempDir()
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl[:4], 2)
	entries := []struct {
		tag  uint16
		perm uint16
		id   uint32
	}{
		{tag: 0x01, perm: 7, id: ^uint32(0)}, // ACL_USER_OBJ
		{tag: 0x02, perm: 7, id: 424242},     // ACL_USER
		{tag: 0x04, perm: 5, id: ^uint32(0)}, // ACL_GROUP_OBJ
		{tag: 0x10, perm: 7, id: ^uint32(0)}, // ACL_MASK
		{tag: 0x20, perm: 0, id: ^uint32(0)}, // ACL_OTHER
	}
	for i, entry := range entries {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(acl[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(acl[offset+2:offset+4], entry.perm)
		binary.LittleEndian.PutUint32(acl[offset+4:offset+8], entry.id)
	}
	if err := unix.Setxattr(dir, "system.posix_acl_access", acl, 0); err != nil {
		if err == unix.ENOTSUP || err == unix.EOPNOTSUPP || err == unix.EPERM {
			t.Skipf("filesystem does not allow POSIX ACL test setup: %v", err)
		}
		t.Fatal(err)
	}
	if err := checkAncestorACL(dir); err == nil {
		t.Fatal("ancestor ACL with a named user was accepted")
	}
}

func TestCheckAncestorACLAllowsCurrentUserEntry(t *testing.T) {
	dir := t.TempDir()
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl[:4], 2)
	entries := []struct {
		tag  uint16
		perm uint16
		id   uint32
	}{
		{tag: 0x01, perm: 7, id: ^uint32(0)}, // ACL_USER_OBJ
		{tag: 0x02, perm: 7, id: uint32(os.Geteuid())},
		{tag: 0x04, perm: 5, id: ^uint32(0)}, // ACL_GROUP_OBJ
		{tag: 0x10, perm: 7, id: ^uint32(0)}, // ACL_MASK
		{tag: 0x20, perm: 0, id: ^uint32(0)}, // ACL_OTHER
	}
	for i, entry := range entries {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(acl[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(acl[offset+2:offset+4], entry.perm)
		binary.LittleEndian.PutUint32(acl[offset+4:offset+8], entry.id)
	}
	if err := unix.Setxattr(dir, "system.posix_acl_access", acl, 0); err != nil {
		if err == unix.ENOTSUP || err == unix.EOPNOTSUPP || err == unix.EPERM {
			t.Skipf("filesystem does not allow POSIX ACL test setup: %v", err)
		}
		t.Fatal(err)
	}
	if err := checkAncestorACL(dir); err != nil {
		t.Fatalf("ACL entry for current user rejected: %v", err)
	}
}
