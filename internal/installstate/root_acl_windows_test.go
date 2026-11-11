package installstate

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestStandardProgramDataRootAccess(t *testing.T) {
	root := `C:\ProgramData`
	t.Setenv("ProgramData", root)
	// Exact native Windows Server 2022 descriptor: the last Users ACE is 0x116,
	// not DELETE_CHILD. Inherit-only CreatorOwner applies to new children only.
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var inherit, users *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &inherit); err != nil {
		t.Fatal(err)
	}
	if inherit.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
		t.Fatal("CreatorOwner must remain inherit-only")
	}
	if err := windows.GetAce(acl, 4, &users); err != nil {
		t.Fatal(err)
	}
	if uint32(users.Mask) != 0x116 {
		t.Fatalf("unexpected ProgramData Users mask: %#x", users.Mask)
	}
	if !allowedUntrustedAccess(uint32(users.Mask), root, true, false) {
		t.Fatal("standard ProgramData root self-access was refused")
	}
	if allowedUntrustedAccess(uint32(users.Mask), root+`\Peerimeter`, true, false) {
		t.Fatal("root exception applied to ordinary child")
	}
	if allowedUntrustedAccess(uint32(users.Mask), root, true, true) {
		t.Fatal("root exception applied to private data")
	}
	for _, dangerous := range []uint32{0x40 /* FILE_DELETE_CHILD */, windows.DELETE, windows.WRITE_DAC, windows.WRITE_OWNER, windows.GENERIC_WRITE, windows.GENERIC_ALL} {
		if allowedUntrustedAccess(uint32(users.Mask)|dangerous, root, true, false) {
			t.Fatalf("root accepted unsafe self-access %#x", dangerous)
		}
	}
	if allowedUntrustedAccess(windows.GENERIC_READ, root, false, true) {
		t.Fatal("private file allowed foreign read")
	}
}
