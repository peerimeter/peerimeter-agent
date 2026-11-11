package installstate

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func isReparse(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && st.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
func trustedSystemAlias(string, os.FileInfo) bool { return false }
func trustedSIDs() ([]*windows.SID, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	a, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	s, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	t, _ := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	return []*windows.SID{u.User.Sid, a, s, t}, nil
}
func trusted(sid *windows.SID, all []*windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	for _, s := range all {
		if s != nil && sid.Equals(s) {
			return true
		}
	}
	return false
}
func checkACL(path string, private, directory bool) error {
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return errors.New("installation security descriptor unavailable")
	}
	all, e := trustedSIDs()
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || !trusted(owner, all) {
		return errors.New("installation resource has an untrusted Windows owner")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return errors.New("installation resource requires a restrictive Windows ACL")
	}
	const readonly = windows.GENERIC_READ | windows.GENERIC_EXECUTE | windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_DATA | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_EA | windows.FILE_EXECUTE
	mask := uint32(readonly)
	clean := filepath.Clean(path)
	if directory && (filepath.Dir(clean) == clean || strings.EqualFold(clean, filepath.Clean(os.Getenv("ProgramData")))) {
		mask |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil {
			return errors.New("cannot inspect installation Windows ACL")
		}
		if a.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || a.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported installation Windows ACL entry")
		}
		if trusted((*windows.SID)(unsafe.Pointer(&a.SidStart)), all) {
			continue
		}
		if a.Mask != 0 && (private || uint32(a.Mask)&^mask != 0) {
			return errors.New("installation resource grants unsafe Windows access")
		}
	}
	return nil
}
func checkTrust(path string, info os.FileInfo, directory bool) error {
	if !directory {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return err
		}
		var metadata windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(h, &metadata)
		windows.CloseHandle(h)
		if err != nil || metadata.NumberOfLinks != 1 || metadata.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
			return errors.New("installation files must not have hard links or reparse points")
		}
	}
	return checkACL(path, false, directory)
}
func checkPrivate(path string, info os.FileInfo) error { return checkACL(path, true, false) }
func protect(path string) error {
	all, e := trustedSIDs()
	if e != nil {
		return e
	}
	who := all[0]
	owner := (*windows.SID)(nil)
	if windows.GetCurrentProcessToken().IsElevated() {
		who = all[1]
		owner = who
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + who.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		flags |= windows.OWNER_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, owner, nil, acl, nil)
}
func lockInventory(path string) (*os.File, error) {
	existed := false
	if info, err := os.Lstat(path); err == nil {
		existed = true
		if err := CheckFile(path); err != nil {
			return nil, err
		}
		if err := checkPrivate(path, info); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), "installation-lock")
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !info.Mode().IsRegular() || isReparse(info) {
		f.Close()
		return nil, errors.New("installation lock must not be a reparse point")
	}
	if !existed {
		if e := protect(path); e != nil {
			f.Close()
			return nil, e
		}
	}
	var o windows.Overlapped
	if windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &o) != nil {
		f.Close()
		return nil, errors.New("another installation inventory operation is running")
	}
	return f, nil
}
