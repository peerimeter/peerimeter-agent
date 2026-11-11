package secret

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func trustedSIDs() ([]*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, errors.New("private key: cannot inspect current Windows identity")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, errors.New("private key: cannot resolve SYSTEM identity")
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, errors.New("private key: cannot resolve Administrators identity")
	}
	return []*windows.SID{user.User.Sid, system, admins}, nil
}

func trusted(sid *windows.SID, allowed []*windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	for _, permitted := range allowed {
		if sid.Equals(permitted) {
			return true
		}
	}
	return false
}

func inspectHandle(handle windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return errors.New("private key: file metadata unavailable")
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return errors.New("private key: require a regular file without links or reparse points")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("private key: Windows security descriptor unavailable")
	}
	allowed, err := trustedSIDs()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner, allowed) {
		return errors.New("private key: owner must be current user, SYSTEM or Administrators")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("private key: a restrictive Windows DACL is required")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return errors.New("private key: cannot inspect Windows access entry")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			// Deny entries cannot grant access; they do not reduce the strict
			// allowlist requirement for any other entries.
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Mask == 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !trusted(sid, allowed) {
				return errors.New("private key: Windows DACL grants access outside current user, SYSTEM and Administrators")
			}
		default:
			// Fail closed on callback, object-specific and other ACE formats.
			return errors.New("private key: unsupported Windows access entry")
		}
	}
	runtime.KeepAlive(sd)
	return nil
}

func openProtected(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("open private key: invalid path")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("open private key: file unavailable")
	}
	if err := inspectHandle(handle); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), "private-key"), nil
}

func createProtected(path string) (*os.File, error) {
	allowed, err := trustedSIDs()
	if err != nil {
		return nil, err
	}
	// The DACL is protected from inheritance and supplied to CreateFile, so
	// key bytes are never temporarily exposed through an inherited ACL.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + allowed[0].String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, errors.New("create private key: cannot construct private Windows DACL")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("create private key: invalid path")
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, &attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, errors.New("create private key: destination exists or is unavailable")
	}
	return os.NewFile(uintptr(handle), "private-key"), nil
}
