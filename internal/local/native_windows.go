package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func trustedStateOwner(owner, current *windows.SID) bool {
	return owner != nil && (owner.Equals(current) || owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}
func prepareDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create agent state directory")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return errors.New("invalid Windows state directory path")
	}
	// Inspect and modify the same non-reparse handle. Excluding share-delete
	// prevents a rename/replacement race while validating ownership and the DACL.
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return errors.New("cannot securely open Windows state directory")
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("state directory must be a regular directory without reparse points")
	}
	currentSD, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("cannot verify Windows state directory ownership")
	}
	owner, _, err := currentSD.Owner()
	if err != nil || !trustedStateOwner(owner, user.User.Sid) {
		return errors.New("Windows state directory must belong to the current user, SYSTEM or Administrators")
	}
	// Inherit administrative access for non-secret metadata created by SYSTEM.
	// Key files retain their separately protected, restrictive secret-package ACL.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return errors.New("cannot protect Windows state directory")
	}
	return nil
}
func openLock(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("cannot open agent lock")
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		windows.CloseHandle(h)
		return nil, errors.New("another agent already owns this state directory")
	}

	return os.NewFile(uintptr(h), "agent-lock"), nil
}
func pipeName(dir string) string {
	path, _ := filepath.Abs(dir)
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return `\\.\pipe\peerimeter-` + hex.EncodeToString(sum[:12])
}
func resolveOperator(operator string) (string, error) {
	if operator == "" {
		return "", nil
	}
	if len(operator) > 256 || strings.TrimSpace(operator) != operator || strings.ContainsAny(operator, "\x00\r\n") {
		return "", errors.New("invalid local operator identity")
	}
	var sid *windows.SID
	var err error
	if strings.HasPrefix(strings.ToUpper(operator), "S-") {
		sid, err = windows.StringToSid(operator)
		if err == nil && sid.IsValid() {
			_, _, _, err = sid.LookupAccount("")
		}
	} else {
		sid, _, _, err = windows.LookupSID("", operator)
	}
	if err != nil || sid == nil || !sid.IsValid() {
		return "", errors.New("local operator account or SID does not exist")
	}
	return sid.String(), nil
}

// Generic write also maps to FILE_CREATE_PIPE_INSTANCE on named pipes. Client
// access must list only the concrete data/attribute/synchronization rights.
const pipeClientAccess uint32 = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA |
	windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE | windows.READ_CONTROL

func listen(dir string, operator string) (net.Listener, error) {
	operatorSID, err := resolveOperator(operator)
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	descriptor := "D:P(A;;GA;;;" + user.User.Sid.String() + ")(A;;GA;;;SY)(A;;GA;;;BA)"
	if operatorSID != "" && operatorSID != user.User.Sid.String() {
		descriptor += "(A;;0x00120183;;;" + operatorSID + ")"
	}
	return winio.ListenPipe(pipeName(dir), &winio.PipeConfig{SecurityDescriptor: descriptor, MessageMode: false, InputBufferSize: 4096, OutputBufferSize: 4096})
}
func dial(ctx context.Context, dir string) (net.Conn, error) {
	return winio.DialPipeAccess(ctx, pipeName(dir), pipeClientAccess)
}
