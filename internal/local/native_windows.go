package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func trustedStateOwner(owner, current *windows.SID) bool {
	return owner != nil && (owner.Equals(current) || owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}
func prepareDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create agent state directory %s: %w", dir, err)
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
		return fmt.Errorf("cannot securely open Windows state directory %s: %w", dir, err)
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

func prepareServiceDirectory(dir string) error {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return prepareDirectory(dir)
	} else if err != nil {
		return fmt.Errorf("cannot inspect Windows service state directory %s: %w", dir, err)
	}
	if err := inspectExistingStateDirectory(dir); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return errors.New("invalid Windows service state directory path")
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("cannot inspect Windows service state directory %s: %w", dir, err)
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("cannot verify Windows service state directory owner")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return errors.New("cannot verify Windows service state directory owner")
	}
	if !owner.Equals(user.User.Sid) && (owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return nil
	}
	return prepareDirectory(dir)
}
func inspectExistingStateDirectory(dir string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return errors.New("cannot inspect existing Windows state directory")
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("existing Windows state directory must not be a reparse point")
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !trustedStateOwner(owner, user.User.Sid) {
		return errors.New("existing Windows state directory has an untrusted owner")
	}
	return nil
}
func openStateLock(dir string, existing bool) (*os.File, error) {
	if existing {
		if err := inspectExistingStateDirectory(dir); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(dir, "agent.lock")
	disposition := uint32(windows.OPEN_ALWAYS)
	if existing {
		disposition = windows.OPEN_EXISTING
	}

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if existing && errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot open agent lock")
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, errors.New("Windows agent lock must be a regular file without links")
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		windows.CloseHandle(h)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, fmt.Errorf("%w: another agent already owns this state directory", ErrBusy)
		}
		return nil, errors.New("cannot lock Windows agent coordination file")
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

func listen(dir string, operator string, beforeListen ...func() error) (net.Listener, error) {
	return listenWithHooks(dir, operator, callListenHooks(beforeListen), nil)
}
func listenWithHooks(dir, operator string, beforeListen, onClose func() error) (net.Listener, error) {
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
	listener, err := winio.ListenPipe(pipeName(dir), &winio.PipeConfig{SecurityDescriptor: descriptor, MessageMode: false, InputBufferSize: 4096, OutputBufferSize: 4096})
	if err != nil {
		return nil, err
	}
	wrapped := &hookedPipeListener{Listener: listener, onClose: onClose}
	// A custom runtime path may not exist yet. Prepare it only after the first
	// pipe instance proves exclusive ownership of this control namespace.
	if err := prepareDirectory(dir); err != nil {
		return nil, errors.Join(err, wrapped.Close())
	}
	if beforeListen != nil {
		if err := beforeListen(); err != nil {
			return nil, errors.Join(err, wrapped.Close())
		}
	}
	return wrapped, nil
}
func dial(ctx context.Context, dir string) (net.Conn, error) {
	return winio.DialPipeAccess(ctx, pipeName(dir), pipeClientAccess)
}

func compatibilityLock(string) (*os.File, error) { return nil, nil }

type hookedPipeListener struct {
	net.Listener
	onClose    func() error
	once       sync.Once
	closeError error
}

func (l *hookedPipeListener) Close() error {
	l.once.Do(func() {
		l.closeError = l.Listener.Close()
		if l.onClose != nil {
			l.closeError = errors.Join(l.closeError, l.onClose())
		}
	})
	return l.closeError
}
