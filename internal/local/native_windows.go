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
)

func prepareDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create agent state directory")
	}
	// Protect state from modification by unprivileged identities, including inherited ACLs.
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
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
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return `\\.\pipe\peerimeter-` + hex.EncodeToString(sum[:12])
}
func listen(dir string) (net.Listener, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(pipeName(dir), &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")(A;;GA;;;SY)(A;;GA;;;BA)", MessageMode: false, InputBufferSize: 4096, OutputBufferSize: 4096})
}
func dial(ctx context.Context, dir string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, pipeName(dir))
}
