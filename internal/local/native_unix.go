//go:build linux || darwin

package local

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func prepareDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create protected agent state directory")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0066 != 0 {
		return errors.New("state directory must be owner-controlled (chmod 700 or 711), without group/other read or write access, and not a symbolic link")
	}
	var stat unix.Stat_t
	if unix.Stat(dir, &stat) != nil || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("state directory must belong to the current effective user")
	}
	return nil
}
func openLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open agent lock")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(fd)
		return nil, errors.New("another agent already owns this state directory")
	}
	return os.NewFile(uintptr(fd), "agent-lock"), nil
}
func resolveOperator(operator string) (int, error) {
	if operator == "" {
		return os.Geteuid(), nil
	}
	if len(operator) > 256 || strings.TrimSpace(operator) != operator || strings.ContainsAny(operator, "\x00\r\n") {
		return 0, errors.New("invalid local operator identity")
	}
	var account *user.User
	var err error
	if uid, parseErr := strconv.ParseUint(operator, 10, 32); parseErr == nil {
		account, err = user.LookupId(strconv.FormatUint(uid, 10))
	} else {
		account, err = user.Lookup(operator)
	}
	if err != nil {
		return 0, errors.New("local operator account does not exist")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uint64(int(uid)) != uid || uid == 1<<32-1 {
		return 0, errors.New("invalid local operator UID")
	}
	if os.Geteuid() != 0 && int(uid) != os.Geteuid() {
		return 0, errors.New("delegating local control to another user requires root privileges")
	}
	return int(uid), nil
}
func listen(dir string, operator string) (net.Listener, error) {
	uid, err := resolveOperator(operator)
	if err != nil {
		return nil, err
	}
	if err := prepareDirectory(dir); err != nil {
		return nil, err
	}
	// Hide the path while creating the socket, including on a restart of a
	// delegated 0711 directory. An unusually permissive process umask must not
	// expose a briefly writable socket to an unauthorized account.
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, errors.New("cannot protect state directory during local socket creation")
	}
	path := filepath.Join(dir, "control.sock")
	st, err := os.Lstat(path)
	if err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("control socket path is occupied by another resource")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("cannot create local control socket (check permissions/path length)")
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	if uid != os.Geteuid() {
		if err := os.Chown(path, uid, -1); err != nil {
			listener.Close()
			return nil, errors.New("cannot delegate local control socket ownership")
		}
	}
	if operator != "" && os.Geteuid() == 0 {
		// Execute-only access permits reaching this socket without listing state
		// or reading root-owned 0600 configuration, lock and private-key files.
		if err := os.Chmod(dir, 0711); err != nil {
			listener.Close()
			return nil, errors.New("cannot enable operator traversal of state directory")
		}
	}
	return &authenticatedListener{Listener: listener, operator: uint32(uid), owner: uint32(os.Geteuid()), credentials: peerUID}, nil
}
func dial(ctx context.Context, dir string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", filepath.Join(dir, "control.sock"))
}

// Socket ownership is an access convenience, not the authorization boundary:
// even if its owner broadens chmod permissions, only the configured delegate,
// the service identity and root may use the HTTP control protocol.
type authenticatedListener struct {
	net.Listener
	operator, owner uint32
	credentials     func(net.Conn) (uint32, error)
}

func (l *authenticatedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := l.credentials(connection)
		if err != nil || (uid != 0 && uid != l.owner && uid != l.operator) {
			connection.Close()
			continue
		}
		return connection, nil
	}
}
