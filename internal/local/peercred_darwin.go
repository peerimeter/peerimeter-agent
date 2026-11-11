package local

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
)

func peerUID(connection net.Conn) (uint32, error) {
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("local control requires a Unix connection")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var inspect error
	if err := raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			inspect = err
			return
		}
		uid = credential.Uid
	}); err != nil {
		return 0, err
	}
	return uid, inspect
}
