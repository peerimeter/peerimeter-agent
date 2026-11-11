//go:build linux || darwin

package local

import (
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestUnixOperatorIdentityAndProtectedSocket(t *testing.T) {
	uid := strconv.Itoa(os.Geteuid())
	if got, err := resolveOperator(uid); err != nil || got != os.Geteuid() {
		t.Fatalf("current UID not resolved: %d %v", got, err)
	}
	account, err := user.LookupId(uid)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := resolveOperator(account.Username); err != nil || got != os.Geteuid() {
		t.Fatal("current username not resolved")
	}
	dir, err := os.MkdirTemp("", "pmop-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("private-test-data"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := listen(dir, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var stat unix.Stat_t
	if err := unix.Stat(filepath.Join(dir, "control.sock"), &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0600 {
		t.Fatal("control socket permissions or ownership incorrect")
	}
	info, err := os.Stat(key)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("delegation weakened key permissions")
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0700)
	if os.Geteuid() == 0 {
		want = 0711
	}
	if info.Mode().Perm() != want {
		t.Fatal("incorrect operator directory traversal permissions")
	}
}
func TestUnixInvalidOperatorHasNoListenerSideEffects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(path, []byte("existing resource"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0711); err != nil {
		t.Fatal(err)
	}
	if listener, err := listen(dir, "peerimeter-user-does-not-exist-83bf"); err == nil {
		listener.Close()
		t.Fatal("invalid identity accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing resource" {
		t.Fatal("invalid identity modified control path")
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0711 {
		t.Fatal("invalid identity changed directory permissions")
	}
}
func TestUnixStateTraversalDoesNotPermitReadOrWrite(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0700, 0711} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := prepareDirectory(dir); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []os.FileMode{0755, 0770, 0720, 0702} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := prepareDirectory(dir); err == nil {
			t.Fatalf("insecure state mode %o accepted", mode)
		}
	}
}

func TestUnixControlRejectsUnconfiguredPeerEvenWithWritableSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "pmauth-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "control.sock")
	raw, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Geteuid())
	other := owner + 1
	if other == 0 {
		other++
	}
	count := 0
	listener := &authenticatedListener{Listener: raw, owner: owner, operator: owner, credentials: func(net.Conn) (uint32, error) {
		count++
		if count == 1 {
			return other, nil
		}
		return owner, nil
	}}
	accepted := make(chan net.Conn, 1)
	failures := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			failures <- err
			return
		}
		accepted <- connection
	}()
	first, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("unauthorized peer was not rejected: %v", err)
	}
	second, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	select {
	case connection := <-accepted:
		connection.Close()
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("authorized operator was not accepted after rejecting another identity")
	}
}
