package local

import (
	"context"
	"golang.org/x/sys/windows"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWindowsOperatorSIDAndAccount(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	if got, err := resolveOperator(sid); err != nil || got != sid {
		t.Fatalf("current SID not resolved: %s %v", got, err)
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	if domain != "" {
		account = domain + `\` + account
	}
	if got, err := resolveOperator(account); err != nil || got != sid {
		t.Fatal("current account not resolved")
	}
	dir := t.TempDir()
	listener, err := listen(dir, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	client, err := dial(ctx, dir)
	if err != nil {
		t.Fatalf("concrete client access mask cannot connect: %v", err)
	}
	defer client.Close()
	select {
	case server := <-accepted:
		server.Close()
	case <-ctx.Done():
		t.Fatal("concrete-mask client was not accepted")
	}
	listener.Close()
	if listener, err := listen(dir, "S-invalid-identity"); err == nil {
		listener.Close()
		t.Fatal("invalid SID accepted")
	}
	if listener, err := listen(dir, "peerimeter-user-does-not-exist-83bf"); err == nil {
		listener.Close()
		t.Fatal("invalid account accepted")
	}
}
func TestWindowsPipeNamesIgnoreFilesystemCase(t *testing.T) {
	if pipeName(`C:\ProgramData\Peerimeter`) != pipeName(`c:/PROGRAMDATA/peerimeter/.`) {
		t.Fatal("same Windows path produced case-sensitive pipe aliases")
	}
	if pipeName(`C:\ProgramData\Peerimeter`) == pipeName(`C:\ProgramData\Peerimeter-other`) {
		t.Fatal("different state paths share a named pipe")
	}
}
func TestWindowsStateOwnerPolicy(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{user.User.Sid.String(), "S-1-5-18", "S-1-5-32-544"} {
		sid, err := windows.StringToSid(text)
		if err != nil || !trustedStateOwner(sid, user.User.Sid) {
			t.Fatalf("trusted owner rejected: %s", text)
		}
	}
	other, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	if trustedStateOwner(other, user.User.Sid) || trustedStateOwner(nil, user.User.Sid) {
		t.Fatal("untrusted state-directory owner accepted")
	}
	if !strings.HasPrefix(pipeName(t.TempDir()), `\\.\pipe\peerimeter-`) {
		t.Fatal("invalid named pipe prefix")
	}
}

func TestWindowsPipeClientRightsCannotCreateInstancesOrChangeACL(t *testing.T) {
	const createPipeInstance uint32 = 0x00000004
	if pipeClientAccess != 0x00120183 {
		t.Fatalf("client SDDL and requested rights disagree: %08x", pipeClientAccess)
	}
	if pipeClientAccess&(windows.WRITE_DAC|windows.WRITE_OWNER|createPipeInstance|windows.GENERIC_ALL|windows.GENERIC_WRITE) != 0 {
		t.Fatal("operator can alter pipe permissions or create a server instance")
	}
}
