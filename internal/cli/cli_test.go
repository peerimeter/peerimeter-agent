package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := Execute(context.Background(), args, &out, &err)
	return code, out.String(), err.String()
}
func TestExampleValidatesAndRefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "example")
	if c, _, e := invoke(t, "generate-example", "--directory", dir); c != 0 {
		t.Fatal(e)
	}
	for _, name := range []string{"a", "b"} {
		if c, o, e := invoke(t, "validate-config", "--config", filepath.Join(dir, "peer-"+name+".json")); c != 0 || !strings.Contains(o, `"state":"valid"`) {
			t.Fatalf("%d %s %s", c, o, e)
		}
	}
	keyPath := filepath.Join(dir, "peer-a.key")
	before, _ := os.ReadFile(keyPath)
	if c, _, _ := invoke(t, "generate-example", "--directory", dir); c == 0 {
		t.Fatal("overwrote existing example")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("private key replaced")
	}
	// Unit tests must never call a privileged real backend.
	var out, errOut bytes.Buffer
	state := filepath.Join(t.TempDir(), "state")
	code := execute(context.Background(), []string{"run", "--config", filepath.Join(dir, "peer-a.json"), "--state-dir", state}, &out, &errOut, rejectBackend{})
	if code != 3 || out.Len() != 0 || strings.Contains(errOut.String(), strings.TrimSpace(string(before))) {
		t.Fatalf("unsafe backend failure: %d %s", code, errOut.String())
	}

}
func TestSelfPeerRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "example")
	if c, _, e := invoke(t, "generate-example", "--directory", dir); c != 0 {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "peer-a.json")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := secret.Load(cfg.Interface.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := secret.Public(key)
	cfg.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(pub[:])
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, _, e := invoke(t, "validate-config", "--config", path)
	if c == 0 || !strings.Contains(e, "matches the local") {
		t.Fatalf("%d %s", c, e)
	}
}
func TestErrorRedaction(t *testing.T) {
	for _, args := range [][]string{{"SECRET-UNKNOWN-COMMAND"}, {"run", "--private-key", "SUPERSECRET"}, {"run", "--config", "SECRET-MISSING-PATH"}} {
		c, _, e := invoke(t, args...)
		if c == 0 || strings.Contains(e, "SECRET") {
			t.Fatalf("unsafe error %d %s", c, e)
		}
	}
}

type rejectBackend struct{}

func (rejectBackend) Start(context.Context, platform.Desired) (platform.Session, error) {
	return nil, platform.ErrUnavailable
}
func (rejectBackend) Inspect(context.Context) (platform.Snapshot, error) {
	return platform.Snapshot{}, platform.ErrUnavailable
}
