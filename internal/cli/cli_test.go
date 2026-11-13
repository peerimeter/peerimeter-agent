package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
		if c, o, e := invoke(t, "validate-config", "--config", filepath.Join(dir, "peer-"+name+".json")); c != 0 || !strings.Contains(o, "valid") || !strings.Contains(o, "State") {
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

func TestGenerateThreePeerMeshWithLocalSTUNMapping(t *testing.T) {
	previous := probeExampleEndpoint
	probeExampleEndpoint = func(port int, server string) (stunprobe.Result, error) {
		if port != 51821 || server != "stun.example:3478" {
			t.Fatalf("unexpected STUN request: %d %s", port, server)
		}
		return stunprobe.Result{MappedAddress: "203.0.113.5:62000"}, nil
	}
	defer func() { probeExampleEndpoint = previous }()
	dir := filepath.Join(t.TempDir(), "mesh")
	if code, _, stderr := invoke(t, "generate-example", "--directory", dir, "--peers", "3", "--stun-peer", "2", "--stun-server", "stun.example:3478"); code != 0 {
		t.Fatal(stderr)
	}
	for i, name := range []string{"a", "b", "c"} {
		path := filepath.Join(dir, "peer-"+name+".json")
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Peers) != 2 || cfg.Interface.ListenPort != 51820+i {
			t.Fatalf("unexpected peer %s config: %+v", name, cfg)
		}
		if code, _, stderr := invoke(t, "validate-config", "--config", path); code != 0 {
			t.Fatal(stderr)
		}
		for _, peer := range cfg.Peers {
			if peer.AllowedIPs[0] == "10.80.0.2/32" && peer.Endpoint != "203.0.113.5:62000" {
				t.Fatalf("STUN endpoint missing from %s", name)
			}
		}
	}
}

func TestGenerateRejectsInvalidCountBeforeCreatingDirectory(t *testing.T) {
	for _, count := range []string{"1", "254"} {
		dir := filepath.Join(t.TempDir(), "mesh")
		if code, _, _ := invoke(t, "generate-example", "--directory", dir, "--peers", count); code == 0 {
			t.Fatalf("accepted %s peers", count)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("created directory for invalid peer count %s", count)
		}
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
	for _, args := range [][]string{{"SECRET-UNKNOWN-COMMAND"}, {"run", "--private-key", "SUPERSECRET"}} {
		c, _, e := invoke(t, args...)
		if c == 0 || strings.Contains(e, "SECRET") {
			t.Fatalf("unsafe error %d %s", c, e)
		}
	}
}

func TestConfigLoadErrorDiagnostics(t *testing.T) {
	for _, format := range []string{"console", "text", "json"} {
		t.Run(format, func(t *testing.T) {
			t.Setenv("PEERIMETER_LOG_FORMAT", format)
			path := filepath.Join(t.TempDir(), "missing-config.json")
			for _, debug := range []bool{false, true} {
				args := []string{"validate-config", "--config", path}
				if debug {
					args = append(args, "--debug")
				}
				code, out, stderr := invoke(t, args...)
				message := stderr
				trace := ""
				if format == "json" {
					var entry struct {
						Message    string `json:"msg"`
						StackTrace string `json:"stacktrace"`
					}
					if err := json.Unmarshal([]byte(stderr), &entry); err != nil {
						t.Fatal(err)
					}
					message, trace = entry.Message, entry.StackTrace
				} else if strings.Contains(stderr, "stacktrace=") {
					trace = stderr
				}
				if code != 1 || out != "" || !strings.Contains(message, "open static config") || !strings.Contains(message, strconv.Quote(path)) {
					t.Fatalf("missing config context: %d %q %s", code, out, stderr)
				}
				if debug {
					if !strings.Contains(trace, "internal/config.Load") || !strings.Contains(trace, "config.go:") {
						t.Fatalf("missing source stack: %s", stderr)
					}
				} else if trace != "" {
					t.Fatalf("stack shown without --debug: %s", stderr)
				}
			}
		})
	}
}

func TestDebugErrorRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	for _, data := range []string{
		`{"private_key":"SUPERSECRET"}`,
		`{"version":"SUPERSECRET"}`,
		`{"secret":"SUPERSECRET"`,
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		for _, debug := range []bool{false, true} {
			args := []string{"validate-config", "--config", path}
			if debug {
				args = append(args, "--debug")
			}
			if code, _, stderr := invoke(t, args...); code != 1 || strings.Contains(stderr, "SUPERSECRET") {
				t.Fatalf("unsafe config error: %d %s", code, stderr)
			}
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

func TestCobraHelpAndCompletion(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}, {"run", "--help"}, {"service", "install", "--help"}, {"completion", "bash"}} {
		code, out, err := invoke(t, args...)
		if code != 0 || out == "" || err != "" {
			t.Fatalf("%v: %d %s %s", args, code, out, err)
		}
		if len(args) == 0 && (!strings.Contains(out, "Usage:") || !strings.Contains(out, "Available Commands")) {
			t.Fatalf("bare invocation did not print root help: %s", out)
		}
	}
	code, out, err := invoke(t, "run", "--config")
	if code == 0 || out != "" || err == "" {
		t.Fatal("missing flag value accepted")
	}
	code, _, err = invoke(t, "version", "SECRET-POSITIONAL")
	if code == 0 || strings.Contains(err, "SECRET") {
		t.Fatal("positional error leaked input")
	}
}

func TestPeerHumanAndJSONUseSamePublicSnapshot(t *testing.T) {
	base := ""
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "pmpeer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	runtimeDir := filepath.Join(dir, "control")
	closeServer, err := local.Serve(context.Background(), runtimeDir, local.Operations{Snapshot: func(context.Context) (platform.Snapshot, error) {
		return platform.Snapshot{NetworkID: "mesh-test", InterfaceName: "pm-test", ListenPort: 51820, Peers: []platform.PeerState{{PublicKey: "public-test", AllowedIPs: []string{"10.80.0.2/32"}, PersistentKeepaliveSeconds: 25}}}, nil
	}, Reload: func(context.Context) error { return nil }, Stop: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()

	for _, operation := range []string{"status", "sync"} {
		for _, machine := range []bool{false, true} {
			args := []string{operation, "--runtime-dir", runtimeDir}
			if machine {
				args = append(args, "--json")
			}
			code, out, stderr := invoke(t, args...)
			if code != 0 || stderr != "" || out == "" || (machine && !json.Valid([]byte(out))) || (!machine && json.Valid([]byte(out))) {
				t.Fatalf("%s JSON=%t: %d %s %s", operation, machine, code, out, stderr)
			}
		}
	}
	code, out, stderr := invoke(t, "peers", "--runtime-dir", runtimeDir, "--color", "never")
	if code != 0 || stderr != "" || !strings.Contains(out, "Connection") || strings.Contains(out, "PEERIMETER /") || !strings.Contains(out, "public-test") || !strings.Contains(out, "Handshake") {
		t.Fatalf("human output: %d %s %s", code, out, stderr)
	}

	var wgOutput string
	for _, args := range [][]string{
		{"wg", "--runtime-dir", runtimeDir, "--color", "never"},
		{"wg", "show", "--runtime-dir", runtimeDir, "--color", "never"},
		{"wg", "--runtime-dir", runtimeDir, "--color", "never", "show"},
	} {
		code, out, stderr := invoke(t, args...)
		if code != 0 || stderr != "" || !strings.Contains(out, "peer: public-test") || !strings.Contains(out, "private key: (hidden)") {
			t.Fatalf("%v: %d %s %s", args, code, out, stderr)
		}
		if wgOutput != "" && out != wgOutput {
			t.Fatal("wg and wg show differ")
		}
		wgOutput = out
	}
	for _, args := range [][]string{
		{"wg", "--json", "--runtime-dir", runtimeDir},
		{"wg", "show", "--json", "--runtime-dir", runtimeDir},
		{"--json", "peers", "--runtime-dir", runtimeDir},
	} {
		code, out, stderr := invoke(t, args...)
		if code != 0 || stderr != "" || !json.Valid([]byte(out)) || strings.Contains(out, "\x1b") {
			t.Fatalf("%v: %d %s %s", args, code, out, stderr)
		}
	}
	code, out, stderr = invoke(t, "peers", "--runtime-dir", runtimeDir, "--json")
	var peers []platform.PeerState
	if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &peers) != nil || len(peers) != 1 || peers[0].PublicKey != "public-test" {
		t.Fatalf("JSON output: %d %s %s", code, out, stderr)
	}
}

func TestCommandResultsDefaultToConsoleWithJSONOptIn(t *testing.T) {
	for _, machine := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "examples")
		args := []string{"generate-example", "--directory", dir, "--peers", "3"}
		if machine {
			args = append(args, "--json")
		}
		code, out, stderr := invoke(t, args...)
		if code != 0 || stderr != "" {
			t.Fatalf("%d %s", code, stderr)
		}
		if machine {
			var result map[string]string
			if err := json.Unmarshal([]byte(out), &result); err != nil || result["state"] != "example_generated" {
				t.Fatalf("invalid JSON: %s", out)
			}
		} else if !strings.Contains(out, "Example configuration generated") || !strings.Contains(out, "keep private") || strings.Contains(out, "{") || strings.Contains(out, "\n\n") {
			t.Fatalf("invalid console output: %s", out)
		}
		args = []string{"validate-config", "--config", filepath.Join(dir, "peer-a.json")}
		if machine {
			args = append(args, "--json")
		}
		code, out, stderr = invoke(t, args...)
		if code != 0 || stderr != "" || (machine && !json.Valid([]byte(out))) || (!machine && (!strings.Contains(out, "Peer count") || !strings.Contains(out, "2"))) {
			t.Fatalf("validation: %d %s %s", code, out, stderr)
		}
	}
}

func TestSingleFieldConsoleOutputSanitizesControlCharacters(t *testing.T) {
	var out strings.Builder
	if err := renderResponse(&out, []byte(`{"\u001bresult":"first\nsecond\u001b[2J"}`), false, 80); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "Result: first\nsecond[2J\n"; got != want {
		t.Fatalf("renderResponse() = %q, want %q", got, want)
	}
}

func TestSTUNConsoleAndJSON(t *testing.T) {
	previous := probeSTUN
	defer func() { probeSTUN = previous }()
	probeSTUN = func(port int, server string) (stunprobe.Result, error) {
		return stunprobe.Result{Server: server, LocalAddress: "0.0.0.0:51820", MappedAddress: "203.0.113.1:62000"}, nil
	}
	for _, machine := range []bool{false, true} {
		args := []string{"stun", "51820", "--server", "stun.example:3478"}
		if machine {
			args = append(args, "--json")
		}
		code, out, stderr := invoke(t, args...)
		if code != 0 || stderr != "" || !strings.Contains(out, "203.0.113.1:62000") || strings.Contains(out, "\x1b") {
			t.Fatalf("%d %s %s", code, out, stderr)
		}
		if machine && !json.Valid([]byte(out)) {
			t.Fatal(out)
		}
		if !machine && !strings.Contains(out, "STUN SERVER") {
			t.Fatal(out)
		}
	}
	m := stunModel{}
	next, cmd := m.Update(stunResultMsg{result: stunprobe.Result{MappedAddress: "203.0.113.1:62000"}})
	if !next.(stunModel).done || cmd == nil {
		t.Fatal("STUN completion did not exit UI")
	}
}
