package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEligiblePeerEntriesExcludePeersWithoutUsableEndpoint(t *testing.T) {
	peers := map[string]json.RawMessage{
		"reachable":   json.RawMessage(`{"version":1,"node_id":"reachable","public_key":"key-a","tunnel_address":"10.90.0.2","listen_port":51820,"local_addresses":["192.168.1.20/24"]}`),
		"unreachable": json.RawMessage(`{"version":1,"node_id":"unreachable","public_key":"key-b","tunnel_address":"10.90.0.3","listen_port":51820,"local_addresses":["10.20.0.20/24"]}`),
	}

	entries, routes := eligiblePeerEntries([]string{"192.168.1.10/24"}, peers)
	if len(entries) != 1 || entries[0].id != "reachable" {
		t.Fatalf("eligible entries = %#v, want only reachable peer", entries)
	}
	if entries[0].endpoint != "192.168.1.20:51820" {
		t.Fatalf("endpoint = %q, want LAN endpoint", entries[0].endpoint)
	}
	if !reflect.DeepEqual(routes, []string{"10.90.0.2/32"}) {
		t.Fatalf("routes = %#v, want only configured peer route", routes)
	}
}

func TestJoinDebugIncludesServiceErrorResponse(t *testing.T) {
	const responseBody = `{"error":"node ID is registered with another public key"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()
	bundle, err := json.Marshal(struct {
		Version         int    `json:"version"`
		APIURL          string `json:"api_url"`
		NetworkID       string `json:"network_id"`
		EnrollmentToken string `json:"enrollment_token"`
	}{Version: 1, APIURL: server.URL, NetworkID: "network-a", EnrollmentToken: "join-secret"})
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bundle)
	directories := []string{"--config-dir", filepath.Join(t.TempDir(), "config"), "--state-dir", filepath.Join(t.TempDir(), "state"), "--runtime-dir", filepath.Join(t.TempDir(), "runtime")}

	args := append([]string{"join", "--token", token}, directories...)
	code, _, stderr := invoke(t, args...)
	if code == 0 || !strings.Contains(stderr, "service API returned HTTP 409") || strings.Contains(stderr, "node ID is registered") {
		t.Fatalf("join without debug = %d, %q; want sanitized HTTP 409", code, stderr)
	}

	args = append(args, "--debug")
	code, _, stderr = invoke(t, args...)
	if code == 0 || !strings.Contains(stderr, responseBody) || strings.Contains(stderr, "join-secret") {
		t.Fatalf("join with debug = %d, %q; want response JSON without request token", code, stderr)
	}
}

func TestReadJoinTokenSources(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(" file-token \n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, token, tokenFile, stdin, want string
	}{
		{name: "stdin default", tokenFile: "-", stdin: " stdin-token \n", want: "stdin-token"},
		{name: "token file", tokenFile: file, stdin: "ignored", want: "file-token"},
		{name: "inline token", token: "inline-token", tokenFile: "-", stdin: "ignored", want: "inline-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := readJoinToken(test.token, test.tokenFile, bytes.NewBufferString(test.stdin))
			if err != nil || got != test.want {
				t.Fatalf("readJoinToken() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestJoinResultUsesConsoleOutputByDefault(t *testing.T) {
	var output bytes.Buffer
	if err := renderResponse(&output, []byte(`{"state":"registered","network_id":"mesh","node_id":"laptop","tunnel_address":"10.0.0.2","peer_count":3}`), false, 80); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "Joined network mesh as laptop (10.0.0.2); 3 peers configured.\n"; got != want {
		t.Fatalf("renderResponse() = %q; want %q", got, want)
	}
}

func TestDefaultNodeIDDropsLocalDomainSuffix(t *testing.T) {
	id, err := defaultNodeID("zero-m5-max.localdomain")
	if err != nil || id != "zero-m5-max" {
		t.Fatalf("defaultNodeID() = %q, %v; want zero-m5-max", id, err)
	}
	id, err = defaultNodeID("workstation")
	if err != nil || id != "workstation" {
		t.Fatalf("defaultNodeID() = %q, %v; want workstation", id, err)
	}
	if _, err := defaultNodeID(".localdomain"); err == nil {
		t.Fatal("empty hostname after suffix removal was accepted")
	}
}
