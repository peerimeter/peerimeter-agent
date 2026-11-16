package serviceapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJoinToken(t *testing.T) {
	wire, _ := json.Marshal(JoinBundle{Version: 1, APIURL: "https://api.example/prefix/", NetworkID: "mesh-a", EnrollmentToken: "secret-key"})
	bundle, err := DecodeJoinToken(base64.RawURLEncoding.EncodeToString(wire))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.APIURL != "https://api.example/prefix" || bundle.NetworkID != "mesh-a" || bundle.EnrollmentToken != "secret-key" {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}
}

func TestDecodeJoinTokenRejectsInvalidBundles(t *testing.T) {
	for _, wire := range []string{
		`{"version":2,"api_url":"https://api.example","network_id":"mesh-a","enrollment_token":"key"}`,
		`{"version":1,"api_url":"http://api.example","network_id":"mesh-a","enrollment_token":"key"}`,
		`{"version":1,"api_url":"https://user:pass@api.example","network_id":"mesh-a","enrollment_token":"key"}`,
		`{"version":1,"api_url":"https://api.example?key=secret","network_id":"mesh-a","enrollment_token":"key"}`,
		`{"version":1,"api_url":"https://api.example?","network_id":"mesh-a","enrollment_token":"key"}`,
		`{"version":1,"api_url":"https://api.example/#","network_id":"mesh-a","enrollment_token":"key"}`,
		`{"version":1,"api_url":"https://api.example:99999","network_id":"mesh-a","enrollment_token":"key"}`,
		`{"version":1,"api_url":"https://api.example","network_id":"mesh-a","enrollment_token":""}`,
		`{"version":1,"api_url":"https://api.example","network_id":"mesh-a","enrollment_token":"bad token"}`,
		`{"version":1,"api_url":"https://api.example","network_id":"mesh-a","enrollment_token":"key","extra":true}`,
		`{"version":1,"api_url":"https://api.example","network_id":"mesh-a","enrollment_token":"key"} {}`,
	} {
		token := base64.RawURLEncoding.EncodeToString([]byte(wire))
		if _, err := DecodeJoinToken(token); err == nil {
			t.Errorf("accepted invalid bundle %s", wire)
		}
	}
	if _, err := DecodeJoinToken("not a token"); err == nil {
		t.Fatal("accepted malformed base64url")
	}
}

func TestConfigRoundTripAndAuth(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path == "/api/v1/networks/net-a/config" && r.Method == http.MethodPut {
			data, _ := io.ReadAll(r.Body)
			if string(data) != `{"version":1,"name":"mesh"}` {
				t.Errorf("PUT body = %s", data)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/v1/networks/net-a/nodes/node-a/config" && r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"version":1,"public_key":"abc"}`)
			return
		}
		if r.URL.Path == "/api/v1/networks/net-a/nodes/node-a/peers" && r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"version":1,"peers":{"node-b":{"version":1,"public_key":"def"}}}`)
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()
	client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: "test-secret"}, server.Client())
	if err := client.PushNetwork(context.Background(), "net-a", []byte(`{"version":1,"name":"mesh"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := client.PullNode(context.Background(), "net-a", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"version":1,"public_key":"abc"}` || calls != 2 {
		t.Fatalf("response=%s calls=%d", got, calls)
	}
	peers, err := client.PullPeers(context.Background(), "net-a", "node-a")
	if err != nil || peers.Peers["node-b"] == nil || calls != 3 {
		t.Fatalf("peer response=%+v calls=%d err=%v", peers, calls, err)
	}
}

func TestGetNetworkValidatesNetworkCIDRResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/networks/net-a" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"version":1,"id":"net-a","name":"mesh","cidr":"10.90.0.0/24"}`)
	}))
	defer server.Close()
	client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: "key"}, server.Client())
	got, err := client.GetNetwork(context.Background(), "net-a")
	if err != nil || got.CIDR != "10.90.0.0/24" {
		t.Fatalf("network=%+v err=%v", got, err)
	}

	for _, cidr := range []string{"10.90.0.1/24", "8.8.8.0/24", "192.168.0.0/15", "10.90.0.0/31", "bad"} {
		if validNetworkResource(NetworkResource{Version: 1, ID: "net-a", Name: "mesh", CIDR: cidr}) {
			t.Errorf("accepted invalid service network CIDR %q", cidr)
		}
	}
	mismatch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"version":1,"id":"other-network","name":"mesh","cidr":"10.90.0.0/24"}`)
	}))
	defer mismatch.Close()
	wrongClient := newClient(JoinBundle{APIURL: mismatch.URL, EnrollmentToken: "key"}, mismatch.Client())
	if _, err := wrongClient.GetNetwork(context.Background(), "net-a"); err == nil {
		t.Fatal("accepted a network resource with a different ID")
	}
}

func TestRegisterNodeReturnsAllocatedTunnelAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/networks/net-a/nodes/node-a/registration" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"version":1,"node_id":"node-a","tunnel_address":"10.90.0.2","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`)
	}))
	defer server.Close()
	client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: "key"}, server.Client())
	public := make([]byte, 32)
	public[0] = 1
	result, err := client.RegisterNode(context.Background(), "net-a", "node-a", NodeRegistration{Version: 1, PublicKey: base64.StdEncoding.EncodeToString(public), ListenPort: 51820, PrimaryInterface: "eth0", LocalAddresses: []string{"192.168.1.12/24"}})
	if err != nil || result.TunnelAddress != "10.90.0.2" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestClientRejectsInvalidDataAndIDsWithoutRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected network request")
	}))
	defer server.Close()
	client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: "key"}, server.Client())
	if err := client.PushNetwork(context.Background(), "../bad", []byte(`{"version":1}`)); err == nil {
		t.Fatal("accepted invalid network ID")
	}
	if err := client.PushNode(context.Background(), "net-a", "node-a", []byte(`[]`)); err == nil {
		t.Fatal("accepted non-object config")
	}
	if err := client.PushNode(context.Background(), "net-a", "node-a", []byte(`{"version":2}`)); err == nil {
		t.Fatal("accepted unsupported config version")
	}
	if _, err := client.PullNetwork(context.Background(), strings.Repeat("n", 129)); err == nil {
		t.Fatal("accepted overlong network ID")
	}
}

func TestPullPeersRejectsMalformedPeerDocuments(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"peers":null}`,
		`{"version":1,"peers":{"../bad":{"version":1}}}`,
		`{"version":1,"peers":{"node-b":null}}`,
		`{"version":1,"peers":{"node-b":{"version":2}}}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: "key"}, server.Client())
		if _, err := client.PullPeers(context.Background(), "net-a", "node-a"); err == nil {
			t.Errorf("accepted malformed peer set %s", body)
		}
		server.Close()
	}
}

func TestResponseAndRequestErrorsDoNotLeakToken(t *testing.T) {
	secret := "do-not-print-this-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, secret, http.StatusUnauthorized)
	}))
	defer server.Close()
	client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: secret}, server.Client())
	_, err := client.PullNetwork(context.Background(), "net-a")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe API error: %v", err)
	}
}

func TestAPIClientDoesNotFollowRedirectsWithBearerToken(t *testing.T) {
	var redirectedCalls int
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedCalls++
		_, _ = io.WriteString(w, `{"version":1}`)
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirectTarget.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: "secret-key"}, newHTTPClient())
	if _, err := client.PullNetwork(context.Background(), "net-a"); err == nil {
		t.Fatal("accepted redirect as a config response")
	}
	if redirectedCalls != 0 {
		t.Fatal("followed redirect to another server")
	}
}
