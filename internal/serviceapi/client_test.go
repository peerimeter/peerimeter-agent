package serviceapi

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
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

func TestDecodeJoinTokenAllowsLocalHTTPByDefault(t *testing.T) {
	for _, apiURL := range []string{"http://localhost:8080/api", "http://LOCALHOST.:8080/api", "http://127.0.0.1:8080/api", "http://[::1]:8080/api"} {
		wire, _ := json.Marshal(JoinBundle{Version: 1, APIURL: apiURL, NetworkID: "mesh-a", EnrollmentToken: "secret-key"})
		if _, err := DecodeJoinToken(base64.RawURLEncoding.EncodeToString(wire)); err != nil {
			t.Errorf("default join token decoding rejected loopback URL %q: %v", apiURL, err)
		}
	}
	for _, host := range []string{"service.localhost", "127.0.0.2.example", "api.example"} {
		if isLoopbackHost(host) {
			t.Errorf("treated non-loopback hostname %q as a local endpoint", host)
		}
	}
}

func TestDecodeJoinTokenAllowsRemoteHTTPOnlyWhenExplicitlyEnabled(t *testing.T) {
	wire, _ := json.Marshal(JoinBundle{Version: 1, APIURL: "http://api.example/prefix/", NetworkID: "mesh-a", EnrollmentToken: "secret-key"})
	token := base64.RawURLEncoding.EncodeToString(wire)
	if _, err := DecodeJoinToken(token); err == nil {
		t.Fatal("default join token decoding accepted remote HTTP")
	}
	bundle, err := DecodeJoinTokenWithInsecureHTTP(token, true)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.APIURL != "http://api.example/prefix" {
		t.Fatalf("unexpected HTTP API URL: %q", bundle.APIURL)
	}
}

func TestLocalHTTPClientBypassesProxyAndUsesLoopback(t *testing.T) {
	var proxyCalled atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalled.Store(true)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Errorf("Authorization = %q", got)
		}
		_, _ = io.WriteString(w, `{"version":1,"id":"mesh-a","name":"mesh","cidr":"10.90.0.0/24"}`)
	}))
	defer api.Close()
	parsed, err := url.Parse(api.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	client := New(JoinBundle{APIURL: "http://localhost:" + parsed.Port(), EnrollmentToken: "test-secret"})
	if _, err := client.GetNetwork(context.Background(), "mesh-a"); err != nil {
		t.Fatal(err)
	}
	if proxyCalled.Load() {
		t.Fatal("localhost API request was sent through the configured proxy")
	}
}

func TestLocalHTTPClientRejectsNonLoopbackResolvedAddress(t *testing.T) {
	for _, test := range []struct {
		address net.Addr
		want    bool
	}{
		{address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, want: true},
		{address: &net.TCPAddr{IP: net.ParseIP("::1")}, want: true},
		{address: &net.TCPAddr{IP: net.ParseIP("192.0.2.10")}, want: false},
		{address: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, want: false},
	} {
		if got := isLoopbackRemoteAddress(test.address); got != test.want {
			t.Errorf("isLoopbackRemoteAddress(%v) = %v; want %v", test.address, got, test.want)
		}
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

func TestPullPeersUsesEnrollmentAuthorization(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != "/api/v1/networks/net-a/nodes/node-a/peers" || r.Method != http.MethodGet {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"version":1,"peers":{"node-b":{"version":1,"public_key":"def"}}}`)
	}))
	defer server.Close()
	client := newClient(JoinBundle{APIURL: server.URL, EnrollmentToken: "test-secret"}, server.Client())
	peers, err := client.PullPeers(context.Background(), "net-a", "node-a")
	if err != nil || peers.Peers["node-b"] == nil || calls != 1 {
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
		debugClient := newClientWithDebug(JoinBundle{APIURL: server.URL, EnrollmentToken: "key"}, server.Client(), true)
		if _, err := debugClient.PullPeers(context.Background(), "net-a", "node-a"); err == nil || !strings.Contains(err.Error(), "service returned an invalid peer list") || !strings.Contains(err.Error(), "peers") {
			t.Errorf("debug error for malformed peer set = %v", err)
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
	_, err := client.PullPeers(context.Background(), "net-a", "node-a")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe API error: %v", err)
	}
}

func TestHTTPErrorResponseDetailsRequireDebug(t *testing.T) {
	const token = "private&enrollment-token"
	responseData, err := json.Marshal(map[string]string{
		"error":         "node ID is registered with another public key",
		"authorization": token,
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody := string(responseData)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, responseBody)
	}))
	defer server.Close()

	for _, test := range []struct {
		name     string
		debug    bool
		wantBody string
	}{
		{name: "normal", wantBody: "service API returned HTTP 409"},
		{name: "debug", debug: true, wantBody: `{"authorization":"[REDACTED]","error":"node ID is registered with another public key"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newClientWithDebug(JoinBundle{APIURL: server.URL, EnrollmentToken: token}, server.Client(), test.debug)
			_, err := client.PullPeers(context.Background(), "net-a", "node-a")
			if err == nil || !strings.Contains(err.Error(), test.wantBody) {
				t.Fatalf("error = %v, want %q", err, test.wantBody)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error leaked the enrollment token: %v", err)
			}
			encodedToken, _ := json.Marshal(token)
			if escapedToken := string(encodedToken[1 : len(encodedToken)-1]); strings.Contains(err.Error(), escapedToken) {
				t.Fatalf("error leaked the escaped enrollment token: %v", err)
			}
			if !test.debug && strings.Contains(err.Error(), "node ID is registered") {
				t.Fatalf("normal error exposed response details: %v", err)
			}
		})
	}
}

func TestDebugTransportErrorRedactsTokenFromMalformedStatusLine(t *testing.T) {
	const token = "private-enrollment-token"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverErr <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = fmt.Fprintf(connection, "HTTP/1.1 %s invalid\r\nContent-Length: 0\r\n\r\n", token)
		serverErr <- err
	}()

	bundle := JoinBundle{APIURL: "http://" + listener.Addr().String(), EnrollmentToken: token}
	client := newClientWithDebug(bundle, newAPIHTTPClient(bundle.APIURL), true)
	_, requestErr := client.GetNetwork(context.Background(), "net-a")
	if requestErr == nil || strings.Contains(requestErr.Error(), token) || !strings.Contains(requestErr.Error(), "[REDACTED]") {
		t.Fatalf("debug transport error = %v; want redacted status-line error", requestErr)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("write malformed status line: %v", err)
	}
}

func TestHTTPErrorResponseDetailsRedactNumericToken(t *testing.T) {
	const token = "1234567890123456"
	responseBody := fmt.Sprintf(`{"token":%s}`, token)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, responseBody)
	}))
	defer server.Close()

	client := newClientWithDebug(JoinBundle{APIURL: server.URL, EnrollmentToken: token}, server.Client(), true)
	_, err := client.PullPeers(context.Background(), "net-a", "node-a")
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), `"token":"[REDACTED]"`) {
		t.Fatalf("debug error = %v; want numeric token redacted in valid JSON", err)
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
	if _, err := client.PullPeers(context.Background(), "net-a", "node-a"); err == nil {
		t.Fatal("accepted redirect as a config response")
	}
	if redirectedCalls != 0 {
		t.Fatal("followed redirect to another server")
	}
}
