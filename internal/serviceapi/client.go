// Package serviceapi implements the version 1 JSON API used by peerimeter-service.
package serviceapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxConfigSize = 1 << 20
const maxBundleSize = 8 << 10

// JoinBundle is the decoded Base64URL JSON token returned by the service.
// enrollment_token is scoped to the bundle's network by the service.
type JoinBundle struct {
	Version         int    `json:"version"`
	APIURL          string `json:"api_url"`
	NetworkID       string `json:"network_id"`
	EnrollmentToken string `json:"enrollment_token"`
}

type PeerSet struct {
	Version int                        `json:"version"`
	Peers   map[string]json.RawMessage `json:"peers"`
}

type NetworkResource struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
}

type NodeRegistration struct {
	Version          int      `json:"version"`
	PublicKey        string   `json:"public_key"`
	ListenPort       int      `json:"listen_port"`
	PrimaryInterface string   `json:"primary_interface"`
	LocalAddresses   []string `json:"local_addresses"`
	PublicEndpoint   string   `json:"public_endpoint,omitempty"`
}

type RegisteredNode struct {
	NodeID        string `json:"node_id"`
	TunnelAddress string `json:"tunnel_address"`
}

// DecodeJoinToken validates and decodes an unpadded Base64URL join token.
func DecodeJoinToken(token string) (JoinBundle, error) {
	return DecodeJoinTokenWithInsecureHTTP(token, false)
}

// DecodeJoinTokenWithInsecureHTTP optionally permits plain HTTP API URLs for
// explicitly configured local or development services. HTTPS remains required
// unless allowInsecureHTTP is true.
func DecodeJoinTokenWithInsecureHTTP(token string, allowInsecureHTTP bool) (JoinBundle, error) {
	var bundle JoinBundle
	if len(token) == 0 || len(token) > maxBundleSize*2 {
		return bundle, errors.New("join token is empty or too large")
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(data) > maxBundleSize {
		return bundle, errors.New("join token is not valid unpadded Base64URL")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return JoinBundle{}, errors.New("join token has an invalid JSON bundle")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return JoinBundle{}, errors.New("join token must contain exactly one JSON object")
	}
	if bundle.Version != 1 || !validAPIToken(bundle.EnrollmentToken) || !validNetworkID(bundle.NetworkID) {
		return JoinBundle{}, errors.New("join token has an unsupported version or missing API token or network ID")
	}
	u, err := url.Parse(bundle.APIURL)
	if err != nil {
		return JoinBundle{}, errors.New("join token api_url is invalid")
	}
	localHTTP := u.Scheme == "http" && isLoopbackHost(u.Hostname())
	allowedScheme := u.Scheme == "https" || localHTTP || (allowInsecureHTTP && u.Scheme == "http")
	if !allowedScheme || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(bundle.APIURL, "#") || u.Opaque != "" {
		return JoinBundle{}, errors.New("join token api_url must be an absolute HTTPS URL, or HTTP to localhost or a loopback IP (or HTTP with --allow-insecure-http), without credentials, query or fragment")
	}
	if port := u.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return JoinBundle{}, errors.New("join token api_url is invalid")
		}
	}
	bundle.APIURL = strings.TrimRight(bundle.APIURL, "/")
	return bundle, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func validNetworkID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func validAPIToken(token string) bool {
	if len(token) == 0 || len(token) > 4096 {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < 0x21 || token[i] > 0x7e {
			return false
		}
	}
	return true
}

// Client calls the service with the shared API token from a validated bundle.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func New(bundle JoinBundle) *Client {
	return newClient(bundle, newAPIHTTPClient(bundle.APIURL))
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newAPIHTTPClient(apiURL string) *http.Client {
	client := newHTTPClient()
	u, err := url.Parse(apiURL)
	if err != nil || u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
		return client
	}
	client.Transport = &http.Transport{
		DialContext: dialLoopbackContext,
	}
	return client
}

func dialLoopbackContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if !isLoopbackRemoteAddress(conn.RemoteAddr()) {
		_ = conn.Close()
		return nil, errors.New("localhost HTTP API resolved to a non-loopback address")
	}
	return conn, nil
}

func isLoopbackRemoteAddress(address net.Addr) bool {
	remote, ok := address.(*net.TCPAddr)
	return ok && remote.IP.IsLoopback()
}

func newClient(bundle JoinBundle, client *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(bundle.APIURL, "/"), token: bundle.EnrollmentToken, http: client}
}

func (c *Client) PullNetwork(ctx context.Context, networkID string) ([]byte, error) {
	if !validID(networkID) {
		return nil, errors.New("network ID is invalid")
	}
	return c.request(ctx, http.MethodGet, "/api/v1/networks/"+url.PathEscape(networkID)+"/config", nil)
}

func (c *Client) GetNetwork(ctx context.Context, networkID string) (NetworkResource, error) {
	if !validID(networkID) {
		return NetworkResource{}, errors.New("network ID is invalid")
	}
	data, err := c.request(ctx, http.MethodGet, "/api/v1/networks/"+url.PathEscape(networkID), nil)
	if err != nil {
		return NetworkResource{}, err
	}
	var result NetworkResource
	if err := json.Unmarshal(data, &result); err != nil || result.ID != networkID || !validNetworkResource(result) {
		return NetworkResource{}, errors.New("service returned an invalid network")
	}
	return result, nil
}

func validNetworkResource(n NetworkResource) bool {
	prefix, err := netip.ParsePrefix(n.CIDR)
	return n.Version == 1 && validID(n.ID) && strings.TrimSpace(n.Name) != "" && len(n.Name) <= 128 && err == nil && prefix.Addr().Is4() && prefix == prefix.Masked() && prefix.Bits() >= 8 && prefix.Bits() <= 30 && privateIPv4Prefix(prefix)
}

func privateIPv4Prefix(prefix netip.Prefix) bool {
	for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		block, _ := netip.ParsePrefix(raw)
		if block.Contains(prefix.Addr()) && prefix.Bits() >= block.Bits() {
			return true
		}
	}
	return false
}

func (c *Client) PushNetwork(ctx context.Context, networkID string, config []byte) error {
	if !validID(networkID) {
		return errors.New("network ID is invalid")
	}
	_, err := c.request(ctx, http.MethodPut, "/api/v1/networks/"+url.PathEscape(networkID)+"/config", config)
	return err
}

func (c *Client) PullNode(ctx context.Context, networkID, nodeID string) ([]byte, error) {
	if !validID(networkID) || !validID(nodeID) {
		return nil, errors.New("network or node ID is invalid")
	}
	return c.request(ctx, http.MethodGet, "/api/v1/networks/"+url.PathEscape(networkID)+"/nodes/"+url.PathEscape(nodeID)+"/config", nil)
}

// PullPeers returns the other node documents registered for a network.
func (c *Client) PullPeers(ctx context.Context, networkID, nodeID string) (PeerSet, error) {
	if !validID(networkID) || !validID(nodeID) {
		return PeerSet{}, errors.New("network or node ID is invalid")
	}
	data, err := c.request(ctx, http.MethodGet, "/api/v1/networks/"+url.PathEscape(networkID)+"/nodes/"+url.PathEscape(nodeID)+"/peers", nil)
	if err != nil {
		return PeerSet{}, err
	}
	if !validPeerSet(data) {
		return PeerSet{}, errors.New("service returned an invalid peer list")
	}
	var result PeerSet
	if err := json.Unmarshal(data, &result); err != nil || result.Version != 1 || result.Peers == nil {
		return PeerSet{}, errors.New("service returned an invalid peer list")
	}
	return result, nil
}

func (c *Client) RegisterNode(ctx context.Context, networkID, nodeID string, registration NodeRegistration) (RegisteredNode, error) {
	if !validID(networkID) || !validID(nodeID) || !validNodeRegistration(registration) {
		return RegisteredNode{}, errors.New("node registration is invalid")
	}
	body, err := json.Marshal(registration)
	if err != nil {
		return RegisteredNode{}, errors.New("could not encode node registration")
	}
	data, err := c.request(ctx, http.MethodPut, "/api/v1/networks/"+url.PathEscape(networkID)+"/nodes/"+url.PathEscape(nodeID)+"/registration", body)
	if err != nil {
		return RegisteredNode{}, err
	}
	var result RegisteredNode
	if err := json.Unmarshal(data, &result); err != nil || result.NodeID != nodeID {
		return RegisteredNode{}, errors.New("service returned an invalid registration")
	}
	address, err := netip.ParseAddr(result.TunnelAddress)
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return RegisteredNode{}, errors.New("service returned an invalid tunnel address")
	}
	return result, nil
}

func validNodeRegistration(registration NodeRegistration) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(registration.PublicKey)
	if registration.Version != 1 || err != nil || len(key) != 32 || allZero(key) || base64.StdEncoding.EncodeToString(key) != registration.PublicKey || registration.ListenPort < 1 || registration.ListenPort > 65535 || strings.TrimSpace(registration.PrimaryInterface) == "" || len(registration.PrimaryInterface) > 64 || len(registration.LocalAddresses) == 0 || len(registration.LocalAddresses) > 16 {
		return false
	}
	for _, raw := range registration.LocalAddresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() == 0 || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsLoopback() || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() || prefix.Addr().Is4In6() {
			return false
		}
	}
	if registration.PublicEndpoint != "" {
		endpoint, err := netip.ParseAddrPort(registration.PublicEndpoint)
		if err != nil || endpoint.Port() == 0 || !endpoint.Addr().IsGlobalUnicast() || endpoint.Addr().Zone() != "" || endpoint.Addr().Is4In6() {
			return false
		}
	}
	return true
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func (c *Client) PushNode(ctx context.Context, networkID, nodeID string, config []byte) error {
	if !validID(networkID) || !validID(nodeID) {
		return errors.New("network or node ID is invalid")
	}
	_, err := c.request(ctx, http.MethodPut, "/api/v1/networks/"+url.PathEscape(networkID)+"/nodes/"+url.PathEscape(nodeID)+"/config", config)
	return err
}

func (c *Client) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if c.token == "" || c.http == nil {
		return nil, errors.New("service API client is not configured")
	}
	if len(body) > maxConfigSize {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	if body != nil && !validConfig(body) {
		return nil, errors.New("configuration must be a JSON object with version 1")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("could not create service API request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("service API request failed")
	}
	defer res.Body.Close()
	if method == http.MethodPut && res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if method == http.MethodPut && res.StatusCode == http.StatusOK {
		data, err := io.ReadAll(io.LimitReader(res.Body, maxConfigSize+1))
		if err != nil || len(data) > maxConfigSize || !validConfig(data) {
			return nil, errors.New("service returned an invalid registration")
		}
		return data, nil
	}
	if method == http.MethodGet && res.StatusCode == http.StatusOK {
		data, err := io.ReadAll(io.LimitReader(res.Body, maxConfigSize+1))
		if err != nil || len(data) > maxConfigSize || (!validConfig(data) && !validPeerSet(data)) {
			return nil, errors.New("service returned an invalid configuration")
		}
		return data, nil
	}
	return nil, fmt.Errorf("service API returned HTTP %d", res.StatusCode)
}

func validPeerSet(data []byte) bool {
	var value struct {
		Version int                        `json:"version"`
		Peers   map[string]json.RawMessage `json:"peers"`
	}
	if err := json.Unmarshal(data, &value); err != nil || value.Version != 1 || value.Peers == nil {
		return false
	}
	for id, config := range value.Peers {
		if !validID(id) || !validConfig(config) {
			return false
		}
	}
	return true
}

func validConfig(data []byte) bool {
	var value map[string]json.RawMessage
	if !json.Valid(data) || json.Unmarshal(data, &value) != nil || value == nil {
		return false
	}
	var version int
	return json.Unmarshal(value["version"], &version) == nil && version == 1
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}
