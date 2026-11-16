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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxConfigSize = 1 << 20
const maxBundleSize = 8 << 10

// JoinBundle is the decoded Base64URL JSON token returned by the service.
// enrollment_token is currently the service's shared static API key.
type JoinBundle struct {
	Version         int    `json:"version"`
	APIURL          string `json:"api_url"`
	EnrollmentToken string `json:"enrollment_token"`
}

// DecodeJoinToken validates and decodes an unpadded Base64URL join token.
func DecodeJoinToken(token string) (JoinBundle, error) {
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
	if bundle.Version != 1 || !validAPIToken(bundle.EnrollmentToken) {
		return JoinBundle{}, errors.New("join token has an unsupported version or missing API token")
	}
	u, err := url.Parse(bundle.APIURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(bundle.APIURL, "#") || u.Opaque != "" {
		return JoinBundle{}, errors.New("join token api_url must be an absolute HTTPS URL without credentials, query or fragment")
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
	return newClient(bundle, newHTTPClient())
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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
	if method == http.MethodGet && res.StatusCode == http.StatusOK {
		data, err := io.ReadAll(io.LimitReader(res.Body, maxConfigSize+1))
		if err != nil || len(data) > maxConfigSize || !validConfig(data) {
			return nil, errors.New("service returned an invalid configuration")
		}
		return data, nil
	}
	return nil, fmt.Errorf("service API returned HTTP %d", res.StatusCode)
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
