// Package config defines the offline static configuration contract. It performs
// no network access and never opens a referenced private key.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/peerimeter/peerimeter-agent/internal/diagnostic"
)

const (
	MaxSize               = 1 << 20
	maxIdentifierBytes    = 128
	maxNetworkNameBytes   = 128
	maxInterfaceAddresses = 16
	maxPeers              = 1024
	maxAllowedIPsPerPeer  = 256
	maxTotalRoutes        = 4096
	maxListenPort         = 65535
)

// Config is the version 1 static configuration. Keep credentials in a separate
// protected file; they must never be embedded in this structure.
type Config struct {
	Version   int       `json:"version" yaml:"version"`
	Mode      string    `json:"mode" yaml:"mode"`
	Network   Network   `json:"network" yaml:"network"`
	Interface Interface `json:"interface" yaml:"interface"`
	Peers     []Peer    `json:"peers" yaml:"peers"`
}
type Network struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
	CIDR string `json:"cidr,omitempty" yaml:"cidr,omitempty"`
}
type Interface struct {
	PrivateKeyFile string   `json:"private_key_file" yaml:"private_key_file"`
	Address        []string `json:"address" yaml:"address"`
	ListenPort     int      `json:"listen_port" yaml:"listen_port"`
	Name           string   `json:"name,omitempty" yaml:"name,omitempty"`
}
type Peer struct {
	PublicKey                  string   `json:"public_key" yaml:"public_key"`
	AllowedIPs                 []string `json:"allowed_ips" yaml:"allowed_ips"`
	Endpoint                   string   `json:"endpoint" yaml:"endpoint"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds,omitempty" yaml:"persistent_keepalive_seconds,omitempty"`
}

// Load strictly decodes and validates a config for this OS. Relative key paths
// resolve against the config file directory, independently of the working directory.
func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, diagnostic.Wrap(fmt.Errorf("open static config %q: %w", path, err))
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return cfg, diagnostic.Wrap(fmt.Errorf("read static config %q: %w", path, err))
	}
	if len(data) > MaxSize {
		return cfg, diagnostic.Wrap(errors.New("static config exceeds 1 MiB"))
	}
	if err := checkYAML(data); err != nil {
		return cfg, diagnostic.Wrap(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, diagnostic.Wrap(fmt.Errorf("decode static YAML config %q (check field names and value types)", path))
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, diagnostic.Wrap(errors.New("static config must contain exactly one YAML document"))
	}
	if err := Validate(cfg, runtime.GOOS); err != nil {
		return Config{}, diagnostic.Wrap(err)
	}
	if !filepath.IsAbs(cfg.Interface.PrivateKeyFile) {
		cfg.Interface.PrivateKeyFile = filepath.Join(filepath.Dir(path), cfg.Interface.PrivateKeyFile)
	}
	cfg.Interface.PrivateKeyFile, err = filepath.Abs(cfg.Interface.PrivateKeyFile)
	if err != nil {
		return Config{}, diagnostic.Wrap(fmt.Errorf("resolve private key path %q from static config %q: %w", cfg.Interface.PrivateKeyFile, path, err))
	}
	return cfg, nil
}

func MarshalYAML(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func invalid(field string) error { return fmt.Errorf("invalid static config: %s", field) }

// Validate checks the complete desired state before any OS changes. Endpoints
// must be numeric IP:port literals: validation never performs DNS lookups.
func Validate(cfg Config, targetOS string) error {
	if targetOS != "linux" && targetOS != "darwin" && targetOS != "windows" {
		return invalid("unsupported operating system")
	}
	if cfg.Version != 1 {
		return invalid("version must be 1")
	}
	if cfg.Mode != "static" {
		return invalid("mode must be static")
	}
	if !ValidIdentifier(cfg.Network.ID) {
		return invalid("network.id must be a 1–128 byte ASCII identifier")
	}
	if strings.TrimSpace(cfg.Network.Name) == "" || len(cfg.Network.Name) > maxNetworkNameBytes || strings.IndexFunc(cfg.Network.Name, unicode.IsControl) >= 0 {
		return invalid("network.name must be nonempty, at most 128 bytes, without control characters")
	}
	if cfg.Network.CIDR != "" {
		prefix, err := netip.ParsePrefix(cfg.Network.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 8 || prefix.Bits() > 30 || !IsPrivateIPv4Prefix(prefix) {
			return invalid("network.cidr must be a canonical private IPv4 prefix between /8 and /30")
		}
	}
	local, err := validateInterface(cfg.Interface, targetOS)
	if err != nil {
		return err
	}
	if len(cfg.Peers) > maxPeers {
		return invalid(fmt.Sprintf("peers supports at most %d entries", maxPeers))
	}
	state := peerValidationState{keys: map[string]bool{}, endpoints: map[netip.AddrPort]bool{}}
	for i, peer := range cfg.Peers {
		if err := validatePeer(i, peer, local, &state); err != nil {
			return err
		}
	}
	for endpoint := range state.endpoints {
		for _, route := range state.routes {
			if route.Contains(endpoint.Addr()) {
				return invalid("peer endpoint falls inside a tunnel route")
			}
		}
	}
	return nil
}

type peerValidationState struct {
	keys      map[string]bool
	endpoints map[netip.AddrPort]bool
	routes    []netip.Prefix
}

func validateInterface(iface Interface, targetOS string) ([]netip.Prefix, error) {
	if strings.TrimSpace(iface.PrivateKeyFile) == "" || strings.ContainsRune(iface.PrivateKeyFile, 0) {
		return nil, invalid("interface.private_key_file is required")
	}
	if iface.ListenPort < 1 || iface.ListenPort > maxListenPort {
		return nil, invalid("interface.listen_port must be 1–65535")
	}
	if iface.Name != "" {
		if targetOS != "linux" {
			return nil, invalid("interface.name is supported only on Linux")
		}
		if !interfaceName(iface.Name) {
			return nil, invalid("interface.name must be a safe Linux interface name of at most 15 bytes")
		}
	}
	if len(iface.Address) == 0 || len(iface.Address) > maxInterfaceAddresses {
		return nil, invalid("interface.address requires 1–16 prefixes")
	}
	var local []netip.Prefix
	for _, raw := range iface.Address {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() == 0 || !usable(prefix.Addr()) || prefix.Addr().Is4In6() {
			return nil, invalid("interface.address contains an invalid unicast prefix")
		}
		for _, previous := range local {
			if prefix.Overlaps(previous) {
				return nil, invalid("interface.address contains overlapping prefixes")
			}
		}
		local = append(local, prefix)
	}
	return local, nil
}

func validatePeer(index int, peer Peer, local []netip.Prefix, state *peerValidationState) error {
	field := fmt.Sprintf("peers[%d]", index)
	key, err := base64.StdEncoding.Strict().DecodeString(peer.PublicKey)
	if err != nil || len(key) != 32 || IsAllZeroKey(key) || base64.StdEncoding.EncodeToString(key) != peer.PublicKey {
		return invalid(field + ".public_key must be a canonical nonzero 32-byte base64 key")
	}
	if state.keys[peer.PublicKey] {
		return invalid(field + ".public_key is duplicated")
	}
	state.keys[peer.PublicKey] = true
	endpoint, err := netip.ParseAddrPort(peer.Endpoint)
	if err != nil || endpoint.Port() == 0 || (!endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLoopback()) || endpoint.Addr().Zone() != "" || endpoint.Addr().Is4In6() {
		return invalid(field + ".endpoint must be a numeric unicast IP:port")
	}
	if state.endpoints[endpoint] {
		return invalid(field + ".endpoint is duplicated")
	}
	state.endpoints[endpoint] = true
	for _, own := range local {
		if own.Contains(endpoint.Addr()) {
			return invalid(field + ".endpoint falls inside a local tunnel prefix")
		}
	}
	if peer.PersistentKeepaliveSeconds < 0 || peer.PersistentKeepaliveSeconds > maxListenPort {
		return invalid(field + ".persistent_keepalive_seconds must be 0–65535")
	}
	if len(peer.AllowedIPs) == 0 || len(peer.AllowedIPs) > maxAllowedIPsPerPeer {
		return invalid(field + ".allowed_ips requires 1–256 prefixes")
	}
	for _, raw := range peer.AllowedIPs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || !usable(prefix.Addr()) || prefix.Addr().Is4In6() {
			return invalid(field + ".allowed_ips contains an invalid canonical unicast prefix (default routes are unsupported)")
		}
		for _, own := range local {
			if prefix.Contains(own.Addr()) {
				return invalid(field + ".allowed_ips contains a local interface address")
			}
		}
		for _, previous := range state.routes {
			if prefix.Overlaps(previous) {
				return invalid(field + ".allowed_ips overlaps another configured route")
			}
		}
		if len(state.routes) >= maxTotalRoutes {
			return invalid("allowed_ips exceeds 4096 total routes")
		}
		state.routes = append(state.routes, prefix)
	}
	return nil
}

func IsPrivateIPv4Prefix(prefix netip.Prefix) bool {
	for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		block, _ := netip.ParsePrefix(raw)
		if block.Contains(prefix.Addr()) && prefix.Bits() >= block.Bits() {
			return true
		}
	}
	return false
}
func usable(a netip.Addr) bool { return a.IsValid() && a.IsGlobalUnicast() && a.Zone() == "" }
func IsAllZeroKey(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func ValidIdentifier(s string) bool {
	if len(s) == 0 || len(s) > maxIdentifierBytes {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}
func interfaceName(s string) bool { return len(s) <= 15 && ValidIdentifier(s) }

func checkYAML(data []byte) error {
	bad := errors.New("static config contains invalid YAML structure")
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return errors.New("static config contains invalid YAML")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return bad
	}
	var walk func(*yaml.Node, int, string) error
	walk = func(node *yaml.Node, depth int, path string) error {
		if depth > 32 || node.Kind == yaml.AliasNode || node.Tag == "!!null" {
			return bad
		}
		switch node.Kind {
		case yaml.MappingNode:
			seen := make(map[string]bool, len(node.Content)/2)
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i], node.Content[i+1]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] || key.Value == "<<" {
					return bad
				}
				seen[key.Value] = true
				childPath := key.Value
				if path != "" {
					childPath = path + "." + key.Value
				}
				switch childPath {
				case "version", "interface.listen_port", "peers.persistent_keepalive_seconds":
					if value.Kind != yaml.ScalarNode || value.Tag != "!!int" {
						return errors.New("static config contains an invalid integer field")
					}
				}
				if childPath == "interface.name" && (value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "") {
					return errors.New("static config contains an invalid interface.name")
				}
				if err := walk(value, depth+1, childPath); err != nil {
					return err
				}
			}
		case yaml.SequenceNode:
			for _, child := range node.Content {
				if err := walk(child, depth+1, path); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(document.Content[0], 0, "")
}
