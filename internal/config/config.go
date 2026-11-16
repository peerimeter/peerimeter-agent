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

const MaxSize = 1 << 20

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
	if !identifier(cfg.Network.ID) {
		return invalid("network.id must be a 1–128 byte ASCII identifier")
	}
	if strings.TrimSpace(cfg.Network.Name) == "" || len(cfg.Network.Name) > 128 || strings.IndexFunc(cfg.Network.Name, unicode.IsControl) >= 0 {
		return invalid("network.name must be nonempty, at most 128 bytes, without control characters")
	}
	if cfg.Network.CIDR != "" {
		prefix, err := netip.ParsePrefix(cfg.Network.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 8 || prefix.Bits() > 30 || !prefix.Addr().IsPrivate() {
			return invalid("network.cidr must be a canonical private IPv4 prefix between /8 and /30")
		}
	}
	if strings.TrimSpace(cfg.Interface.PrivateKeyFile) == "" || strings.ContainsRune(cfg.Interface.PrivateKeyFile, 0) {
		return invalid("interface.private_key_file is required")
	}
	if cfg.Interface.ListenPort < 1 || cfg.Interface.ListenPort > 65535 {
		return invalid("interface.listen_port must be 1–65535")
	}
	if cfg.Interface.Name != "" {
		if targetOS != "linux" {
			return invalid("interface.name is supported only on Linux")
		}
		if !interfaceName(cfg.Interface.Name) {
			return invalid("interface.name must be a safe Linux interface name of at most 15 bytes")
		}
	}
	if len(cfg.Interface.Address) == 0 || len(cfg.Interface.Address) > 16 {
		return invalid("interface.address requires 1–16 prefixes")
	}
	var local []netip.Prefix
	for _, raw := range cfg.Interface.Address {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Bits() == 0 || !usable(p.Addr()) || p.Addr().Is4In6() {
			return invalid("interface.address contains an invalid unicast prefix")
		}
		for _, prev := range local {
			if p.Overlaps(prev) {
				return invalid("interface.address contains overlapping prefixes")
			}
		}
		local = append(local, p)
	}
	if len(cfg.Peers) > 1024 {
		return invalid("peers supports at most 1024 entries")
	}
	keys := map[string]bool{}
	var routes []netip.Prefix
	endpoints := map[netip.AddrPort]bool{}
	for i, peer := range cfg.Peers {
		field := fmt.Sprintf("peers[%d]", i)
		key, err := base64.StdEncoding.Strict().DecodeString(peer.PublicKey)
		if err != nil || len(key) != 32 || allZero(key) || base64.StdEncoding.EncodeToString(key) != peer.PublicKey {
			return invalid(field + ".public_key must be a canonical nonzero 32-byte base64 key")
		}
		if keys[peer.PublicKey] {
			return invalid(field + ".public_key is duplicated")
		}
		keys[peer.PublicKey] = true
		ep, err := netip.ParseAddrPort(peer.Endpoint)
		if err != nil || ep.Port() == 0 || (!ep.Addr().IsGlobalUnicast() && !ep.Addr().IsLoopback()) || ep.Addr().Zone() != "" || ep.Addr().Is4In6() {
			return invalid(field + ".endpoint must be a numeric unicast IP:port")
		}
		if endpoints[ep] {
			return invalid(field + ".endpoint is duplicated")
		}
		endpoints[ep] = true
		for _, own := range local {
			if own.Contains(ep.Addr()) {
				return invalid(field + ".endpoint falls inside a local tunnel prefix")
			}
		}
		if peer.PersistentKeepaliveSeconds < 0 || peer.PersistentKeepaliveSeconds > 65535 {
			return invalid(field + ".persistent_keepalive_seconds must be 0–65535")
		}
		if len(peer.AllowedIPs) == 0 || len(peer.AllowedIPs) > 256 {
			return invalid(field + ".allowed_ips requires 1–256 prefixes")
		}
		for _, raw := range peer.AllowedIPs {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p != p.Masked() || p.Bits() == 0 || !usable(p.Addr()) || p.Addr().Is4In6() {
				return invalid(field + ".allowed_ips contains an invalid canonical unicast prefix (default routes are unsupported)")
			}
			for _, own := range local {
				if p.Contains(own.Addr()) {
					return invalid(field + ".allowed_ips contains a local interface address")
				}
			}
			for _, prev := range routes {
				if p.Overlaps(prev) {
					return invalid(field + ".allowed_ips overlaps another configured route")
				}
			}
			if len(routes) >= 4096 {
				return invalid("allowed_ips exceeds 4096 total routes")
			}
			routes = append(routes, p)
		}
	}
	for endpoint := range endpoints {
		for _, route := range routes {
			if route.Contains(endpoint.Addr()) {
				return invalid("peer endpoint falls inside a tunnel route")
			}
		}
	}
	return nil
}
func usable(a netip.Addr) bool { return a.IsValid() && a.IsGlobalUnicast() && a.Zone() == "" }
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}
func interfaceName(s string) bool { return len(s) <= 15 && identifier(s) }

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
