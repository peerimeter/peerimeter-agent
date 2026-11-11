// Package config defines the offline static configuration contract. It performs
// no network access and never opens a referenced private key.
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxSize = 1 << 20

// Config is the version 1 static configuration. Keep credentials in a separate
// protected file; they must never be embedded in this structure.
type Config struct {
	Version   int       `json:"version"`
	Mode      string    `json:"mode"`
	Network   Network   `json:"network"`
	Interface Interface `json:"interface"`
	Peers     []Peer    `json:"peers"`
}
type Network struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Interface struct {
	PrivateKeyFile string   `json:"private_key_file"`
	Address        []string `json:"address"`
	ListenPort     int      `json:"listen_port"`
	Name           string   `json:"name,omitempty"`
}
type Peer struct {
	PublicKey                  string   `json:"public_key"`
	AllowedIPs                 []string `json:"allowed_ips"`
	Endpoint                   string   `json:"endpoint"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds,omitempty"`
}

// Load strictly decodes and validates a config for this OS. Relative key paths
// resolve against the config file directory, independently of the working directory.
func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, errors.New("cannot open static config")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return cfg, errors.New("cannot read static config")
	}
	if len(data) > MaxSize {
		return cfg, errors.New("static config exceeds 1 MiB")
	}
	if err := checkJSON(data); err != nil {
		return cfg, err
	}
	if err := checkShape(data); err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, errors.New("static config has invalid fields or field types")
	}
	if err := Validate(cfg, runtime.GOOS); err != nil {
		return Config{}, err
	}
	if !filepath.IsAbs(cfg.Interface.PrivateKeyFile) {
		cfg.Interface.PrivateKeyFile = filepath.Join(filepath.Dir(path), cfg.Interface.PrivateKeyFile)
	}
	cfg.Interface.PrivateKeyFile, err = filepath.Abs(cfg.Interface.PrivateKeyFile)
	if err != nil {
		return Config{}, errors.New("cannot resolve private key path")
	}
	return cfg, nil
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
	if len(cfg.Peers) == 0 || len(cfg.Peers) > 1024 {
		return invalid("peers requires 1–1024 entries")
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

// checkJSON rejects duplicate members, trailing values, nulls and excessive
// nesting before decoding structs. Error text intentionally excludes input data.
func checkJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("static config must contain valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("static config exceeds maximum JSON nesting")
		}
		tok, err := dec.Token()
		if err != nil || tok == nil {
			return errors.New("static config contains invalid JSON or null")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return errors.New("static config contains invalid JSON")
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("static config contains duplicate or invalid JSON members")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("static config contains invalid JSON")
			}
		case '[':
			for dec.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("static config contains invalid JSON")
			}
		default:
			return errors.New("static config contains invalid JSON")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("static config must contain exactly one JSON value")
	}
	return nil
}

// checkShape makes member spelling case-sensitive and distinguishes required
// members from zero values, unlike encoding/json's default struct matching.
func checkShape(data []byte) error {
	bad := errors.New("static config contains unknown or missing fields")
	object := func(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
		var m map[string]json.RawMessage
		if json.Unmarshal(data, &m) != nil || m == nil {
			return nil, bad
		}
		allowed := map[string]bool{}
		for _, k := range required {
			allowed[k] = true
			if _, ok := m[k]; !ok {
				return nil, bad
			}
		}
		for _, k := range optional {
			allowed[k] = true
		}
		for k := range m {
			if !allowed[k] {
				return nil, bad
			}
		}
		return m, nil
	}
	root, err := object(data, []string{"version", "mode", "network", "interface", "peers"}, nil)
	if err != nil {
		return err
	}
	if _, err = object(root["network"], []string{"id", "name"}, nil); err != nil {
		return err
	}
	iface, err := object(root["interface"], []string{"private_key_file", "address", "listen_port"}, []string{"name"})
	if err != nil {
		return err
	}
	if raw, ok := iface["name"]; ok {
		var name string
		if json.Unmarshal(raw, &name) != nil || name == "" {
			return bad
		}
	}
	var peers []json.RawMessage
	if json.Unmarshal(root["peers"], &peers) != nil {
		return bad
	}
	for _, p := range peers {
		if _, err = object(p, []string{"public_key", "allowed_ips", "endpoint"}, []string{"persistent_keepalive_seconds"}); err != nil {
			return err
		}
	}
	return nil
}
