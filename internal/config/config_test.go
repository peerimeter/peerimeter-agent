package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture() Config {
	key := make([]byte, 32)
	key[0] = 1
	return Config{Version: 1, Mode: "static", Network: Network{ID: "network-home", Name: "Home Network"}, Interface: Interface{PrivateKeyFile: "keys/local.key", Address: []string{"10.80.0.1/32", "fd80::1/128"}, ListenPort: 51820}, Peers: []Peer{{PublicKey: base64.StdEncoding.EncodeToString(key), AllowedIPs: []string{"10.80.0.2/32", "fd80::2/128"}, Endpoint: "127.0.0.1:51821", PersistentKeepaliveSeconds: 25}}}
}
func TestValidate(t *testing.T) {
	for _, os := range []string{"linux", "darwin", "windows"} {
		if err := Validate(fixture(), os); err != nil {
			t.Fatalf("%s: %v", os, err)
		}
	}
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"version", func(c *Config) { c.Version = 2 }},
		{"mode", func(c *Config) { c.Mode = "managed" }},
		{"id", func(c *Config) { c.Network.ID = "bad/id" }},
		{"empty name", func(c *Config) { c.Network.Name = " \t" }},
		{"key reference", func(c *Config) { c.Interface.PrivateKeyFile = "" }},
		{"port", func(c *Config) { c.Interface.ListenPort = 65536 }},
		{"address", func(c *Config) { c.Interface.Address = []string{"not-a-cidr"} }},
		{"address overlap", func(c *Config) { c.Interface.Address = []string{"10.80.0.1/24", "10.80.0.2/32"} }},
		{"address default route", func(c *Config) { c.Interface.Address = []string{"10.80.0.1/0"} }},
		{"address multicast", func(c *Config) { c.Interface.Address = []string{"224.0.0.1/32"} }},
		{"mapped IPv6", func(c *Config) { c.Interface.Address = []string{"::ffff:10.80.0.1/128"} }},
		{"no peers", func(c *Config) { c.Peers = nil }},
		{"bad key", func(c *Config) { c.Peers[0].PublicKey = "secret-invalid-key" }},
		{"zero key", func(c *Config) { c.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"duplicate key", func(c *Config) { c.Peers = append(c.Peers, c.Peers[0]) }},
		{"hostname endpoint", func(c *Config) { c.Peers[0].Endpoint = "do-not-resolve.example:51820" }},
		{"zero endpoint port", func(c *Config) { c.Peers[0].Endpoint = "192.0.2.1:0" }},
		{"unspecified endpoint", func(c *Config) { c.Peers[0].Endpoint = "0.0.0.0:1" }},
		{"broadcast endpoint", func(c *Config) { c.Peers[0].Endpoint = "255.255.255.255:1" }},
		{"endpoint in local tunnel prefix", func(c *Config) {
			c.Interface.Address = []string{"10.80.0.1/24"}
			c.Peers[0].Endpoint = "10.80.0.3:51821"
		}},
		{"endpoint in own allowed route", func(c *Config) { c.Peers[0].Endpoint = "10.80.0.2:51821" }},
		{"endpoint in other peer route", func(c *Config) {
			p := c.Peers[0]
			b := make([]byte, 32)
			b[0] = 2
			p.PublicKey = base64.StdEncoding.EncodeToString(b)
			p.Endpoint = "10.80.0.2:51822"
			p.AllowedIPs = []string{"10.80.0.3/32"}
			c.Peers = append(c.Peers, p)
		}},
		{"keepalive", func(c *Config) { c.Peers[0].PersistentKeepaliveSeconds = -1 }},
		{"route host bits", func(c *Config) { c.Peers[0].AllowedIPs = []string{"10.80.0.2/24"} }},
		{"route owns local", func(c *Config) { c.Peers[0].AllowedIPs = []string{"10.80.0.0/24"} }},
		{"default route", func(c *Config) { c.Peers[0].AllowedIPs = []string{"0.0.0.0/0"} }},
		{"route duplicates", func(c *Config) { c.Peers[0].AllowedIPs = []string{"10.80.0.2/32", "10.80.0.2/32"} }},
		{"route overlaps peers", func(c *Config) {
			p := c.Peers[0]
			b := make([]byte, 32)
			b[0] = 2
			p.PublicKey = base64.StdEncoding.EncodeToString(b)
			p.Endpoint = "127.0.0.1:51822"
			c.Peers = append(c.Peers, p)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fixture()
			tc.change(&c)
			if err := Validate(c, "linux"); err == nil {
				t.Fatal("accepted invalid configuration")
			} else if strings.Contains(err.Error(), "secret-invalid-key") {
				t.Fatal("error leaked input")
			}
		})
	}
	c := fixture()
	c.Interface.Name = "wg-prod"
	if err := Validate(c, "linux"); err != nil {
		t.Fatal(err)
	}
	for _, os := range []string{"darwin", "windows"} {
		if err := Validate(c, os); err == nil {
			t.Fatalf("accepted Linux override on %s", os)
		}
	}
}
func TestLoadStrictAndRelativePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "static.json")
	data, err := json.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(string(data))
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interface.PrivateKeyFile != filepath.Join(dir, "keys", "local.key") {
		t.Fatal("key path not relative to config")
	}
	// Load must not require the referenced key to exist.
	if _, err := os.Stat(cfg.Interface.PrivateKeyFile); !os.IsNotExist(err) {
		t.Fatal("unexpected key fixture")
	}
	for name, mutate := range map[string]func(string) string{
		"duplicate":                  func(s string) string { return strings.Replace(s, `"version":1`, `"version":1,"version":1`, 1) },
		"case-insensitive duplicate": func(s string) string { return strings.Replace(s, `"version":1`, `"version":1,"Version":1`, 1) },
		"unknown": func(s string) string {
			return strings.Replace(s, `"mode":"static"`, `"mode":"static","password":"do-not-echo"`, 1)
		},
		"missing": func(s string) string { return strings.Replace(s, `"version":1,`, "", 1) },
		"empty explicit interface": func(s string) string {
			return strings.Replace(s, `"listen_port":51820`, `"listen_port":51820,"name":""`, 1)
		},
		"case spelling": func(s string) string { return strings.Replace(s, `"version":1`, `"VERSION":1`, 1) },
		"trailing":      func(s string) string { return s + ` {}` },
		"null":          func(s string) string { return strings.Replace(s, `"name":"Home Network"`, `"name":null`, 1) },
		"type":          func(s string) string { return strings.Replace(s, `"version":1`, `"version":"do-not-echo"`, 1) },
		"syntax":        func(s string) string { return `{"secret":"do-not-echo"` },
	} {
		t.Run(name, func(t *testing.T) {
			write(mutate(string(data)))
			_, err := Load(path)
			if err == nil {
				t.Fatal("accepted malformed JSON")
			}
			if strings.Contains(err.Error(), "do-not-echo") {
				t.Fatal("error leaked input")
			}
		})
	}
	write(strings.Repeat(" ", MaxSize+1))
	if _, err := Load(path); err == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestPublicTemplates(t *testing.T) {
	for _, name := range []string{"peer-a.json", "peer-b.json"} {
		cfg, err := Load(filepath.Join("..", "..", "examples", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(cfg.Peers) != 1 {
			t.Fatal("each template must describe the other peer")
		}
	}
}
