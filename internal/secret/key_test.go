package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustGenerate(t *testing.T) [32]byte {
	t.Helper()
	key, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGenerateAndPublic(t *testing.T) {
	key := mustGenerate(t)
	if key == mustGenerate(t) || key[0]&7 != 0 || key[31]&128 != 0 || key[31]&64 == 0 {
		t.Fatal("private keys must be random and clamped")
	}
	// RFC 7748 Alice X25519 test vector, also the WireGuard public-key
	// derivation primitive. The private vector is public test data.
	input, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	var private [32]byte
	copy(private[:], input)
	public, err := Public(private)
	if err != nil || hex.EncodeToString(public[:]) != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("public-key derivation did not match RFC 7748: %v", err)
	}
	if _, err := Public([32]byte{}); err == nil {
		t.Fatal("zero private key accepted")
	}
}

func TestWriteLoadRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	key := mustGenerate(t)
	if err := WriteNew(path, key); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got != key {
		t.Fatalf("protected key round trip failed: %v", err)
	}
	if err := WriteNew(path, mustGenerate(t)); err == nil {
		t.Fatal("overwrote an existing key")
	}
	got, err = Load(path)
	if err != nil || got != key {
		t.Fatal("existing key changed after refused overwrite")
	}
}

func TestInvalidFilesAndRedaction(t *testing.T) {
	key := mustGenerate(t)
	encoded := base64.StdEncoding.EncodeToString(key[:])
	for name, data := range map[string]string{
		"invalid":  "PRIVATE-MATERIAL-must-not-be-echoed",
		"zero":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"size":     strings.Repeat(encoded, 4),
		"padding":  encoded[:len(encoded)-1],
		"multiple": encoded + "\n" + encoded,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sensitive-path.key")
			f, err := createProtected(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(data); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("accepted invalid private key")
			} else if strings.Contains(err.Error(), data) || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "PRIVATE-MATERIAL") {
				t.Fatal("error discloses sensitive material or path")
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("missing key accepted")
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("directory accepted as a key")
	}
	path := filepath.Join(t.TempDir(), "zero.key")
	if err := WriteNew(path, [32]byte{}); err == nil {
		t.Fatal("wrote a zero key")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("zero key attempt created a file")
	}
}

func TestHardLinkRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.key")
	if err := WriteNew(path, mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hardlink.key")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("hard-linked key accepted")
	}
}

func TestNewFileIsBase64(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	key := mustGenerate(t)
	if err := WriteNew(path, key); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte(base64.StdEncoding.EncodeToString(key[:])+"\n")) {
		t.Fatal("key encoding is not standard WireGuard base64")
	}
}
