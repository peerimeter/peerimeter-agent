// Package secret handles protected local WireGuard key files. Callers must not
// log keys or serialize them into general configuration or diagnostic output.
package secret

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
)

// Generate returns a freshly generated, clamped X25519 WireGuard private key.
func Generate() ([32]byte, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return [32]byte{}, errors.New("generate private key: random source failed")
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

// Public derives the WireGuard public key without exposing private material.
func Public(key [32]byte) ([32]byte, error) {
	if key == [32]byte{} {
		return [32]byte{}, errors.New("private key must not be zero")
	}
	private, err := ecdh.X25519().NewPrivateKey(key[:])
	if err != nil {
		return [32]byte{}, errors.New("derive public key: invalid private key")
	}
	var public [32]byte
	copy(public[:], private.PublicKey().Bytes())
	return public, nil
}

// Load checks the opened file's security and reads a base64-encoded 32-byte
// private key. Error messages deliberately omit paths and file contents.
func Load(path string) ([32]byte, error) {
	f, err := openProtected(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil || len(data) > 128 {
		return [32]byte{}, errors.New("read private key: unreadable or oversized file")
	}
	encoded := strings.TrimSpace(string(data))
	if len(encoded) != 44 {
		return [32]byte{}, errors.New("private key: expected a base64-encoded 32-byte key")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, errors.New("private key: expected a base64-encoded 32-byte key")
	}
	var key [32]byte
	copy(key[:], decoded)
	if key == [32]byte{} {
		return [32]byte{}, errors.New("private key must not be zero")
	}
	return key, nil
}

// WriteNew creates a key file with private permissions at creation time. It
// refuses to replace an existing file. The containing directory must be trusted.
func WriteNew(path string, key [32]byte) error {
	if key == [32]byte{} {
		return errors.New("private key must not be zero")
	}
	f, err := createProtected(path)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		f.Close()
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	if _, err := io.WriteString(f, base64.StdEncoding.EncodeToString(key[:])+"\n"); err != nil {
		return errors.New("write private key: write failed")
	}
	if err := f.Sync(); err != nil {
		return errors.New("write private key: sync failed")
	}
	if err := f.Close(); err != nil {
		return errors.New("write private key: close failed")
	}
	succeeded = true
	return nil
}
