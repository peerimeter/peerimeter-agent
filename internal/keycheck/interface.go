// Package keycheck validates the relationship between a configuration's
// interface key and its peer public keys.
package keycheck

import (
	"encoding/base64"
	"errors"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

func LoadAndVerifyInterfaceKey(cfg config.Config) ([32]byte, error) {
	key, err := secret.Load(cfg.Interface.PrivateKeyFile)
	if err != nil {
		return [32]byte{}, err
	}
	public, err := secret.Public(key)
	if err != nil {
		return [32]byte{}, err
	}
	encodedPublic := base64.StdEncoding.EncodeToString(public[:])
	for _, peer := range cfg.Peers {
		if peer.PublicKey == encodedPublic {
			return [32]byte{}, errors.New("peer public key matches the local interface key")
		}
	}
	return key, nil
}
