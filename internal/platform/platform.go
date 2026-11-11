// Package platform defines the native networking boundary. Implementations own
// their interfaces/routes and must never remove unrelated OS resources.
package platform

import (
	"context"
	"errors"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
)

var ErrUnavailable = errors.New("native WireGuard agent runtime is unavailable in Phase 0; Phase 1 implements tunnel and service management")

// Desired includes private material only in memory; never serialize or log it.
type Desired struct {
	Config        config.Config
	InterfaceName string
	PrivateKey    [32]byte
}
type PeerState struct {
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	ReceivedBytes uint64    `json:"received_bytes"`
	SentBytes     uint64    `json:"sent_bytes"`
}
type Snapshot struct {
	NetworkID     string      `json:"network_id"`
	InterfaceName string      `json:"interface_name"`
	State         string      `json:"state"`
	Peers         []PeerState `json:"peers"`
}

// Backend opens the native tunnel only after complete configuration validation.
// On partial failure it must roll back resources created by that call.
type Backend interface {
	Start(context.Context, Desired) (Session, error)
	Inspect(context.Context) (Snapshot, error)
}

// Session applies desired state without resetting unaffected peers. Close must
// be idempotent and remove only resources owned by this session.
type Session interface {
	Reconcile(context.Context, Desired) error
	Snapshot(context.Context) (Snapshot, error)
	Close(context.Context) error
}

// Native makes the incomplete implementation explicit; no fake running tunnel.
func Native() Backend { return unavailable{} }

type unavailable struct{}

func (unavailable) Start(context.Context, Desired) (Session, error) { return nil, ErrUnavailable }
func (unavailable) Inspect(context.Context) (Snapshot, error)       { return Snapshot{}, ErrUnavailable }
