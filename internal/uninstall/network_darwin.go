package uninstall

import (
	"context"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
)

// Native utun adapters and their interface routes are descriptor-scoped. The
// exclusive persistent-state lock proves the owning agent has shut down; the OS
// releases its utun handle when that process exits. Never guess another utun ID.
func cleanupOwnedNetwork(ctx context.Context, _ installstate.Profile) error { return ctx.Err() }
func scheduleRemoval(removalPlan) (string, error) {
	return "", errors.New("deferred removal is only used on Windows")
}
