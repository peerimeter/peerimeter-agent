package platform

import (
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/config"
)

func TestCloneDesiredCopiesNestedConfiguration(t *testing.T) {
	original := Desired{Config: config.Config{
		Interface: config.Interface{Address: []string{"10.0.0.1/32"}},
		Peers:     []config.Peer{{AllowedIPs: []string{"10.0.0.2/32"}}},
	}}
	cloned := cloneDesired(original)
	cloned.Config.Interface.Address[0] = "10.0.0.3/32"
	cloned.Config.Peers[0].AllowedIPs[0] = "10.0.0.4/32"
	cloned.Config.Peers[0].PublicKey = "changed"
	if original.Config.Interface.Address[0] != "10.0.0.1/32" ||
		original.Config.Peers[0].AllowedIPs[0] != "10.0.0.2/32" || original.Config.Peers[0].PublicKey != "" {
		t.Fatal("clone shares mutable configuration with its source")
	}
}
