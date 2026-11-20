package platform

import "github.com/peerimeter/peerimeter-agent/internal/config"

const defaultTunnelMTU = 1420

func cloneDesired(desired Desired) Desired {
	desired.Config.Interface.Address = append([]string(nil), desired.Config.Interface.Address...)
	desired.Config.Peers = append([]config.Peer(nil), desired.Config.Peers...)
	for i := range desired.Config.Peers {
		desired.Config.Peers[i].AllowedIPs = append([]string(nil), desired.Config.Peers[i].AllowedIPs...)
	}
	return desired
}
