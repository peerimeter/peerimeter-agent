package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/discovery"
	"github.com/peerimeter/peerimeter-agent/internal/serviceapi"
	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
)

func refreshManagedRegistration(ctx context.Context, client *serviceapi.Client, networkID, nodeID, publicKey string, underlay discovery.Underlay, desired config.Config) error {
	registeredNodes, err := client.PullNetworkPeers(ctx, networkID)
	if err != nil {
		return fmt.Errorf("cannot read current node registration: %w", err)
	}
	raw, ok := registeredNodes.Peers[nodeID]
	if !ok {
		return errors.New("node is not registered in the selected network; run join again")
	}
	var previous registeredPeer
	if err := json.Unmarshal(raw, &previous); err != nil || previous.Version != 1 || previous.NodeID != nodeID || previous.TunnelAddress == "" {
		return errors.New("service returned an invalid current node registration")
	}

	if previous.PublicKey != publicKey {
		return errors.New("joined network key does not match the registered node; run join again")
	}
	address, err := netip.ParseAddr(previous.TunnelAddress)
	if err != nil || !configuredAddress(desired.Interface.Address, address) {
		return errors.New("registered tunnel address does not match the joined network configuration")
	}

	publicEndpoint := previous.PublicEndpoint
	if mapped, probeErr := stunprobe.Probe(desired.Interface.ListenPort, ""); probeErr == nil {
		publicEndpoint = mapped.MappedAddress
	}
	updated, err := client.RegisterNode(ctx, networkID, nodeID, serviceapi.NodeRegistration{
		Version: 1, PublicKey: publicKey, ListenPort: desired.Interface.ListenPort,
		PrimaryInterface: underlay.Name, LocalAddresses: underlay.Addresses,
		PublicEndpoint: publicEndpoint,
	})
	if err != nil {
		return fmt.Errorf("cannot refresh node registration: %w", err)
	}
	if updated.TunnelAddress != previous.TunnelAddress {
		return errors.New("service changed the registered tunnel address; run join to reconcile the local configuration")
	}
	return nil
}

func configuredAddress(prefixes []string, address netip.Addr) bool {
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Addr() == address {
			return true
		}
	}
	return false
}
