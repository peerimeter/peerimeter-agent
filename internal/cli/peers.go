package cli

import (
	"encoding/json"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
	"github.com/spf13/cobra"
)

type networkPeerSnapshot struct {
	NetworkID   string               `json:"network_id"`
	NetworkName string               `json:"network_name"`
	Interface   string               `json:"interface_name"`
	Peers       []platform.PeerState `json:"peers"`
}

func newPeerViewCommand(app *application) *cobra.Command {
	var options paths.Options
	var networkID string
	cmd := &cobra.Command{Use: "wg", Short: "Show interfaces and peers for configured networks (defaults to show)", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		snapshots, readErr := readNetworkSnapshots(cmd.Context(), layout, networkID)
		if len(snapshots) == 0 {
			return readErr
		}
		if app.jsonOutput {
			if len(snapshots) == 1 {
				if err := json.NewEncoder(app.out).Encode(snapshots[0].Peers); err != nil {
					return err
				}
				return readErr
			}
			networks := make([]networkPeerSnapshot, 0, len(snapshots))
			for _, snapshot := range snapshots {
				networks = append(networks, networkPeerSnapshot{NetworkID: snapshot.NetworkID, NetworkName: snapshot.NetworkName, Interface: snapshot.InterfaceName, Peers: snapshot.Peers})
			}
			if err := json.NewEncoder(app.out).Encode(struct {
				Networks []networkPeerSnapshot `json:"networks"`
			}{Networks: networks}); err != nil {
				return err
			}
			return readErr
		}
		for i, snapshot := range snapshots {
			if i > 0 {
				if _, err := app.out.Write([]byte("\n")); err != nil {
					return err
				}
			}
			if err := presentation.PeerList(app.out, snapshot, time.Now(), shouldColor(app.out, app.color)); err != nil {
				return err
			}
		}
		return readErr
	})}
	directoryFlagSet(cmd.PersistentFlags(), &options)
	cmd.PersistentFlags().StringVar(&networkID, "network", "", "Configured network ID (defaults to all networks)")
	return cmd
}
