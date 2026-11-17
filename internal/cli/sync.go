package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/discovery"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

func newSyncCommand(app *application) *cobra.Command {
	var networkID, nodeID, apiURL, configPath string
	var allowInsecureHTTP bool
	var dirs paths.Options
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Refresh joined peers and reconcile the running agent",
		Long:  "When a joined network has saved Service API metadata, sync pulls its current peer list, updates the local network configuration, and reloads the running tunnel. Otherwise it reloads the local configuration as before. With multiple joined networks, --network-id is required. Older joins may need --api-url and --node-id once.",
		Args:  noArguments,
		RunE: app.handleResponse(func(cmd *cobra.Command) error {
			layout, err := paths.Resolve(dirs)
			if err != nil {
				return err
			}
			networks, err := managedNetworkIDs(layout.StateDir)
			if err != nil {
				return err
			}
			if len(networks) == 0 && networkID == "" {
				return local.Request(cmd.Context(), layout.RuntimeDir, "reload", app.out)
			}
			if len(networks) == 0 {
				return errors.New("no joined network credentials found; run join before syncing Service API peers")
			}
			if networkID == "" {
				switch len(networks) {
				case 1:
					networkID = networks[0]
				default:
					return fmt.Errorf("--network-id is required when multiple networks are joined (%s)", strings.Join(networks, ", "))
				}
			} else {
				found := false
				for _, joinedID := range networks {
					if joinedID == networkID {
						found = true
						break
					}
				}
				if !found {
					return errors.New("no saved credential found for --network-id")
				}
			}

			metadata, metadataErr := readManagedNetworkMetadata(layout.StateDir, networkID)
			// TODO(peerimeter): Remove the local-only fallback when legacy joins no longer need compatibility.
			if shouldFallbackToLocalSync(metadata, metadataErr, nodeID, apiURL) {
				return local.Request(cmd.Context(), layout.RuntimeDir, "reload", app.out)
			}
			if nodeID == "" {
				nodeID = metadata.NodeID
			}
			if nodeID == "" {
				return errors.New("--node-id is required because this network has no saved node ID")
			}
			options := serviceConfigOptions{networkID: networkID, nodeID: nodeID, apiURL: apiURL, allowInsecureHTTP: allowInsecureHTTP}
			client, saveMigration, err := managedServiceClient(options, layout)
			if err != nil {
				return err
			}
			configPath = syncConfigPath(configPath, layout.ConfigDir, networkID)
			current, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("cannot load joined network configuration: %w", err)
			}
			if current.Network.ID != networkID {
				return errors.New("joined configuration network ID does not match --network-id")
			}
			underlay, err := discovery.PrimaryUnderlay(cmd.Context())
			if err != nil {
				return err
			}
			updated, err := refreshManagedPeers(cmd.Context(), client, networkID, nodeID, underlay.Addresses, current)
			if err != nil {
				return err
			}
			if err := saveMigration(); err != nil {
				return err
			}
			if err := config.Validate(updated, runtime.GOOS); err != nil {
				return err
			}
			data, err := config.MarshalYAML(updated)
			if err != nil {
				return err
			}
			if err := writeConfigFile(configPath, data); err != nil {
				return errors.New("cannot securely update joined network configuration")
			}
			if err := local.Request(cmd.Context(), layout.RuntimeDir, "reload", app.out); err != nil {
				return fmt.Errorf("peer list updated in local config, but the running tunnel could not be reloaded: %w", err)
			}
			return nil
		}),
	}
	cmd.Flags().StringVar(&networkID, "network-id", "", "Joined network ID (required when multiple networks are joined)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "Node ID (defaults to the joined node; required if not saved)")
	cmd.Flags().StringVar(&configPath, "config", "", "WireGuard configuration path (defaults to the joined network YAML)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Service API URL (required once for older joins without saved service metadata)")
	cmd.Flags().BoolVar(&allowInsecureHTTP, "allow-insecure-http", false, "Allow a non-local HTTP API URL (sends the enrollment token without TLS)")
	directoryFlags(cmd, &dirs)
	return cmd
}

func shouldFallbackToLocalSync(metadata managedNetworkMetadata, metadataErr error, nodeID, apiURL string) bool {
	return (metadataErr != nil || metadata.NodeID == "") && nodeID == "" && apiURL == ""
}

func syncConfigPath(override, configDir, networkID string) string {
	if override != "" {
		return override
	}
	servicePath := filepath.Join(configDir, "service.yaml")
	if cfg, err := config.Load(servicePath); err == nil && cfg.Network.ID == networkID {
		return servicePath
	}
	return filepath.Join(configDir, networkID+".yaml")
}
