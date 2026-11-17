package cli

import (
	"encoding/json"
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
		Short: "Refresh this node's registration and reconcile the running agent",
		Long:  "For a joined network, sync updates this node's primary interface addresses in the Service API, then pulls the current peer list and applies it to the running agent configuration. It verifies the selected network matches the running network. --config, if supplied, must identify that active file. Windows UNC config paths are not supported. Without complete saved metadata it reloads the local configuration as before. With one joined network, --network-id is optional; with multiple joined networks it is required. Older joins may need --api-url and --node-id once. It preserves the last public endpoint when STUN cannot bind the configured WireGuard port.",
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
			identity, err := local.GetIdentity(cmd.Context(), layout.RuntimeDir)
			if err != nil {
				return err
			}
			if identity.NetworkID != networkID {
				return fmt.Errorf("running agent network %q does not match selected network %q", identity.NetworkID, networkID)
			}
			if identity.PublicKey == "" {
				return errors.New("running agent did not report its public key; restart it with the updated agent before syncing")
			}
			configPath, err = syncConfigPath(configPath, identity.ConfigPath)
			if err != nil {
				return err
			}
			configData, err := local.GetConfig(cmd.Context(), layout.RuntimeDir, identity)
			if err != nil {
				return err
			}
			var current config.Config
			if err := json.Unmarshal(configData, &current); err != nil {
				return errors.New("running agent returned an invalid configuration")
			}
			client, saveMigration, err := managedServiceClient(options, layout)
			if err != nil {
				return err
			}
			if current.Network.ID != networkID {
				return errors.New("joined configuration network ID does not match --network-id")
			}
			underlay, err := discovery.PrimaryUnderlay(cmd.Context())
			if err != nil {
				return err
			}
			if err := refreshManagedRegistration(cmd.Context(), client, networkID, nodeID, identity.PublicKey, underlay, current); err != nil {
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
			if err := local.ApplyConfig(cmd.Context(), layout.RuntimeDir, identity, data, app.out); err != nil {
				return fmt.Errorf("cannot apply refreshed peer configuration: %w", err)
			}
			return nil
		}),
	}
	cmd.Flags().StringVar(&networkID, "network-id", "", "Joined network ID (required when multiple networks are joined)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "Node ID (defaults to the joined node; required if not saved)")
	cmd.Flags().StringVar(&configPath, "config", "", "WireGuard configuration path (must match the running agent's active config)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Service API URL (required once for older joins without saved service metadata)")
	cmd.Flags().BoolVar(&allowInsecureHTTP, "allow-insecure-http", false, "Allow a non-local HTTP API URL (sends the enrollment token without TLS)")
	directoryFlags(cmd, &dirs)
	return cmd
}

func shouldFallbackToLocalSync(metadata managedNetworkMetadata, metadataErr error, nodeID, apiURL string) bool {
	return (metadataErr != nil || metadata.NodeID == "") && nodeID == "" && apiURL == ""
}

func syncConfigPath(override, runtimePath string) (string, error) {
	if runtimePath == "" {
		return "", errors.New("running agent did not report its configuration path; restart it with the updated agent before syncing")
	}
	if !filepath.IsAbs(runtimePath) || runtime.GOOS == "windows" && strings.HasPrefix(strings.ReplaceAll(runtimePath, "/", "\\"), `\\`) {
		return "", errors.New("cannot resolve running agent configuration path")
	}
	runtimePath = filepath.Clean(runtimePath)
	if override == "" {
		return runtimePath, nil
	}
	var err error
	override, err = filepath.EvalSymlinks(override)
	if err != nil {
		return "", errors.New("cannot resolve --config path")
	}
	override, err = filepath.Abs(override)
	if err != nil {
		return "", errors.New("cannot resolve --config path")
	}
	pathsMatch := filepath.Clean(override) == runtimePath
	if runtime.GOOS == "windows" {
		pathsMatch = strings.EqualFold(filepath.Clean(override), runtimePath)
	}
	if !pathsMatch {
		return "", errors.New("--config must identify the configuration file used by the running agent")
	}
	return runtimePath, nil
}
