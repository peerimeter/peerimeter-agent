package cli

import (
	"context"
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
			return runSync(cmd.Context(), app, syncOptions{networkID: networkID, nodeID: nodeID, apiURL: apiURL, configPath: configPath, allowInsecureHTTP: allowInsecureHTTP, dirs: dirs})
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

type syncOptions struct {
	networkID         string
	nodeID            string
	apiURL            string
	configPath        string
	allowInsecureHTTP bool
	dirs              paths.Options
}

func runSync(ctx context.Context, app *application, opts syncOptions) error {
	layout, err := paths.Resolve(opts.dirs)
	if err != nil {
		return err
	}
	networkID, err := selectManagedNetwork(layout.StateDir, opts.networkID)
	if err != nil {
		return err
	}
	if networkID == "" {
		return local.Request(ctx, layout.RuntimeDir, "reload", app.out)
	}
	metadata, metadataErr := readManagedNetworkMetadata(layout.StateDir, networkID)
	// TODO(peerimeter): Remove the local-only fallback when legacy joins no longer need compatibility.
	if shouldFallbackToLocalSync(metadata, metadataErr, opts.nodeID, opts.apiURL) {
		return local.Request(ctx, layout.RuntimeDir, "reload", app.out)
	}
	nodeID := opts.nodeID
	if nodeID == "" {
		nodeID = metadata.NodeID
	}
	if nodeID == "" {
		return errors.New("--node-id is required because this network has no saved node ID")
	}
	serviceOptions := serviceConfigOptions{networkID: networkID, nodeID: nodeID, apiURL: opts.apiURL, allowInsecureHTTP: opts.allowInsecureHTTP}
	identity, err := local.GetIdentity(ctx, layout.RuntimeDir)
	if err != nil {
		return err
	}
	if identity.NetworkID != networkID {
		return fmt.Errorf("running agent network %q does not match selected network %q", identity.NetworkID, networkID)
	}
	if identity.PublicKey == "" {
		return errors.New("running agent did not report its public key; restart it with the updated agent before syncing")
	}
	_, err = syncConfigPath(opts.configPath, identity.ConfigPath)
	if err != nil {
		return err
	}
	configData, err := local.GetConfig(ctx, layout.RuntimeDir, identity)
	if err != nil {
		return err
	}
	var current config.Config
	if err := json.Unmarshal(configData, &current); err != nil {
		return errors.New("running agent returned an invalid configuration")
	}
	client, saveMigration, err := managedServiceClient(serviceOptions, layout)
	if err != nil {
		return err
	}
	if current.Network.ID != networkID {
		return errors.New("joined configuration network ID does not match --network-id")
	}
	underlay, err := discovery.PrimaryUnderlay(ctx)
	if err != nil {
		return err
	}
	if err := refreshManagedRegistration(ctx, client, networkID, nodeID, identity.PublicKey, underlay, current); err != nil {
		return err
	}
	updated, err := refreshManagedPeers(ctx, client, networkID, nodeID, underlay.Addresses, current)
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
	if err := local.ApplyConfig(ctx, layout.RuntimeDir, identity, data, app.out); err != nil {
		return fmt.Errorf("cannot apply refreshed peer configuration: %w", err)
	}
	return nil
}

func selectManagedNetwork(stateDir, requestedID string) (string, error) {
	networks, err := managedNetworkIDs(stateDir)
	if err != nil {
		return "", err
	}
	if len(networks) == 0 {
		if requestedID == "" {
			return "", nil
		}
		return "", errors.New("no joined network credentials found; run join before syncing Service API peers")
	}
	if requestedID == "" {
		if len(networks) == 1 {
			return networks[0], nil
		}
		return "", fmt.Errorf("--network-id is required when multiple networks are joined (%s)", strings.Join(networks, ", "))
	}
	for _, networkID := range networks {
		if networkID == requestedID {
			return requestedID, nil
		}
	}
	return "", errors.New("no saved credential found for --network-id")
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
