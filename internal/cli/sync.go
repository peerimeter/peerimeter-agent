package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		Short: "Refresh all joined networks or select one with --network-id",
		Long:  "For each selected joined network, sync updates this node's primary interface addresses in the Service API, then pulls the current peer list and applies it to that network's running configuration. It verifies each selected network matches its running agent. --config, if supplied, must identify the selected active file. Windows UNC config paths are not supported. Joined networks without saved YAML metadata must be rejoined or synced with --api-url and --node-id on every invocation. By default all joined networks are selected; --network-id selects one. Pass --network-id to sync a network without metadata, and repeat the command for each affected network. It preserves the last public endpoint when STUN cannot bind the configured WireGuard port.",
		Args:  noArguments,
		RunE: app.handleResponse(func(cmd *cobra.Command) error {
			return runSync(cmd.Context(), app, syncOptions{networkID: networkID, nodeID: nodeID, apiURL: apiURL, configPath: configPath, allowInsecureHTTP: allowInsecureHTTP, dirs: dirs})
		}),
	}
	cmd.Flags().StringVar(&networkID, "network-id", "", "Joined network ID (defaults to all joined networks)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "Node ID (defaults to the joined node; required if not saved)")
	cmd.Flags().StringVar(&configPath, "config", "", "WireGuard configuration path (must match the running agent's active config)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Service API URL (required on each sync without saved YAML metadata)")
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
	networks, err := managedNetworkIDs(layout.StateDir)
	if err != nil {
		return err
	}
	if len(networks) == 0 {
		if opts.networkID != "" {
			return errors.New("no joined network credentials found; run join before syncing Service API peers")
		}
		return syncManagedNetwork(ctx, app, opts, layout, "")
	}
	selected, err := selectManagedNetworkIDs(networks, opts.networkID)
	if err != nil {
		return err
	}
	if len(selected) > 1 && (opts.configPath != "" || opts.nodeID != "" || opts.apiURL != "") {
		return errors.New("--config, --node-id and --api-url require selecting one network with --network-id")
	}
	originalOutput := app.out
	app.out = io.Discard
	defer func() { app.out = originalOutput }()
	var failures []error
	for _, networkID := range selected {
		if err := syncManagedNetwork(ctx, app, opts, layout, networkID); err != nil {
			failures = append(failures, fmt.Errorf("network %q: %w", networkID, err))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	if len(selected) == 1 {
		return json.NewEncoder(originalOutput).Encode(map[string]string{"state": "reconciled", "network_id": selected[0]})
	}
	return json.NewEncoder(originalOutput).Encode(map[string]any{"state": "reconciled", "network_ids": selected})
}

func syncManagedNetwork(ctx context.Context, app *application, opts syncOptions, layout paths.Layout, networkID string) error {
	if networkID == "" {
		return local.Request(ctx, layout.RuntimeDir, "reload", app.out)
	}
	runtimeLayout, err := controlNetworkLayout(ctx, layout, networkID)
	if err != nil {
		return err
	}
	runtimeDir := runtimeLayout.RuntimeDir
	metadata, metadataErr := readManagedNetworkMetadata(layout.StateDir, networkID)
	if metadataErr != nil && opts.apiURL == "" {
		return metadataErr
	}
	nodeID := opts.nodeID
	if nodeID == "" && metadataErr == nil {
		nodeID = metadata.NodeID
	}
	if nodeID == "" {
		return errors.New("--node-id is required because this network has no saved node ID")
	}
	serviceOptions := serviceConfigOptions{networkID: networkID, apiURL: opts.apiURL, allowInsecureHTTP: opts.allowInsecureHTTP, debug: app.debug}
	identity, err := local.GetIdentity(ctx, runtimeDir)
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
	configData, err := local.GetConfig(ctx, runtimeDir, identity)
	if err != nil {
		return err
	}
	var current config.Config
	if err := json.Unmarshal(configData, &current); err != nil {
		return errors.New("running agent returned an invalid configuration")
	}
	client, err := managedServiceClient(serviceOptions, layout)
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
	if err := config.Validate(updated, runtime.GOOS); err != nil {
		return err
	}
	data, err := config.MarshalYAML(updated)
	if err != nil {
		return err
	}
	if err := local.ApplyConfig(ctx, runtimeDir, identity, data, app.out); err != nil {
		return fmt.Errorf("cannot apply refreshed peer configuration: %w", err)
	}
	return nil
}

func selectManagedNetworkIDs(networks []string, requestedID string) ([]string, error) {
	if requestedID == "" {
		return networks, nil
	}
	for _, networkID := range networks {
		if networkID == requestedID {
			return []string{requestedID}, nil
		}
	}
	return nil, errors.New("no saved credential found for --network-id")
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
