package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

const defaultDaemonSyncInterval = 5 * time.Minute

type daemonOptions struct {
	path, override, operator, networkID string
	interval                            time.Duration
	paths                               paths.Options
}

func newDaemonCommand(app *application) *cobra.Command {
	var path, override, operator, networkID string
	var interval time.Duration
	var options paths.Options
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run configured networks and sync joined networks at startup and periodically",
		Long:  "Load every YAML network from config-dir and run each in its own local runtime. Refresh each joined network's service registration and peer list when the network starts, then at a regular interval. Sync failures are logged and retried at the next interval.",
		Args:  noArguments,
		RunE: app.handle(func(cmd *cobra.Command) error {
			return runDaemon(cmd, app, daemonOptions{path: path, override: override, operator: operator, networkID: networkID, interval: interval, paths: options})
		}),
	}
	cmd.Flags().StringVar(&path, "config", "", "Direct static YAML path (overrides installed config-dir/service.yaml)")
	cmd.Flags().StringVar(&networkID, "network", "", "Run only this configured network (defaults to all)")
	cmd.Flags().StringVar(&override, "interface", "", "Linux-only initial local interface name override")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	cmd.Flags().DurationVar(&interval, "sync-interval", defaultDaemonSyncInterval, "How often to sync the joined network after startup")
	directoryFlags(cmd, &options)
	return cmd
}

func runDaemon(cmd *cobra.Command, app *application, opts daemonOptions) error {
	if opts.interval <= 0 {
		return errors.New("--sync-interval must be greater than zero")
	}
	restoreLogger, err := withJSONStderrLogger(app.jsonOutput)
	if err != nil {
		return err
	}
	defer restoreLogger()
	layout, err := paths.Resolve(opts.paths)
	if err != nil {
		return err
	}
	if opts.path != "" {
		if opts.networkID != "" {
			return errors.New("--network cannot be used with --config")
		}
		activeConfig, err := config.Load(opts.path)
		if err != nil {
			return err
		}
		profileOptions := opts.paths
		profileOptions.RuntimeDir = layout.RuntimeDir
		background := func(ctx context.Context) {
			runPeriodicSync(ctx, opts.interval, func(ctx context.Context) error {
				return syncActiveDaemonNetwork(ctx, layout, profileOptions, activeConfig.Network.ID)
			})
		}
		return staticCommandWithBackground(cmd.Context(), cmd.Name(), opts.path, opts.override, layout, opts.operator, app.out, app.backend, nil, 0, background)
	}
	configs, err := loadSelectedManagedConfigs(layout, opts.networkID)
	if err != nil {
		return err
	}
	return runManagedConfigs(cmd.Context(), cmd.Name(), opts.override, opts.operator, layout, configs, opts.interval, app.out, app.backend, func(ctx context.Context, item managedConfig, profile paths.Layout) error {
		profileOptions := opts.paths
		profileOptions.RuntimeDir = profile.RuntimeDir
		return syncActiveDaemonNetwork(ctx, layout, profileOptions, item.networkID)
	})
}

func syncActiveDaemonNetwork(ctx context.Context, layout paths.Layout, options paths.Options, activeNetworkID string) error {
	networks, err := managedNetworkIDs(layout.StateDir)
	if err != nil {
		return err
	}
	targetNetwork := ""
	if len(networks) > 0 {
		for _, id := range networks {
			if id == activeNetworkID {
				targetNetwork = id
				break
			}
		}
	}
	if targetNetwork == "" {
		return local.Request(ctx, options.RuntimeDir, "reload", io.Discard)
	}
	if code := Execute(ctx, daemonSyncArgs(options, targetNetwork), io.Discard, os.Stderr); code != 0 {
		return errors.New("sync command failed")
	}
	return nil
}

func runPeriodicSync(ctx context.Context, interval time.Duration, syncOnce func(context.Context) error) {
	if ctx.Err() != nil {
		return
	}
	if err := syncOnce(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("daemon sync failed", "error", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := syncOnce(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("daemon sync failed", "error", err)
			}
		}
	}
}

func daemonSyncArgs(options paths.Options, networkID string) []string {
	args := []string{"sync"}
	if networkID != "" {
		args = append(args, "--network-id", networkID)
	}
	if options.ConfigDir != "" {
		args = append(args, "--config-dir", options.ConfigDir)
	}
	if options.StateDir != "" {
		args = append(args, "--state-dir", options.StateDir)
	}
	if options.RuntimeDir != "" {
		args = append(args, "--runtime-dir", options.RuntimeDir)
	}
	return args
}
