package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

const defaultDaemonSyncInterval = 5 * time.Minute

type daemonOptions struct {
	path, override, operator string
	interval                 time.Duration
	paths                    paths.Options
}

func newDaemonCommand(app *application) *cobra.Command {
	var path, override, operator string
	var interval time.Duration
	var options paths.Options
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the agent and periodically sync its joined network",
		Long:  "Run the native WireGuard agent in the foreground and refresh its service registration and peer list at a regular interval. Sync failures are logged and retried at the next interval.",
		Args:  noArguments,
		RunE: app.handle(func(cmd *cobra.Command) error {
			return runDaemon(cmd, app, daemonOptions{path: path, override: override, operator: operator, interval: interval, paths: options})
		}),
	}
	cmd.Flags().StringVar(&path, "config", "", "Direct static YAML path (overrides installed config-dir/service.yaml)")
	cmd.Flags().StringVar(&override, "interface", "", "Linux-only initial local interface name override")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	cmd.Flags().DurationVar(&interval, "sync-interval", defaultDaemonSyncInterval, "How often to sync the joined network")
	directoryFlags(cmd, &options)
	return cmd
}

func runDaemon(cmd *cobra.Command, app *application, opts daemonOptions) error {
	if opts.interval <= 0 {
		return errors.New("--sync-interval must be greater than zero")
	}
	if app.jsonOutput {
		handler, err := logging.NewHandler("json", os.Stderr)
		if err != nil {
			return err
		}
		previous := slog.Default()
		slog.SetDefault(slog.New(handler))
		defer slog.SetDefault(previous)
	}
	layout, err := paths.Resolve(opts.paths)
	if err != nil {
		return err
	}
	if opts.path == "" {
		opts.path = filepath.Join(layout.ConfigDir, "service.yaml")
	}
	activeConfig, err := config.Load(opts.path)
	if err != nil {
		return err
	}
	background := func(ctx context.Context) {
		runPeriodicSync(ctx, opts.interval, func(ctx context.Context) error {
			return syncActiveDaemonNetwork(ctx, layout, opts.paths, activeConfig.Network.ID)
		})
	}
	return staticCommandWithBackground(cmd.Context(), cmd.Name(), opts.path, opts.override, layout, opts.operator, app.out, app.backend, nil, 0, background)
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
		if targetNetwork == "" {
			return errors.New("no saved sync credential for the daemon's active network")
		}
	}
	if code := Execute(ctx, daemonSyncArgs(options, targetNetwork), io.Discard, os.Stderr); code != 0 {
		return errors.New("sync command failed")
	}
	return nil
}

func runPeriodicSync(ctx context.Context, interval time.Duration, syncOnce func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := syncOnce(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("scheduled sync failed", "error", err)
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
