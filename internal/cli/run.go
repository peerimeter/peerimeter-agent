package cli

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

func withJSONStderrLogger(enabled bool) (func(), error) {
	if !enabled {
		return func() {}, nil
	}
	handler, err := logging.NewHandler("json", os.Stderr)
	if err != nil {
		return nil, err
	}
	previous := slog.Default()
	slog.SetDefault(slog.New(handler))
	return func() { slog.SetDefault(previous) }, nil
}

func newRunCommand(app *application) *cobra.Command {
	var path, override, operator, networkID string
	var options paths.Options
	cmd := &cobra.Command{Use: "run", Short: "Run configured WireGuard networks in the foreground", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
		return runForeground(cmd, app, daemonOptions{path: path, override: override, operator: operator, networkID: networkID, paths: options})
	})}
	cmd.Flags().StringVar(&path, "config", "", "Direct static YAML path (runs only this network)")
	cmd.Flags().StringVar(&networkID, "network", "", "Run only this configured network (defaults to all)")
	cmd.Flags().StringVar(&override, "interface", "", "Linux-only initial local interface name override")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	directoryFlags(cmd, &options)
	return cmd
}

func runForeground(cmd *cobra.Command, app *application, opts daemonOptions) error {
	restoreLogger, err := withJSONStderrLogger(app.jsonOutput)
	if err != nil {
		return err
	}
	defer restoreLogger()

	if opts.paths.ConfigDir == "" && runtime.GOOS != "windows" && os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		if configDir, ok := sudoUserConfigDir(os.Getenv("SUDO_HOME")); ok {
			opts.paths.ConfigDir = configDir
		}
	}
	layout, err := paths.Resolve(opts.paths)
	if err != nil {
		return err
	}
	if opts.path != "" {
		if opts.networkID != "" {
			return errors.New("--network cannot be used with --config")
		}
		return staticCommand(cmd.Context(), cmd.Name(), opts.path, opts.override, layout, opts.operator, app.out, app.backend)
	}
	configs, err := loadSelectedManagedConfigs(layout, opts.networkID)
	if err != nil {
		return err
	}
	return runManagedConfigs(cmd.Context(), cmd.Name(), opts.override, opts.operator, layout, configs, 0, app.out, app.backend, nil)
}

func sudoUserConfigDir(home string) (string, bool) {
	if !filepath.IsAbs(home) {
		return "", false
	}
	configDir := filepath.Join(home, ".config", "peerimeter-agent")
	info, err := os.Stat(configDir)
	return configDir, err == nil && info.IsDir()
}
