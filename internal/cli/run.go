package cli

import (
	"errors"
	"log/slog"
	"os"

	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

func newRunCommand(app *application) *cobra.Command {
	var path, override, operator, networkID string
	var options paths.Options
	cmd := &cobra.Command{Use: "run", Short: "Run configured WireGuard networks in the foreground", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
		if app.jsonOutput {
			handler, err := logging.NewHandler("json", os.Stderr)
			if err != nil {
				return err
			}
			previous := slog.Default()
			slog.SetDefault(slog.New(handler))
			defer slog.SetDefault(previous)
		}
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		if path != "" {
			if networkID != "" {
				return errors.New("--network cannot be used with --config")
			}
			return staticCommand(cmd.Context(), cmd.Name(), path, override, layout, operator, app.out, app.backend)
		}
		configs, err := discoverManagedConfigs(layout)
		if err != nil {
			return err
		}
		configs, err = matchingConfig(configs, networkID)
		if err != nil {
			return err
		}
		return runManagedConfigs(cmd.Context(), cmd.Name(), override, operator, layout, configs, 0, app.out, app.backend, nil)
	})}
	cmd.Flags().StringVar(&path, "config", "", "Direct static YAML path (runs only this network)")
	cmd.Flags().StringVar(&networkID, "network", "", "Run only this configured network (defaults to all)")
	cmd.Flags().StringVar(&override, "interface", "", "Linux-only initial local interface name override")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	directoryFlags(cmd, &options)
	return cmd
}
