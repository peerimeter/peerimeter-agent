package cli

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

func newRunCommand(app *application) *cobra.Command {
	var path, override, operator string
	var options paths.Options
	cmd := &cobra.Command{Use: "run", Short: "Run the native WireGuard agent in the foreground", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
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
		if path == "" {
			path = filepath.Join(layout.ConfigDir, "service.yaml")
		}
		return staticCommand(cmd.Context(), cmd.Name(), path, override, layout, operator, app.out, app.backend)
	})}
	cmd.Flags().StringVar(&path, "config", "", "Direct static YAML path (overrides installed config-dir/service.yaml)")
	cmd.Flags().StringVar(&override, "interface", "", "Linux-only initial local interface name override")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	directoryFlags(cmd, &options)
	return cmd
}
