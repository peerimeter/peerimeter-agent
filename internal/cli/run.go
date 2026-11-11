package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
	"path/filepath"
)

func newRunCommand(app *application) *cobra.Command {
	var path, override, operator string
	var options paths.Options
	cmd := &cobra.Command{Use: "run", Short: "Run the native WireGuard agent in the foreground", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		if path == "" {
			path = filepath.Join(layout.ConfigDir, "service.json")
		}
		return staticCommand(cmd.Context(), cmd.Name(), path, override, layout, operator, app.out, app.backend)
	})}
	cmd.Flags().StringVar(&path, "config", "", "Direct static JSON path (overrides installed config-dir/service.json)")
	cmd.Flags().StringVar(&override, "interface", "", "Linux-only initial local interface name override")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	directoryFlags(cmd, &options)
	return cmd
}
