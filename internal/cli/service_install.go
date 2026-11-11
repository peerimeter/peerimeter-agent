package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
)

func newServiceInstallCommand(app *application) *cobra.Command {
	var cfg service.Config
	cmd := &cobra.Command{Use: "install", Short: "Register service with protected configuration snapshots and boot activation", Args: noArguments, RunE: app.handle(func(*cobra.Command) error { return serviceAction(app, "install", cfg) })}
	cmd.Flags().StringVar(&cfg.ConfigPath, "config", "", "Absolute source JSON path (otherwise use installed config-dir/service.json)")
	cmd.Flags().StringVar(&cfg.Operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	serviceDirectories(cmd, &cfg)
	return cmd
}
