package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
)

func newServiceMigrateCommand(app *application) *cobra.Command {
	var cfg service.Config
	cmd := &cobra.Command{Use: "migrate", Short: "Safely migrate the legacy combined Unix service layout", Args: noArguments, RunE: app.handle(func(*cobra.Command) error { return serviceAction(app, "migrate", cfg) })}
	cmd.Flags().StringVar(&cfg.Operator, "operator", "", "Authorized local operator for the migrated service")
	serviceDirectories(cmd, &cfg)
	return cmd
}
