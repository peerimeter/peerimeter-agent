package cli

import (
	"errors"
	"github.com/spf13/cobra"
)

func newServiceCommand(app *application) *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Manage the native system service", Args: noArguments, RunE: app.handle(func(*cobra.Command) error { return errors.New("service action required; use service --help") })}
	cmd.AddCommand(newServiceInstallCommand(app), newServiceMigrateCommand(app), newServiceStartCommand(app), newServiceStopCommand(app), newServiceUninstallCommand(app))
	return cmd
}
