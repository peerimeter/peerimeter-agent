package cli

import "github.com/spf13/cobra"

func newServiceCommand(app *application) *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Manage the native system service"}
	cmd.AddCommand(newServiceInstallCommand(app), newServiceStartCommand(app), newServiceStopCommand(app), newServiceStatusCommand(app), newServiceUninstallCommand(app))
	return cmd
}
