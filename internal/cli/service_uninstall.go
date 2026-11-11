package cli

import "github.com/spf13/cobra"

func newServiceUninstallCommand(app *application) *cobra.Command {
	return newServiceAction(app, "uninstall", "Remove service registration while preserving config and keys")
}
