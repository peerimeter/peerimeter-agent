package cli

import "github.com/spf13/cobra"

func newServiceStartCommand(app *application) *cobra.Command {
	return newServiceAction(app, "start", "Start the installed native service")
}
