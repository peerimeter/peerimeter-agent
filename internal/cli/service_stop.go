package cli

import "github.com/spf13/cobra"

func newServiceStopCommand(app *application) *cobra.Command {
	return newServiceAction(app, "stop", "Stop the installed native service")
}
