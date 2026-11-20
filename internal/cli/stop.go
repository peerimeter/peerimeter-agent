package cli

import "github.com/spf13/cobra"

func newStopCommand(app *application) *cobra.Command {
	return newControlCommand(app, "stop", "Gracefully stop all configured networks or select one with --network", "stop")
}
