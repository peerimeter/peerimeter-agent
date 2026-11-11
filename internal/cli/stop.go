package cli

import "github.com/spf13/cobra"

func newStopCommand(app *application) *cobra.Command {
	return newControlCommand(app, "stop", "Gracefully stop the local agent and remove its owned tunnel", "stop")
}
