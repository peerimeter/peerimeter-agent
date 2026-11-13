package cli

import "github.com/spf13/cobra"

func newStatusCommand(app *application) *cobra.Command {
	return newControlCommand(app, "status", "Read actual local tunnel status (or --json)", "status")
}
