package cli

import "github.com/spf13/cobra"

func newSyncCommand(app *application) *cobra.Command {
	return newControlCommand(app, "sync", "Validate and reconcile the original static configuration", "reload")
}
