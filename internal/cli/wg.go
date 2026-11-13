package cli

import "github.com/spf13/cobra"

func newWGCommand(app *application) *cobra.Command {
	cmd := newPeerViewCommand(app, true)
	cmd.AddCommand(&cobra.Command{Use: "show", Short: "Show WireGuard interface and peers", Args: noArguments, RunE: cmd.RunE})
	return cmd
}
