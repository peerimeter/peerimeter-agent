package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

func newControlCommand(app *application, name, short, operation string) *cobra.Command {
	var options paths.Options
	var networkID string
	cmd := &cobra.Command{Use: name, Short: short, Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		return requestAllNetworks(cmd.Context(), layout, networkID, operation, app.out)
	})}
	directoryFlags(cmd, &options)
	cmd.Flags().StringVar(&networkID, "network", "", "Configured network ID (defaults to all networks)")
	return cmd
}
