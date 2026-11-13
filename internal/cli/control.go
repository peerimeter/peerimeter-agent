package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
)

func newControlCommand(app *application, name, short, operation string) *cobra.Command {
	var options paths.Options
	cmd := &cobra.Command{Use: name, Short: short, Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		return local.Request(cmd.Context(), layout.RuntimeDir, operation, app.out)
	})}
	directoryFlags(cmd, &options)
	return cmd
}
