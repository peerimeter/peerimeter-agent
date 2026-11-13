package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
	"path/filepath"
)

func newValidateConfigCommand(app *application) *cobra.Command {
	var path, override string
	var options paths.Options
	cmd := &cobra.Command{Use: "validate-config", Short: "Validate static JSON and protected key without OS changes", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		if path == "" {
			path = filepath.Join(layout.ConfigDir, "service.json")
		}
		return staticCommand(cmd.Context(), cmd.Name(), path, override, layout, "", app.out, app.backend)
	})}
	cmd.Flags().StringVar(&path, "config", "", "Direct static JSON path (overrides installed configuration)")
	cmd.Flags().StringVar(&override, "interface", "", "Linux-only local interface name override")
	directoryFlags(cmd, &options)
	return cmd
}
