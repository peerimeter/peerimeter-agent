package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/uninstall"
	"github.com/spf13/cobra"
)

func newUninstallCommand(app *application) *cobra.Command {
	var options uninstall.Options
	cmd := &cobra.Command{Use: "uninstall", Short: "Remove this tracked agent installation and its managed data", Long: "Completely remove the selected installation, including protected installed config and keys. Operator-supplied original files and unrelated resources are preserved. Use --dry-run to inspect removal without changes.", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error { return uninstall.Execute(cmd.Context(), options, app.out) })}
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "List owned resources without changing files, processes or services")
	cmd.Flags().StringVar(&options.InstallDir, "install-dir", "", "Tracked installation directory (defaults to this executable's directory)")
	cmd.Flags().StringVar(&options.DocDir, "doc-dir", "", "Verify the recorded notices directory")
	cmd.Flags().StringVar(&options.DataDir, "data-dir", "", "Verify the recorded installation inventory directory")
	cmd.Flags().StringVar(&options.LockDir, "lock-dir", "", "Verify the recorded installation lock directory")
	cmd.Flags().StringVar(&options.ConfigDir, "config-dir", "", "Select a tracked installed configuration directory")
	cmd.Flags().StringVar(&options.StateDir, "state-dir", "", "Select a tracked persistent state directory")
	cmd.Flags().StringVar(&options.RuntimeDir, "runtime-dir", "", "Select a tracked runtime directory")
	return cmd
}
