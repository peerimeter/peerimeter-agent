package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/uninstall"
	"github.com/spf13/cobra"
)

func newUninstallCommand(app *application) *cobra.Command {
	var options uninstall.Options
	cmd := &cobra.Command{Use: "uninstall", Short: "Remove this tracked agent installation and its managed data", Long: "Remove the selected installation and its tracked managed data. The files to be removed are listed and confirmation is required unless --yes is supplied. Operator-supplied original config files are preserved. --purge also removes every file and nested directory inside tracked state, config and runtime directories.", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		options.ConfirmIn = app.in
		options.ConfirmOut = app.promptOut
		options.Confirm = func(prompt string) (bool, error) {
			return confirmInteractive(app.in, app.promptOut, prompt, app.color)
		}
		return uninstall.Execute(cmd.Context(), options, app.out)
	})}
	cmd.Flags().BoolVar(&options.Yes, "yes", false, "Confirm removal without prompting")
	cmd.Flags().BoolVar(&options.Purge, "purge", false, "Also delete every file under tracked state, config and runtime directories")
	cmd.Flags().StringVar(&options.InstallDir, "install-dir", "", "Tracked installation directory (defaults to this executable's directory)")
	cmd.Flags().StringVar(&options.DocDir, "doc-dir", "", "Verify the recorded notices directory")
	cmd.Flags().StringVar(&options.DataDir, "data-dir", "", "Verify the recorded installation inventory directory")
	cmd.Flags().StringVar(&options.LockDir, "lock-dir", "", "Verify the recorded installation lock directory")
	cmd.Flags().StringVar(&options.ConfigDir, "config-dir", "", "Select a tracked installed configuration directory")
	cmd.Flags().StringVar(&options.StateDir, "state-dir", "", "Select a tracked persistent state directory")
	cmd.Flags().StringVar(&options.RuntimeDir, "runtime-dir", "", "Select a tracked runtime directory")
	return cmd
}
