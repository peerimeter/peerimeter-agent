package cli

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newStatusCommand(app *application) *cobra.Command {
	var options paths.Options
	var watch bool
	var networkID string
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Read local tunnel status for configured networks",
		Args:  noArguments,
	}
	normalRun := app.handleResponse(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		snapshots, err := readNetworkSnapshots(cmd.Context(), layout, networkID)
		if err != nil {
			return err
		}
		return writeNetworkSnapshots(app.out, snapshots)
	})
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !watch {
			if cmd.Flags().Changed("interval") {
				app.ran = true
				return errors.New("--interval requires --watch")
			}
			return normalRun(cmd, args)
		}
		app.ran = true
		if interval <= 0 {
			return errors.New("--interval must be greater than zero")
		}
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		runtimes, err := networkRuntimeLayouts(layout, networkID)
		if err != nil {
			return err
		}
		if len(runtimes) != 1 {
			return errors.New("status --watch requires --network when multiple networks are configured")
		}
		if app.jsonOutput {
			return watchStatusJSON(cmd.Context(), runtimes[0].RuntimeDir, interval, app.out)
		}
		if !interactiveTerminal(cmd, app.out) {
			return errors.New("status --watch needs an interactive terminal; use --json for a snapshot stream")
		}
		return watchStatusTerminal(cmd, runtimes[0].RuntimeDir, interval, app)
	}
	directoryFlags(cmd, &options)
	cmd.Flags().StringVar(&networkID, "network", "", "Configured network ID (defaults to all networks)")
	cmd.Flags().BoolVar(&watch, "watch", false, "Continuously refresh until interrupted")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "Refresh interval for --watch")
	return cmd
}

func interactiveTerminal(cmd *cobra.Command, out io.Writer) bool {
	in, inputOK := cmd.InOrStdin().(*os.File)
	output, outputOK := out.(*os.File)
	return inputOK && outputOK && term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(output.Fd()))
}
