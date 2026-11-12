// Package cli exposes the offline agent command tree. Each command lives in its
// own source file; command factories keep flags isolated between invocations.
package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/spf13/cobra"
)

type application struct {
	out     io.Writer
	backend platform.Backend
	ran     bool
}

func (app *application) handle(f func(*cobra.Command) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error { app.ran = true; return f(cmd) }
}
func noArguments(_ *cobra.Command, args []string) error {
	if len(args) != 0 {
		return errors.New("unexpected positional arguments")
	}
	return nil
}
func Execute(ctx context.Context, args []string, out, errOut io.Writer) int {
	return execute(ctx, args, out, errOut, platform.Native())
}
func execute(ctx context.Context, args []string, out, errOut io.Writer, backend platform.Backend) int {
	app := &application{out: out, backend: backend}
	root := newRootCommand(app)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	if !app.ran {
		err = errors.New("invalid command or arguments; use --help")
	}
	handler, handlerErr := logging.NewHandler(os.Getenv(logging.FormatEnv), errOut)
	if handlerErr != nil {
		_, _ = io.WriteString(errOut, "ERROR: "+err.Error()+"\n")
	} else {
		slog.New(handler).Error(err.Error())
	}
	if errors.Is(err, platform.ErrUnavailable) {
		return 3
	}
	return 1
}
func newRootCommand(app *application) *cobra.Command {
	root := &cobra.Command{Use: "peerimeter-agent", Short: "Offline cross-platform WireGuard agent", SilenceUsage: true, SilenceErrors: true, DisableSuggestions: true, RunE: app.handle(func(*cobra.Command) error { return errors.New("command required; use --help") })}
	root.SetOut(app.out)
	root.SetErr(io.Discard)
	root.SetFlagErrorFunc(func(*cobra.Command, error) error { return errors.New("invalid command flags; use --help") })
	root.SetHelpCommand(&cobra.Command{Use: "help [command]", Short: "Show command help", RunE: func(_ *cobra.Command, args []string) error {
		app.ran = true
		target, remaining, err := root.Find(args)
		if err != nil || len(remaining) != 0 {
			return errors.New("unknown help topic; use --help")
		}
		return target.Help()
	}})
	root.AddCommand(newVersionCommand(app), newGenerateExampleCommand(app), newRunCommand(app), newValidateConfigCommand(app), newStatusCommand(app), newPeersCommand(app), newSyncCommand(app), newStopCommand(app), newServiceCommand(app), newUninstallCommand(app), newRegisterInstallationCommand(app), newStunCommand(app))
	return root
}
