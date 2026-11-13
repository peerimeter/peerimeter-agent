// Package cli exposes the offline agent command tree. Each command lives in its
// own source file; command factories keep flags isolated between invocations.
package cli

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/term"
	"io"
	"log/slog"
	"os"

	"github.com/peerimeter/peerimeter-agent/internal/diagnostic"
	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/spf13/cobra"
)

type application struct {
	out        io.Writer
	backend    platform.Backend
	ran        bool
	debug      bool
	jsonOutput bool
	color      string
}

func (app *application) handle(f func(*cobra.Command) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error { app.ran = true; return f(cmd) }
}

func (app *application) handleResponse(f func(*cobra.Command) error) func(*cobra.Command, []string) error {
	return app.handle(func(cmd *cobra.Command) error {
		if app.jsonOutput {
			return f(cmd)
		}
		original := app.out
		var raw bytes.Buffer
		app.out = &raw
		defer func() { app.out = original }()
		err := f(cmd)
		if raw.Len() > 0 {
			if renderErr := renderResponse(original, raw.Bytes(), shouldColor(original, app.color), outputWidth(original)); err == nil {
				err = renderErr
			}
		}
		return err
	})
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
		logger := slog.New(handler)
		if app.debug {
			if trace, ok := diagnostic.StackTrace(err); ok {
				logger.Error(err.Error(), "stacktrace", trace)
			} else {
				logger.Error(err.Error())
			}
		} else {
			logger.Error(err.Error())
		}
	}
	if errors.Is(err, platform.ErrUnavailable) {
		return 3
	}
	return 1
}
func newRootCommand(app *application) *cobra.Command {
	root := &cobra.Command{
		Use:   "peerimeter-agent",
		Short: "Offline cross-platform WireGuard agent",
		Long: `Offline cross-platform WireGuard agent.

Environment variables:
  PEERIMETER_LOG_FORMAT  Log format: console (default), text, or json.
  NO_COLOR               Disable ANSI colors when set.
  TERM=dumb              Disable ANSI colors for dumb terminals.`,
		SilenceUsage:       true,
		SilenceErrors:      true,
		DisableSuggestions: true,
		RunE:               app.handle(func(*cobra.Command) error { return errors.New("command required; use --help") }),
	}
	root.PersistentPreRunE = func(*cobra.Command, []string) error {
		if app.color != "auto" && app.color != "always" && app.color != "never" {
			return errors.New("color must be auto, always or never")
		}
		return nil
	}
	root.SetOut(app.out)
	root.PersistentFlags().StringVar(&app.color, "color", "auto", "Color mode: auto, always or never (auto respects NO_COLOR)")
	root.PersistentFlags().BoolVar(&app.jsonOutput, "json", false, "Print machine-readable JSON for command results")
	root.PersistentFlags().BoolVar(&app.debug, "debug", false, "include captured stack trace when an error occurs")
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
	root.AddCommand(newVersionCommand(app), newGenerateExampleCommand(app), newRunCommand(app), newValidateConfigCommand(app), newStatusCommand(app), newPeersCommand(app), newWGCommand(app), newSyncCommand(app), newStopCommand(app), newServiceCommand(app), newUninstallCommand(app), newRegisterInstallationCommand(app), newStunCommand(app))
	return root
}

func outputWidth(out io.Writer) int {
	if file, ok := out.(*os.File); ok {
		if width, _, err := term.GetSize(int(file.Fd())); err == nil {
			return width
		}
	}
	return 80
}
