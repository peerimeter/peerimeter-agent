// Package cli exposes the static agent and optional service API command tree.
// Each command lives in its own source file; command factories keep flags
// isolated between invocations.
package cli

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/term"
	"io"
	"log/slog"
	"os"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/diagnostic"
	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/spf13/cobra"
)

type application struct {
	out        io.Writer
	promptOut  io.Writer
	in         io.Reader
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
	settings, err := config.LoadEnvironment()
	if err != nil {
		_, _ = io.WriteString(errOut, err.Error()+"\n")
		return 2
	}
	return ExecuteWithEnvironment(ctx, args, out, errOut, settings)
}
func ExecuteWithEnvironment(ctx context.Context, args []string, out, errOut io.Writer, settings config.Environment) int {
	return executeWithEnvironment(ctx, args, out, errOut, platform.Native(), settings)
}
func execute(ctx context.Context, args []string, out, errOut io.Writer, backend platform.Backend) int {
	settings, err := config.LoadEnvironment()
	if err != nil {
		_, _ = io.WriteString(errOut, err.Error()+"\n")
		return 2
	}
	return executeWithEnvironment(ctx, args, out, errOut, backend, settings)
}
func executeWithEnvironment(ctx context.Context, args []string, out, errOut io.Writer, backend platform.Backend, settings config.Environment) int {
	app := &application{out: out, promptOut: errOut, in: os.Stdin, backend: backend}
	root := newRootCommand(app)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	if !app.ran {
		err = errors.New("invalid command or arguments; use --help")
	}
	format := settings.LogFormat
	if app.jsonOutput {
		format = "json"
	}
	handler, handlerErr := logging.NewHandler(format, errOut)
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
		Short: "Cross-platform WireGuard agent with offline and service API modes",
		Long: `Cross-platform WireGuard agent.

Static WireGuard operation works without a Peerimeter service. The config
subcommands can optionally pull or push network and node YAML over HTTPS.

Use "peerimeter-agent info" to view environment variables and resolved directories.`,
		SilenceUsage:       true,
		SilenceErrors:      true,
		DisableSuggestions: true,
		RunE: app.handle(func(cmd *cobra.Command) error {
			if err := renderVersion(app.out, shouldColor(app.out, app.color)); err != nil {
				return err
			}
			if err := cmd.Help(); err != nil {
				return err
			}
			return checkForUpgrade(cmd.Context(), app.out, app.color, false, false)
		}),
	}
	root.PersistentPreRunE = func(*cobra.Command, []string) error {
		if app.color != "auto" && app.color != "always" && app.color != "never" {
			return errors.New("color must be auto, always or never")
		}
		return nil
	}
	root.SetOut(app.out)
	root.PersistentFlags().StringVar(&app.color, "color", "auto", "Color mode: auto, always or never (auto respects NO_COLOR)")
	root.PersistentFlags().BoolVar(&app.jsonOutput, "json", false, "Use JSON output and structured logs where supported")
	root.PersistentFlags().BoolVar(&app.debug, "debug", false, "include captured stack trace when an error occurs")
	var showHidden bool
	root.Flags().BoolVar(&showHidden, "all", false, "List all commands, including hidden commands")
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd == root && showHidden {
			restore := showHiddenCommands(root)
			defer restore()
		}
		defaultHelp(cmd, args)
	})
	root.SetErr(io.Discard)
	root.SetFlagErrorFunc(func(*cobra.Command, error) error { return errors.New("invalid command flags; use --help") })
	helpCommand := &cobra.Command{Use: "help [command]", Short: "Show command help", RunE: func(_ *cobra.Command, args []string) error {
		app.ran = true
		if showHidden && len(args) == 0 {
			restore := showHiddenCommands(root)
			defer restore()
			return root.Help()
		}
		target, remaining, err := root.Find(args)
		if err != nil || len(remaining) != 0 {
			return errors.New("unknown help topic; use --help")
		}
		return target.Help()
	}}
	helpCommand.Flags().BoolVar(&showHidden, "all", false, "List all commands, including hidden commands")
	root.SetHelpCommand(helpCommand)
	root.AddCommand(newVersionCommand(app), newInfoCommand(app), newUpdateCommand(app), newSelfUpdateCommand(app), newUpdateHelperCommand(app), newUpdateRecoveryHelperCommand(app), newGenerateExampleCommand(app), newConfigAPICommand(app), newJoinCommand(app), newRunCommand(app), newValidateConfigCommand(app), newStatusCommand(app), newWGCommand(app), newSyncCommand(app), newStopCommand(app), newServiceCommand(app), newUninstallCommand(app), newRegisterInstallationCommand(app), newStunCommand(app))
	return root
}

func showHiddenCommands(root *cobra.Command) func() {
	var hidden []*cobra.Command
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		for _, command := range parent.Commands() {
			if command.Hidden {
				hidden = append(hidden, command)
				command.Hidden = false
			}
			visit(command)
		}
	}
	visit(root)
	return func() {
		for _, command := range hidden {
			command.Hidden = true
		}
	}
}

func outputWidth(out io.Writer) int {
	if file, ok := out.(*os.File); ok {
		if width, _, err := term.GetSize(int(file.Fd())); err == nil {
			return width
		}
	}
	return 80
}
