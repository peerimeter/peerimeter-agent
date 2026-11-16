package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
	"github.com/spf13/cobra"
)

var environmentRows = [][]string{
	{"PEERIMETER_LOG_FORMAT", "Log format: console (default), text, or json"},
	{"NO_COLOR", "Disable ANSI colors when set"},
	{"TERM", "Set to dumb to disable ANSI colors"},
}

func directoryRows() [][]string {
	layout, err := paths.Resolve(paths.Options{})
	if err != nil {
		return [][]string{{"install", "executable directory (installer-selected)"}}
	}
	executable, executableErr := os.Executable()
	installDir := "installer-selected"
	if executableErr == nil {
		installDir = filepath.Dir(executable)
	}
	rows := [][]string{
		{"install", installDir},
		{"config", layout.ConfigDir},
		{"data", layout.StateDir},
		{"runtime", layout.RuntimeDir},
	}
	if executableErr == nil {
		if inv, loadErr := installstate.Load(installDir); loadErr == nil {
			rows[0][1] = inv.InstallDir
			rows = append(rows,
				[]string{"installer data", inv.DataDir},
				[]string{"docs", inv.DocDir},
				[]string{"locks", inv.LockDir},
			)
		}
	}
	return rows
}

func writeInfoTables(out io.Writer, color bool, width int) error {
	if _, err := fmt.Fprintln(out, "Environment"); err != nil {
		return err
	}
	if err := presentation.Table(out, []string{"VARIABLE", "DESCRIPTION"}, environmentRows, color, width); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Directories"); err != nil {
		return err
	}
	return presentation.Table(out, []string{"DIRECTORY", "PATH"}, directoryRows(), color, width)
}

func newInfoCommand(app *application) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show environment variables and resolved directories",
		Args:  noArguments,
		RunE: app.handle(func(cmd *cobra.Command) error {
			if app.jsonOutput {
				return json.NewEncoder(app.out).Encode(struct {
					Environment [][]string `json:"environment"`
					Directories [][]string `json:"directories"`
				}{Environment: environmentRows, Directories: directoryRows()})
			}
			return writeInfoTables(app.out, shouldColor(app.out, app.color), outputWidth(app.out))
		}),
	}
}
