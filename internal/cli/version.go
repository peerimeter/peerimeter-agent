package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"io"
	"os"
	"runtime"
	"strings"
)

// Version is replaced by release builds with -ldflags -X.
var Version = "0.0.0-dev"

// The orbit and P echo the project's pink/purple peer-network logo.
const versionLogo = `        .---o---.
      .'  PPPPP  '.
     o    PP  PP   \
     |    PPPPP    o   P E E R I M E T E R
      '.  PP     .'    WireGuard mesh agent
        '--o---'`

func newVersionCommand(app *application) *cobra.Command {
	cmd := &cobra.Command{Use: "version", Short: "Show the Peerimeter logo and version (or --json)", Args: noArguments, RunE: app.handle(func(*cobra.Command) error {
		if app.color != "auto" && app.color != "always" && app.color != "never" {
			return errors.New("color must be auto, always or never")
		}
		if app.jsonOutput {
			return json.NewEncoder(app.out).Encode(map[string]string{"version": Version, "go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
		}
		return renderVersion(app.out, shouldColor(app.out, app.color))
	})}
	return cmd
}
func shouldColor(out io.Writer, mode string) bool {
	if mode == "never" {
		return false
	}
	if mode == "always" {
		return true
	}
	if _, set := os.LookupEnv("NO_COLOR"); set || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := out.(*os.File)
	return ok && term.IsTerminal(int(file.Fd())) && enableTerminalColors(file)
}
func renderVersion(out io.Writer, color bool) error {
	palette := []int{198, 199, 165, 129, 93, 63}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	for i, line := range strings.Split(versionLogo, "\n") {
		if color {
			line = fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", palette[i%len(palette)], line)
		}
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return presentation.Table(out, nil, [][]string{
		{"Agent", Version},
		{"Platform", runtime.GOOS + "/" + runtime.GOARCH},
		{"Go", runtime.Version()},
	}, color, versionOutputWidth(out))
}

func versionOutputWidth(out io.Writer) int {
	if file, ok := out.(*os.File); ok {
		if width, _, err := term.GetSize(int(file.Fd())); err == nil && width > 0 {
			return width
		}
	}
	return 80
}
