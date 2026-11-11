package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
	"github.com/spf13/cobra"
	"time"
)

func newPeersCommand(app *application) *cobra.Command {
	var options paths.Options
	var jsonOutput bool
	var color string
	cmd := &cobra.Command{Use: "peers", Short: "Show WireGuard peers in wgshow style (or --json)", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
		if color != "auto" && color != "always" && color != "never" {
			return errors.New("color must be auto, always or never")
		}
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		if jsonOutput {
			return local.Request(cmd.Context(), layout.RuntimeDir, "peers", app.out)
		}
		var raw bytes.Buffer
		if err := local.Request(cmd.Context(), layout.RuntimeDir, "status", &raw); err != nil {
			return err
		}
		var snapshot platform.Snapshot
		if err := json.Unmarshal(raw.Bytes(), &snapshot); err != nil {
			return errors.New("cannot decode local public peer state")
		}
		return presentation.PeerList(app.out, snapshot, time.Now(), shouldColor(app.out, color))
	})}
	directoryFlags(cmd, &options)
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print stable machine-readable public peer state")
	cmd.Flags().StringVar(&color, "color", "auto", "Color mode: auto, always or never")
	return cmd
}
