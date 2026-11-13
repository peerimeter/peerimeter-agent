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
	return newPeerViewCommand(app, false)
}

func newPeerViewCommand(app *application, wireguard bool) *cobra.Command {
	var options paths.Options
	use, short := "peers", "Show peers with a styled overview (or --json)"
	if wireguard {
		use, short = "wg", "Show WireGuard interface and peers (defaults to show)"
	}
	cmd := &cobra.Command{Use: use, Short: short, Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
		if app.color != "auto" && app.color != "always" && app.color != "never" {
			return errors.New("color must be auto, always or never")
		}
		layout, err := paths.Resolve(options)
		if err != nil {
			return err
		}
		if app.jsonOutput {
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
		if wireguard {
			return presentation.PeerList(app.out, snapshot, time.Now(), shouldColor(app.out, app.color))
		}
		return presentation.PeerOverview(app.out, snapshot, time.Now(), shouldColor(app.out, app.color), outputWidth(app.out))
	})}
	if wireguard {
		directoryFlagSet(cmd.PersistentFlags(), &options)
	} else {
		directoryFlags(cmd, &options)
	}
	return cmd
}
