package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
	"github.com/spf13/cobra"
)

func newPeerViewCommand(app *application) *cobra.Command {
	var options paths.Options
	cmd := &cobra.Command{Use: "wg", Short: "Show WireGuard interface and peers (defaults to show)", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
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
		return presentation.PeerList(app.out, snapshot, time.Now(), shouldColor(app.out, app.color))
	})}
	directoryFlagSet(cmd.PersistentFlags(), &options)
	return cmd
}
