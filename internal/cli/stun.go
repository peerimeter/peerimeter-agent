package cli

import (
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
	"strconv"

	"github.com/spf13/cobra"
)

func newStunCommand(app *application) *cobra.Command {
	var server string
	port := 0
	cmd := &cobra.Command{
		Use:   "stun [local-udp-port]",
		Short: "Probe the public UDP mapping with STUN",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return errors.New("usage: stun [local-udp-port]")
			}
			if len(args) == 1 {
				value, err := strconv.Atoi(args[0])
				if err != nil || value < 1 || value > 65535 {
					return errors.New("local UDP port must be between 1 and 65535")
				}
				port = value
			}
			return nil
		},
		RunE: app.handle(func(cmd *cobra.Command) error {
			var result stunprobe.Result
			var err error
			if app.jsonOutput {
				result, err = probeSTUN(port, server)
			} else {
				result, err = runSTUN(cmd.Context(), app.out, port, server)
			}
			if err != nil {
				return err
			}
			if app.jsonOutput {
				return json.NewEncoder(app.out).Encode(result)
			}
			return presentation.Table(app.out, []string{"STUN SERVER", "LOCAL ADDRESS", "MAPPED ADDRESS"}, [][]string{{result.Server, result.LocalAddress, result.MappedAddress}}, shouldColor(app.out, app.color), outputWidth(app.out))
		}),
	}
	cmd.Flags().StringVar(&server, "server", "", "Use only this STUN server instead of the default Google fallback list")
	return cmd
}
