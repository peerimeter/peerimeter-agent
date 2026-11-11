package cli

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
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
			result, err := stunprobe.Probe(port, server)
			if err != nil {
				return err
			}
			return json.NewEncoder(app.out).Encode(result)
		}),
	}
	cmd.Flags().StringVar(&server, "server", "stun.l.google.com:19302", "STUN server host:port")
	return cmd
}
