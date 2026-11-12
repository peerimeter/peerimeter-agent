package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
	"github.com/spf13/cobra"
)

func newStunCommand(app *application) *cobra.Command {
	var server string
	var jsonOutput bool
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
			if jsonOutput {
				return json.NewEncoder(app.out).Encode(result)
			}
			_, err = fmt.Fprintf(app.out, "STUN server: %s\nLocal address: %s\nMapped address: %s\n", result.Server, result.LocalAddress, result.MappedAddress)
			return err
		}),
	}
	cmd.Flags().StringVar(&server, "server", "", "Use only this STUN server instead of the default Google fallback list")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print the result as JSON")
	return cmd
}
