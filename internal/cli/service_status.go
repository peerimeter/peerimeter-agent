package cli

import (
	"encoding/json"

	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
)

func newServiceStatusCommand(app *application) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the native service is installed and running",
		Args:  noArguments,
		RunE: app.handleResponse(func(*cobra.Command) error {
			status, err := service.Inspect()
			if err != nil {
				return err
			}
			return json.NewEncoder(app.out).Encode(status)
		}),
	}
}
