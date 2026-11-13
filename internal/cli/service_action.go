package cli

import (
	"encoding/json"
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
)

func serviceAction(app *application, action string, cfg service.Config) error {
	if err := service.Manage(action, cfg); err != nil {
		return err
	}
	return json.NewEncoder(app.out).Encode(map[string]string{"state": action})
}
func newServiceAction(app *application, action, short string) *cobra.Command {
	return &cobra.Command{Use: action, Short: short, Args: noArguments, RunE: app.handleResponse(func(*cobra.Command) error { return serviceAction(app, action, service.Config{}) })}
}
