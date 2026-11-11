package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
)

func directoryFlags(cmd *cobra.Command, options *paths.Options) {
	cmd.Flags().StringVar(&options.ConfigDir, "config-dir", "", "Installed configuration/key directory (platform default when omitted)")
	cmd.Flags().StringVar(&options.StateDir, "state-dir", "", "Persistent identity/state directory (platform default when omitted)")
	cmd.Flags().StringVar(&options.RuntimeDir, "runtime-dir", "", "Disposable local control directory (platform default when omitted)")
}
func serviceDirectories(cmd *cobra.Command, cfg *service.Config) {
	cmd.Flags().StringVar(&cfg.ConfigDirectory, "config-dir", "", "Installed configuration/key directory")
	cmd.Flags().StringVar(&cfg.StateDirectory, "state-dir", "", "Persistent identity/state directory")
	cmd.Flags().StringVar(&cfg.RuntimeDirectory, "runtime-dir", "", "Disposable local control directory")
}
