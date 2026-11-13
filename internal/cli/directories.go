package cli

import (
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func directoryFlags(cmd *cobra.Command, options *paths.Options) {
	directoryFlagSet(cmd.Flags(), options)
}

func directoryFlagSet(flags *pflag.FlagSet, options *paths.Options) {
	flags.StringVar(&options.ConfigDir, "config-dir", "", "Installed configuration/key directory (platform default when omitted)")
	flags.StringVar(&options.StateDir, "state-dir", "", "Persistent identity/state directory (platform default when omitted)")
	flags.StringVar(&options.RuntimeDir, "runtime-dir", "", "Disposable local control directory (platform default when omitted)")
}
func serviceDirectories(cmd *cobra.Command, cfg *service.Config) {
	cmd.Flags().StringVar(&cfg.ConfigDirectory, "config-dir", "", "Installed configuration/key directory")
	cmd.Flags().StringVar(&cfg.StateDirectory, "state-dir", "", "Persistent identity/state directory")
	cmd.Flags().StringVar(&cfg.RuntimeDirectory, "runtime-dir", "", "Disposable local control directory")
}
