package cli

import (
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func newRegisterInstallationCommand(app *application) *cobra.Command {
	var dir string
	var allowInsecureInstallDir bool
	cmd := &cobra.Command{Use: "register-installation", Hidden: true, Args: noArguments, RunE: app.handle(func(*cobra.Command) error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		actual, err := installstate.Canonical(filepath.Dir(exe))
		if err != nil {
			return err
		}
		requested, err := installstate.Canonical(dir)
		if err != nil {
			return err
		}
		same := actual == requested
		if runtime.GOOS == "windows" {
			same = strings.EqualFold(actual, requested)
		}
		if !same {
			return errors.New("installation registration must run from the selected installed program directory")
		}
		if err := installstate.RegisterWithPolicy(dir, allowInsecureInstallDir); err != nil {
			return err
		}
		return json.NewEncoder(app.out).Encode(map[string]string{"state": "registered"})
	})}
	cmd.Flags().StringVar(&dir, "install-dir", "", "Absolute installed program directory")
	cmd.Flags().BoolVar(&allowInsecureInstallDir, "allow-insecure-install-dir", false, "Allow group/other writable installation directories (keeps owner and link checks)")
	_ = cmd.MarkFlagRequired("install-dir")
	return cmd
}
