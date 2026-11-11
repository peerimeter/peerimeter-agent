package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func newGenerateExampleCommand(app *application) *cobra.Command {
	var directory string
	cmd := &cobra.Command{Use: "generate-example", Short: "Create paired configs and fresh protected local keys", Args: noArguments, RunE: app.handle(func(*cobra.Command) error {
		if err := generate(directory); err != nil {
			return err
		}
		return json.NewEncoder(app.out).Encode(map[string]string{"state": "example_generated", "credentials": "protected local key files; keep private"})
	})}
	cmd.Flags().StringVar(&directory, "directory", "", "New destination directory (must not exist)")
	_ = cmd.MarkFlagRequired("directory")
	return cmd
}
func generate(directory string) error {
	// Exclusive directory creation prevents overwriting an existing config or key.
	if err := os.Mkdir(directory, 0700); err != nil {
		return errors.New("example destination must be a new directory inside an existing trusted parent")
	}
	var keys [2][32]byte
	var pubs [2][32]byte
	for i := range keys {
		var err error
		keys[i], err = secret.Generate()
		if err != nil {
			return err
		}
		pubs[i], err = secret.Public(keys[i])
		if err != nil {
			return err
		}
	}
	names := []string{"a", "b"}
	for i, name := range names {
		if err := secret.WriteNew(filepath.Join(directory, "peer-"+name+".key"), keys[i]); err != nil {
			return err
		}
		cfg := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "example-network", Name: "example"}, Interface: config.Interface{PrivateKeyFile: "peer-" + name + ".key", Address: []string{fmt.Sprintf("10.80.0.%d/32", i+1)}, ListenPort: 51820 + i}, Peers: []config.Peer{{PublicKey: base64.StdEncoding.EncodeToString(pubs[1-i][:]), AllowedIPs: []string{fmt.Sprintf("10.80.0.%d/32", 2-i)}, Endpoint: fmt.Sprintf("127.0.0.1:%d", 51821-i), PersistentKeepaliveSeconds: 25}}}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return errors.New("cannot encode example config")
		}
		if err := os.WriteFile(filepath.Join(directory, "peer-"+name+".json"), append(data, '\n'), 0600); err != nil {
			return errors.New("cannot write example config")
		}
	}
	return nil
}
