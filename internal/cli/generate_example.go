package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
	"github.com/spf13/cobra"
)

const maxExamplePeers = 253 // 10.80.0.1 through 10.80.0.253

var probeExampleEndpoint = stunprobe.Probe

func newGenerateExampleCommand(app *application) *cobra.Command {
	var directory, stunServer string
	var count, stunPeer int
	cmd := &cobra.Command{Use: "generate-example", Short: "Create static mesh configs and fresh protected local keys", Args: noArguments, RunE: app.handle(func(*cobra.Command) error {
		if err := generateMesh(directory, count, stunPeer, stunServer); err != nil {
			return err
		}
		return json.NewEncoder(app.out).Encode(map[string]string{"state": "example_generated", "credentials": "protected local key files; keep private"})
	})}
	cmd.Flags().StringVar(&directory, "directory", "", "New destination directory (must not exist)")
	cmd.Flags().IntVar(&count, "peers", 2, "Number of peers to generate (2–253)")
	cmd.Flags().IntVar(&stunPeer, "stun-peer", 0, "One-based peer number on this machine whose public UDP endpoint is probed")
	cmd.Flags().StringVar(&stunServer, "stun-server", "", "STUN server for --stun-peer (defaults to the standard fallback list)")
	_ = cmd.MarkFlagRequired("directory")
	return cmd
}

func examplePeerName(i int) string {
	if i < 26 {
		return fmt.Sprintf("peer-%c", 'a'+i)
	}
	return fmt.Sprintf("peer-%d", i+1)
}

func generateMesh(directory string, count, stunPeer int, stunServer string) error {
	if count < 2 || count > maxExamplePeers {
		return errors.New("peer count must be between 2 and 253")
	}
	if stunPeer < 0 || stunPeer > count {
		return errors.New("STUN peer must be between 1 and the generated peer count")
	}
	if stunServer != "" && stunPeer == 0 {
		return errors.New("--stun-server requires --stun-peer")
	}
	endpoints := make([]string, count)
	for i := range endpoints {
		endpoints[i] = fmt.Sprintf("127.0.0.1:%d", 51820+i)
	}
	if stunPeer != 0 {
		result, err := probeExampleEndpoint(51820+stunPeer-1, stunServer)
		if err != nil {
			return fmt.Errorf("STUN probe for selected peer failed: %w", err)
		}
		endpoints[stunPeer-1] = result.MappedAddress
	}
	// Exclusive creation prevents overwriting existing credentials.
	if err := os.Mkdir(directory, 0700); err != nil {
		return errors.New("example destination must be a new directory inside an existing trusted parent")
	}
	keys := make([][32]byte, count)
	pubs := make([][32]byte, count)
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
	for i := range keys {
		name := examplePeerName(i)
		if err := secret.WriteNew(filepath.Join(directory, name+".key"), keys[i]); err != nil {
			return err
		}
		cfg := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: "example-network", Name: "example"}, Interface: config.Interface{PrivateKeyFile: name + ".key", Address: []string{fmt.Sprintf("10.80.0.%d/32", i+1)}, ListenPort: 51820 + i}}
		for j := range keys {
			if j == i {
				continue
			}
			cfg.Peers = append(cfg.Peers, config.Peer{PublicKey: base64.StdEncoding.EncodeToString(pubs[j][:]), AllowedIPs: []string{fmt.Sprintf("10.80.0.%d/32", j+1)}, Endpoint: endpoints[j], PersistentKeepaliveSeconds: 25})
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return errors.New("cannot encode example config")
		}
		if err := os.WriteFile(filepath.Join(directory, name+".json"), append(data, '\n'), 0600); err != nil {
			return errors.New("cannot write example config")
		}
	}
	return nil
}
