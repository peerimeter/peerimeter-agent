package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/discovery"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/serviceapi"
	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
	"github.com/spf13/cobra"
)

type registeredPeer struct {
	Version        int      `json:"version"`
	NodeID         string   `json:"node_id"`
	PublicKey      string   `json:"public_key"`
	TunnelAddress  string   `json:"tunnel_address"`
	ListenPort     int      `json:"listen_port"`
	LocalAddresses []string `json:"local_addresses"`
	PublicEndpoint string   `json:"public_endpoint"`
}

type peerEntry struct {
	id       string
	peer     registeredPeer
	endpoint string
}

func defaultNodeID(hostname string) (string, error) {
	id := strings.TrimSpace(hostname)
	id = strings.TrimSuffix(id, ".localdomain")
	if id == "" {
		return "", errors.New("cannot determine hostname for default node ID")
	}
	return id, nil
}

func eligiblePeerEntries(underlay []string, peers map[string]json.RawMessage) ([]peerEntry, []string) {
	entries := make([]peerEntry, 0, len(peers))
	routes := make([]string, 0, len(peers))
	for peerID, raw := range peers {
		var peer registeredPeer
		if err := json.Unmarshal(raw, &peer); err != nil || peer.Version != 1 || peer.NodeID != peerID || peer.PublicKey == "" || peer.TunnelAddress == "" {
			continue
		}
		endpoint, ok := discovery.SelectEndpoint(underlay, peer.LocalAddresses, peer.ListenPort, peer.PublicEndpoint)
		if !ok {
			continue
		}
		entries = append(entries, peerEntry{id: peerID, peer: peer, endpoint: endpoint})
		routes = append(routes, peer.TunnelAddress+"/32")
	}
	return entries, routes
}

func newJoinCommand(app *application) *cobra.Command {
	var networkID, nodeID, operator string
	var allowInsecureHTTP bool
	var listenPort int
	var dirs paths.Options
	cmd := &cobra.Command{Use: "join", Short: "Register this agent with a service-managed network", Args: noArguments, RunE: app.handle(func(cmd *cobra.Command) error {
		data, err := io.ReadAll(io.LimitReader(app.in, 16<<10+1))
		if err != nil || len(data) > 16<<10 {
			return errors.New("could not read join token from stdin or token is too large")
		}
		token := strings.TrimSpace(string(data))
		bundle, err := serviceapi.DecodeJoinTokenWithInsecureHTTP(token, allowInsecureHTTP)
		if err != nil {
			return err
		}
		client := serviceapi.New(bundle)
		networkID = bundle.NetworkID
		if listenPort < 1 || listenPort > 65535 {
			return errors.New("--listen-port must be between 1 and 65535")
		}
		layout, err := paths.Resolve(dirs)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(layout.ConfigDir, 0o700); err != nil {
			return errors.New("cannot create protected agent configuration directory")
		}
		if err := localJoinDirectory(layout.ConfigDir); err != nil {
			return err
		}
		if err := local.ValidateOperator(operator); err != nil {
			return err
		}
		network, err := client.GetNetwork(cmd.Context(), networkID)
		if err != nil {
			return err
		}
		keyPath := filepath.Join(layout.ConfigDir, networkID+".key")
		private, err := secret.Load(keyPath)
		if err != nil {
			if _, statErr := os.Lstat(keyPath); statErr == nil {
				return err
			}
			private, err = secret.Generate()
			if err != nil {
				return err
			}
			if err := secret.WriteNew(keyPath, private); err != nil {
				return err
			}
		}
		public, err := secret.Public(private)
		if err != nil {
			return err
		}
		publicText := base64.StdEncoding.EncodeToString(public[:])
		if nodeID == "" {
			hostname, hostErr := os.Hostname()
			if hostErr != nil {
				return errors.New("cannot determine hostname for default node ID")
			}
			nodeID, err = defaultNodeID(hostname)
			if err != nil {
				return err
			}
		}
		underlay, err := discovery.PrimaryUnderlay(cmd.Context())
		if err != nil {
			return err
		}
		publicEndpoint := ""
		if mapped, err := stunprobe.Probe(listenPort, ""); err == nil {
			publicEndpoint = mapped.MappedAddress
		} else {
			// LAN candidates still work when STUN is unavailable.
			fmt.Fprintln(os.Stderr, "STUN endpoint discovery unavailable; joining with LAN candidates only")
		}
		registered, err := client.RegisterNode(cmd.Context(), networkID, nodeID, serviceapi.NodeRegistration{
			Version: 1, PublicKey: publicText, ListenPort: listenPort, PrimaryInterface: underlay.Name,
			LocalAddresses: underlay.Addresses, PublicEndpoint: publicEndpoint,
		})
		if err != nil {
			return err
		}
		address, err := netip.ParseAddr(registered.TunnelAddress)
		prefix, prefixErr := netip.ParsePrefix(network.CIDR)
		if err != nil || prefixErr != nil || !prefix.Contains(address) {
			return errors.New("service assigned a tunnel address outside the network CIDR")
		}
		configPath := filepath.Join(layout.ConfigDir, networkID+".yaml")
		loadConfig := func(ctx context.Context) (config.Config, error) {
			peers, err := client.PullPeers(ctx, networkID, nodeID)
			if err != nil {
				return config.Config{}, err
			}
			desired := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: network.ID, Name: network.Name, CIDR: network.CIDR}, Interface: config.Interface{PrivateKeyFile: keyPath, Address: []string{address.String() + "/32"}, ListenPort: listenPort}}
			entries, routes := eligiblePeerEntries(underlay.Addresses, peers.Peers)
			for _, entry := range entries {
				peer := entry.peer
				endpoint := entry.endpoint
				if discovery.EndpointConflictsWithRoutes(endpoint, routes) {
					endpoint = peer.PublicEndpoint
					if endpoint == "" || discovery.EndpointConflictsWithRoutes(endpoint, routes) {
						continue
					}
				}
				desired.Peers = append(desired.Peers, config.Peer{PublicKey: peer.PublicKey, AllowedIPs: []string{peer.TunnelAddress + "/32"}, Endpoint: endpoint, PersistentKeepaliveSeconds: 25})
			}
			encoded, err := config.MarshalYAML(desired)
			if err != nil {
				return config.Config{}, err
			}
			if err := config.Validate(desired, runtime.GOOS); err != nil {
				return config.Config{}, err
			}
			if err := writeConfigFile(configPath, encoded); err != nil {
				return config.Config{}, errors.New("cannot securely update managed network configuration")
			}
			return desired, nil
		}
		initial, err := loadConfig(cmd.Context())
		if err != nil {
			return err
		}
		if err := saveManagedToken(filepath.Join(layout.StateDir, "managed", networkID+".token"), bundle.EnrollmentToken); err != nil {
			return err
		}
		if err := json.NewEncoder(app.out).Encode(map[string]any{"state": "registered", "network_id": networkID, "node_id": nodeID, "tunnel_address": registered.TunnelAddress, "peer_count": len(initial.Peers)}); err != nil {
			return err
		}
		return nil
	})}
	cmd.Long = "Register this agent using a network-scoped Base64URL token read from stdin and save its managed configuration. The network ID comes from the token; the node ID defaults to the machine hostname. Start a tunnel separately with run --config."
	cmd.Flags().StringVar(&nodeID, "node-id", "", "Optional stable node ID (defaults to hostname)")
	cmd.Flags().IntVar(&listenPort, "listen-port", 51820, "WireGuard UDP listen port")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	cmd.Flags().BoolVar(&allowInsecureHTTP, "allow-insecure-http", false, "Allow HTTP API URLs outside localhost (sends the enrollment token without TLS)")
	directoryFlags(cmd, &dirs)
	return cmd
}

func localJoinDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return errors.New("agent configuration path is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("agent configuration directory must not be accessible by group or other users")
	}
	return nil
}

func saveManagedToken(path, token string) error {
	if existing, err := secret.ReadProtectedText(path, 16<<10); err == nil {
		if strings.TrimSpace(existing) == token {
			return nil
		}
		return errors.New("a different managed service credential is already stored")
	} else if _, statErr := os.Lstat(path); statErr == nil {
		return errors.New("existing managed service credential is not readable safely")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.New("cannot create protected managed state directory")
	}
	file, err := secret.CreateProtectedFile(path)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(file, token); err != nil {
		file.Close()
		_ = os.Remove(path)
		return errors.New("cannot save protected service credential")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return errors.New("cannot save protected service credential")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("cannot save protected service credential")
	}
	return nil
}
