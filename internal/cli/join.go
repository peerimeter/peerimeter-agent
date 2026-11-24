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
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/serviceapi"
	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
	"github.com/spf13/cobra"
)

const (
	defaultPersistentKeepaliveSeconds = 25
	maxCredentialFileBytes            = 16 << 10
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

type managedNetworkMetadata struct {
	Version           int    `json:"version" yaml:"version"`
	APIURL            string `json:"api_url" yaml:"api_url"`
	NetworkID         string `json:"network_id" yaml:"network_id"`
	NodeID            string `json:"node_id" yaml:"node_id"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http,omitempty" yaml:"allow_insecure_http,omitempty"`
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

func refreshManagedPeers(ctx context.Context, client *serviceapi.Client, networkID, nodeID string, underlay []string, desired config.Config) (config.Config, error) {
	peers, err := client.PullPeers(ctx, networkID, nodeID)
	if err != nil {
		return config.Config{}, err
	}
	desired.Peers = nil
	entries, routes := eligiblePeerEntries(underlay, peers.Peers)
	for _, entry := range entries {
		peer := entry.peer
		endpoint := entry.endpoint
		if discovery.EndpointConflictsWithRoutes(endpoint, routes) {
			endpoint = peer.PublicEndpoint
			if endpoint == "" || discovery.EndpointConflictsWithRoutes(endpoint, routes) {
				continue
			}
		}
		desired.Peers = append(desired.Peers, config.Peer{PublicKey: peer.PublicKey, AllowedIPs: []string{peer.TunnelAddress + "/32"}, Endpoint: endpoint, PersistentKeepaliveSeconds: defaultPersistentKeepaliveSeconds})
	}
	return desired, nil
}

func newJoinCommand(app *application) *cobra.Command {
	var nodeID, operator, token, tokenFile string
	var allowInsecureHTTP bool
	var listenPort int
	var dirs paths.Options
	cmd := &cobra.Command{Use: "join", Short: "Register this agent with a service-managed network", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		if token != "" && cmd.Flags().Changed("token-file") {
			return errors.New("--token and --token-file cannot be used together")
		}
		return runJoin(cmd.Context(), app, joinOptions{nodeID: nodeID, operator: operator, token: token, tokenFile: tokenFile, listenPort: listenPort, listenPortSet: cmd.Flags().Changed("listen-port"), allowInsecureHTTP: allowInsecureHTTP, dirs: dirs})
	})}
	cmd.Long = "Register this agent using a network-scoped Base64URL token and save its managed configuration. The token is read from stdin by default. The network ID comes from the token; the node ID defaults to the machine hostname. Start a tunnel separately with run --config."
	cmd.Flags().StringVar(&token, "token", "", "Join token (prefer --token-file for sensitive values)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "-", "Read join token from this file, or - for stdin (default)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "Optional stable node ID (defaults to hostname)")
	cmd.Flags().IntVar(&listenPort, "listen-port", 0, "WireGuard UDP listen port (allocated automatically when omitted)")
	cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
	cmd.Flags().BoolVar(&allowInsecureHTTP, "allow-insecure-http", false, "Allow HTTP API URLs outside localhost (sends the enrollment token without TLS)")
	directoryFlags(cmd, &dirs)
	return cmd
}

type joinOptions struct {
	nodeID            string
	operator          string
	token             string
	tokenFile         string
	listenPort        int
	listenPortSet     bool
	allowInsecureHTTP bool
	dirs              paths.Options
}

func runJoin(ctx context.Context, app *application, opts joinOptions) error {
	token, err := readJoinToken(opts.token, opts.tokenFile, app.in)
	if err != nil {
		return err
	}
	bundle, err := serviceapi.DecodeJoinTokenWithInsecureHTTP(token, opts.allowInsecureHTTP)
	if err != nil {
		return err
	}
	client := serviceapi.NewWithDebug(bundle, app.debug)
	networkID := bundle.NetworkID
	layout, err := paths.Resolve(opts.dirs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(layout.ConfigDir, 0o700); err != nil {
		return errors.New("cannot create protected agent configuration directory")
	}
	if err := localJoinDirectory(layout.ConfigDir); err != nil {
		return err
	}
	if err := local.ValidateOperator(opts.operator); err != nil {
		return err
	}
	managedStateDir := filepath.Join(layout.StateDir, "managed")
	if err := local.PrepareDirectory(managedStateDir); err != nil {
		return err
	}
	joinLock, err := installstate.LockNamed(managedStateDir, ".join.lock", false)
	if err != nil {
		return fmt.Errorf("cannot serialize network enrollment: %w", err)
	}
	defer joinLock.Close()
	opts.listenPort, err = resolveOrAllocateJoinPort(opts, layout, networkID)
	if err != nil {
		return err
	}
	network, err := client.GetNetwork(ctx, networkID)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(layout.ConfigDir, networkID+".key")
	_, publicText, err := loadOrGenerateNetworkKey(keyPath)
	if err != nil {
		return err
	}
	nodeID, err := resolveNodeID(opts.nodeID)
	if err != nil {
		return err
	}
	underlay, err := discovery.PrimaryUnderlay(ctx)
	if err != nil {
		return err
	}
	publicEndpoint := ""
	if mapped, err := stunprobe.Probe(opts.listenPort, ""); err == nil {
		publicEndpoint = mapped.MappedAddress
	} else {
		// LAN candidates still work when STUN is unavailable.
		fmt.Fprintln(os.Stderr, "STUN endpoint discovery unavailable; joining with LAN candidates only")
	}
	registered, err := client.RegisterNode(ctx, networkID, nodeID, serviceapi.NodeRegistration{
		Version: 1, AgentCLIVersion: Version, PublicKey: publicText, ListenPort: opts.listenPort, PrimaryInterface: underlay.Name,
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
	desired := config.Config{Version: 1, Mode: "static", Network: config.Network{ID: network.ID, Name: network.Name, CIDR: network.CIDR}, Interface: config.Interface{PrivateKeyFile: keyPath, Address: []string{address.String() + "/32"}, ListenPort: opts.listenPort}}
	initial, err := refreshManagedPeers(ctx, client, networkID, nodeID, underlay.Addresses, desired)
	if err != nil {
		return err
	}
	if err := persistJoinedNetworkState(layout, bundle, nodeID, opts.allowInsecureHTTP, initial); err != nil {
		return err
	}
	if err := json.NewEncoder(app.out).Encode(map[string]any{"state": "registered", "network_id": networkID, "node_id": nodeID, "tunnel_address": registered.TunnelAddress, "peer_count": len(initial.Peers)}); err != nil {
		return err
	}
	return nil
}

func resolveOrAllocateJoinPort(opts joinOptions, layout paths.Layout, networkID string) (int, error) {
	if !opts.listenPortSet {
		return allocateListenPort(layout.ConfigDir, layout.StateDir, networkID)
	}
	if opts.listenPort < 1 || opts.listenPort > maxUDPPort {
		return 0, errors.New("--listen-port must be between 1 and 65535")
	}
	if err := ensureListenPortAvailable(layout.ConfigDir, layout.StateDir, networkID, opts.listenPort); err != nil {
		return 0, err
	}
	return opts.listenPort, nil
}

func persistJoinedNetworkState(layout paths.Layout, bundle serviceapi.JoinBundle, nodeID string, allowInsecureHTTP bool, initial config.Config) error {
	encoded, err := config.MarshalYAML(initial)
	if err != nil {
		return err
	}
	if err := config.Validate(initial, runtime.GOOS); err != nil {
		return err
	}
	configPath := filepath.Join(layout.ConfigDir, initial.Network.ID+".yaml")
	if err := writeConfigFile(configPath, encoded); err != nil {
		return errors.New("cannot securely update managed network configuration")
	}
	if err := saveManagedToken(filepath.Join(layout.StateDir, "managed", initial.Network.ID+".token"), bundle.EnrollmentToken); err != nil {
		return err
	}
	return saveManagedNetworkMetadata(layout.StateDir, managedNetworkMetadata{
		Version: 1, APIURL: bundle.APIURL, NetworkID: initial.Network.ID, NodeID: nodeID,
		AllowInsecureHTTP: allowInsecureHTTP,
	})
}

func readJoinToken(token, tokenFile string, stdin io.Reader) (string, error) {
	if token != "" {
		token = strings.TrimSpace(token)
		if token == "" {
			return "", errors.New("join token is empty")
		}
		return token, nil
	}
	reader := stdin
	if tokenFile != "-" {
		file, err := os.Open(tokenFile)
		if err != nil {
			return "", fmt.Errorf("cannot open join token file: %w", err)
		}
		defer file.Close()
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxCredentialFileBytes+1))
	if err != nil || len(data) > maxCredentialFileBytes {
		return "", errors.New("could not read join token from stdin or token is too large")
	}
	token = strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("join token is empty")
	}
	return token, nil
}

func loadOrGenerateNetworkKey(keyPath string) ([32]byte, string, error) {
	private, err := secret.Load(keyPath)
	if err != nil {
		if _, statErr := os.Lstat(keyPath); statErr == nil {
			return [32]byte{}, "", err
		}
		private, err = secret.Generate()
		if err != nil {
			return [32]byte{}, "", err
		}
		if err := secret.WriteNew(keyPath, private); err != nil {
			return [32]byte{}, "", err
		}
	}
	public, err := secret.Public(private)
	if err != nil {
		return [32]byte{}, "", err
	}
	return private, base64.StdEncoding.EncodeToString(public[:]), nil
}

func resolveNodeID(nodeID string) (string, error) {
	if nodeID != "" {
		return nodeID, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", errors.New("cannot determine hostname for default node ID")
	}
	return defaultNodeID(hostname)
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
	if existing, err := secret.ReadProtectedText(path, maxCredentialFileBytes); err == nil {
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
