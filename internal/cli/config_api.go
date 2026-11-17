package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/serviceapi"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type serviceConfigOptions struct {
	kind, networkID, nodeID, file, apiURL string
	dirs                                  paths.Options
	allowInsecureHTTP                     bool
}

func newConfigAPICommand(app *application) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Pull or push network and node YAML through the service API", Args: noArguments}
	var pull serviceConfigOptions
	pullCmd := &cobra.Command{Use: "pull", Short: "Download a network or node configuration", Long: "Download configuration using the token and service URL saved by join. With one joined network, --network-id is optional; with multiple joined networks, --network-id is required. --file defaults to a separate Service API YAML path and does not overwrite the WireGuard configuration created by join. For --kind node, the joined node ID is used unless --node-id is supplied. --api-url is required only for older joins that did not save service metadata; supplying it saves the missing metadata for later commands.", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(pull.dirs)
		if err != nil {
			return err
		}
		if err := resolveConfigSelection(&pull, layout); err != nil {
			return err
		}
		if err := validateConfigSelection(pull); err != nil {
			return err
		}
		client, err := managedServiceClient(pull, layout)
		if err != nil {
			return err
		}
		var data []byte
		if pull.kind == "network" {
			data, err = client.PullNetwork(cmd.Context(), pull.networkID)
		} else {
			data, err = client.PullNode(cmd.Context(), pull.networkID, pull.nodeID)
		}
		if err != nil {
			return err
		}
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			return errors.New("service returned an invalid configuration")
		}
		data, err = config.MarshalYAML(value)
		if err != nil {
			return errors.New("could not encode pulled configuration as YAML")
		}
		if err := os.MkdirAll(filepath.Dir(pull.file), 0o700); err != nil {
			return errors.New("could not create protected configuration directory")
		}
		if err := writeConfigFile(pull.file, data); err != nil {
			return errors.New("could not securely write pulled configuration")
		}
		return writeJSONLine(app.out, map[string]string{"state": "config_pulled", "kind": pull.kind, "network_id": pull.networkID, "file": pull.file})
	})}
	addServiceConfigFlags(pullCmd, &pull)

	var push serviceConfigOptions
	pushCmd := &cobra.Command{Use: "push", Short: "Upload a network or node configuration", Long: "Upload configuration using the token and service URL saved by join. With one joined network, --network-id is optional; with multiple joined networks, --network-id is required. --file defaults to a separate Service API YAML path and does not upload the WireGuard configuration created by join. For --kind node, the joined node ID is used unless --node-id is supplied. --api-url is required only for older joins that did not save service metadata; supplying it saves the missing metadata for later commands.", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		layout, err := paths.Resolve(push.dirs)
		if err != nil {
			return err
		}
		if err := resolveConfigSelection(&push, layout); err != nil {
			return err
		}
		if err := validateConfigSelection(push); err != nil {
			return err
		}
		client, err := managedServiceClient(push, layout)
		if err != nil {
			return err
		}
		data, err := readConfigFile(push.file)
		if err != nil {
			return err
		}
		value, err := decodeYAMLConfig(data)
		if err != nil {
			return errors.New("configuration file is not valid YAML")
		}
		data, err = json.Marshal(value)
		if err != nil {
			return errors.New("could not encode configuration for the service API")
		}
		if push.kind == "network" {
			err = client.PushNetwork(cmd.Context(), push.networkID, data)
		} else {
			err = client.PushNode(cmd.Context(), push.networkID, push.nodeID, data)
		}
		if err != nil {
			return err
		}
		return writeJSONLine(app.out, map[string]string{"state": "config_pushed", "kind": push.kind, "network_id": push.networkID})
	})}
	addServiceConfigFlags(pushCmd, &push)

	cmd.AddCommand(pullCmd, pushCmd)
	return cmd
}

func decodeYAMLConfig(data []byte) (any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("configuration must contain exactly one YAML document")
	}
	return value, nil
}

func addServiceConfigFlags(cmd *cobra.Command, options *serviceConfigOptions) {
	cmd.Flags().StringVar(&options.kind, "kind", "network", "Configuration kind: network or node")
	cmd.Flags().StringVar(&options.networkID, "network-id", "", "Managed network ID (required when multiple networks are joined)")
	cmd.Flags().StringVar(&options.nodeID, "node-id", "", "Node ID (defaults to the joined node; required for --kind node if no node ID was saved)")
	cmd.Flags().StringVar(&options.file, "file", "", "YAML file (defaults to a separate Service API configuration path)")
	cmd.Flags().StringVar(&options.apiURL, "api-url", "", "Service API URL (required once for older joins without saved service metadata)")
	cmd.Flags().BoolVar(&options.allowInsecureHTTP, "allow-insecure-http", false, "Allow a non-local HTTP API URL (sends the enrollment token without TLS)")
	cmd.Flags().StringVar(&options.dirs.ConfigDir, "config-dir", "", "Installed configuration/key directory")
	cmd.Flags().StringVar(&options.dirs.StateDir, "state-dir", "", "Persistent identity/state directory")
}

func resolveConfigSelection(options *serviceConfigOptions, layout paths.Layout) error {
	if options.kind != "network" && options.kind != "node" {
		return errors.New("--kind must be network or node")
	}
	if options.networkID == "" {
		networks, err := managedNetworkIDs(layout.StateDir)
		if err != nil {
			return err
		}
		switch len(networks) {
		case 0:
			return errors.New("no joined networks found; run join before config pull or push")
		case 1:
			options.networkID = networks[0]
		default:
			return fmt.Errorf("--network-id is required when multiple networks are joined (%s)", strings.Join(networks, ", "))
		}
	}
	if options.kind == "node" && options.nodeID == "" {
		metadata, err := readManagedNetworkMetadata(layout.StateDir, options.networkID)
		if err != nil {
			return err
		}
		if metadata.NodeID == "" {
			return errors.New("--node-id is required because this network has no saved node ID")
		}
		options.nodeID = metadata.NodeID
	}
	if options.kind == "node" && !validManagedNetworkID(options.nodeID) {
		return errors.New("--node-id is invalid")
	}
	if options.file == "" && options.kind == "network" {
		options.file = filepath.Join(layout.ConfigDir, "service-api", options.networkID, "network.yaml")
	} else if options.file == "" && options.kind == "node" && options.nodeID != "" {
		options.file = filepath.Join(layout.ConfigDir, "service-api", options.networkID, "nodes", options.nodeID+".yaml")
	}
	return nil
}

func managedNetworkIDs(stateDir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(stateDir, "managed"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot read managed network credentials")
	}
	var networks []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".token") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".token")
		if validManagedNetworkID(id) {
			networks = append(networks, id)
		}
	}
	sort.Strings(networks)
	return networks, nil
}

func validManagedNetworkID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func readManagedNetworkMetadata(stateDir, networkID string) (managedNetworkMetadata, error) {
	var metadata managedNetworkMetadata
	data, err := secret.ReadProtectedText(filepath.Join(stateDir, "managed", networkID+".json"), 16<<10)
	if err != nil {
		return metadata, errors.New("managed service metadata is unavailable; rejoin this network or supply --api-url")
	}
	if err := json.Unmarshal([]byte(data), &metadata); err != nil || metadata.Version != 1 || metadata.NetworkID != networkID {
		return managedNetworkMetadata{}, errors.New("managed service metadata is invalid; rejoin this network")
	}
	return metadata, nil
}

func managedServiceClient(options serviceConfigOptions, layout paths.Layout) (*serviceapi.Client, error) {
	if !validManagedNetworkID(options.networkID) {
		return nil, errors.New("--network-id is invalid")
	}
	metadata, metadataErr := readManagedNetworkMetadata(layout.StateDir, options.networkID)
	apiURL := options.apiURL
	allowInsecureHTTP := options.allowInsecureHTTP
	if apiURL == "" {
		if metadataErr != nil {
			return nil, metadataErr
		}
		apiURL = metadata.APIURL
		allowInsecureHTTP = allowInsecureHTTP || metadata.AllowInsecureHTTP
	}
	token, err := secret.ReadProtectedText(filepath.Join(layout.StateDir, "managed", options.networkID+".token"), 16<<10)
	if err != nil {
		return nil, errors.New("managed network credential is unavailable; run join before config pull or push")
	}
	bundle := serviceapi.JoinBundle{Version: 1, APIURL: apiURL, NetworkID: options.networkID, EnrollmentToken: strings.TrimSpace(token)}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return nil, errors.New("could not validate managed service credential")
	}
	validated, err := serviceapi.DecodeJoinTokenWithInsecureHTTP(base64.RawURLEncoding.EncodeToString(encoded), allowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	// TODO(peerimeter): Remove this legacy migration after all supported join versions save service metadata.
	if metadataErr != nil && options.apiURL != "" {
		metadata := managedNetworkMetadata{Version: 1, APIURL: validated.APIURL, NetworkID: options.networkID, NodeID: options.nodeID, AllowInsecureHTTP: allowInsecureHTTP}
		if err := saveManagedNetworkMetadata(layout.StateDir, metadata); err != nil {
			return nil, err
		}
	}
	return serviceapi.New(validated), nil
}

func saveManagedNetworkMetadata(stateDir string, metadata managedNetworkMetadata) error {
	dir := filepath.Join(stateDir, "managed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("cannot create protected managed state directory")
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return errors.New("cannot encode managed network metadata")
	}
	path := filepath.Join(dir, metadata.NetworkID+".json")
	if err := writeConfigFile(path, append(data, '\n')); err != nil {
		return errors.New("cannot securely save managed network metadata")
	}
	return nil
}

func validateConfigSelection(options serviceConfigOptions) error {
	if options.kind != "network" && options.kind != "node" {
		return errors.New("--kind must be network or node")
	}
	if !validManagedNetworkID(options.networkID) {
		return errors.New("a valid network ID is required")
	}
	if options.kind == "node" && options.nodeID == "" {
		return errors.New("--node-id is required when --kind is node")
	}
	if options.kind == "node" && !validManagedNetworkID(options.nodeID) {
		return errors.New("--node-id is invalid")
	}
	if options.kind == "network" && options.nodeID != "" {
		return errors.New("--node-id is only valid with --kind node")
	}
	if options.file == "" {
		return errors.New("--file is required")
	}
	return nil
}

func readConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("configuration file is unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("configuration file is unreadable or exceeds 1 MiB")
	}
	return data, nil
}

func writeConfigFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, tmpPath, err := createPullTempFile(dir)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := secret.VerifyProtectedFile(tmp); err != nil {
		tmp.Close()
		return errors.New("temporary configuration file is not private")
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceConfigFile(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func createPullTempFile(dir string) (*os.File, string, error) {
	for range 8 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", errors.New("could not create a private temporary file")
		}
		path := filepath.Join(dir, ".peerimeter-pull-"+hex.EncodeToString(suffix[:])+".tmp")
		file, err := secret.CreateProtectedFile(path)
		if err == nil {
			return file, path, nil
		}
	}
	return nil, "", errors.New("could not create a private temporary file")
}

func writeJSONLine(out io.Writer, value any) error { return json.NewEncoder(out).Encode(value) }
