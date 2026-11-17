package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/serviceapi"
)

type serviceConfigOptions struct {
	networkID, nodeID, apiURL string
	allowInsecureHTTP         bool
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

func managedServiceClient(options serviceConfigOptions, layout paths.Layout) (*serviceapi.Client, func() error, error) {
	if !validManagedNetworkID(options.networkID) {
		return nil, nil, errors.New("--network-id is invalid")
	}
	metadata, metadataErr := readManagedNetworkMetadata(layout.StateDir, options.networkID)
	apiURL := options.apiURL
	allowInsecureHTTP := options.allowInsecureHTTP
	if apiURL == "" {
		if metadataErr != nil {
			return nil, nil, metadataErr
		}
		apiURL = metadata.APIURL
		allowInsecureHTTP = allowInsecureHTTP || metadata.AllowInsecureHTTP
	}
	token, err := secret.ReadProtectedText(filepath.Join(layout.StateDir, "managed", options.networkID+".token"), 16<<10)
	if err != nil {
		return nil, nil, errors.New("managed network credential is unavailable; run join before syncing")
	}
	bundle := serviceapi.JoinBundle{Version: 1, APIURL: apiURL, NetworkID: options.networkID, EnrollmentToken: strings.TrimSpace(token)}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return nil, nil, errors.New("could not validate managed service credential")
	}
	validated, err := serviceapi.DecodeJoinTokenWithInsecureHTTP(base64.RawURLEncoding.EncodeToString(encoded), allowInsecureHTTP)
	if err != nil {
		return nil, nil, err
	}
	// TODO(peerimeter): Remove this legacy migration after all supported join versions save service metadata.
	needsMigration := metadataErr != nil && options.apiURL != "" || metadataErr == nil && metadata.NodeID == "" && options.nodeID != ""
	if needsMigration {
		metadata = managedNetworkMetadata{Version: 1, APIURL: validated.APIURL, NetworkID: options.networkID, NodeID: options.nodeID, AllowInsecureHTTP: allowInsecureHTTP}
	}
	return serviceapi.New(validated), func() error {
		if !needsMigration {
			return nil
		}
		return saveManagedNetworkMetadata(layout.StateDir, metadata)
	}, nil
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

func writeConfigFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, tmpPath, err := createPrivateConfigTempFile(dir)
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

func createPrivateConfigTempFile(dir string) (*os.File, string, error) {
	for range 8 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", errors.New("could not create a private temporary file")
		}
		path := filepath.Join(dir, ".peerimeter-config-"+hex.EncodeToString(suffix[:])+".tmp")
		file, err := secret.CreateProtectedFile(path)
		if err == nil {
			return file, path, nil
		}
	}
	return nil, "", errors.New("could not create a private temporary file")
}
