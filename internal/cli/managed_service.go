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

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/serviceapi"
	"gopkg.in/yaml.v3"
)

type serviceConfigOptions struct {
	networkID, apiURL string
	allowInsecureHTTP bool
	debug             bool
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
		if config.ValidIdentifier(id) {
			networks = append(networks, id)
		}
	}
	sort.Strings(networks)
	return networks, nil
}

func readManagedNetworkMetadata(stateDir, networkID string) (managedNetworkMetadata, error) {
	var metadata managedNetworkMetadata
	metadataPath := filepath.Join(stateDir, "managed", networkID+".yaml")
	data, err := secret.ReadProtectedText(metadataPath, 16<<10)
	if err != nil {
		return metadata, errors.New("managed service metadata is unavailable; rejoin this network or supply --api-url")
	}
	if yaml.Unmarshal([]byte(data), &metadata) != nil || metadata.Version != 1 || metadata.NetworkID != networkID {
		return managedNetworkMetadata{}, errors.New("managed service metadata is invalid; rejoin this network")
	}
	return metadata, nil
}

func managedServiceClient(options serviceConfigOptions, layout paths.Layout) (*serviceapi.Client, error) {
	if !config.ValidIdentifier(options.networkID) {
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
		return nil, errors.New("managed network credential is unavailable; run join before syncing")
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
	return serviceapi.NewWithDebug(validated, options.debug), nil
}

func saveManagedNetworkMetadata(stateDir string, metadata managedNetworkMetadata) error {
	dir := filepath.Join(stateDir, "managed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("cannot create protected managed state directory")
	}
	data, err := yaml.Marshal(metadata)
	if err != nil {
		return errors.New("cannot encode managed service metadata")
	}
	path := filepath.Join(dir, metadata.NetworkID+".yaml")
	if err := writeConfigFile(path, data); err != nil {
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
