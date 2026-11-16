package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/serviceapi"
	"github.com/spf13/cobra"
)

type serviceConfigOptions struct {
	token, tokenFile string
	kind             string
	networkID        string
	nodeID           string
	file             string
}

func newConfigAPICommand(app *application) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Pull or push network and node JSON through the service API", Args: noArguments}
	var pull serviceConfigOptions
	pullCmd := &cobra.Command{Use: "pull", Short: "Download a network or node configuration", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		client, err := serviceClient(pull)
		if err != nil {
			return err
		}
		if err := validateConfigSelection(pull); err != nil {
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
		if err := writeConfigFile(pull.file, data); err != nil {
			return errors.New("could not securely write pulled configuration")
		}
		return writeJSONLine(app.out, map[string]string{"state": "config_pulled", "kind": pull.kind, "network_id": pull.networkID, "file": pull.file})
	})}
	addServiceConfigFlags(pullCmd, &pull)
	pullCmd.Flags().StringVar(&pull.file, "file", "", "Output file for the downloaded JSON configuration")
	_ = pullCmd.MarkFlagRequired("file")

	var push serviceConfigOptions
	pushCmd := &cobra.Command{Use: "push", Short: "Upload a network or node configuration", Args: noArguments, RunE: app.handleResponse(func(cmd *cobra.Command) error {
		client, err := serviceClient(push)
		if err != nil {
			return err
		}
		if err := validateConfigSelection(push); err != nil {
			return err
		}
		data, err := readConfigFile(push.file)
		if err != nil {
			return err
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
	pushCmd.Flags().StringVar(&push.file, "file", "", "JSON configuration file to upload")
	_ = pushCmd.MarkFlagRequired("file")

	cmd.AddCommand(pullCmd, pushCmd)
	return cmd
}

func addServiceConfigFlags(cmd *cobra.Command, options *serviceConfigOptions) {
	cmd.Flags().StringVar(&options.token, "token", "", "Base64URL JSON join token (visible in process listings; prefer --token-file)")
	cmd.Flags().StringVar(&options.tokenFile, "token-file", "", "Protected file containing the join token")
	cmd.Flags().StringVar(&options.kind, "kind", "network", "Configuration kind: network or node")
	cmd.Flags().StringVar(&options.networkID, "network-id", "", "Network ID stored by the service")
	cmd.Flags().StringVar(&options.nodeID, "node-id", "", "Node ID (required for --kind node)")
	_ = cmd.MarkFlagRequired("network-id")
}

func serviceClient(options serviceConfigOptions) (*serviceapi.Client, error) {
	if (options.token == "") == (options.tokenFile == "") {
		return nil, errors.New("provide exactly one of --token or --token-file")
	}
	token := options.token
	if options.tokenFile != "" {
		value, err := secret.ReadProtectedText(options.tokenFile, 16<<10)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(value)
	}
	bundle, err := serviceapi.DecodeJoinToken(token)
	if err != nil {
		return nil, err
	}
	return serviceapi.New(bundle), nil
}

func validateConfigSelection(options serviceConfigOptions) error {
	if options.kind != "network" && options.kind != "node" {
		return errors.New("--kind must be network or node")
	}
	if options.networkID == "" {
		return errors.New("--network-id is required")
	}
	if options.kind == "node" && options.nodeID == "" {
		return errors.New("--node-id is required when --kind is node")
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
