// Package cli implements offline commands without control-plane dependencies.
package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/peerimeter/peerimeter-agent/internal/agent"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/ifname"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

const Version = "0.0.0-dev"

func Execute(ctx context.Context, args []string, out, errOut io.Writer) int {
	return execute(ctx, args, out, errOut, platform.Native())
}
func execute(ctx context.Context, args []string, out, errOut io.Writer, backend platform.Backend) int {
	err := command(ctx, args, out, backend)
	if err == nil {
		return 0
	}
	// Structured errors never include raw JSON, flag values or private material.
	_ = json.NewEncoder(errOut).Encode(map[string]string{"level": "error", "message": err.Error()})
	if errors.Is(err, platform.ErrUnavailable) {
		return 3
	}
	return 1
}
func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}
func command(ctx context.Context, args []string, out io.Writer, backend platform.Backend) error {
	if len(args) == 0 {
		return errors.New("command required: version, generate-example, validate-config, run, status, peers")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return errors.New("version accepts no arguments")
		}
		return json.NewEncoder(out).Encode(map[string]string{"version": Version, "go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
	case "generate-example":
		f := flags(args[0])
		directory := f.String("directory", "", "new destination directory")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *directory == "" {
			return errors.New("usage: generate-example --directory <new-directory>")
		}
		if err := generate(*directory); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"state": "example_generated", "credentials": "protected local key files; keep private"})
	case "validate-config", "run":
		f := flags(args[0])
		path := f.String("config", "", "static config path")
		override := f.String("interface", "", "Linux local name override")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *path == "" {
			return errors.New("usage: validate-config|run --config <path> [--interface <Linux-name>]")
		}
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		if *override != "" {
			if runtime.GOOS != "linux" {
				return errors.New("--interface is supported only on Linux")
			}
			cfg.Interface.Name = *override
			if err := config.Validate(cfg, runtime.GOOS); err != nil {
				return err
			}
		}
		private, err := secret.Load(cfg.Interface.PrivateKeyFile)
		if err != nil {
			return err
		}
		public, err := secret.Public(private)
		if err != nil {
			return err
		}
		for _, p := range cfg.Peers {
			if p.PublicKey == base64.StdEncoding.EncodeToString(public[:]) {
				return errors.New("peer public key matches the local interface key")
			}
		}
		name := ""
		if runtime.GOOS == "linux" {
			name, err = ifname.Resolve(cfg.Network.ID, cfg.Network.Name, cfg.Interface.Name)
			if err != nil {
				return err
			}
		}
		if args[0] == "validate-config" {
			return json.NewEncoder(out).Encode(map[string]any{"state": "valid", "version": cfg.Version, "network_id": cfg.Network.ID, "peer_count": len(cfg.Peers), "interface_name": name})
		}
		return agent.Run(ctx, backend, platform.Desired{Config: cfg, InterfaceName: name, PrivateKey: private})
	case "status", "peers":
		if len(args) != 1 {
			return errors.New("status and peers accept no arguments")
		}
		snapshot, err := backend.Inspect(ctx)
		if err != nil {
			return err
		}
		if args[0] == "peers" {
			return json.NewEncoder(out).Encode(snapshot.Peers)
		}
		return json.NewEncoder(out).Encode(snapshot)
	case "service":
		return errors.New("service management is implemented in Phase 1; use foreground run after native backend integration")
	default:
		return errors.New("unknown command; use version, generate-example, validate-config, run, status or peers")
	}
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
