// Package cli implements offline commands without control-plane dependencies.
package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/peerimeter/peerimeter-agent/internal/agent"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/ifname"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

var Version = "0.0.0-dev"

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
func command(ctx context.Context, args []string, out io.Writer, backend platform.Backend) error {
	root := &cobra.Command{Use: "peerimeter-agent", Short: "Offline cross-platform WireGuard agent", SilenceUsage: true, SilenceErrors: true, DisableSuggestions: true}
	root.SetOut(out)
	root.SetErr(io.Discard)
	ran := false
	noArgs := func(_ *cobra.Command, args []string) error {
		if len(args) != 0 {
			return errors.New("unexpected positional arguments")
		}
		return nil
	}
	wrap := func(handler func(*cobra.Command) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error { ran = true; return handler(cmd) }
	}
	root.RunE = wrap(func(*cobra.Command) error { return errors.New("command required; use --help") })
	root.SetFlagErrorFunc(func(*cobra.Command, error) error { return errors.New("invalid command flags; use --help") })
	root.SetHelpCommand(&cobra.Command{Use: "help", Short: "Show root command help (use subcommand --help for details)", Args: noArgs, RunE: wrap(func(*cobra.Command) error { return root.Help() })})
	version := &cobra.Command{Use: "version", Short: "Print agent and Go version as JSON", Args: noArgs, RunE: wrap(func(*cobra.Command) error {
		return json.NewEncoder(out).Encode(map[string]string{"version": Version, "go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
	})}
	root.AddCommand(version)
	var directory string
	example := &cobra.Command{Use: "generate-example", Short: "Create paired configs and fresh protected local keys", Args: noArgs, RunE: wrap(func(*cobra.Command) error {
		if err := generate(directory); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"state": "example_generated", "credentials": "protected local key files; keep private"})
	})}
	example.Flags().StringVar(&directory, "directory", "", "New destination directory (must not exist)")
	_ = example.MarkFlagRequired("directory")
	root.AddCommand(example)
	for _, name := range []string{"validate-config", "run"} {
		var path, override, operator string
		stateDir := local.DefaultDirectory()
		cmd := &cobra.Command{Use: name, Short: map[string]string{"validate-config": "Validate static JSON and protected key without OS changes", "run": "Run the native WireGuard agent in the foreground"}[name], Args: noArgs}
		cmd.Flags().StringVar(&path, "config", "", "Static JSON configuration file")
		_ = cmd.MarkFlagRequired("config")
		cmd.Flags().StringVar(&override, "interface", "", "Linux-only initial local interface name override")
		if name == "run" {
			cmd.Flags().StringVar(&stateDir, "state-dir", stateDir, "Protected local agent state directory")
			cmd.Flags().StringVar(&operator, "operator", "", "Authorized local username/UID or Windows account/SID")
		}
		cmd.RunE = wrap(func(cmd *cobra.Command) error {
			if path == "" {
				return errors.New("config path is required")
			}
			return staticCommand(cmd.Context(), cmd.Name(), path, override, stateDir, operator, out, backend)
		})
		root.AddCommand(cmd)
	}
	for _, name := range []string{"status", "peers", "sync", "stop"} {
		var dir string
		cmd := &cobra.Command{Use: name, Short: map[string]string{"status": "Read actual local tunnel status as JSON", "peers": "Read actual local peer handshake/counters as JSON", "sync": "Validate and reconcile the running agent's original static config", "stop": "Gracefully stop the local agent and remove its owned tunnel"}[name], Args: noArgs}
		cmd.Flags().StringVar(&dir, "state-dir", local.DefaultDirectory(), "Local agent state directory")
		cmd.RunE = wrap(func(cmd *cobra.Command) error {
			operation := cmd.Name()
			if operation == "sync" {
				operation = "reload"
			}
			return local.Request(cmd.Context(), dir, operation, out)
		})
		root.AddCommand(cmd)
	}
	group := &cobra.Command{Use: "service", Short: "Manage the native system service", Args: noArgs, RunE: wrap(func(*cobra.Command) error { return errors.New("service action required; use service --help") })}
	for _, name := range []string{"install", "start", "stop", "uninstall"} {
		cfg := service.Config{StateDirectory: local.DefaultDirectory()}
		cmd := &cobra.Command{Use: name, Short: map[string]string{"install": "Register service with protected snapshots and boot activation", "start": "Start the installed native service", "stop": "Stop the installed native service", "uninstall": "Remove service registration while preserving config and keys"}[name], Args: noArgs}
		if name == "install" {
			cmd.Flags().StringVar(&cfg.ConfigPath, "config", "", "Absolute static JSON path")
			_ = cmd.MarkFlagRequired("config")
			cmd.Flags().StringVar(&cfg.StateDirectory, "state-dir", cfg.StateDirectory, "Absolute protected state directory")
			cmd.Flags().StringVar(&cfg.Operator, "operator", "", "Authorized local username/UID or Windows account/SID")
		}
		cmd.RunE = wrap(func(cmd *cobra.Command) error {
			if err := service.Manage(cmd.Name(), cfg); err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(map[string]string{"state": cmd.Name()})
		})
		group.AddCommand(cmd)
	}
	root.AddCommand(group)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	// Cobra/pflag parse errors can contain raw flag values or unknown commands.
	// Preserve operational errors, but never echo untrusted arguments on failure.
	if err != nil && !ran {
		return errors.New("invalid command or arguments; use --help")
	}
	return err
}

func staticCommand(ctx context.Context, commandName, path, override, stateDir, operator string, out io.Writer, backend platform.Backend) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if override != "" {
		if runtime.GOOS != "linux" {
			return errors.New("--interface is supported only on Linux")
		}
		cfg.Interface.Name = override
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
	if commandName == "validate-config" {
		return json.NewEncoder(out).Encode(map[string]any{"state": "valid", "version": cfg.Version, "network_id": cfg.Network.ID, "peer_count": len(cfg.Peers), "interface_name": name})
	}
	if err := local.ValidateOperator(operator); err != nil {
		return err
	}
	guard, err := local.Acquire(stateDir)
	if err != nil {
		return err
	}
	defer guard.Close()
	if runtime.GOOS == "linux" {
		name, err = guard.InterfaceChoice(cfg.Network.ID, cfg.Network.Name, cfg.Interface.Name)
		if err != nil {
			return err
		}
	}
	token, err := guard.OwnershipToken()
	if err != nil {
		return err
	}
	desired := platform.Desired{Config: cfg, InterfaceName: name, PrivateKey: private, OwnershipToken: token}
	reload := func() (platform.Desired, error) {
		next, err := config.Load(path)
		if err != nil {
			return platform.Desired{}, err
		}
		if override != "" {
			next.Interface.Name = override
		}
		if err = config.Validate(next, runtime.GOOS); err != nil {
			return platform.Desired{}, err
		}
		if runtime.GOOS == "linux" {
			if next.Interface.Name != "" && next.Interface.Name != name {
				return platform.Desired{}, errors.New("reload cannot rename a persisted local interface")
			}
		}
		key, err := secret.Load(next.Interface.PrivateKeyFile)
		if err != nil {
			return platform.Desired{}, err
		}
		pub, err := secret.Public(key)
		if err != nil {
			return platform.Desired{}, err
		}
		for _, peer := range next.Peers {
			if peer.PublicKey == base64.StdEncoding.EncodeToString(pub[:]) {
				return platform.Desired{}, errors.New("peer public key matches the local interface key")
			}
		}
		return platform.Desired{Config: next, InterfaceName: name, PrivateKey: key, OwnershipToken: token}, nil
	}
	return agent.RunManaged(ctx, backend, desired, stateDir, reload, operator)
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
