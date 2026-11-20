package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/agent"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/ifname"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/keycheck"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

type reloadOptions struct {
	path          string
	override      string
	interfaceName string
	ownership     string
	remote        func(context.Context) (config.Config, error)
}

func staticCommand(ctx context.Context, commandName, path, override string, layout paths.Layout, operator string, out io.Writer, backend platform.Backend) error {
	return staticCommandWithRefresh(ctx, commandName, path, override, layout, operator, out, backend, nil, 0)
}

func staticCommandWithRefresh(ctx context.Context, commandName, path, override string, layout paths.Layout, operator string, out io.Writer, backend platform.Backend, remoteReload func(context.Context) (config.Config, error), refresh time.Duration) error {
	return staticCommandWithBackground(ctx, commandName, path, override, layout, operator, out, backend, remoteReload, refresh, nil)
}

func staticCommandWithBackground(ctx context.Context, commandName, path, override string, layout paths.Layout, operator string, out io.Writer, backend platform.Backend, remoteReload func(context.Context) (config.Config, error), refresh time.Duration, background func(context.Context)) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return errors.New("cannot make static config path absolute")
	}
	if commandName == "run" || commandName == "daemon" {
		installstate.TrustSudoUserForRun()
		secret.TrustSudoUserForRun()
	}
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
	private, err := keycheck.LoadAndVerifyInterfaceKey(cfg)
	if err != nil {
		return err
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
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	startup, err := installstate.CaptureStartup(filepath.Dir(exe))
	if err != nil {
		return err
	}
	defer startup.Close()
	guard, err := local.Acquire(layout.StateDir)
	if err != nil {
		return err
	}
	defer guard.Close()
	if err := startup.Check(); err != nil {
		return err
	}
	if err := startup.RegisterProfile(installstate.Profile{StateDir: layout.StateDir, RuntimeDir: layout.RuntimeDir}); err != nil {
		return err
	}
	if err := startup.Close(); err != nil {
		return err
	}
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
	reload := buildReloadFunc(reloadOptions{path: path, override: override, interfaceName: name, ownership: token, remote: remoteReload})
	ready := func() error {
		if err := startup.Check(); err != nil {
			return err
		}
		return installstate.RegisterProfile(filepath.Dir(exe), installstate.Profile{StateDir: layout.StateDir, RuntimeDir: layout.RuntimeDir, ClaimRuntime: true})
	}
	replaceConfig := func(data []byte) (func() error, error) {
		previous, err := os.ReadFile(path)
		if err != nil {
			return nil, errors.New("cannot read the active configuration before sync")
		}
		if err := writeConfigFile(path, data); err != nil {
			return nil, errors.New("cannot securely update the active configuration")
		}
		return func() error { return writeConfigFile(path, previous) }, nil
	}
	return agent.RunManagedWithBackground(ctx, agent.ManagedOptions{
		Backend: backend, Desired: desired, Directory: layout.RuntimeDir, Reload: reload,
		Operator: operator, InstanceID: local.InstanceID(layout.StateDir), BeforeServe: ready, OnClose: func() error {
			return installstate.ReleaseRuntime(filepath.Dir(exe), layout.StateDir, layout.RuntimeDir)
		}, RefreshInterval: refresh, ConfigPath: path, ReplaceConfig: replaceConfig, Background: background,
	})
}

func buildReloadFunc(options reloadOptions) func(context.Context) (platform.Desired, error) {
	return func(ctx context.Context) (platform.Desired, error) {
		next, err := loadReloadConfig(ctx, options)
		if err != nil {
			return platform.Desired{}, err
		}
		if err := validateReloadInterface(next, options.interfaceName); err != nil {
			return platform.Desired{}, err
		}
		key, err := keycheck.LoadAndVerifyInterfaceKey(next)
		if err != nil {
			return platform.Desired{}, err
		}
		return platform.Desired{Config: next, InterfaceName: options.interfaceName, PrivateKey: key, OwnershipToken: options.ownership}, nil
	}
}

func loadReloadConfig(ctx context.Context, options reloadOptions) (config.Config, error) {
	var next config.Config
	var err error
	if options.remote != nil {
		next, err = options.remote(ctx)
	} else {
		next, err = config.Load(options.path)
	}
	if err != nil {
		return config.Config{}, err
	}
	if options.override != "" {
		next.Interface.Name = options.override
	}
	if err := config.Validate(next, runtime.GOOS); err != nil {
		return config.Config{}, err
	}
	return next, nil
}

func validateReloadInterface(cfg config.Config, currentName string) error {
	if runtime.GOOS == "linux" && cfg.Interface.Name != "" && cfg.Interface.Name != currentName {
		return errors.New("reload cannot rename a persisted local interface")
	}
	return nil
}
