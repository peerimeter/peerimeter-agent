package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/agent"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/ifname"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func staticCommand(ctx context.Context, commandName, path, override string, layout paths.Layout, operator string, out io.Writer, backend platform.Backend) error {
	if commandName == "run" {
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
	ready := func() error {
		if err := startup.Check(); err != nil {
			return err
		}
		return installstate.RegisterProfile(filepath.Dir(exe), installstate.Profile{StateDir: layout.StateDir, RuntimeDir: layout.RuntimeDir, ClaimRuntime: true})
	}
	return agent.RunManaged(ctx, backend, desired, layout.RuntimeDir, reload, operator, local.InstanceID(layout.StateDir), ready, func() error {
		return installstate.ReleaseRuntime(filepath.Dir(exe), layout.StateDir, layout.RuntimeDir)
	})
}
