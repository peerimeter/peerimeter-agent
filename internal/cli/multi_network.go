package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/ifname"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/keycheck"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/secret"
)

type managedConfig struct {
	networkID     string
	path          string
	config        config.Config
	profileScoped bool
}

func discoverManagedConfigs(layout paths.Layout) ([]managedConfig, error) {
	networkIDs, err := managedNetworkIDs(layout.StateDir)
	if err != nil {
		return nil, err
	}
	managedIDs := make(map[string]bool, len(networkIDs))
	for _, id := range networkIDs {
		managedIDs[id] = true
	}
	entries, err := os.ReadDir(layout.ConfigDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("network configuration directory does not exist; pass --config-dir or join a network first")
		}
		return nil, errors.New("cannot read network configuration directory")
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Name() == "service.yaml" {
			return false
		}
		if entries[j].Name() == "service.yaml" {
			return true
		}
		return entries[i].Name() < entries[j].Name()
	})
	configs := make([]managedConfig, 0, len(entries))
	seenIDs := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("network configuration %q must not be a symlink", entry.Name())
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("network configuration %q is not a regular file", entry.Name())
		}
		path := filepath.Join(layout.ConfigDir, entry.Name())
		cfg, err := config.Load(path)
		if err != nil {
			return nil, fmt.Errorf("load network configuration %q: %w", entry.Name(), err)
		}
		if entry.Name() != "service.yaml" && strings.TrimSuffix(entry.Name(), ".yaml") != cfg.Network.ID {
			return nil, fmt.Errorf("configuration %q filename must match its network ID %q", path, cfg.Network.ID)
		}
		if seenIDs[cfg.Network.ID] {
			if entry.Name() == "service.yaml" {
				continue
			}
			return nil, fmt.Errorf("network %q has more than one configuration file", cfg.Network.ID)
		}
		seenIDs[cfg.Network.ID] = true
		profileScoped := entry.Name() != "service.yaml" || managedIDs[cfg.Network.ID]
		configs = append(configs, managedConfig{networkID: cfg.Network.ID, path: path, config: cfg, profileScoped: profileScoped})
	}
	for _, networkID := range networkIDs {
		if !seenIDs[networkID] {
			return nil, fmt.Errorf("registered network %q has no %s.yaml configuration", networkID, networkID)
		}
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].networkID < configs[j].networkID })
	if len(configs) == 0 {
		return nil, errors.New("no network YAML configurations found in config-dir")
	}
	return configs, nil
}

func networkLayout(layout paths.Layout, networkID string) paths.Layout {
	profile := filepath.Join("networks", networkID)
	layout.StateDir = filepath.Join(layout.StateDir, profile)
	layout.RuntimeDir = filepath.Join(layout.RuntimeDir, profile)
	return layout
}

func runManagedConfigs(ctx context.Context, commandName, override, operator string, layout paths.Layout, configs []managedConfig, interval time.Duration, out io.Writer, backend platform.Backend, background func(context.Context, managedConfig, paths.Layout) error) error {
	if len(configs) == 0 {
		return errors.New("no registered network configurations found")
	}
	if override != "" && len(configs) > 1 {
		return errors.New("--interface requires selecting one network with --network")
	}
	if err := validateNetworkConflicts(configs); err != nil {
		return err
	}
	if err := local.ValidateOperator(operator); err != nil {
		return err
	}
	if commandName == "run" || commandName == "daemon" {
		installstate.TrustSudoUserForRun()
		secret.TrustSudoUserForRun()
	}
	for _, item := range configs {
		if _, err := keycheck.LoadAndVerifyInterfaceKey(item.config); err != nil {
			return fmt.Errorf("network %q key: %w", item.networkID, err)
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(configs))
	var workers sync.WaitGroup
	for _, item := range configs {
		item := item
		profileLayout := layout
		if item.profileScoped {
			profileLayout = networkLayout(layout, item.networkID)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			var periodic func(context.Context)
			if background != nil {
				periodic = func(ctx context.Context) {
					runPeriodicSync(ctx, interval, func(ctx context.Context) error {
						return background(ctx, item, profileLayout)
					})
				}
			}
			err := staticCommandWithBackground(runCtx, commandName, item.path, override, profileLayout, operator, out, backend, nil, 0, periodic)
			if err != nil && !errors.Is(err, context.Canceled) {
				results <- fmt.Errorf("network %q stopped: %w", item.networkID, err)
				return
			}
			results <- err
		}()
	}
	remaining := len(configs)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			cancel()
			workers.Wait()
			return nil
		case err := <-results:
			remaining--
			if err != nil && !errors.Is(err, context.Canceled) {
				cancel()
				workers.Wait()
				return err
			}
		}
	}
	workers.Wait()
	return nil
}

func validateNetworkConflicts(configs []managedConfig) error {
	for i := range configs {
		firstName := ""
		if runtime.GOOS == "linux" {
			var err error
			firstName, err = ifname.Resolve(configs[i].networkID, configs[i].config.Network.Name, configs[i].config.Interface.Name)
			if err != nil {
				return fmt.Errorf("network %q interface: %w", configs[i].networkID, err)
			}
		}
		firstRoutes := networkPrefixes(configs[i].config)
		for j := i + 1; j < len(configs); j++ {
			if runtime.GOOS == "linux" {
				secondName, err := ifname.Resolve(configs[j].networkID, configs[j].config.Network.Name, configs[j].config.Interface.Name)
				if err != nil {
					return fmt.Errorf("network %q interface: %w", configs[j].networkID, err)
				}
				if firstName == secondName {
					return fmt.Errorf("networks %q and %q use the same Linux interface name %q", configs[i].networkID, configs[j].networkID, firstName)
				}
			}
			if configs[i].config.Interface.ListenPort == configs[j].config.Interface.ListenPort {
				return fmt.Errorf("networks %q and %q use the same WireGuard listen port %d", configs[i].networkID, configs[j].networkID, configs[i].config.Interface.ListenPort)
			}
			for _, firstPrefix := range firstRoutes {
				for _, secondPrefix := range networkPrefixes(configs[j].config) {
					if firstPrefix.Overlaps(secondPrefix) {
						return fmt.Errorf("networks %q and %q have overlapping routes", configs[i].networkID, configs[j].networkID)
					}
				}
			}
		}
	}
	return nil
}

func networkPrefixes(cfg config.Config) []netip.Prefix {
	values := append([]string(nil), cfg.Interface.Address...)
	for _, peer := range cfg.Peers {
		values = append(values, peer.AllowedIPs...)
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}

func matchingConfig(configs []managedConfig, networkID string) ([]managedConfig, error) {
	if networkID == "" {
		return configs, nil
	}
	for _, item := range configs {
		if item.networkID == networkID {
			return []managedConfig{item}, nil
		}
	}
	return nil, fmt.Errorf("network %q is not registered in this configuration directory", networkID)
}

func allocateListenPort(configDir, stateDir, networkID string) (int, error) {
	existingPort, usedPorts, err := configuredListenPorts(configDir, stateDir, networkID)
	if err != nil {
		return 0, err
	}
	if existingPort != 0 {
		return existingPort, nil
	}
	for port := 51820; port <= 65535; port++ {
		if _, used := usedPorts[port]; !used {
			return port, nil
		}
	}
	return 0, errors.New("no available WireGuard listen port remains")
}

func ensureListenPortAvailable(configDir, stateDir, networkID string, port int) error {
	_, usedPorts, err := configuredListenPorts(configDir, stateDir, networkID)
	if err != nil {
		return err
	}
	if otherNetwork, used := usedPorts[port]; used {
		return fmt.Errorf("--listen-port %d is already assigned to network %q", port, otherNetwork)
	}
	return nil
}

func configuredListenPorts(configDir, stateDir, networkID string) (int, map[int]string, error) {
	entries, err := os.ReadDir(configDir)
	if err != nil && !os.IsNotExist(err) {
		return 0, nil, errors.New("cannot read network configuration directory")
	}
	usedPorts := make(map[int]string)
	configuredIDs := make(map[string]bool)
	var existingPort int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		cfg, err := config.Load(filepath.Join(configDir, entry.Name()))
		if err != nil {
			return 0, nil, fmt.Errorf("load network configuration %q: %w", entry.Name(), err)
		}
		if cfg.Network.ID == networkID {
			if entry.Name() == networkID+".yaml" || existingPort == 0 {
				existingPort = cfg.Interface.ListenPort
			}
			configuredIDs[cfg.Network.ID] = true
			continue
		}
		usedPorts[cfg.Interface.ListenPort] = cfg.Network.ID
		configuredIDs[cfg.Network.ID] = true
	}
	registered, err := managedNetworkIDs(stateDir)
	if err != nil {
		return 0, nil, err
	}
	for _, id := range registered {
		if id == networkID {
			continue
		}
		if !configuredIDs[id] {
			return 0, nil, fmt.Errorf("registered network %q has no configuration in config-dir", id)
		}
	}
	return existingPort, usedPorts, nil
}
