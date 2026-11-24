package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

type networkSnapshots struct {
	Networks []platform.Snapshot `json:"networks"`
}

type networkRuntime struct {
	networkID string
	layout    paths.Layout
}

func networkRuntimeLayouts(ctx context.Context, layout paths.Layout, requestedID string) ([]networkRuntime, error) {
	profileDir := filepath.Join(layout.RuntimeDir, "networks")
	entries, err := os.ReadDir(profileDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("cannot read network runtime profiles")
	}
	profiles := make([]networkRuntime, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !config.ValidIdentifier(entry.Name()) {
			continue
		}
		profiles = append(profiles, networkRuntime{networkID: entry.Name(), layout: networkLayout(layout, entry.Name())})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].networkID < profiles[j].networkID })
	if requestedID != "" {
		for _, profile := range profiles {
			if profile.networkID == requestedID {
				return []networkRuntime{profile}, nil
			}
		}
	}

	var root *networkRuntime
	if _, err := os.Stat(layout.RuntimeDir); err == nil {
		identity, identityErr := local.GetIdentity(ctx, layout.RuntimeDir)
		if identityErr == nil {
			root = &networkRuntime{networkID: identity.NetworkID, layout: layout}
		} else if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	} else if !os.IsNotExist(err) {
		return nil, errors.New("cannot inspect local runtime directory")
	}
	if requestedID != "" {
		if root != nil && root.networkID == requestedID {
			return []networkRuntime{*root}, nil
		}
		return nil, fmt.Errorf("network %q has no known runtime profile", requestedID)
	}
	if root != nil {
		profiles = append([]networkRuntime{*root}, profiles...)
	}
	if len(profiles) == 0 {
		return []networkRuntime{{layout: layout}}, nil
	}
	return profiles, nil
}

func controlNetworkLayout(ctx context.Context, layout paths.Layout, networkID string) (paths.Layout, error) {
	profile := networkLayout(layout, networkID)
	if _, err := os.Stat(profile.RuntimeDir); err == nil {
		return profile, nil
	} else if !os.IsNotExist(err) {
		return paths.Layout{}, errors.New("cannot inspect network runtime profile")
	}
	if _, err := os.Stat(layout.RuntimeDir); err == nil {
		identity, identityErr := local.GetIdentity(ctx, layout.RuntimeDir)
		if identityErr == nil && identity.NetworkID == networkID {
			return layout, nil
		}
		if ctx.Err() != nil {
			return paths.Layout{}, ctx.Err()
		}
	} else if !os.IsNotExist(err) {
		return paths.Layout{}, errors.New("cannot inspect local runtime directory")
	}
	return profile, nil
}

func readNetworkSnapshots(ctx context.Context, layout paths.Layout, requestedID string) ([]platform.Snapshot, error) {
	runtimes, err := networkRuntimeLayouts(ctx, layout, requestedID)
	if err != nil {
		return nil, err
	}
	snapshots := make([]platform.Snapshot, 0, len(runtimes))
	var failures []error
	for _, runtime := range runtimes {
		var output bufferWriter
		if err := local.Request(ctx, runtime.layout.RuntimeDir, "status", &output); err != nil {
			failures = append(failures, fmt.Errorf("network %q: %w", runtime.networkID, err))
			continue
		}
		var snapshot platform.Snapshot
		if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil {
			failures = append(failures, fmt.Errorf("network %q: cannot decode local status", runtime.networkID))
			continue
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, errors.Join(failures...)
}

func writeStatusSnapshots(out io.Writer, snapshots []platform.Snapshot, serviceStatus service.Status, inspectionErr error) error {
	encoder := json.NewEncoder(out)
	installed, running, statusError := statusFields(serviceStatus, inspectionErr)
	if len(snapshots) == 1 {
		return encoder.Encode(struct {
			platform.Snapshot
			ServiceInstalled   *bool  `json:"service_installed,omitempty"`
			ServiceRunning     *bool  `json:"service_running,omitempty"`
			ServiceStatusError string `json:"service_status_error,omitempty"`
		}{Snapshot: snapshots[0], ServiceInstalled: installed, ServiceRunning: running, ServiceStatusError: statusError})
	}
	return encoder.Encode(struct {
		Networks           []platform.Snapshot `json:"networks"`
		ServiceInstalled   *bool               `json:"service_installed,omitempty"`
		ServiceRunning     *bool               `json:"service_running,omitempty"`
		ServiceStatusError string              `json:"service_status_error,omitempty"`
	}{Networks: snapshots, ServiceInstalled: installed, ServiceRunning: running, ServiceStatusError: statusError})
}

func statusFields(status service.Status, inspectionErr error) (*bool, *bool, string) {
	if inspectionErr != nil {
		return nil, nil, inspectionErr.Error()
	}
	return &status.Installed, &status.Running, ""
}

func requestAllNetworks(ctx context.Context, layout paths.Layout, requestedID, operation string, out io.Writer) error {
	runtimes, err := networkRuntimeLayouts(ctx, layout, requestedID)
	if err != nil {
		return err
	}
	var failures []error
	succeeded := 0
	for _, runtime := range runtimes {
		var raw bufferWriter
		if err := local.Request(ctx, runtime.layout.RuntimeDir, operation, &raw); err != nil {
			failures = append(failures, fmt.Errorf("network %q: %w", runtime.networkID, err))
			continue
		}
		succeeded++
		if len(runtimes) == 1 {
			if _, err := out.Write(raw.Bytes()); err != nil {
				return err
			}
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if len(runtimes) > 1 && succeeded > 0 {
		if err := json.NewEncoder(out).Encode(map[string]any{"state": operation, "network_count": succeeded}); err != nil {
			return err
		}
	}
	return nil
}

type bufferWriter struct{ data []byte }

func (buffer *bufferWriter) Write(data []byte) (int, error) {
	buffer.data = append(buffer.data, data...)
	return len(data), nil
}

func (buffer *bufferWriter) Bytes() []byte { return buffer.data }
