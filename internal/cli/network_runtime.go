package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/paths"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

type networkSnapshots struct {
	Networks []platform.Snapshot `json:"networks"`
}

func networkRuntimeLayouts(layout paths.Layout, requestedID string) ([]paths.Layout, error) {
	configs, configErr := discoverManagedConfigs(layout)
	if configErr == nil {
		layouts := make([]paths.Layout, 0, len(configs))
		for _, item := range configs {
			if requestedID != "" && requestedID != item.networkID {
				continue
			}
			if item.profileScoped {
				layouts = append(layouts, controlNetworkLayout(layout, item.networkID))
			} else {
				layouts = append(layouts, layout)
			}
		}
		if len(layouts) == 0 {
			return nil, fmt.Errorf("network %q is not registered", requestedID)
		}
		return layouts, nil
	}
	ids, err := managedNetworkIDs(layout.StateDir)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		if requestedID != "" {
			identity, identityErr := local.GetIdentity(context.Background(), layout.RuntimeDir)
			if identityErr != nil || identity.NetworkID != requestedID {
				return nil, errors.New("no registered networks found")
			}
			return []paths.Layout{layout}, nil
		}
		return []paths.Layout{layout}, nil
	}
	selected, err := selectManagedNetworkIDs(ids, requestedID)
	if err != nil {
		return nil, err
	}
	layouts := make([]paths.Layout, 0, len(selected))
	for _, id := range selected {
		layouts = append(layouts, controlNetworkLayout(layout, id))
	}
	return layouts, nil
}

func controlNetworkLayout(layout paths.Layout, networkID string) paths.Layout {
	identity, err := local.GetIdentity(context.Background(), layout.RuntimeDir)
	if err == nil && identity.NetworkID == networkID {
		return layout
	}
	return networkLayout(layout, networkID)
}

func readNetworkSnapshots(ctx context.Context, layout paths.Layout, requestedID string) ([]platform.Snapshot, error) {
	runtimes, err := networkRuntimeLayouts(layout, requestedID)
	if err != nil {
		return nil, err
	}
	snapshots := make([]platform.Snapshot, 0, len(runtimes))
	for _, runtimeLayout := range runtimes {
		var raw []byte
		var output bufferWriter
		if err := local.Request(ctx, runtimeLayout.RuntimeDir, "status", &output); err != nil {
			return nil, err
		}
		raw = output.Bytes()
		var snapshot platform.Snapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return nil, errors.New("cannot decode local network status")
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func writeNetworkSnapshots(out io.Writer, snapshots []platform.Snapshot) error {
	if len(snapshots) == 1 {
		return json.NewEncoder(out).Encode(snapshots[0])
	}
	return json.NewEncoder(out).Encode(networkSnapshots{Networks: snapshots})
}

func requestAllNetworks(ctx context.Context, layout paths.Layout, requestedID, operation string, out io.Writer) error {
	runtimes, err := networkRuntimeLayouts(layout, requestedID)
	if err != nil {
		return err
	}
	var failures []error
	for _, runtimeLayout := range runtimes {
		var raw bufferWriter
		if err := local.Request(ctx, runtimeLayout.RuntimeDir, operation, &raw); err != nil {
			failures = append(failures, err)
			continue
		}
		if len(runtimes) == 1 {
			if _, err := out.Write(raw.Bytes()); err != nil {
				return err
			}
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if len(runtimes) > 1 {
		return json.NewEncoder(out).Encode(map[string]any{"state": operation, "network_count": len(runtimes)})
	}
	return err
}

type bufferWriter struct{ data []byte }

func (buffer *bufferWriter) Write(data []byte) (int, error) {
	buffer.data = append(buffer.data, data...)
	return len(data), nil
}

func (buffer *bufferWriter) Bytes() []byte { return buffer.data }
