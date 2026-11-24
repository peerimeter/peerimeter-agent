package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
)

// Only command results pass through here; config files and the local protocol
// retain their machine-readable representation.
func renderResponse(out io.Writer, raw []byte, color bool, width int) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("decode command result: %w", err)
	}
	if rawNetworks, ok := fields["networks"]; ok {
		return renderMultiNetworkSnapshots(out, fields, rawNetworks, color, width)
	}
	if _, ok := fields["network_id"]; ok {
		if _, ok := fields["peers"]; ok {
			var snapshot platform.Snapshot
			if err := json.Unmarshal(raw, &snapshot); err != nil {
				return err
			}
			if err := presentation.StatusOverview(out, snapshot, time.Now(), color, width); err != nil {
				return err
			}
			_, err := writeServiceStatusIfPresent(out, fields)
			return err
		}
	}
	if wrote, err := writeServiceStatusIfPresent(out, fields); wrote || err != nil {
		return err
	}
	if handled, err := renderActionSummary(out, raw, fields, color, width); handled || err != nil {
		return err
	}
	if len(fields) == 1 {
		for key, rawValue := range fields {
			var value any
			decoder := json.NewDecoder(bytes.NewReader(rawValue))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				return err
			}
			lines := strings.Split(consoleValue(value), "\n")
			for i, line := range lines {
				lines[i] = presentation.Safe(line)
			}
			_, err := fmt.Fprintf(out, "%s: %s\n", presentation.Safe(responseLabel(key)), strings.Join(lines, "\n"))
			return err
		}
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, key := range keys {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(fields[key]))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		rows = append(rows, []string{responseLabel(key), consoleValue(value)})
	}
	return presentation.Table(out, nil, rows, color, width)
}

func renderActionSummary(out io.Writer, raw []byte, fields map[string]json.RawMessage, color bool, width int) (bool, error) {
	state, ok := fields["state"]
	if !ok {
		return false, nil
	}
	var status string
	if err := json.Unmarshal(state, &status); err != nil {
		return false, nil
	}
	switch status {
	case "registered":
		var result struct {
			NetworkID     string `json:"network_id"`
			NodeID        string `json:"node_id"`
			TunnelAddress string `json:"tunnel_address"`
			PeerCount     int    `json:"peer_count"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return true, err
		}
		_, err := fmt.Fprintf(out, "Joined network %s as %s (%s); %d peers configured.\n", presentation.Safe(result.NetworkID), presentation.Safe(result.NodeID), presentation.Safe(result.TunnelAddress), result.PeerCount)
		return true, err
	case "example_generated":
		_, err := io.WriteString(out, "Example configuration generated. Credentials: protected local key files; keep private.\n")
		return true, err
	case "removed":
		return renderRemovedSummary(out, fields, color, width)
	default:
		return false, nil
	}
}

func renderRemovedSummary(out io.Writer, fields map[string]json.RawMessage, color bool, width int) (bool, error) {
	var paths []string
	if rawPaths, ok := fields["paths"]; ok {
		if err := json.Unmarshal(rawPaths, &paths); err != nil {
			return true, err
		}
	}
	if len(paths) == 0 {
		_, err := io.WriteString(out, "Installation removed; there were no remaining files to delete.\n")
		return true, err
	}
	if _, err := fmt.Fprintf(out, "Installation removed. Deleted %d files:\n", len(paths)); err != nil {
		return true, err
	}
	rows := make([][]string, len(paths))
	for index, path := range paths {
		rows[index] = []string{path}
	}
	return true, presentation.Table(out, []string{"Deleted files"}, rows, color, width)
}

func renderMultiNetworkSnapshots(out io.Writer, fields map[string]json.RawMessage, rawNetworks json.RawMessage, color bool, width int) error {
	var result networkSnapshots
	if err := json.Unmarshal(rawNetworks, &result.Networks); err != nil {
		return err
	}
	for index, snapshot := range result.Networks {
		if index > 0 {
			if _, err := io.WriteString(out, "\n"); err != nil {
				return err
			}
		}
		if err := presentation.StatusOverview(out, snapshot, time.Now(), color, width); err != nil {
			return err
		}
	}
	_, err := writeServiceStatusIfPresent(out, fields)
	return err
}

func writeServiceStatus(out io.Writer, fields map[string]json.RawMessage) error {
	var status struct {
		Installed *bool  `json:"service_installed"`
		Running   *bool  `json:"service_running"`
		Error     string `json:"service_status_error"`
	}
	if raw, ok := fields["service_installed"]; ok {
		if err := json.Unmarshal(raw, &status.Installed); err != nil {
			return err
		}
	}
	if raw, ok := fields["service_running"]; ok {
		if err := json.Unmarshal(raw, &status.Running); err != nil {
			return err
		}
	}
	if raw, ok := fields["service_status_error"]; ok {
		if err := json.Unmarshal(raw, &status.Error); err != nil {
			return err
		}
	}
	installed := serviceStatusValue(status.Installed)
	running := serviceStatusValue(status.Running)
	if _, err := fmt.Fprintf(out, "Service installed: %s\nService running: %s\n", installed, running); err != nil {
		return err
	}
	if status.Error != "" {
		_, err := fmt.Fprintf(out, "Service status error: %s\n", presentation.Safe(status.Error))
		return err
	}
	return nil
}

func serviceStatusValue(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "yes"
	}
	return "no"
}

func writeServiceStatusIfPresent(out io.Writer, fields map[string]json.RawMessage) (bool, error) {
	if _, ok := fields["service_installed"]; !ok {
		if _, ok := fields["service_status_error"]; !ok {
			return false, nil
		}
	}
	return true, writeServiceStatus(out, fields)
}

func responseLabel(key string) string {
	key = presentation.Safe(key)
	label := strings.ReplaceAll(key, "_", " ")
	if label == "" {
		return "Result"
	}
	return strings.ToUpper(label[:1]) + label[1:]
}

func consoleValue(value any) string {
	switch v := value.(type) {
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = consoleValue(item)
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, strings.ReplaceAll(key, "_", " ")+": "+consoleValue(v[key]))
		}
		return strings.Join(parts, "; ")
	case nil:
		return "none"
	default:
		return fmt.Sprint(v)
	}
}
