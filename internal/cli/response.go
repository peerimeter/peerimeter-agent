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
	if _, ok := fields["network_id"]; ok {
		if _, ok := fields["peers"]; ok {
			var snapshot platform.Snapshot
			if err := json.Unmarshal(raw, &snapshot); err != nil {
				return err
			}
			return presentation.StatusOverview(out, snapshot, time.Now(), color, width)
		}
	}
	if state, ok := fields["state"]; ok {
		var status string
		if err := json.Unmarshal(state, &status); err == nil && status == "removed" {
			var paths []string
			if rawPaths, ok := fields["paths"]; ok {
				if err := json.Unmarshal(rawPaths, &paths); err != nil {
					return err
				}
			}
			if len(paths) == 0 {
				_, err := io.WriteString(out, "Installation removed; there were no remaining files to delete.\n")
				return err
			}
			if _, err := fmt.Fprintf(out, "Installation removed. Deleted %d files:\n", len(paths)); err != nil {
				return err
			}
			rows := make([][]string, len(paths))
			for i, path := range paths {
				rows[i] = []string{path}
			}
			return presentation.Table(out, []string{"Deleted file"}, rows, color, width)
		}
	}
	if len(fields) == 1 {
		for key, rawValue := range fields {
			var value any
			decoder := json.NewDecoder(bytes.NewReader(rawValue))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				return err
			}
			_, err := fmt.Fprintf(out, "%s: %s\n", responseLabel(key), consoleValue(value))
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
	return presentation.Table(out, []string{"Field", "Value"}, rows, color, width)
}

func responseLabel(key string) string {
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
