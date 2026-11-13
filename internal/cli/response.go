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
		label := strings.ReplaceAll(key, "_", " ")
		label = strings.ToUpper(label[:1]) + label[1:]
		rows = append(rows, []string{label, consoleValue(value)})
	}
	return presentation.Table(out, []string{"Field", "Value"}, rows, color, width)
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
