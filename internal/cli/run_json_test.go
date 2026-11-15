package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

func TestRunJSONFormatsErrorsAsStructuredLogs(t *testing.T) {
	t.Setenv("PEERIMETER_LOG_FORMAT", "console")
	var out, errOut bytes.Buffer
	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	code := execute(context.Background(), []string{"run", "--json", "--config", missingConfig}, &out, &errOut, platform.Native())
	if code == 0 || out.Len() != 0 {
		t.Fatalf("unexpected run result: code=%d stdout=%q", code, out.String())
	}
	var record map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &record); err != nil {
		t.Fatalf("run --json did not emit a JSON log: %q: %v", errOut.String(), err)
	}
	message, ok := record["msg"].(string)
	if record["level"] != "ERROR" || !ok || message == "" {
		t.Fatalf("unexpected structured error record: %#v", record)
	}
	if !strings.Contains(message, missingConfig) {
		t.Fatalf("error record omitted config path: %#v", record)
	}
}
