package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

func TestRunJSONFormatsErrorsAsStructuredLogs(t *testing.T) {
	t.Setenv("PEERIMETER_LOG_FORMAT", "console")
	var out, errOut bytes.Buffer
	missingConfig := filepath.Join(t.TempDir(), "missing.yaml")
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

func TestSudoUserConfigDirRequiresExistingDirectory(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "peerimeter-agent")
	if got, ok := sudoUserConfigDir(home); ok || got != configDir {
		t.Fatalf("missing config directory returned %q, %t", got, ok)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, ok := sudoUserConfigDir(home); !ok || got != configDir {
		t.Fatalf("existing config directory returned %q, %t", got, ok)
	}
	if got, ok := sudoUserConfigDir("relative"); ok || got != "" {
		t.Fatalf("relative home returned %q, %t", got, ok)
	}
}
