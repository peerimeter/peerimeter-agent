package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSelfUpdateProgressReportsStartedAndFinishedSteps(t *testing.T) {
	var output bytes.Buffer
	progress := newSelfUpdateProgress(&output)
	wantErr := errors.New("download failed")
	if err := runSelfUpdateAction(progress, "Downloading release package", func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("run update step error = %v; want %v", err, wantErr)
	}
	for _, want := range []string{"→ Downloading release package", "✗ Downloading release package"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("progress output %q does not contain %q", output.String(), want)
		}
	}
}
