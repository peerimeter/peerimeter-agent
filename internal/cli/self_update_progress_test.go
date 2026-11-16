package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"charm.land/bubbles/v2/spinner"
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

func TestSelfUpdateProgressUsesSpinnerWithoutProgressBar(t *testing.T) {
	model := selfUpdateProgressModel{spinner: spinner.New(spinner.WithSpinner(spinner.Dot))}
	updated, cmd := model.Update(selfUpdateProgressStart{message: "Checking the latest stable release"})
	model = updated.(selfUpdateProgressModel)
	if !model.active || cmd == nil || !strings.Contains(model.View().Content, "Checking the latest stable release") || !strings.Contains(model.View().Content, model.spinner.View()) {
		t.Fatalf("active update view does not show its spinner and message: %+v %q", model, model.View().Content)
	}
	updated, cmd = model.Update(model.spinner.Tick())
	model = updated.(selfUpdateProgressModel)
	if cmd == nil || !model.active {
		t.Fatal("spinner did not continue while the update step is active")
	}
	if strings.Contains(model.View().Content, "█") || strings.Contains(model.View().Content, "\n") {
		t.Fatalf("TUI update view still contains a progress bar: %q", model.View().Content)
	}
	updated, _ = model.Update(selfUpdateProgressFinish{err: errors.New("download failed")})
	model = updated.(selfUpdateProgressModel)
	if model.active || !strings.HasPrefix(model.View().Content, "✗ ") {
		t.Fatalf("finished error view is incorrect: %q", model.View().Content)
	}
}

func TestSelfUpdateProgressStopDoesNotPrintCompletedBar(t *testing.T) {
	var output bytes.Buffer
	progress := newSelfUpdateProgress(&output)
	progress.tty = true
	finish := progress.start("Checking the latest stable release")
	finish(nil)
	progress.stop()
	if strings.Contains(output.String(), "████") {
		t.Fatalf("stopped spinner output still contains a completed bar: %q", output.String())
	}
}
