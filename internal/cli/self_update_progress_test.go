package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"charm.land/bubbles/v2/progress"
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

func TestSelfUpdateProgressAdvancesOnceAndWaitsForFinish(t *testing.T) {
	model := selfUpdateProgressModel{bar: progress.New(progress.WithWidth(32))}
	updatedTeaModel, _ := model.Update(selfUpdateProgressStart{message: "Downloading release package"})
	model = updatedTeaModel.(selfUpdateProgressModel)

	previous := model.percent
	for model.percent < 0.9 {
		updatedTeaModel, _ = model.Update(selfUpdateProgressTick{generation: model.generation})
		model = updatedTeaModel.(selfUpdateProgressModel)
		if model.percent < previous {
			t.Fatalf("progress moved backwards from %v to %v", previous, model.percent)
		}
		previous = model.percent
	}
	if model.percent != 0.9 {
		t.Fatalf("active progress = %v; want 0.9", model.percent)
	}
	updatedTeaModel, cmd := model.Update(selfUpdateProgressTick{generation: model.generation})
	if cmd != nil || updatedTeaModel.(selfUpdateProgressModel).percent != 0.9 {
		t.Fatal("progress did not stay at 90% while the update remained active")
	}
	updatedTeaModel, _ = model.Update(selfUpdateProgressFinish{})
	model = updatedTeaModel.(selfUpdateProgressModel)
	if got := model.percent; got != 1 {
		t.Fatalf("finished progress = %v; want 1", got)
	}
	if bar := model.bar.ViewAs(1); bar == "" || !strings.Contains(model.View().Content, bar) {
		t.Fatalf("finished progress bar is not fully rendered: %q", model.View().Content)
	}
}
