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

func TestSelfUpdateProgressStopKeepsCompletedBarVisible(t *testing.T) {
	var output bytes.Buffer
	progress := newSelfUpdateProgress(&output)
	progress.tty = true
	finish := progress.start("Checking the latest stable release")
	finish(nil)
	progress.stop(selfUpdateProgressUpToDate)

	if bar := completedSelfUpdateProgressBar(selfUpdateProgressUpToDate, false); !strings.Contains(output.String(), bar) {
		t.Fatalf("stopped TUI output does not retain the completed bar: %q", output.String())
	}
	if !strings.HasSuffix(output.String(), completedSelfUpdateProgressBar(selfUpdateProgressUpToDate, false)+"\n\n") {
		t.Fatalf("completed bar is not followed by a blank line: %q", output.String())
	}
}

func TestSelfUpdateProgressStopsBeforeUpdateResult(t *testing.T) {
	var output bytes.Buffer
	progress := newSelfUpdateProgress(&output)
	progress.tty = true
	finish := runSelfUpdateAction(progress, "Finalizing update and removing rollback backup", func() error { return nil })
	if finish != nil {
		t.Fatal(finish)
	}
	progress.stop(selfUpdateProgressUpdateSucceeded)
	_, _ = output.WriteString("Updated Peerimeter Agent from v0.19.0 to v0.19.1.\n")

	bar := completedSelfUpdateProgressBar(selfUpdateProgressUpdateSucceeded, false)
	if !strings.HasSuffix(output.String(), bar+"\n\nUpdated Peerimeter Agent from v0.19.0 to v0.19.1.\n") {
		t.Fatalf("update result was not written after the progress UI closed: %q", output.String())
	}
}

func TestSelfUpdateProgressCompletionColorsAreDistinct(t *testing.T) {
	plain := completedSelfUpdateProgressBar(selfUpdateProgressUpToDate, false)
	if strings.Contains(plain, "\x1b[") {
		t.Fatalf("color-disabled progress bar contains ANSI styling: %q", plain)
	}
	upToDate := completedSelfUpdateProgressBar(selfUpdateProgressUpToDate, true)
	updateAvailable := completedSelfUpdateProgressBar(selfUpdateProgressUpdateAvailable, true)
	if upToDate == updateAvailable {
		t.Fatal("up-to-date and update-available bars use the same color")
	}
	updateSucceeded := completedSelfUpdateProgressBar(selfUpdateProgressUpdateSucceeded, true)
	if updateSucceeded != upToDate {
		t.Fatal("successful update should use the completed green bar")
	}
}

func TestSelfUpdateProgressUsesSpinnerOnlyForReleaseCheck(t *testing.T) {
	model := selfUpdateProgressModel{bar: progress.New(progress.WithWidth(32))}
	updated, cmd := model.Update(selfUpdateProgressStart{message: "Checking the latest stable release"})
	model = updated.(selfUpdateProgressModel)
	if !model.spinnerOnly || !model.active || cmd == nil || !strings.Contains(model.View().Content, model.spinner.View()) {
		t.Fatalf("release check should show an active spinner: %+v %q", model, model.View().Content)
	}
	updated, cmd = model.Update(model.spinner.Tick())
	model = updated.(selfUpdateProgressModel)
	if cmd == nil || !model.active {
		t.Fatal("release check spinner did not continue")
	}

	updated, _ = model.Update(selfUpdateProgressStart{message: "Downloading release package"})
	model = updated.(selfUpdateProgressModel)
	if model.spinnerOnly || !strings.Contains(model.View().Content, "\n") {
		t.Fatalf("update step should retain its progress bar: %q", model.View().Content)
	}
}

func TestSelfUpdateProgressDoesNotPrintOrangeUpdateAvailableBar(t *testing.T) {
	var output bytes.Buffer
	progress := newSelfUpdateProgress(&output)
	progress.tty = true
	finish := progress.start("Checking the latest stable release")
	finish(nil)
	progress.stop(selfUpdateProgressUpdateAvailable)
	if strings.Contains(output.String(), completedSelfUpdateProgressBar(selfUpdateProgressUpdateAvailable, false)) {
		t.Fatalf("release check printed the removed orange completion bar: %q", output.String())
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
