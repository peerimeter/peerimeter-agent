package cli

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
)

func TestFindAndCheckActiveProfilesChecksStateDirectory(t *testing.T) {
	stateDir := t.TempDir()
	guard, err := local.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	profiles := []installstate.Profile{{StateDir: stateDir, RuntimeDir: filepath.Join(stateDir, "runtime")}}
	_, err = findAndCheckActiveProfiles(profiles, func(err error) error { return err })
	if !errors.Is(err, local.ErrBusy) {
		t.Fatalf("findAndCheckActiveProfiles() error = %v, want active state directory lock", err)
	}
}
