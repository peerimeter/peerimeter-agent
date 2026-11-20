package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	_, err = findAndCheckActiveProfiles(profiles, func(_ string, err error) error {
		return fmt.Errorf("cannot safely update while an agent profile is active: %w", err)
	})
	if !errors.Is(err, local.ErrBusy) || !strings.Contains(err.Error(), "agent profile is active") {
		t.Fatalf("findAndCheckActiveProfiles() error = %v, want active state directory lock", err)
	}
}
