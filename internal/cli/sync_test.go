package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectManagedNetwork(t *testing.T) {
	stateDir := t.TempDir()
	tokenDir := filepath.Join(stateDir, "managed")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeToken := func(id string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tokenDir, id+".token"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("no credentials preserves local sync selection", func(t *testing.T) {
		got, err := selectManagedNetwork(stateDir, "")
		if err != nil || got != "" {
			t.Fatalf("selectManagedNetwork() = %q, %v; want empty selection", got, err)
		}
	})
	t.Run("explicit network requires a saved credential", func(t *testing.T) {
		_, err := selectManagedNetwork(stateDir, "network-a")
		if err == nil || err.Error() != "no joined network credentials found; run join before syncing Service API peers" {
			t.Fatalf("selectManagedNetwork() error = %v", err)
		}
	})
	writeToken("network-a")
	t.Run("single network is selected by default", func(t *testing.T) {
		got, err := selectManagedNetwork(stateDir, "")
		if err != nil || got != "network-a" {
			t.Fatalf("selectManagedNetwork() = %q, %v; want network-a", got, err)
		}
	})
	writeToken("network-b")
	t.Run("multiple networks require an explicit choice", func(t *testing.T) {
		_, err := selectManagedNetwork(stateDir, "")
		if err == nil || !strings.Contains(err.Error(), "--network-id is required when multiple networks are joined") {
			t.Fatalf("selectManagedNetwork() error = %v", err)
		}
	})
	t.Run("unknown explicit network is rejected", func(t *testing.T) {
		_, err := selectManagedNetwork(stateDir, "network-c")
		if err == nil || err.Error() != "no saved credential found for --network-id" {
			t.Fatalf("selectManagedNetwork() error = %v", err)
		}
	})
}
