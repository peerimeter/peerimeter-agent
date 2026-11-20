package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/paths"
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

	writeToken("network-a")
	t.Run("one network is selected by default", func(t *testing.T) {
		got, err := selectManagedNetworkIDs([]string{"network-a"}, "")
		if err != nil || !reflect.DeepEqual(got, []string{"network-a"}) {
			t.Fatalf("selectManagedNetworkIDs() = %#v, %v; want network-a", got, err)
		}
	})
	writeToken("network-b")
	t.Run("all networks are selected by default", func(t *testing.T) {
		got, err := selectManagedNetworkIDs([]string{"network-a", "network-b"}, "")
		if err != nil || !reflect.DeepEqual(got, []string{"network-a", "network-b"}) {
			t.Fatalf("selectManagedNetworkIDs() = %#v, %v; want both networks", got, err)
		}
	})
	t.Run("unknown explicit network is rejected", func(t *testing.T) {
		_, err := selectManagedNetworkIDs([]string{"network-a", "network-b"}, "network-c")
		if err == nil || err.Error() != "no saved credential found for --network-id" {
			t.Fatalf("selectManagedNetworkIDs() error = %v", err)
		}
	})
}

func TestSyncRejectsNetworkSelectionWithoutSavedCredentials(t *testing.T) {
	root := t.TempDir()
	app := &application{out: io.Discard}
	err := runSync(context.Background(), app, syncOptions{networkID: "network-missing", dirs: paths.Options{
		ConfigDir:  filepath.Join(root, "config"),
		StateDir:   filepath.Join(root, "state"),
		RuntimeDir: filepath.Join(root, "runtime"),
	}})
	if err == nil || err.Error() != "no joined network credentials found; run join before syncing Service API peers" {
		t.Fatalf("runSync() error = %v; want missing joined credential error", err)
	}
}
