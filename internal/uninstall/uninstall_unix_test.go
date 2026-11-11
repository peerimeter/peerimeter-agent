//go:build linux || darwin

package uninstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func prepareUninstall(t *testing.T) (string, installstate.Profile) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "pm-uninstall-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "installation")
	p := installstate.Profile{ConfigDir: filepath.Join(base, "config"), StateDir: filepath.Join(base, "state"), RuntimeDir: filepath.Join(base, "runtime")}
	for _, d := range []string{dir, p.ConfigDir, p.StateDir, p.RuntimeDir} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range installstate.ProgramNames() {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.Register(dir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(p.ConfigDir, "service.json"), filepath.Join(p.ConfigDir, "service.key"), filepath.Join(p.StateDir, "network.json")} {
		if err := os.WriteFile(path, []byte("private fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := installstate.RegisterProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	return dir, p
}
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		s, e := os.Lstat(p)
		if e != nil {
			return e
		}
		v := s.Mode().String() + s.ModTime().String()
		if s.Mode().IsRegular() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			h := sha256.Sum256(b)
			v += hex.EncodeToString(h[:])
		}
		out[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestDryRunIsReadOnlyAndListsManagedIdentity(t *testing.T) {
	dir, p := prepareUninstall(t)
	if err := os.Remove(filepath.Join(dir, installstate.LockFilename)); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, filepath.Dir(dir))
	var out bytes.Buffer
	if err := Execute(context.Background(), Options{InstallDir: dir, DryRun: true}, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshotTree(t, filepath.Dir(dir))) {
		t.Fatal("dry-run changed filesystem metadata or contents")
	}
	var result report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.State != "dry_run" {
		t.Fatal("invalid dry-run report")
	}
	found := false
	for _, path := range result.Paths {
		if path == filepath.Join(p.ConfigDir, "service.key") {
			found = true
		}
	}
	if !found {
		t.Fatal("dry-run omitted installed private key")
	}
}
func TestFullRemovalPreservesUnrelatedAndSupportsRetry(t *testing.T) {
	dir, p := prepareUninstall(t)
	var untouched []string
	for _, d := range []string{dir, p.ConfigDir, p.StateDir, p.RuntimeDir} {
		path := filepath.Join(d, "unrelated.txt")
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		untouched = append(untouched, path)
	}
	notice := filepath.Join(dir, "peerimeter-agent.NOTICES.txt")
	if err := os.WriteFile(notice, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, filepath.Dir(dir))
	if err := Execute(context.Background(), Options{InstallDir: dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("changed program file was removed")
	}
	if !reflect.DeepEqual(before, snapshotTree(t, filepath.Dir(dir))) {
		t.Fatal("failed preflight mutated the live installation")
	}
	// Missing already-removed package members are safe on partial-failure retry.
	if err := os.Remove(notice); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Execute(context.Background(), Options{InstallDir: dir}, &out); err != nil {
		t.Fatal(err)
	}
	var result report
	_ = json.Unmarshal(out.Bytes(), &result)
	if result.State != "removed" {
		t.Fatal("full removal did not report success")
	}
	for _, path := range untouched {
		b, e := os.ReadFile(path)
		if e != nil || string(b) != "preserve" {
			t.Fatal("unrelated custom-parent content was removed")
		}
	}
	for _, path := range []string{filepath.Join(p.ConfigDir, "service.key"), filepath.Join(p.ConfigDir, "service.json"), filepath.Join(p.StateDir, "network.json"), filepath.Join(p.StateDir, installstate.MarkerFilename), filepath.Join(dir, installstate.Filename)} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatalf("owned file remained: %s", path)
		}
	}
	out.Reset()
	if err := Execute(context.Background(), Options{InstallDir: dir}, &out); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(out.Bytes(), &result)
	if result.State != "already_absent" {
		t.Fatal("repeated removal was not idempotent")
	}
}
func TestLivePersistentGuardPreventsDeletion(t *testing.T) {
	dir, p := prepareUninstall(t)
	guard, err := local.Acquire(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	before := snapshotTree(t, filepath.Dir(dir))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := Execute(ctx, Options{InstallDir: dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("uninstall bypassed a live manager state lock")
	}
	after := snapshotTree(t, filepath.Dir(dir))
	delete(before, filepath.Join(dir, installstate.Filename))
	delete(after, filepath.Join(dir, installstate.Filename))
	delete(before, dir)
	delete(after, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("live lock refusal deleted or changed managed data")
	}
	inv, e := installstate.Load(dir)
	if e != nil || !inv.Removing {
		t.Fatal("incomplete removal must durably prevent a new manager startup")
	}
}
func TestUntrackedOverrideAndSymlinkRefused(t *testing.T) {
	dir, p := prepareUninstall(t)
	outside := t.TempDir()
	if err := Execute(context.Background(), Options{InstallDir: dir, ConfigDir: outside, DryRun: true}, &bytes.Buffer{}); err == nil {
		t.Fatal("untracked directory override accepted")
	}
	key := filepath.Join(p.ConfigDir, "service.key")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(outside, "operator-original.key")
	if err := os.WriteFile(source, []byte("private source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, key); err != nil {
		t.Fatal(err)
	}
	if err := Execute(context.Background(), Options{InstallDir: dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("symlink resource was followed during removal")
	}
	b, e := os.ReadFile(source)
	if e != nil || string(b) != "private source" {
		t.Fatal("operator original key was removed")
	}
}

func TestOwnedDaemonStopsEvenWhenNetworkSnapshotFails(t *testing.T) {
	dir, p := prepareUninstall(t)
	guard, err := local.Acquire(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	var calls atomic.Int32
	stop := make(chan struct{})
	var once sync.Once
	claim := p
	claim.ClaimRuntime = true
	closeControl, err := local.Serve(context.Background(), p.RuntimeDir, local.Operations{
		InstanceID:   local.InstanceID(p.StateDir),
		BeforeListen: func() error { return installstate.RegisterProfile(dir, claim) },
		OnClose:      func() error { return installstate.ReleaseRuntime(dir, p.StateDir, p.RuntimeDir) },
		Snapshot: func(context.Context) (platform.Snapshot, error) {
			calls.Add(1)
			return platform.Snapshot{}, errors.New("native interface drift")
		},
		Reload: func(context.Context) error { return nil }, Stop: func() { once.Do(func() { close(stop) }) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeControl()
	done := make(chan error, 1)
	go func() {
		<-stop
		closeErr := closeControl()
		lockErr := guard.Close()
		done <- errors.Join(closeErr, lockErr)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Execute(ctx, Options{InstallDir: dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("uninstall depended on mutable network health instead of authenticated instance identity")
	}
}
