package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/selfupdate"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

type selfUpdateFixture struct {
	install string
	doc     string
	data    string
	lock    string
	config  string
	state   string
	runtime string
	old     map[string][]byte
	files   map[string][]byte
}

func newSelfUpdateFixture(t *testing.T, serviceProfile bool) selfUpdateFixture {
	t.Helper()
	root := t.TempDir()
	f := selfUpdateFixture{
		install: filepath.Join(root, "programs"),
		doc:     filepath.Join(root, "docs"),
		data:    filepath.Join(root, "data"),
		lock:    filepath.Join(root, "locks"),
		config:  filepath.Join(root, "configuration"),
		state:   filepath.Join(root, "state"),
		runtime: filepath.Join(root, "runtime"),
		old:     make(map[string][]byte),
		files:   make(map[string][]byte),
	}
	for _, dir := range []string{f.install, f.doc, f.data, f.lock, f.config, f.state, f.runtime} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	canonicalize := func(path string) string {
		canonical, err := installstate.Canonical(path)
		if err != nil {
			t.Fatal(err)
		}
		return canonical
	}
	f.install = canonicalize(f.install)
	f.doc = canonicalize(f.doc)
	f.data = canonicalize(f.data)
	f.lock = canonicalize(f.lock)
	f.config = canonicalize(f.config)
	f.state = canonicalize(f.state)
	f.runtime = canonicalize(f.runtime)
	for _, name := range installstate.ProgramNames() {
		contents := []byte("old " + name)
		dir := f.install
		if name == "peerimeter-agent.NOTICES.txt" {
			dir = f.doc
		}
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0700); err != nil {
			t.Fatal(err)
		}
		f.old[name] = contents
		f.files[name] = []byte("new " + name)
	}
	// The Windows runtime dependency is intentionally unchanged by agent updates.
	if runtime.GOOS == "windows" {
		f.files["wireguard.dll"] = append([]byte(nil), f.old["wireguard.dll"]...)
	}
	if err := installstate.RegisterWithDirectories(f.install, f.doc, f.data, f.lock, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.config, "private.key"), []byte("profile secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.state, "state.json"), []byte(`{"keep":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	profile := installstate.Profile{ConfigDir: f.config, StateDir: f.state, RuntimeDir: f.runtime, Service: serviceProfile}
	if err := installstate.RegisterProfile(f.install, profile); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f selfUpdateFixture) deps(tag string, manage updateServiceManager, wait updateServiceWaiter) selfUpdateDeps {
	return selfUpdateDeps{
		fetch: func(_ context.Context, _ *http.Client, goos, goarch string) (string, map[string][]byte, error) {
			if goos != "linux" || goarch != runtime.GOARCH {
				return "", nil, fmt.Errorf("unexpected target %s/%s", goos, goarch)
			}
			files := make(map[string][]byte, len(f.files))
			for name, data := range f.files {
				files[name] = append([]byte(nil), data...)
			}
			return tag, files, nil
		},
		verify: func(_ context.Context, path, version string) error {
			if filepath.Base(path) != "peerimeter-agent" || version != tag {
				return fmt.Errorf("unexpected verification target %s at %s", path, version)
			}
			return nil
		},
		manage: manage,
		wait:   wait,
	}
}

func TestSelfUpdateIntegrationUpdatesOwnedFilesAndPreservesProfileData(t *testing.T) {
	f := newSelfUpdateFixture(t, false)
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, true, f.install, "v1.0.0", "linux", runtime.GOARCH, f.deps("v1.2.0", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	var result selfUpdateResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode update result %q: %v", output.String(), err)
	}
	if result.State != "updated" || result.PreviousVersion != "v1.0.0" || result.UpdatedVersion != "v1.2.0" || len(result.Files) != len(f.files) {
		t.Fatalf("unexpected result: %+v", result)
	}
	for name, want := range f.files {
		dir := f.install
		if name == "peerimeter-agent.NOTICES.txt" {
			dir = f.doc
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("program file %s = %q, %v; want %q", name, got, err, want)
		}
	}
	for path, want := range map[string]string{
		filepath.Join(f.config, "private.key"): "profile secret",
		filepath.Join(f.state, "state.json"):   `{"keep":true}`,
	} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("profile data %s = %q, %v; want %q", path, got, err, want)
		}
	}
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	if inv.DataDir != f.data || inv.DocDir != f.doc || inv.LockDir != f.lock || len(inv.Profiles) != 1 || inv.Profiles[0].ConfigDir != f.config || inv.Profiles[0].StateDir != f.state || inv.Profiles[0].RuntimeDir != f.runtime {
		t.Fatalf("update changed inventory paths: %+v", inv)
	}
	if _, err := os.Stat(filepath.Join(f.lock, selfupdate.JournalFilename)); !os.IsNotExist(err) {
		t.Fatalf("committed update journal remains: %v", err)
	}
}

func TestSelfUpdateIntegrationServiceReadinessFailureRollsBack(t *testing.T) {
	f := newSelfUpdateFixture(t, true)
	var actions []string
	manage := func(action string, cfg service.Config) error {
		if cfg.ConfigDirectory != f.config || cfg.StateDirectory != f.state || cfg.RuntimeDirectory != f.runtime {
			t.Fatalf("service action received wrong profile paths: %+v", cfg)
		}
		actions = append(actions, action)
		return nil
	}
	waits := 0
	wait := func(context.Context, string) error {
		waits++
		if waits == 1 {
			return errors.New("updated service did not answer status")
		}
		return nil
	}
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, false, f.install, "v1.0.0", "linux", runtime.GOARCH, f.deps("v1.2.0", manage, wait))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("previous program files were restored")) {
		t.Fatalf("expected successful rollback error, got %v", err)
	}
	if want := []string{"stop", "start", "stop", "start"}; !reflect.DeepEqual(actions, want) {
		t.Fatalf("service actions = %v; want %v", actions, want)
	}
	for name, want := range f.old {
		dir := f.install
		if name == "peerimeter-agent.NOTICES.txt" {
			dir = f.doc
		}
		got, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("rollback did not restore %s: %q, %v", name, got, readErr)
		}
	}
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range inv.Files {
		got, hashErr := installstate.Hash(installstate.ResourcePath(inv, file))
		if hashErr != nil || got != file.SHA256 {
			t.Fatalf("inventory hash for %s was not restored: %s, %v", file.Name, got, hashErr)
		}
	}
}

func TestSelfUpdateIntegrationRefusesProfileChangesDuringReleaseFetch(t *testing.T) {
	f := newSelfUpdateFixture(t, true)
	var actions []string
	manage := func(action string, _ service.Config) error {
		actions = append(actions, action)
		return nil
	}
	deps := f.deps("v1.2.0", manage, func(context.Context, string) error { return nil })
	fetch := deps.fetch
	deps.fetch = func(ctx context.Context, client *http.Client, goos, goarch string) (string, map[string][]byte, error) {
		root := t.TempDir()
		profile := installstate.Profile{
			ConfigDir:  filepath.Join(root, "configuration"),
			StateDir:   filepath.Join(root, "state"),
			RuntimeDir: filepath.Join(root, "runtime"),
			Service:    true,
		}
		for _, dir := range []string{profile.ConfigDir, profile.StateDir, profile.RuntimeDir} {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return "", nil, err
			}
		}
		if err := installstate.RegisterProfile(f.install, profile); err != nil {
			return "", nil, err
		}
		return fetch(ctx, client, goos, goarch)
	}
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, false, f.install, "v1.0.0", "linux", runtime.GOARCH, deps)
	if err == nil || !strings.Contains(err.Error(), "changed while the release was being fetched") {
		t.Fatalf("expected changed profile set to abort update, got %v", err)
	}
	if !reflect.DeepEqual(actions, []string{"stop", "start"}) {
		t.Fatalf("service actions after profile change: %v", actions)
	}
	assertSelfUpdateFiles(t, f, f.old)
}

func TestSelfUpdateIntegrationRefusesProfileStartingDuringReleaseFetch(t *testing.T) {
	f := newSelfUpdateFixture(t, false)
	deps := f.deps("v1.2.0", nil, nil)
	fetchCalled := false
	deps.fetch = func(_ context.Context, _ *http.Client, _, _ string) (string, map[string][]byte, error) {
		fetchCalled = true
		// staticCommand holds the persistent state guard while the backend starts,
		// before it owns the runtime guard. Simulate that startup window.
		guard, err := local.Acquire(f.state)
		if err != nil {
			return "", nil, err
		}
		t.Cleanup(func() { _ = guard.Close() })
		return "v1.2.0", f.files, nil
	}
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, true, f.install, "v1.0.0", "linux", runtime.GOARCH, deps)
	if err == nil || !strings.Contains(err.Error(), "agent process started while the release was being fetched") {
		t.Fatalf("expected update to refuse a starting profile (fetch called: %v), got %v", fetchCalled, err)
	}
	assertSelfUpdateFiles(t, f, f.old)
}

func TestWindowsUpdateHelperRetainsOriginalServiceProfileForCleanup(t *testing.T) {
	original := installstate.Profile{ID: "original-service", Service: true, StateDir: "old-state", RuntimeDir: "old-runtime"}
	added := installstate.Profile{ID: "new-service", Service: true, StateDir: "new-state", RuntimeDir: "new-runtime"}
	profile, multiple := serviceProfileForHelper([]installstate.Profile{original, added}, []installstate.Profile{original}, true)
	if profile == nil || profile.ID != original.ID || profile.StateDir != original.StateDir || !multiple {
		t.Fatalf("helper cleanup profile = %#v, want original stopped service %#v", profile, original)
	}
	profile, multiple = serviceProfileForHelper([]installstate.Profile{added}, nil, false)
	if profile == nil || profile.ID != added.ID || multiple {
		t.Fatalf("helper fallback profile = %#v, multiple = %v", profile, multiple)
	}
	profile, multiple = serviceProfileForHelper([]installstate.Profile{added}, []installstate.Profile{{ID: "foreground"}}, true)
	if profile != nil || multiple {
		t.Fatalf("helper selected a service that was not stopped before update: %#v, multiple = %v", profile, multiple)
	}
}

func TestSelfUpdateIntegrationDoesNotRollbackUntilUpdatedServiceStops(t *testing.T) {
	f := newSelfUpdateFixture(t, true)
	var actions []string
	stopCalls := 0
	manage := func(action string, _ service.Config) error {
		actions = append(actions, action)
		if action == "stop" {
			stopCalls++
			if stopCalls == 2 {
				return errors.New("service manager refused to stop updated service")
			}
		}
		return nil
	}
	wait := func(context.Context, string) error { return errors.New("updated service did not answer status") }
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, false, f.install, "v1.0.0", "linux", runtime.GOARCH, f.deps("v1.2.0", manage, wait))
	if err == nil || !strings.Contains(err.Error(), "rollback is pending a later update recovery") {
		t.Fatalf("expected rollback to remain pending while service is running, got %v", err)
	}
	if !reflect.DeepEqual(actions, []string{"stop", "start", "stop"}) {
		t.Fatalf("service actions while stop failed: %v", actions)
	}
	assertSelfUpdateFiles(t, f, f.files)
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(inv.LockDir, selfupdate.JournalFilename)); err != nil {
		t.Fatalf("rollback journal was removed while the updated service could still be running: %v", err)
	}
}

func TestSelfUpdateIntegrationStopsPartiallyStartedServiceBeforeRollback(t *testing.T) {
	f := newSelfUpdateFixture(t, true)
	var actions []string
	startCalls := 0
	manage := func(action string, _ service.Config) error {
		actions = append(actions, action)
		if action == "start" {
			startCalls++
			if startCalls == 1 {
				return errors.New("service start returned an error after launching")
			}
		}
		return nil
	}
	wait := func(context.Context, string) error { return nil }
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, false, f.install, "v1.0.0", "linux", runtime.GOARCH, f.deps("v1.2.0", manage, wait))
	if err == nil || !strings.Contains(err.Error(), "previous program files were restored") {
		t.Fatalf("expected rollback after stopping partially started service, got %v", err)
	}
	if want := []string{"stop", "start", "stop", "start"}; !reflect.DeepEqual(actions, want) {
		t.Fatalf("service actions = %v; want %v", actions, want)
	}
	assertSelfUpdateFiles(t, f, f.old)
}

func TestSelfUpdateIntegrationKeepsJournalWhenPartiallyStartedServiceWillNotStop(t *testing.T) {
	f := newSelfUpdateFixture(t, true)
	stopCalls := 0
	manage := func(action string, _ service.Config) error {
		if action == "start" {
			return errors.New("service start returned after launching")
		}
		stopCalls++
		if stopCalls == 2 {
			return errors.New("service manager could not stop partially started service")
		}
		return nil
	}
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, false, f.install, "v1.0.0", "linux", runtime.GOARCH, f.deps("v1.2.0", manage, func(context.Context, string) error { return nil }))
	if err == nil || !strings.Contains(err.Error(), "rollback is pending a later update recovery") {
		t.Fatalf("expected rollback to remain pending after stop failure, got %v", err)
	}
	assertSelfUpdateFiles(t, f, f.files)
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(inv.LockDir, selfupdate.JournalFilename)); err != nil {
		t.Fatalf("rollback journal was not retained: %v", err)
	}
}

func TestSelfUpdateIntegrationLeavesJournalWhenNewProfileStartsBeforeRollback(t *testing.T) {
	f := newSelfUpdateFixture(t, true)
	newState := filepath.Join(t.TempDir(), "new state")
	newRuntime := filepath.Join(t.TempDir(), "new runtime")
	if err := os.Mkdir(newState, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(newRuntime, 0700); err != nil {
		t.Fatal(err)
	}
	var stateGuard *local.Guard
	defer func() {
		if stateGuard != nil {
			_ = stateGuard.Close()
		}
	}()
	manage := func(string, service.Config) error { return nil }
	wait := func(context.Context, string) error {
		if stateGuard != nil {
			return nil
		}
		profile := installstate.Profile{StateDir: newState, RuntimeDir: newRuntime}
		if err := installstate.RegisterProfile(f.install, profile); err != nil {
			return err
		}
		var err error
		stateGuard, err = local.Acquire(newState)
		if err != nil {
			return err
		}
		return errors.New("updated service readiness failed")
	}
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, false, f.install, "v1.0.0", "linux", runtime.GOARCH, f.deps("v1.2.0", manage, wait))
	if err == nil || !strings.Contains(err.Error(), "automatic rollback is pending because an agent profile may still be running") {
		t.Fatalf("expected rollback to remain pending for active profile, got %v", err)
	}
	assertSelfUpdateFiles(t, f, f.files)
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(inv.LockDir, selfupdate.JournalFilename)); err != nil {
		t.Fatalf("rollback journal was not retained: %v", err)
	}
}

func TestSelfUpdateIntegrationRestartsManagedServiceAfterReplacement(t *testing.T) {
	f := newSelfUpdateFixture(t, true)
	var actions []string
	manage := func(action string, _ service.Config) error {
		actions = append(actions, action)
		return nil
	}
	var waitedFor []string
	wait := func(_ context.Context, runtimeDir string) error {
		waitedFor = append(waitedFor, runtimeDir)
		inv, err := installstate.Load(f.install)
		if err != nil {
			return err
		}
		concurrent, err := selfupdate.LockUpdate(inv)
		if err == nil {
			_ = concurrent.Close()
			return errors.New("another update acquired ownership before readiness verification completed")
		}
		return nil
	}
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, true, f.install, "v1.0.0", "linux", runtime.GOARCH, f.deps("v1.2.0", manage, wait))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actions, []string{"stop", "start"}) || !reflect.DeepEqual(waitedFor, []string{f.runtime}) {
		t.Fatalf("managed service lifecycle: actions=%v waits=%v", actions, waitedFor)
	}
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	updateLock, err := selfupdate.LockUpdate(inv)
	if err != nil {
		t.Fatalf("update ownership lock was not released after commit: %v", err)
	}
	if err := updateLock.Close(); err != nil {
		t.Fatal(err)
	}
	var result selfUpdateResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.State != "updated" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestSelfUpdateIntegrationRestoresFilesWhenNewBinaryCannotStart(t *testing.T) {
	f := newSelfUpdateFixture(t, false)
	deps := f.deps("v1.2.0", nil, nil)
	deps.verify = func(context.Context, string, string) error {
		return errors.New("new binary failed to start")
	}
	var output bytes.Buffer
	err := selfUpdateAt(context.Background(), &output, false, f.install, "v1.0.0", "linux", runtime.GOARCH, deps)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("previous program files were restored")) {
		t.Fatalf("expected binary-start failure and rollback, got %v", err)
	}
	assertSelfUpdateFiles(t, f, f.old)
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range inv.Files {
		got, hashErr := installstate.Hash(installstate.ResourcePath(inv, file))
		if hashErr != nil || got != file.SHA256 {
			t.Fatalf("inventory hash for %s was not restored: %s, %v", file.Name, got, hashErr)
		}
	}
}

func TestSelfUpdateIntegrationDoesNotFetchWhenCurrentAndRefusesTampering(t *testing.T) {
	t.Run("already current", func(t *testing.T) {
		f := newSelfUpdateFixture(t, false)
		var output bytes.Buffer
		err := selfUpdateAt(context.Background(), &output, true, f.install, "v1.2.0", "linux", runtime.GOARCH, f.deps("v1.2.0", nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		var result selfUpdateResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.State != "up_to_date" {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		assertSelfUpdateFiles(t, f, f.old)
	})
	t.Run("modified installed executable", func(t *testing.T) {
		f := newSelfUpdateFixture(t, false)
		path := filepath.Join(f.install, installstate.ProgramNames()[0])
		if err := os.WriteFile(path, []byte("operator-modified"), 0700); err != nil {
			t.Fatal(err)
		}
		deps := f.deps("v1.2.0", nil, nil)
		deps.fetch = func(context.Context, *http.Client, string, string) (string, map[string][]byte, error) {
			t.Fatal("release was fetched for a modified installation")
			return "", nil, nil
		}
		var output bytes.Buffer
		err := selfUpdateAt(context.Background(), &output, true, f.install, "v1.0.0", "linux", runtime.GOARCH, deps)
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte("was modified")) {
			t.Fatalf("expected modified-file refusal, got %v", err)
		}
	})
}

func TestSelfUpdateIntegrationRecoversInterruptedTransactionBeforeFetching(t *testing.T) {
	f := newSelfUpdateFixture(t, false)
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	updateLock, err := selfupdate.LockUpdate(inv)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := installstate.Lock(f.install)
	if err != nil {
		_ = updateLock.Close()
		t.Fatal(err)
	}
	if _, _, _, err := selfupdate.Apply(inv, f.files); err != nil {
		_ = lock.Close()
		_ = updateLock.Close()
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		_ = updateLock.Close()
		t.Fatal(err)
	}
	if err := updateLock.Close(); err != nil {
		t.Fatal(err)
	}
	deps := f.deps("v1.2.0", nil, nil)
	deps.fetch = func(context.Context, *http.Client, string, string) (string, map[string][]byte, error) {
		t.Fatal("release fetched before interrupted transaction recovery")
		return "", nil, nil
	}
	var output bytes.Buffer
	if err := selfUpdateAt(context.Background(), &output, true, f.install, "v1.0.0", "linux", runtime.GOARCH, deps); err != nil {
		t.Fatal(err)
	}
	var result selfUpdateResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.State != "recovered" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertSelfUpdateFiles(t, f, f.old)
}

func TestSelfUpdateIntegrationLeavesRecoveryPendingWhileProfileIsActive(t *testing.T) {
	f := newSelfUpdateFixture(t, false)
	inv, err := installstate.Load(f.install)
	if err != nil {
		t.Fatal(err)
	}
	updateLock, err := selfupdate.LockUpdate(inv)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := installstate.Lock(f.install)
	if err != nil {
		_ = updateLock.Close()
		t.Fatal(err)
	}
	if _, _, _, err := selfupdate.Apply(inv, f.files); err != nil {
		_ = lock.Close()
		_ = updateLock.Close()
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		_ = updateLock.Close()
		t.Fatal(err)
	}
	if err := updateLock.Close(); err != nil {
		t.Fatal(err)
	}
	active, err := local.Acquire(f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	deps := f.deps("v1.2.0", nil, nil)
	deps.fetch = func(context.Context, *http.Client, string, string) (string, map[string][]byte, error) {
		t.Fatal("release fetched while an agent profile was active during recovery")
		return "", nil, nil
	}
	var output bytes.Buffer
	err = selfUpdateAt(context.Background(), &output, true, f.install, "v1.0.0", "linux", runtime.GOARCH, deps)
	if err == nil || !strings.Contains(err.Error(), "agent profile is active") {
		t.Fatalf("expected recovery to remain pending while the profile is active, got %v", err)
	}
	for name, want := range f.files {
		path := filepath.Join(f.install, name)
		if name == "peerimeter-agent.NOTICES.txt" {
			path = filepath.Join(f.doc, name)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("active profile recovery unexpectedly changed %s: got %q err=%v", name, got, err)
		}
	}
}

func assertSelfUpdateFiles(t *testing.T, f selfUpdateFixture, want map[string][]byte) {
	t.Helper()
	for name, contents := range want {
		dir := f.install
		if name == "peerimeter-agent.NOTICES.txt" {
			dir = f.doc
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, contents) {
			t.Fatalf("file %s = %q, %v; want %q", name, got, err, contents)
		}
	}
}
