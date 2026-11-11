package service

import (
	"context"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestWindowsServiceArgumentsPreservePaths(t *testing.T) {
	cfg := Config{ConfigPath: `C:\ProgramData\Peerimeter Agent\service.json`, StateDirectory: `C:\ProgramData\Peerimeter Agent\state`}
	want := []string{"run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", serviceRuntime(cfg), "--config-dir", snapshotDirectory(cfg)}
	if got := serviceArguments(cfg); !reflect.DeepEqual(got, want) {
		t.Fatal("SCM arguments must preserve config paths as individual arguments")
	}
}

func TestWindowsServiceStopWaitsForRuntimeCleanup(t *testing.T) {
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 8)
	cleanup := make(chan struct{})
	stopping := make(chan struct{})
	finished := make(chan uint32, 1)
	handler := windowsHandler{ctx: context.Background(), run: func(ctx context.Context) error {
		<-ctx.Done()
		close(stopping)
		<-cleanup
		return nil
	}}
	go func() { _, code := handler.Execute(nil, requests, statuses); finished <- code }()
	if status := <-statuses; status.State != svc.StartPending {
		t.Fatal("must report service startup")
	}
	if status := <-statuses; status.State != svc.Running || status.Accepts&svc.AcceptStop == 0 {
		t.Fatal("must accept stop while running")
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case <-stopping:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not cancel foreground runtime")
	}
	if status := <-statuses; status.State != svc.StopPending {
		t.Fatal("must remain stop-pending during tunnel teardown")
	}
	select {
	case <-finished:
		t.Fatal("reported stopped before runtime cleanup completed")
	default:
	}
	close(cleanup)
	select {
	case code := <-finished:
		if code != 0 {
			t.Fatal("graceful shutdown reported failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service did not finish after cleanup")
	}
}

func TestWindowsServiceArgumentsDelegateOperator(t *testing.T) {
	cfg := Config{ConfigPath: `C:\ProgramData\Peerimeter\service.json`, StateDirectory: `C:\ProgramData\Peerimeter`, Operator: "S-1-5-21-100-200-300-1001"}
	got := serviceArguments(cfg)
	if len(got) != 11 || got[9] != "--operator" || got[10] != cfg.Operator {
		t.Fatal("Windows service must preserve the explicit local operator identity")
	}
}

func TestWindowsReadOnlyProbeRejectsAmbiguousUnquotedServicePath(t *testing.T) {
	executable := `C:\Program Files\Peerimeter\peerimeter-agent.exe`
	if owned, err := windowsRegistrationUsesExecutable(`"`+executable+`" run --config C:\config.json`, executable); err != nil || !owned {
		t.Fatal("quoted own service was not detected", err)
	}
	if owned, err := windowsRegistrationUsesExecutable(executable+` run`, executable); err == nil || owned {
		t.Fatal("ambiguous unquoted spaced executable was treated as foreign")
	}
	if owned, err := windowsRegistrationUsesExecutable(`C:\Windows\System32\svchost.exe -k LocalService`, executable); err != nil || owned {
		t.Fatal("unrelated unambiguous service executable was changed", err)
	}
}
