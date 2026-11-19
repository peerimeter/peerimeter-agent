package cli

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestStartAndWaitForUpdatedService(t *testing.T) {
	startErr := errors.New("start failed")
	waitErr := errors.New("readiness failed")
	stopErr := errors.New("stop failed")
	tests := []struct {
		name                string
		startError          error
		waitError           error
		stopError           error
		wantCalls           []string
		wantError           string
		wantRollbackPending bool
	}{
		{name: "ready", wantCalls: []string{"start", "wait"}},
		{name: "start failure stopped", startError: startErr, wantCalls: []string{"start", "stop"}, wantError: "restart service: start failed"},
		{name: "readiness failure stopped", waitError: waitErr, wantCalls: []string{"start", "wait", "stop"}, wantError: "service not ready: readiness failed"},
		{name: "start failure could not stop", startError: startErr, stopError: stopErr, wantCalls: []string{"start", "stop"}, wantError: "rollback is pending", wantRollbackPending: true},
		{name: "readiness failure could not stop", waitError: waitErr, stopError: stopErr, wantCalls: []string{"start", "wait", "stop"}, wantError: "rollback is pending", wantRollbackPending: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			err := startAndWaitForUpdatedService(
				func() error { calls = append(calls, "start"); return test.startError },
				func() error { calls = append(calls, "wait"); return test.waitError },
				func() error { calls = append(calls, "stop"); return test.stopError },
				"restart service",
				"service not ready",
			)
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, test.wantCalls)
			}
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
			if got := rollbackMustWaitForRecovery(err); got != test.wantRollbackPending {
				t.Fatalf("rollbackMustWaitForRecovery() = %t, want %t", got, test.wantRollbackPending)
			}
		})
	}
}
