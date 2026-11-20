package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
)

func TestWindowsUpdateResultState(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "updated", want: "updated"},
		{name: "failed", err: errors.New("replacement failed"), want: "failed"},
		{name: "recovery pending", err: fmt.Errorf("preserve details: %w", windowsHelperRecoveryPending(errors.New("restore failed"))), want: "pending"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := windowsUpdateResultState(test.err); got != test.want {
				t.Fatalf("windowsUpdateResultState() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRestartAfterWindowsReplacementFailureJoinsRestartError(t *testing.T) {
	profile := &installstate.Profile{Service: true}
	replacementErr := fmt.Errorf("%w: file is busy", errWindowsHelperReplacementFailed)
	restartErr := errors.New("service restart failed")
	got, attempted := restartAfterWindowsReplacementFailure(replacementErr, profile, func(installstate.Profile) error {
		return restartErr
	})
	if !attempted || !errors.Is(got, errWindowsHelperReplacementFailed) || !errors.Is(got, restartErr) {
		t.Fatalf("restart result = %v, attempted %t; want both failures", got, attempted)
	}

	got, attempted = restartAfterWindowsReplacementFailure(replacementErr, profile, func(installstate.Profile) error {
		return nil
	})
	if !attempted || got.Error() != replacementErr.Error() {
		t.Fatalf("successful restart changed replacement error: %v, attempted %t", got, attempted)
	}
}

func TestRecoveryPendingSuppressesWindowsServiceRestart(t *testing.T) {
	called := false
	profile := &installstate.Profile{Service: true}
	cause := errors.New("journal recovery failed")
	pendingErr := windowsHelperRecoveryPending(cause)
	got, attempted := restartAfterWindowsReplacementFailure(pendingErr, profile, func(installstate.Profile) error {
		called = true
		return nil
	})
	if !attempted || called || !errors.Is(got, errWindowsHelperRecoveryPending) || !errors.Is(got, cause) {
		t.Fatalf("pending recovery result = %v, attempted %t, service start called %t", got, attempted, called)
	}
}
