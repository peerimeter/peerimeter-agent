package diagnostic

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestWrapPreservesCauseAndStack(t *testing.T) {
	cause := &os.PathError{Op: "open", Path: "config.json", Err: os.ErrNotExist}
	err := Wrap(cause)
	var pathErr *os.PathError
	if err.Error() != cause.Error() || !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) || pathErr != cause {
		t.Fatalf("lost original error: %v", err)
	}
	outer := fmt.Errorf("load: %w", err)
	trace, ok := StackTrace(outer)
	if !ok || !strings.Contains(trace, "TestWrapPreservesCauseAndStack") || !strings.Contains(trace, "error_test.go:") {
		t.Fatalf("missing caller stack: %q", trace)
	}
	if Wrap(outer) != outer {
		t.Fatal("replaced original stack")
	}
}

func TestUntracedErrors(t *testing.T) {
	if Wrap(nil) != nil {
		t.Fatal("wrapped nil")
	}
	for _, err := range []error{nil, errors.New("plain")} {
		if trace, ok := StackTrace(err); ok || trace != "" {
			t.Fatalf("unexpected stack: %q", trace)
		}
	}
}
