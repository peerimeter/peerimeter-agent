// Package diagnostic adds source locations to errors while preserving their
// original identity for errors.Is and errors.As.
package diagnostic

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

type stackError struct {
	err   error
	stack string
}

func (e *stackError) Error() string      { return e.err.Error() }
func (e *stackError) Unwrap() error      { return e.err }
func (e *stackError) StackTrace() string { return e.stack }

// Wrap records the current call stack and retains err as the wrapped cause.
func Wrap(err error) error {
	if err == nil {
		return nil
	}
	var existing interface{ StackTrace() string }
	if errors.As(err, &existing) {
		return err
	}
	pcs := make([]uintptr, 32)
	var n int
	for {
		n = runtime.Callers(2, pcs)
		if n < len(pcs) {
			break
		}
		pcs = make([]uintptr, len(pcs)*2)
	}
	frames := runtime.CallersFrames(pcs[:n])
	var trace strings.Builder
	for {
		frame, more := frames.Next()
		_, _ = fmt.Fprintf(&trace, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	return &stackError{err: err, stack: trace.String()}
}

// StackTrace returns a captured stack trace from err or one of its causes.
func StackTrace(err error) (string, bool) {
	var traced interface{ StackTrace() string }
	if !errors.As(err, &traced) {
		return "", false
	}
	return traced.StackTrace(), true
}
