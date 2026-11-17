package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(--help) exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("help output lacks Usage section: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("help wrote unexpected stderr: %q", stderr.String())
	}
}

func TestRunRejectsInvalidLogFormat(t *testing.T) {
	t.Setenv("PEERIMETER_LOG_FORMAT", "yaml")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(--help) with invalid log format exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "PEERIMETER_LOG_FORMAT") {
		t.Fatalf("stderr = %q, want log-format error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid environment unexpectedly wrote stdout: %q", stdout.String())
	}
}
