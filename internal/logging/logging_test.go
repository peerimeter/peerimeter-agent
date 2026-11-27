package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestWireGuardDriverWriterMapsMessagesToLevels(t *testing.T) {
	var output bytes.Buffer
	handler, err := NewHandler("json", &output)
	if err != nil {
		t.Fatal(err)
	}
	writer := NewWireGuardDriverWriter(slog.New(handler))
	messages := []struct {
		message string
		level   string
	}{
		{message: "Failed to remove adapter when closing", level: "ERROR"},
		{message: "Adapter started", level: "INFO"},
	}
	for _, item := range messages {
		if _, err := writer.Write([]byte(item.message + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	decoder := json.NewDecoder(&output)
	for _, item := range messages {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record["level"] != item.level || record["msg"] != item.message || record["component"] != "WireGuardNT" {
			t.Fatalf("record = %#v, want level %s and message %q", record, item.level, item.message)
		}
	}
}

func TestNewHandlerConsoleAndText(t *testing.T) {
	for _, format := range []string{"", "console", "text"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			handler, err := NewHandler(format, &out)
			if err != nil {
				t.Fatal(err)
			}
			slog.New(handler).Info("hello\nworld", "peer", "node-a")
			if got, want := out.String(), "INFO hello\\nworld peer=node-a\n"; got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestNewHandlerJSON(t *testing.T) {
	var out bytes.Buffer
	handler, err := NewHandler(" JSON ", &out)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(handler).Warn("degraded", "peer", "node-a")

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if record["level"] != "WARN" || record["msg"] != "degraded" || record["peer"] != "node-a" {
		t.Fatalf("unexpected JSON record: %#v", record)
	}
}

func TestNewHandlerRejectsUnsupportedFormat(t *testing.T) {
	if _, err := NewHandler("yaml", &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), FormatEnv) {
		t.Fatalf("NewHandler error = %v, want unsupported-format error mentioning %s", err, FormatEnv)
	}
}

func TestConsoleHandlerGroupsAndBoundAttributes(t *testing.T) {
	var out bytes.Buffer
	handler := newConsoleHandler(&out).WithAttrs([]slog.Attr{slog.String("service", "agent")}).WithGroup("peer")
	slog.New(handler).Info("ready", "id", "node-a")
	if got, want := out.String(), "INFO ready service=agent peer.id=node-a\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestConsoleHandlerReturnsWriterError(t *testing.T) {
	want := errors.New("write failed")
	handler := newConsoleHandler(failingWriter{err: want})
	err := handler.Handle(context.Background(), slog.NewRecord(time.Time{}, slog.LevelError, "failed", 0))
	if !errors.Is(err, want) {
		t.Fatalf("Handle error = %v, want %v", err, want)
	}
}
