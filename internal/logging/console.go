package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
)

type consoleAttr struct {
	groups []string
	attr   slog.Attr
}

type consoleHandler struct {
	out    io.Writer
	mu     *sync.Mutex
	attrs  []consoleAttr
	groups []string
}

func newConsoleHandler(out io.Writer) *consoleHandler {
	return &consoleHandler{out: out, mu: &sync.Mutex{}}
}

func (h *consoleHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *consoleHandler) Handle(_ context.Context, record slog.Record) error {
	var line strings.Builder
	line.WriteString(strings.ToUpper(record.Level.String()))
	line.WriteByte(' ')
	line.WriteString(strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(record.Message))
	for _, bound := range h.attrs {
		appendConsoleAttr(&line, bound.groups, bound.attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		appendConsoleAttr(&line, h.groups, attr)
		return true
	})
	line.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, line.String())
	return err
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append([]consoleAttr(nil), h.attrs...)
	for _, attr := range attrs {
		clone.attrs = append(clone.attrs, consoleAttr{groups: append([]string(nil), h.groups...), attr: attr})
	}
	return &clone
}

func (h *consoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.groups = append(append([]string(nil), h.groups...), name)
	clone.attrs = append([]consoleAttr(nil), h.attrs...)
	return &clone
}

func appendConsoleAttr(line *strings.Builder, groups []string, attr slog.Attr) {
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		nestedGroups := groups
		if attr.Key != "" {
			nestedGroups = append(append([]string(nil), groups...), attr.Key)
		}
		for _, nested := range value.Group() {
			appendConsoleAttr(line, nestedGroups, nested)
		}
		return
	}
	if attr.Key == "" {
		return
	}
	keyParts := append(append([]string(nil), groups...), attr.Key)
	line.WriteByte(' ')
	line.WriteString(strings.Join(keyParts, "."))
	line.WriteByte('=')
	line.WriteString(formatConsoleValue(value))
}

func formatConsoleValue(value slog.Value) string {
	var text string
	if value.Kind() == slog.KindString {
		text = value.String()
	} else {
		text = fmt.Sprint(value.Any())
	}
	if text == "" || strings.ContainsAny(text, " \t\r\n\"\\") {
		return strconv.Quote(text)
	}
	return text
}
