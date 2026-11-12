// Package logging configures the agent's structured runtime logger.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"
)

const FormatEnv = "PEERIMETER_LOG_FORMAT"

// NewHandler selects console, plain text, or JSON logging. Console output colors
// log levels only when writing to a terminal and honors NO_COLOR.
func NewHandler(format string, out io.Writer) (slog.Handler, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "console":
		var writer io.Writer = out
		if terminalColorEnabled(out) {
			writer = coloredLevels{out: out}
		}
		return newConsoleHandler(writer), nil
	case "text":
		return newConsoleHandler(out), nil
	case "json":
		return slog.NewJSONHandler(out, nil), nil
	default:
		return nil, fmt.Errorf("%s must be console, text, or json", FormatEnv)
	}
}

type coloredLevels struct{ out io.Writer }

func (w coloredLevels) Write(p []byte) (int, error) {
	formatted := string(p)
	for _, level := range []struct{ name, color string }{
		{"DEBUG", "36"}, {"INFO", "35"}, {"WARN", "33"}, {"ERROR", "31"},
	} {
		formatted = strings.Replace(formatted, level.name+" ", "\x1b["+level.color+"m"+level.name+"\x1b[0m ", 1)
	}
	n, err := io.WriteString(w.out, formatted)
	if err != nil {
		return 0, err
	}
	if n != len(formatted) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func terminalColorEnabled(out io.Writer) bool {
	file, ok := out.(*os.File)
	_, noColor := os.LookupEnv("NO_COLOR")
	if !ok || noColor || os.Getenv("TERM") == "dumb" || !term.IsTerminal(int(file.Fd())) {
		return false
	}
	return enableTerminalColors(file)
}
