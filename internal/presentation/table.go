package presentation

import (
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

func newRenderer(out io.Writer, color bool) *lipgloss.Renderer {
	r := lipgloss.NewRenderer(out)
	if color {
		r.SetColorProfile(termenv.ANSI256)
	} else {
		r.SetColorProfile(termenv.Ascii)
	}
	return r
}

// Table gives command results shared cell borders and color policy. Headers
// are optional for tables where row labels already provide enough context.
// Data is sanitized before deliberate multiline cells are rendered.
func Table(out io.Writer, headers []string, rows [][]string, color bool, width int) error {
	r := newRenderer(out, color)
	width = max(20, width)
	padding := 1
	if width < 40 {
		padding = 0
	}
	columns := len(headers)
	if columns == 0 && len(rows) > 0 {
		columns = len(rows[0])
	}
	if columns == 0 {
		return nil
	}
	available := width - columns - 1
	widths := make([]int, columns)
	for col := range widths {
		widths[col] = available / columns
	}
	widths[columns-1] += available % columns
	if columns == 2 {
		widths[0] = min(22, available/3)
		widths[1] = available - widths[0]
	}
	t := table.New().Width(width).Wrap(true).
		Border(lipgloss.RoundedBorder()).BorderRow(true).
		BorderStyle(r.NewStyle().Foreground(lipgloss.Color("60"))).
		StyleFunc(func(row, col int) lipgloss.Style {
			style := r.NewStyle().Padding(0, padding).Width(widths[col])
			if row == table.HeaderRow {
				return style.Bold(true).Foreground(lipgloss.Color("205"))
			}
			if col == 0 {
				return style.Foreground(lipgloss.Color("141"))
			}
			return style
		})
	if len(headers) > 0 {
		wrappedHeaders := make([]string, columns)
		for col, header := range headers {
			wrappedHeaders[col] = ansi.Wrap(safe(header), max(1, widths[col]-2*padding), "")
		}
		t.Headers(wrappedHeaders...)
	}
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, value := range row {
			lines := strings.Split(value, "\n")
			for j, line := range lines {
				lines[j] = safe(line)
			}
			cells[i] = strings.Join(lines, "\n")
		}
		t.Row(cells...)
	}
	_, err := io.WriteString(out, t.String()+"\n")
	return err
}
