package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/peerimeter/peerimeter-agent/internal/local"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/presentation"
	"github.com/spf13/cobra"
)

func watchStatusJSON(ctx context.Context, runtimeDir string, interval time.Duration, out io.Writer) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := local.Request(ctx, runtimeDir, "status", out); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type statusWatchResult struct {
	snapshot platform.Snapshot
	err      error
	updated  time.Time
}

type statusWatchTick struct{}

type statusWatchModel struct {
	ctx      context.Context
	runtime  string
	interval time.Duration
	width    int
	height   int
	scroll   int
	color    bool
	snapshot platform.Snapshot
	err      error
	updated  time.Time
}

func (m statusWatchModel) Init() tea.Cmd {
	return m.fetchStatus
}

func (m statusWatchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusWatchResult:
		m.snapshot, m.err, m.updated = msg.snapshot, msg.err, msg.updated
		m.clampScroll()
		return m, tea.Tick(m.interval, func(time.Time) tea.Msg { return statusWatchTick{} })
	case statusWatchTick:
		return m, m.fetchStatus
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.clampScroll()
	case tea.KeyMsg:
		if msg.String() == "q" || msg.Type == tea.KeyEsc || msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
		page := max(1, m.viewportHeight()-1)
		switch msg.Type {
		case tea.KeyUp:
			m.scroll--
		case tea.KeyDown:
			m.scroll++
		case tea.KeyPgUp:
			m.scroll -= page
		case tea.KeyPgDown:
			m.scroll += page
		case tea.KeyHome:
			m.scroll = 0
		case tea.KeyEnd:
			m.scroll = m.maxScroll()
		case tea.KeyRunes:
			switch string(msg.Runes) {
			case "k":
				m.scroll--
			case "j":
				m.scroll++
			case "u":
				m.scroll -= page
			case "d":
				m.scroll += page
			case "g":
				m.scroll = 0
			case "G":
				m.scroll = m.maxScroll()
			}
		}
		m.clampScroll()
	}
	return m, nil
}

func (m statusWatchModel) View() string {
	lines := m.contentLines()
	m.clampScroll()
	start := m.scroll
	end := min(len(lines), start+m.viewportHeight())
	var view strings.Builder
	view.WriteString(strings.Join(lines[start:end], "\n"))
	view.WriteString("\n\n")
	if m.width >= 70 {
		fmt.Fprintf(&view, "Updated %s · refresh %s · ↑/↓ or pgup/pgdn to scroll · q to quit\n", m.updated.Format("15:04:05"), m.interval)
	} else {
		fmt.Fprintf(&view, "Updated %s · j/k scroll · q quit\n", m.updated.Format("15:04:05"))
	}
	return view.String()
}

func (m statusWatchModel) contentLines() []string {
	var content strings.Builder
	if m.err != nil {
		fmt.Fprintf(&content, "Status unavailable: %s\nRetrying every %s.\n", presentation.Safe(m.err.Error()), m.interval)
	} else if m.updated.IsZero() {
		content.WriteString("Loading status…\n")
	} else {
		_ = presentation.StatusOverview(&content, m.snapshot, m.updated, m.color, m.width)
	}
	lines := strings.Split(strings.TrimRight(content.String(), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func (m statusWatchModel) viewportHeight() int {
	return max(1, m.height-3)
}

func (m statusWatchModel) maxScroll() int {
	return max(0, len(m.contentLines())-m.viewportHeight())
}

func (m *statusWatchModel) clampScroll() {
	m.scroll = max(0, min(m.scroll, m.maxScroll()))
}

func (m statusWatchModel) fetchStatus() tea.Msg {
	var raw bytes.Buffer
	err := local.Request(m.ctx, m.runtime, "status", &raw)
	if err != nil {
		return statusWatchResult{err: err, updated: time.Now()}
	}
	var snapshot platform.Snapshot
	if err := json.Unmarshal(raw.Bytes(), &snapshot); err != nil {
		return statusWatchResult{err: fmt.Errorf("cannot decode local status: %w", err), updated: time.Now()}
	}
	return statusWatchResult{snapshot: snapshot, updated: time.Now()}
}

func watchStatusTerminal(cmd *cobra.Command, runtimeDir string, interval time.Duration, app *application) error {
	model := statusWatchModel{
		ctx:      cmd.Context(),
		runtime:  runtimeDir,
		interval: interval,
		width:    outputWidth(app.out),
		color:    shouldColor(app.out, app.color),
	}
	program := tea.NewProgram(model,
		tea.WithContext(cmd.Context()),
		tea.WithInput(cmd.InOrStdin()),
		tea.WithOutput(app.out),
		tea.WithAltScreen(),
	)
	_, err := program.Run()
	if errors.Is(err, tea.ErrProgramKilled) && cmd.Context().Err() != nil {
		return nil
	}
	return err
}
