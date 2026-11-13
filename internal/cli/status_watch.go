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
		return m, tea.Tick(m.interval, func(time.Time) tea.Msg { return statusWatchTick{} })
	case statusWatchTick:
		return m, m.fetchStatus
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		if msg.String() == "q" || msg.Type == tea.KeyEsc || msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m statusWatchModel) View() string {
	var view strings.Builder
	if m.err != nil {
		fmt.Fprintf(&view, "Status unavailable: %s\nRetrying every %s.\n", presentation.Safe(m.err.Error()), m.interval)
	} else if m.updated.IsZero() {
		view.WriteString("Loading status…\n")
	} else {
		_ = presentation.StatusOverview(&view, m.snapshot, m.updated, m.color, m.width)
	}
	fmt.Fprintf(&view, "\nUpdated %s · refresh every %s · q to quit\n", m.updated.Format("15:04:05"), m.interval)
	return view.String()
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
