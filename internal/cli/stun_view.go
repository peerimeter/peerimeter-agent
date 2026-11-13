package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/peerimeter/peerimeter-agent/internal/stunprobe"
	"golang.org/x/term"
)

var probeSTUN = stunprobe.Probe

type stunResultMsg struct {
	result stunprobe.Result
	err    error
}
type stunTickMsg struct{}
type stunModel struct {
	port   int
	server string
	frame  int
	done   bool
	result stunprobe.Result
	err    error
}

func (m stunModel) Init() tea.Cmd {
	return tea.Batch(func() tea.Msg { r, err := probeSTUN(m.port, m.server); return stunResultMsg{r, err} }, stunTick)
}
func stunTick() tea.Msg { time.Sleep(100 * time.Millisecond); return stunTickMsg{} }
func (m stunModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case stunResultMsg:
		m.done, m.result, m.err = true, msg.result, msg.err
		return m, tea.Quit
	case stunTickMsg:
		m.frame++
		return m, stunTick
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" || msg.String() == "esc" {
			m.done, m.err = true, context.Canceled
			return m, tea.Quit
		}
	}
	return m, nil
}
func (m stunModel) View() string {
	if m.done {
		return ""
	}
	return fmt.Sprintf("%c Probing public UDP mapping with STUN... (q to cancel)\n", "|/-\\"[m.frame%4])
}
func runSTUN(ctx context.Context, out io.Writer, port int, server string) (stunprobe.Result, error) {
	file, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) || os.Getenv("TERM") == "dumb" {
		return probeSTUN(port, server)
	}
	model, err := tea.NewProgram(stunModel{port: port, server: server}, tea.WithContext(ctx), tea.WithInput(os.Stdin), tea.WithOutput(out)).Run()
	if err != nil {
		return stunprobe.Result{}, err
	}
	m := model.(stunModel)
	return m.result, m.err
}
