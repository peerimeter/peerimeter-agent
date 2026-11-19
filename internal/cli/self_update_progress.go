package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"golang.org/x/term"
)

type selfUpdateProgress struct {
	out         io.Writer
	tty         bool
	mu          sync.Mutex
	program     *tea.Program
	stopped     chan struct{}
	finished    bool
	finishErr   error
	color       bool
	message     string
	spinnerOnly bool
}

type selfUpdateProgressOutcome uint8

const (
	selfUpdateProgressNeutral selfUpdateProgressOutcome = iota
	selfUpdateProgressUpToDate
	selfUpdateProgressUpdateAvailable
	selfUpdateProgressUpdateSucceeded
)

type selfUpdateProgressStart struct{ message string }
type selfUpdateProgressFinish struct{ err error }
type selfUpdateProgressTick struct{ generation uint64 }
type selfUpdateProgressClose struct{}

type selfUpdateProgressModel struct {
	bar         progress.Model
	spinner     spinner.Model
	message     string
	active      bool
	spinnerOnly bool
	color       bool
	err         error
	percent     float64
	generation  uint64
}

func newSelfUpdateProgress(out io.Writer, colorMode ...string) *selfUpdateProgress {
	mode := "auto"
	if len(colorMode) > 0 {
		mode = colorMode[0]
	}
	p := &selfUpdateProgress{out: out, color: shouldColor(out, mode)}
	if file, ok := out.(*os.File); ok && os.Getenv("TERM") != "dumb" {
		p.tty = term.IsTerminal(int(file.Fd()))
	}
	return p
}

func (p *selfUpdateProgress) start(message string) func(error) {
	if p == nil || p.out == nil {
		return func(error) {}
	}
	if !p.tty {
		_, _ = fmt.Fprintf(p.out, "→ %s\n", message)
		return func(err error) {
			line := "✓ " + message
			if err != nil {
				line = selfUpdateRed("✗ "+message, p.color)
			} else {
				line = selfUpdateGreen(line, p.color)
			}
			_, _ = fmt.Fprintln(p.out, line)
		}
	}

	p.mu.Lock()
	p.finished = false
	p.finishErr = nil
	p.message = message
	p.spinnerOnly = message == "Checking the latest stable release"
	p.mu.Unlock()
	program := p.getProgram()
	program.Send(selfUpdateProgressStart{message: message})
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			p.mu.Lock()
			p.finished = true
			p.finishErr = err
			p.mu.Unlock()
			program.Send(selfUpdateProgressFinish{err: err})
		})
	}
}

func (p *selfUpdateProgress) getProgram() *tea.Program {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.program == nil {
		model := selfUpdateProgressModel{bar: newSelfUpdateProgressBar(p.color), spinner: spinner.New(spinner.WithSpinner(spinner.Line)), color: p.color}
		program := tea.NewProgram(model, tea.WithInput(nil), tea.WithOutput(p.out))
		stopped := make(chan struct{})
		p.program = program
		p.stopped = stopped
		go func() {
			_, _ = program.Run()
			close(stopped)
		}()
	}
	return p.program
}

func newSelfUpdateProgressBar(color bool) progress.Model {
	options := []progress.Option{
		progress.WithWidth(32),
		progress.WithoutPercentage(),
	}
	if color {
		options = append(options, progress.WithDefaultBlend())
	}
	bar := progress.New(options...)
	if !color {
		bar.FullColor = lipgloss.NoColor{}
		bar.EmptyColor = lipgloss.NoColor{}
	}
	return bar
}

func (p *selfUpdateProgress) stop(outcome ...selfUpdateProgressOutcome) {
	if p == nil || !p.tty {
		return
	}
	result := selfUpdateProgressNeutral
	if len(outcome) > 0 {
		result = outcome[0]
	}
	p.mu.Lock()
	program, stopped := p.program, p.stopped
	finished, finishErr := p.finished, p.finishErr
	message, spinnerOnly := p.message, p.spinnerOnly
	p.mu.Unlock()
	if program == nil {
		return
	}
	program.Send(selfUpdateProgressClose{})
	<-stopped
	if finished && finishErr != nil {
		_, _ = fmt.Fprintf(p.out, "%s\n\n", selfUpdateRed("✗ "+message, p.color))
	} else if finished && spinnerOnly {
		_, _ = fmt.Fprintf(p.out, "%s\n\n", selfUpdateGreen("✓ "+message, p.color))
	} else if finished && finishErr == nil && result != selfUpdateProgressNeutral && result != selfUpdateProgressUpdateAvailable {
		_, _ = fmt.Fprintln(p.out, completedSelfUpdateProgressBar(result, p.color))
		_, _ = fmt.Fprintln(p.out)
	} else {
		_, _ = fmt.Fprintln(p.out)
	}
	p.mu.Lock()
	if p.program == program {
		p.program = nil
		p.stopped = nil
		p.finished = false
		p.finishErr = nil
		p.message = ""
		p.spinnerOnly = false
	}
	p.mu.Unlock()
}

func completedSelfUpdateProgressBar(outcome selfUpdateProgressOutcome, color bool) string {
	if !color {
		return strings.Repeat(string(progress.DefaultFullCharFullBlock), 32)
	}
	options := []progress.Option{
		progress.WithWidth(32),
		progress.WithoutPercentage(),
		progress.WithFillCharacters(progress.DefaultFullCharFullBlock, progress.DefaultEmptyCharBlock),
	}
	switch outcome {
	case selfUpdateProgressUpToDate:
		options = append(options, progress.WithColors(lipgloss.Color("#22C55E")))
	case selfUpdateProgressUpdateSucceeded:
		options = append(options, progress.WithColors(lipgloss.Color("#22C55E")))
	case selfUpdateProgressUpdateAvailable:
		options = append(options, progress.WithColors(lipgloss.Color("#F59E0B")))
	}
	bar := progress.New(options...)
	return bar.ViewAs(1)
}

func selfUpdateGreen(text string, color bool) string {
	if !color {
		return text
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#22C55E")).Render(text)
}

func selfUpdateYellow(text string, color bool) string {
	if !color {
		return text
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#EAB308")).Render(text)
}

func selfUpdateRed(text string, color bool) string {
	if !color {
		return text
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Render(text)
}

func (m selfUpdateProgressModel) Init() tea.Cmd { return nil }

func (m selfUpdateProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case selfUpdateProgressStart:
		m.message, m.active, m.err = msg.message, true, nil
		m.generation++
		m.spinnerOnly = msg.message == "Checking the latest stable release"
		if m.spinnerOnly {
			return m, m.spinner.Tick
		}
		return m, tea.Batch(m.spinner.Tick, m.bar.SetPercent(m.percent), selfUpdateProgressTickCmd(m.generation))
	case selfUpdateProgressFinish:
		m.active, m.err = false, msg.err
		m.generation++
		return m, nil
	case selfUpdateProgressTick:
		if m.active && !m.spinnerOnly && msg.generation == m.generation {
			if m.percent >= 0.9 {
				return m, nil
			}
			m.percent += 0.06
			if m.percent > 0.9 {
				m.percent = 0.9
			}
			return m, tea.Batch(m.bar.SetPercent(m.percent), selfUpdateProgressTickCmd(m.generation))
		}
	case spinner.TickMsg:
		if m.active {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	case progress.FrameMsg:
		var cmd tea.Cmd
		m.bar, cmd = m.bar.Update(msg)
		return m, cmd
	case selfUpdateProgressClose:
		return m, tea.Quit
	}
	return m, nil
}

func (m selfUpdateProgressModel) View() tea.View {
	status := "✓ " + m.message
	if m.active {
		status = m.spinner.View() + " " + m.message
	} else if m.err != nil {
		status = selfUpdateRed("✗ "+m.message, m.color)
	} else {
		status = selfUpdateGreen(status, m.color)
	}
	if m.spinnerOnly {
		v := tea.NewView(status)
		v.DisableBracketedPasteMode = true
		return v
	}
	bar := m.bar.View()
	if !m.active && m.err == nil && m.percent == 1 {
		bar = m.bar.ViewAs(1)
	}
	v := tea.NewView(fmt.Sprintf("%s\n%s", status, bar))
	v.DisableBracketedPasteMode = true
	return v
}

func selfUpdateProgressTickCmd(generation uint64) tea.Cmd {
	return tea.Tick(140*time.Millisecond, func(time.Time) tea.Msg { return selfUpdateProgressTick{generation: generation} })
}

func runSelfUpdateStep[T any](progress *selfUpdateProgress, message string, action func() (T, error)) (T, error) {
	finish := progress.start(message)
	result, err := action()
	finish(err)
	return result, err
}

func runSelfUpdateAction(progress *selfUpdateProgress, message string, action func() error) error {
	finish := progress.start(message)
	err := action()
	finish(err)
	return err
}
