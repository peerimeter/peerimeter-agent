package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"charm.land/bubbles/v2/progress"
	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"
)

type selfUpdateProgress struct {
	out     io.Writer
	tty     bool
	mu      sync.Mutex
	program *tea.Program
	stopped chan struct{}
}

type selfUpdateProgressStart struct{ message string }
type selfUpdateProgressFinish struct{ err error }
type selfUpdateProgressTick struct{ generation uint64 }
type selfUpdateProgressClose struct{}

type selfUpdateProgressModel struct {
	bar        progress.Model
	message    string
	active     bool
	err        error
	percent    float64
	generation uint64
}

func newSelfUpdateProgress(out io.Writer) *selfUpdateProgress {
	p := &selfUpdateProgress{out: out}
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
			icon := "✓"
			if err != nil {
				icon = "✗"
			}
			_, _ = fmt.Fprintf(p.out, "%s %s\n", icon, message)
		}
	}

	program := p.getProgram()
	program.Send(selfUpdateProgressStart{message: message})
	var once sync.Once
	return func(err error) {
		once.Do(func() { program.Send(selfUpdateProgressFinish{err: err}) })
	}
}

func (p *selfUpdateProgress) getProgram() *tea.Program {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.program == nil {
		model := selfUpdateProgressModel{bar: progress.New(
			progress.WithWidth(32),
			progress.WithoutPercentage(),
			progress.WithDefaultBlend(),
		)}
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

func (p *selfUpdateProgress) stop() {
	if p == nil || !p.tty {
		return
	}
	p.mu.Lock()
	program, stopped := p.program, p.stopped
	p.mu.Unlock()
	if program == nil {
		return
	}
	program.Send(selfUpdateProgressClose{})
	<-stopped
	_, _ = fmt.Fprintln(p.out)
	p.mu.Lock()
	if p.program == program {
		p.program = nil
		p.stopped = nil
	}
	p.mu.Unlock()
}

func (m selfUpdateProgressModel) Init() tea.Cmd { return nil }

func (m selfUpdateProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case selfUpdateProgressStart:
		m.message, m.active, m.err, m.percent = msg.message, true, nil, 0
		m.generation++
		return m, tea.Batch(m.bar.SetPercent(0), selfUpdateProgressTickCmd(m.generation))
	case selfUpdateProgressFinish:
		m.active, m.err, m.percent = false, msg.err, 1
		m.generation++
		return m, nil
	case selfUpdateProgressTick:
		if m.active && msg.generation == m.generation {
			if m.percent >= 0.9 {
				return m, nil
			}
			m.percent += 0.06
			if m.percent > 0.9 {
				m.percent = 0.9
			}
			return m, tea.Batch(m.bar.SetPercent(m.percent), selfUpdateProgressTickCmd(m.generation))
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
	icon := "✓"
	if m.active {
		icon = "→"
	} else if m.err != nil {
		icon = "✗"
	}
	bar := m.bar.View()
	if !m.active && m.err == nil && m.percent == 1 {
		bar = m.bar.ViewAs(1)
	}
	v := tea.NewView(fmt.Sprintf("%s %s\n%s", icon, m.message, bar))
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
