package cli

import (
	"fmt"
	"io"
	"os"
	"sync"

	"charm.land/bubbles/v2/spinner"
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
type selfUpdateProgressClose struct{}

type selfUpdateProgressModel struct {
	spinner spinner.Model
	message string
	active  bool
	err     error
}

func newSelfUpdateProgress(out io.Writer, _ ...string) *selfUpdateProgress {
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
		model := selfUpdateProgressModel{spinner: spinner.New(spinner.WithSpinner(spinner.Dot))}
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
		m.message, m.active, m.err = msg.message, true, nil
		return m, m.spinner.Tick
	case selfUpdateProgressFinish:
		m.active, m.err = false, msg.err
		return m, nil
	case spinner.TickMsg:
		if m.active {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	case selfUpdateProgressClose:
		return m, tea.Quit
	}
	return m, nil
}

func (m selfUpdateProgressModel) View() tea.View {
	icon := "✓"
	if m.active {
		icon = m.spinner.View()
	} else if m.err != nil {
		icon = "✗"
	}
	v := tea.NewView(fmt.Sprintf("%s %s", icon, m.message))
	v.DisableBracketedPasteMode = true
	return v
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
