package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

type selfUpdateProgress struct {
	out io.Writer
	tty bool
	mu  sync.Mutex
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

	frames := [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan struct{})
	stopped := make(chan struct{})
	var index int
	write := func(frame string) {
		p.mu.Lock()
		defer p.mu.Unlock()
		_, _ = fmt.Fprintf(p.out, "\r%s %s", frame, message)
	}
	write(frames[0])
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				index = (index + 1) % len(frames)
				write(frames[index])
			}
		}
	}()
	return func(err error) {
		close(done)
		<-stopped
		icon := "✓"
		if err != nil {
			icon = "✗"
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		_, _ = fmt.Fprintf(p.out, "\r%s %s\n", icon, message)
	}
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
