package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"golang.org/x/term"
)

type confirmModel struct {
	prompt string
	accept bool
	done   bool
	color  bool
}

func (m confirmModel) Init() tea.Cmd { return nil }

func (m confirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "y", "Y":
		m.accept, m.done = true, true
		return m, tea.Quit
	case "n", "N", "q", "esc", "ctrl+c":
		m.accept, m.done = false, true
		return m, tea.Quit
	case "left", "h", "right", "l", "tab", "shift+tab":
		m.accept = !m.accept
	case "enter":
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func (m confirmModel) View() tea.View {
	selected, unselected := lipgloss.NewStyle().Padding(0, 2), lipgloss.NewStyle().Padding(0, 2)
	if m.color {
		selected = selected.Foreground(lipgloss.Color("#ffffff")).Background(lipgloss.Color("#875fff"))
		unselected = unselected.Foreground(lipgloss.Color("#b2b2b2")).Background(lipgloss.Color("#3a3a3a"))
	} else {
		selected = selected.Reverse(true)
	}
	yes, no := unselected.Render("Yes"), selected.Render("No")
	if m.accept {
		yes, no = selected.Render("Yes"), unselected.Render("No")
	}
	promptStyle := lipgloss.NewStyle().Bold(true)
	if m.color {
		promptStyle = promptStyle.Foreground(lipgloss.Color("#a78bfa"))
	}
	prompt := promptStyle.Render(m.prompt)
	return tea.NewView(prompt + "\n" + lipgloss.JoinHorizontal(lipgloss.Left, yes, no) + "\n\n←/→ select · enter confirm · y/n choose · esc cancel")
}

func confirmInteractive(in io.Reader, out io.Writer, prompt string, colorMode ...string) (bool, error) {
	inputFile, inputIsFile := in.(*os.File)
	outputFile, outputIsFile := out.(*os.File)
	if inputIsFile && outputIsFile && term.IsTerminal(int(inputFile.Fd())) && term.IsTerminal(int(outputFile.Fd())) {
		mode := "auto"
		if len(colorMode) > 0 {
			mode = colorMode[0]
		}
		result, err := tea.NewProgram(confirmModel{prompt: prompt, accept: true, color: shouldColor(out, mode)}, tea.WithInput(in), tea.WithOutput(out)).Run()
		if err != nil {
			return false, fmt.Errorf("show confirmation: %w", err)
		}
		confirmed, ok := result.(confirmModel)
		if !ok || !confirmed.done {
			return false, errors.New("confirmation was interrupted")
		}
		return confirmed.accept, nil
	}
	if _, err := fmt.Fprintf(out, "%s [y/N] ", prompt); err != nil {
		return false, fmt.Errorf("display confirmation: %w", err)
	}
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer = strings.TrimSpace(answer)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}
