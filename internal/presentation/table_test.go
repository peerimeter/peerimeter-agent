package presentation

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestTableUsesContentWidthWhenItFits(t *testing.T) {
	var out strings.Builder
	if err := Table(&out, []string{"State", "Value"}, [][]string{{"valid", "ok"}}, false, 80); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if width := ansi.StringWidth(line); width >= 40 {
			t.Fatalf("table line uses unnecessary width %d: %q", width, line)
		}
	}
}
