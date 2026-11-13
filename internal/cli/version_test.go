package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestVersionLogoAndMachineOutput(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	code, out, err := invoke(t, "version")
	if code != 0 || err != "" || !strings.Contains(out, versionLogo) || !strings.Contains(out, Version) || strings.Contains(out, "\x1b[") {
		t.Fatalf("invalid plain logo: %d %q %s", code, out, err)
	}
	code, out, err = invoke(t, "version", "--color", "always")
	if code != 0 || err != "" || !strings.Contains(out, "\x1b[38;5;") {
		t.Fatal("forced ANSI logo missing")
	}
	for _, color := range []int{198, 199, 165, 129, 93, 63} {
		if !strings.Contains(out, fmt.Sprintf("\x1b[38;5;%dm", color)) {
			t.Fatalf("missing original logo color %d", color)
		}
	}
	if strings.Contains(out, "Field") || strings.Contains(out, "Value") || !strings.Contains(out, "Agent") || !strings.Contains(out, "Platform") || !strings.Contains(out, "Go") {
		t.Fatal("version details should use the shared table without generic headers below the logo")
	}
	code, out, err = invoke(t, "version", "--json", "--color", "always")
	var data map[string]string
	if code != 0 || err != "" || strings.Contains(out, "\x1b[") || json.Unmarshal([]byte(out), &data) != nil || data["version"] != Version || data["go_version"] == "" {
		t.Fatalf("invalid version JSON: %d %q %s", code, out, err)
	}
	code, _, err = invoke(t, "version", "--color", "SECRET-BAD-VALUE")
	if code == 0 || strings.Contains(err, "SECRET") {
		t.Fatal("color parse failure leaked input")
	}
}
