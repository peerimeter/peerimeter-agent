package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type updateTestRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip updateTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return roundTrip(req)
}

func TestCheckUpdateJSON(t *testing.T) {
	for _, test := range []struct {
		name       string
		tag        string
		wantUpdate bool
	}{
		{name: "current", tag: Version},
		{name: "newer stable release", tag: "v1.3.0", wantUpdate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tag_name":"` + test.tag + `","html_url":"https://example.test/release"}`))
			}))
			defer server.Close()

			var out strings.Builder
			if err := checkForUpgradeAt(context.Background(), &out, "never", true, true, server.URL, server.Client()); err != nil {
				t.Fatal(err)
			}
			var result updateCheckResult
			if err := json.Unmarshal([]byte(out.String()), &result); err != nil {
				t.Fatalf("invalid JSON result %q: %v", out.String(), err)
			}
			if result.CurrentVersion != Version || result.LatestVersion != test.tag || result.UpdateAvailable != test.wantUpdate {
				t.Fatalf("unexpected update result: %+v", result)
			}
			if test.wantUpdate && (result.ReleaseURL != "https://example.test/release" || result.InstallCommand == "") {
				t.Fatalf("update result omitted release/install details: %+v", result)
			}
			if !test.wantUpdate && (result.ReleaseURL != "" || result.InstallCommand != "") {
				t.Fatalf("current result unexpectedly contains update details: %+v", result)
			}
		})
	}
}

func TestCheckUpdateConsoleBoxIncludesInstallCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.3.0"}`))
	}))
	defer server.Close()

	var out strings.Builder
	if err := checkForUpgradeAt(context.Background(), &out, "never", true, false, server.URL, server.Client()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Update available") || !strings.Contains(out.String(), installCommand()) {
		t.Fatalf("update alert omitted upgrade/install instructions: %s", out.String())
	}
}
