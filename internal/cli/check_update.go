package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

const latestReleaseURL = "https://api.github.com/repos/peerimeter/peerimeter-agent/releases/latest"

type latestRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

func newUpdateCommand(app *application) *cobra.Command {
	return &cobra.Command{
		Use:   "check-update",
		Short: "Check whether a newer agent version is available",
		Args:  noArguments,
		RunE: app.handle(func(cmd *cobra.Command) error {
			if app.color != "auto" && app.color != "always" && app.color != "never" {
				return errors.New("color must be auto, always or never")
			}
			return checkForUpgrade(cmd.Context(), app.out, app.color, true, app.jsonOutput)
		}),
	}
}

func checkForUpgrade(parent context.Context, out io.Writer, color string, reportCurrent, jsonOutput bool) error {
	return checkForUpgradeAt(parent, out, color, reportCurrent, jsonOutput, latestReleaseURL, http.DefaultClient)
}

func checkForUpgradeAt(parent context.Context, out io.Writer, color string, reportCurrent, jsonOutput bool, endpoint string, client *http.Client) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "peerimeter-agent-update-check")
	resp, err := client.Do(req)
	if err != nil {
		if reportCurrent {
			return fmt.Errorf("check for updates: %w", err)
		}
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if reportCurrent {
			return fmt.Errorf("check for updates: GitHub returned %s", resp.Status)
		}
		return nil
	}
	var release latestRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		if reportCurrent {
			return fmt.Errorf("decode latest release: %w", err)
		}
		return nil
	}
	latest, ok := parseReleaseVersion(release.TagName)
	current, currentOK := parseReleaseVersion(Version)
	if !ok || !currentOK {
		if reportCurrent {
			return fmt.Errorf("cannot compare agent version %q with latest release %q", Version, release.TagName)
		}
		return nil
	}
	if compareVersion(latest, current) <= 0 {
		if reportCurrent {
			if jsonOutput {
				return json.NewEncoder(out).Encode(updateCheckResult{CurrentVersion: Version, LatestVersion: release.TagName})
			}
			_, err := fmt.Fprintf(out, "Peerimeter Agent is up to date (%s).\n", Version)
			return err
		}
		return nil
	}
	if release.HTMLURL == "" {
		release.HTMLURL = "https://github.com/peerimeter/peerimeter-agent/releases/latest"
	}
	if jsonOutput {
		return json.NewEncoder(out).Encode(updateCheckResult{
			CurrentVersion:  Version,
			LatestVersion:   release.TagName,
			UpdateAvailable: true,
			ReleaseURL:      release.HTMLURL,
			UpdateCommand:   "peerimeter-agent update",
		})
	}
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	if shouldColor(out, color) {
		box = box.BorderForeground(lipgloss.Color("198"))
	}
	message := fmt.Sprintf("Update available: %s → %s\nRelease: %s\n\nUpdate with:\npeerimeter-agent update", Version, release.TagName, release.HTMLURL)
	_, err = fmt.Fprintln(out, box.Render(message))
	return err
}

type updateCheckResult struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url,omitempty"`
	UpdateCommand   string `json:"update_command,omitempty"`
}

type releaseVersion struct {
	major, minor, patch int
	pre                 string
}

var releaseVersionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

func parseReleaseVersion(raw string) (releaseVersion, bool) {
	match := releaseVersionPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return releaseVersion{}, false
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return releaseVersion{}, false
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return releaseVersion{}, false
	}
	patch, err := strconv.Atoi(match[3])
	if err != nil {
		return releaseVersion{}, false
	}
	return releaseVersion{major: major, minor: minor, patch: patch, pre: match[4]}, true
}

func compareVersion(a, b releaseVersion) int {
	if a.major != b.major {
		return compareInt(a.major, b.major)
	}
	if a.minor != b.minor {
		return compareInt(a.minor, b.minor)
	}
	if a.patch != b.patch {
		return compareInt(a.patch, b.patch)
	}
	if a.pre == b.pre {
		return 0
	}
	if a.pre == "" {
		return 1
	}
	if b.pre == "" {
		return -1
	}
	return strings.Compare(a.pre, b.pre)
}

func compareInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
