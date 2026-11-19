// Package selfupdate downloads and verifies release program files.
package selfupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const latestURL = "https://api.github.com/repos/peerimeter/peerimeter-agent/releases/latest"
const maxAssetSize = 128 << 20

var latestReleaseEndpoint = latestURL
var releaseDownloadBase = "https://github.com/peerimeter/peerimeter-agent/releases/download/"

type release struct {
	TagName string `json:"tag_name"`
}

// Fetch obtains the platform package and verifies the package's exact SHA-256
// entry from the release's SHA256SUMS file. The manifest and package share the
// HTTPS GitHub release trust channel; no detached signature is implied.
func Fetch(ctx context.Context, client *http.Client, goos, goarch string) (string, map[string][]byte, error) {
	return fetchAt(ctx, client, goos, goarch, latestReleaseEndpoint, releaseDownloadBase)
}

func fetchAt(ctx context.Context, client *http.Client, goos, goarch, latestEndpoint, releaseBase string) (string, map[string][]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	baseURL, err := url.Parse(releaseBase)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return "", nil, errors.New("release base URL must be an HTTPS origin or path")
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var latest release
	if err := getJSON(ctx, client, latestEndpoint, &latest); err != nil {
		return "", nil, err
	}
	if !releaseTag.MatchString(latest.TagName) {
		return "", nil, errors.New("latest release has an invalid version tag")
	}
	arch := ""
	switch goarch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	default:
		return "", nil, fmt.Errorf("self-update does not support %s/%s", goos, goarch)
	}
	asset := "peerimeter-agent-" + goos + "-" + arch
	base := *baseURL
	base.Path += latest.TagName + "/"
	manifest, err := getBytes(ctx, client, base.ResolveReference(&url.URL{Path: "SHA256SUMS"}).String(), 2<<20)
	if err != nil {
		return "", nil, fmt.Errorf("download release checksums: %w", err)
	}
	sums, err := parseSums(manifest)
	if err != nil {
		return "", nil, err
	}
	archiveName := asset + assetExtension(goos)
	archive, err := getBytes(ctx, client, base.ResolveReference(&url.URL{Path: archiveName}).String(), maxAssetSize)
	if err != nil {
		return "", nil, fmt.Errorf("download release package: %w", err)
	}
	if err := verifySum(sums, archiveName, archive); err != nil {
		return "", nil, err
	}
	files, err := unpack(goos, archive)
	if err != nil {
		return "", nil, err
	}
	if goos == "windows" {
		files["pma.exe"] = append([]byte(nil), files["peerimeter-agent.exe"]...)
	} else {
		files["pma"] = append([]byte(nil), files["peerimeter-agent"]...)
	}
	if goos != "windows" {
		noticesName := asset + ".NOTICES.txt"
		notices, err := getBytes(ctx, client, base.ResolveReference(&url.URL{Path: noticesName}).String(), 8<<20)
		if err != nil {
			return "", nil, fmt.Errorf("download release notices: %w", err)
		}
		if err := verifySum(sums, noticesName, notices); err != nil {
			return "", nil, err
		}
		files["peerimeter-agent.NOTICES.txt"] = notices
	}
	return latest.TagName, files, nil
}

var releaseTag = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)

func assetExtension(goos string) string {
	if goos == "windows" {
		return ".zip"
	}
	return ""
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	data, err := getBytes(ctx, client, url, 2<<20)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode release response: %w", err)
	}
	return nil
}

func getBytes(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, errors.New("release downloads require HTTPS")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "peerimeter-agent-self-update")
	if client == nil {
		client = http.DefaultClient
	}
	secureClient := *client
	previousRedirectCheck := client.CheckRedirect
	secureClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if next.URL.Scheme != "https" {
			return errors.New("release redirects require HTTPS")
		}
		if previousRedirectCheck != nil {
			return previousRedirectCheck(next, via)
		}
		if len(via) >= 10 {
			return errors.New("release download stopped after 10 redirects")
		}
		return nil
	}
	resp, err := secureClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request == nil || resp.Request.URL.Scheme != "https" {
		return nil, errors.New("release download did not use HTTPS")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release download returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("release asset exceeds the allowed size")
	}
	return data, nil
}

func parseSums(data []byte) (map[string]string, error) {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return nil, errors.New("release SHA256SUMS contains an invalid entry")
		}
		name := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
			return nil, errors.New("release SHA256SUMS contains an unsafe filename")
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return nil, errors.New("release SHA256SUMS contains an invalid SHA-256 digest")
		}
		if _, exists := result[name]; exists {
			return nil, errors.New("release SHA256SUMS contains a duplicate filename")
		}
		result[name] = strings.ToLower(fields[0])
	}
	if len(result) == 0 {
		return nil, errors.New("release SHA256SUMS is empty")
	}
	return result, nil
}

func verifySum(sums map[string]string, name string, data []byte) error {
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("release SHA256SUMS has no entry for %s", name)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("release checksum verification failed for %s", name)
	}
	return nil
}

func unpack(goos string, archive []byte) (map[string][]byte, error) {
	if goos != "windows" {
		if len(archive) == 0 {
			return nil, errors.New("release binary is empty")
		}
		return map[string][]byte{"peerimeter-agent": archive}, nil
	}
	r, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("open Windows release package: %w", err)
	}
	wanted := map[string]bool{"peerimeter-agent.exe": true, "peerimeter-agent.NOTICES.txt": true, "wireguard.dll": true}
	files := make(map[string][]byte, len(wanted))
	for _, member := range r.File {
		if !wanted[member.Name] || !member.Mode().IsRegular() {
			return nil, errors.New("Windows release package contains an unexpected member")
		}
		if _, exists := files[member.Name]; exists {
			return nil, errors.New("Windows release package contains duplicate members")
		}
		if member.UncompressedSize64 > maxAssetSize {
			return nil, errors.New("Windows package member exceeds the allowed size")
		}
		f, err := member.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxAssetSize+1))
		closeErr := f.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(data)) > maxAssetSize {
			return nil, errors.New("Windows package member exceeds the allowed size")
		}
		files[member.Name] = data
	}
	if len(files) != len(wanted) {
		return nil, errors.New("Windows release package is incomplete")
	}
	return files, nil
}
