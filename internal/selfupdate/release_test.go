package selfupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

type releaseRoundTripper func(*http.Request) (*http.Response, error)

func (f releaseRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchVerifiesReleasePackageAndSeparateNotices(t *testing.T) {
	binary, notices := []byte("binary"), []byte("notices")
	manifest := sumLine("peerimeter-agent-linux-x86_64", binary) + sumLine("peerimeter-agent-linux-x86_64.NOTICES.txt", notices)
	responses := map[string]string{
		latestURL: `{"tag_name":"v1.2.3"}`,
		"https://github.com/peerimeter/peerimeter-agent/releases/download/v1.2.3/SHA256SUMS":                                manifest,
		"https://github.com/peerimeter/peerimeter-agent/releases/download/v1.2.3/peerimeter-agent-linux-x86_64":             string(binary),
		"https://github.com/peerimeter/peerimeter-agent/releases/download/v1.2.3/peerimeter-agent-linux-x86_64.NOTICES.txt": string(notices),
	}
	client := &http.Client{Transport: releaseRoundTripper(func(req *http.Request) (*http.Response, error) {
		body, ok := responses[req.URL.String()]
		if !ok {
			t.Errorf("unexpected release request %s", req.URL)
			body = ""
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
	tag, files, err := Fetch(context.Background(), client, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v1.2.3" || string(files["peerimeter-agent"]) != "binary" || string(files["peerimeter-agent.NOTICES.txt"]) != "notices" {
		t.Fatalf("unexpected fetched package: %q %#v", tag, files)
	}
}

func sumLine(name string, data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func TestParseSumsRejectsAmbiguousAndUnsafeEntries(t *testing.T) {
	good := bytes.Repeat([]byte{0xab}, sha256.Size)
	valid := hex.EncodeToString(good) + "  peerimeter-agent-linux-x86_64\n"
	if _, err := parseSums([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"", "abcd  agent", hex.EncodeToString(good) + "  ../agent", valid + valid,
		hex.EncodeToString(good) + "  agent extra",
	} {
		if _, err := parseSums([]byte(raw)); err == nil {
			t.Errorf("accepted invalid checksum manifest %q", raw)
		}
	}
}

func TestVerifySumAndWindowsArchiveMembers(t *testing.T) {
	data := []byte("agent payload")
	sum := sha256.Sum256(data)
	if err := verifySum(map[string]string{"asset": hex.EncodeToString(sum[:])}, "asset", data); err != nil {
		t.Fatal(err)
	}
	if err := verifySum(map[string]string{"asset": "bad"}, "asset", data); err == nil {
		t.Fatal("accepted wrong digest")
	}

	var zipped bytes.Buffer
	w := zip.NewWriter(&zipped)
	for name, body := range map[string]string{"peerimeter-agent.exe": "exe", "peerimeter-agent.NOTICES.txt": "notices", "wireguard.dll": "dll"} {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := unpack("windows", zipped.Bytes())
	if err != nil || len(files) != 3 {
		t.Fatalf("unpack: %v, files %v", err, files)
	}
	bad := new(bytes.Buffer)
	bw := zip.NewWriter(bad)
	f, _ := bw.Create("../peerimeter-agent.exe")
	_, _ = f.Write([]byte("bad"))
	_ = bw.Close()
	if _, err := unpack("windows", bad.Bytes()); err == nil {
		t.Fatal("accepted unsafe archive member")
	}
	symlinkArchive := new(bytes.Buffer)
	sw := zip.NewWriter(symlinkArchive)
	for _, item := range []struct {
		name string
		mode os.FileMode
		body string
	}{
		{"peerimeter-agent.exe", os.ModeSymlink | 0777, "target.exe"},
		{"peerimeter-agent.NOTICES.txt", 0, "notices"},
		{"wireguard.dll", 0, "dll"},
	} {
		header := &zip.FileHeader{Name: item.name}
		header.SetMode(item.mode)
		f, err := sw.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(item.body))
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unpack("windows", symlinkArchive.Bytes()); err == nil {
		t.Fatal("accepted a symlink as a regular Windows package file")
	}
}

func TestGetBytesRejectsRedirectToPlainHTTP(t *testing.T) {
	client := &http.Client{Transport: releaseRoundTripper(func(req *http.Request) (*http.Response, error) {
		bad, _ := url.Parse("http://example.test/asset")
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("payload")), Request: &http.Request{URL: bad}}, nil
	})}
	if _, err := getBytes(context.Background(), client, "https://example.test/asset", 100); err == nil {
		t.Fatal("accepted final HTTP response")
	}
}

func TestGetBytesRejectsPlainHTTPAtEveryRedirectHop(t *testing.T) {
	hitHTTP := false
	client := &http.Client{Transport: releaseRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme == "http" {
			hitHTTP = true
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://example.test/final"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
		if req.URL.Path == "/start" {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://example.test/plain"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("payload")), Request: req}, nil
	})}
	if _, err := getBytes(context.Background(), client, "https://example.test/start", 100); err == nil {
		t.Fatal("accepted an HTTPS to HTTP to HTTPS redirect chain")
	}
	if hitHTTP {
		t.Fatal("dispatched an HTTP redirect hop before rejecting the chain")
	}
}
