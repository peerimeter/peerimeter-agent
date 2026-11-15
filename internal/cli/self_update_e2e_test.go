package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
)

func TestSelfUpdateBinaryEndToEnd(t *testing.T) {
	if os.Getenv("PEERIMETER_SELF_UPDATE_E2E") != "1" {
		t.Skip("set PEERIMETER_SELF_UPDATE_E2E=1 to build and update real installed agent binaries")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("unsupported E2E platform %s", runtime.GOOS)
	}
	if runtime.GOOS == "linux" {
		// Some Android/Termux environments expose TMPDIR through a symlinked
		// prefix, while the kernel reports /proc/self/exe through /tmp.
		t.Setenv("TMPDIR", "/tmp")
	}

	root := moduleRoot(t)
	temp := t.TempDir()
	artifactDir := filepath.Join(temp, "build")
	if err := os.MkdirAll(artifactDir, 0700); err != nil {
		t.Fatal(err)
	}
	var serverMu sync.RWMutex
	var releaseFiles map[string][]byte
	corruptSums := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			_, _ = io.WriteString(w, `{"tag_name":"v1.2.0"}`)
			return
		}
		serverMu.RLock()
		defer serverMu.RUnlock()
		if data, ok := releaseFiles[strings.TrimPrefix(r.URL.Path, "/download/v1.2.0/")]; ok {
			if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") && corruptSums {
				_, _ = io.WriteString(w, corruptChecksumManifest(string(data)))
				return
			}
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	caPath := filepath.Join(temp, "release-test-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}

	oldBinary := filepath.Join(artifactDir, "old", executableName())
	newBinary := filepath.Join(artifactDir, "new", executableName())
	mismatchedBinary := filepath.Join(artifactDir, "mismatched", executableName())
	if err := os.MkdirAll(filepath.Dir(oldBinary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(newBinary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(mismatchedBinary), 0700); err != nil {
		t.Fatal(err)
	}
	buildAgentE2E(t, root, oldBinary, "v1.0.0", server.URL)
	buildAgentE2E(t, root, newBinary, "v1.2.0", server.URL)
	buildAgentE2E(t, root, mismatchedBinary, "v1.3.0", server.URL)
	newBytes, err := os.ReadFile(newBinary)
	if err != nil {
		t.Fatal(err)
	}
	notices := []byte("self-update E2E notices")
	assetName := "peerimeter-agent-" + runtime.GOOS + "-" + e2eReleaseArch(runtime.GOARCH)
	assetBytes := newBytes
	releaseFiles = map[string][]byte{}
	if runtime.GOOS == "windows" {
		assetName += ".zip"
		dll := []byte("test WireGuardNT binary held constant during agent update")
		assetBytes = makeWindowsE2EArchive(t, newBytes, notices, dll)
		releaseFiles["peerimeter-agent.NOTICES.txt"] = notices
		releaseFiles["wireguard.dll"] = dll
	} else {
		releaseFiles[assetName+".NOTICES.txt"] = notices
	}
	manifest := e2eSumLine(assetName, assetBytes)
	if runtime.GOOS != "windows" {
		manifest += e2eSumLine(assetName+".NOTICES.txt", notices)
	}
	releaseFiles["SHA256SUMS"] = []byte(manifest)
	releaseFiles[assetName] = assetBytes

	for _, test := range []struct {
		name         string
		corrupt      bool
		wantVersion  string
		wantExitCode bool
	}{
		{name: "updates installed binary and preserves profile data", wantVersion: "v1.2.0"},
		{name: "rejects corrupt checksum without replacing binary", corrupt: true, wantVersion: "v1.0.0", wantExitCode: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			install := prepareE2EInstallation(t, oldBinary, notices, releaseFiles)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			serverMu.Lock()
			corruptSums = test.corrupt
			serverMu.Unlock()
			cmd := exec.CommandContext(ctx, filepath.Join(install.installDir, executableName()), "update")
			cmd.Env = withTestEnv(os.Environ(), "SSL_CERT_FILE", caPath)
			cmd.Env = withTestEnv(cmd.Env, "NO_COLOR", "1")
			output, updateErr := cmd.CombinedOutput()
			if test.wantExitCode {
				if updateErr == nil || !bytes.Contains(output, []byte("checksum verification failed")) {
					t.Fatalf("corrupt release was not rejected: err=%v output=%s", updateErr, output)
				}
			} else if updateErr != nil {
				t.Fatalf("update command failed: %v\n%s", updateErr, output)
			}
			waitForE2EVersion(t, ctx, filepath.Join(install.installDir, executableName()), caPath, test.wantVersion)
			if !test.corrupt {
				for path, want := range map[string]string{
					filepath.Join(install.configDir, "service.key"): "profile key must remain",
					filepath.Join(install.stateDir, "state.json"):   `{"keep":true}`,
				} {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != want {
						t.Fatalf("update changed profile data %s: %q, %v", path, got, err)
					}
				}
				if runtime.GOOS == "windows" {
					waitForWindowsUpdateCleanup(t, ctx, install.lockDir)
				}
			}
			serverMu.Lock()
			corruptSums = false
			serverMu.Unlock()
		})
	}

	t.Run("restores old binary when release executable does not match its tag", func(t *testing.T) {
		badBytes, err := os.ReadFile(mismatchedBinary)
		if err != nil {
			t.Fatal(err)
		}
		badAsset := badBytes
		badRelease := make(map[string][]byte)
		badAssetName := "peerimeter-agent-" + runtime.GOOS + "-" + e2eReleaseArch(runtime.GOARCH)
		if runtime.GOOS == "windows" {
			badDLL := releaseFiles["wireguard.dll"]
			badAsset = makeWindowsE2EArchive(t, badBytes, notices, badDLL)
			badRelease["peerimeter-agent.NOTICES.txt"] = notices
			badRelease["wireguard.dll"] = badDLL
			badAssetName += ".zip"
		} else {
			badRelease[badAssetName+".NOTICES.txt"] = notices
		}
		badRelease[badAssetName] = badAsset
		badManifest := e2eSumLine(badAssetName, badAsset)
		if runtime.GOOS != "windows" {
			badManifest += e2eSumLine(badAssetName+".NOTICES.txt", notices)
		}
		badRelease["SHA256SUMS"] = []byte(badManifest)
		serverMu.Lock()
		releaseFiles = badRelease
		corruptSums = false
		serverMu.Unlock()

		install := prepareE2EInstallation(t, oldBinary, notices, badRelease)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(install.installDir, executableName()), "update")
		cmd.Env = withTestEnv(os.Environ(), "SSL_CERT_FILE", caPath)
		cmd.Env = withTestEnv(cmd.Env, "NO_COLOR", "1")
		output, updateErr := cmd.CombinedOutput()
		if runtime.GOOS != "windows" && (updateErr == nil || !bytes.Contains(output, []byte("unexpected version"))) {
			t.Fatalf("mismatched executable was not rolled back: err=%v output=%s", updateErr, output)
		}
		waitForE2EVersion(t, ctx, filepath.Join(install.installDir, executableName()), caPath, "v1.0.0")
		inv, err := installstate.Load(install.installDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range inv.Files {
			digest, hashErr := installstate.Hash(installstate.ResourcePath(inv, file))
			if hashErr != nil || digest != file.SHA256 {
				t.Fatalf("rollback left stale inventory hash for %s: %s %v", file.Name, digest, hashErr)
			}
		}
		if runtime.GOOS == "windows" {
			waitForWindowsUpdateCleanup(t, ctx, install.lockDir)
		}
	})
}

type e2eInstall struct {
	installDir string
	docDir     string
	dataDir    string
	configDir  string
	stateDir   string
	lockDir    string
}

func prepareE2EInstallation(t *testing.T, oldBinary string, notices []byte, release map[string][]byte) e2eInstall {
	t.Helper()
	root := t.TempDir()
	install := e2eInstall{
		installDir: filepath.Join(root, "programs"),
		docDir:     filepath.Join(root, "docs"),
		dataDir:    filepath.Join(root, "data"),
		configDir:  filepath.Join(root, "configuration"),
		stateDir:   filepath.Join(root, "state"),
		lockDir:    filepath.Join(root, "locks"),
	}
	runtimeDir := filepath.Join(root, "runtime")
	for _, dir := range []string{install.installDir, install.configDir, install.stateDir, install.lockDir, install.docDir, install.dataDir, runtimeDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	program, err := os.ReadFile(oldBinary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install.installDir, executableName()), program, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install.docDir, "peerimeter-agent.NOTICES.txt"), notices, 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(filepath.Join(install.installDir, "wireguard.dll"), release["wireguard.dll"], 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(install.configDir, "service.key"), []byte("profile key must remain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install.stateDir, "state.json"), []byte(`{"keep":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	register := exec.Command(filepath.Join(install.installDir, executableName()), "register-installation",
		"--install-dir", install.installDir, "--doc-dir", install.docDir,
		"--data-dir", install.dataDir, "--lock-dir", install.lockDir)
	if output, err := register.CombinedOutput(); err != nil {
		t.Fatalf("register installed binary: %v\n%s", err, output)
	}
	profile := installstate.Profile{ConfigDir: install.configDir, StateDir: install.stateDir, RuntimeDir: runtimeDir}
	if err := installstate.RegisterProfile(install.installDir, profile); err != nil {
		t.Fatal(err)
	}
	return install
}

func buildAgentE2E(t *testing.T, root, output, version, serverURL string) {
	t.Helper()
	ldflags := strings.Join([]string{
		"-X github.com/peerimeter/peerimeter-agent/internal/cli.Version=" + version,
		"-X github.com/peerimeter/peerimeter-agent/internal/selfupdate.latestReleaseEndpoint=" + serverURL + "/latest",
		"-X github.com/peerimeter/peerimeter-agent/internal/selfupdate.releaseDownloadBase=" + serverURL + "/download/",
	}, " ")
	cmd := exec.Command("go", "build", "-mod=readonly", "-ldflags", ldflags, "-o", output, "./cmd/peerimeter-agent")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s agent: %v\n%s", version, err, output)
	}
}

func makeWindowsE2EArchive(t *testing.T, executable, notices, dll []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	for name, contents := range map[string][]byte{
		"peerimeter-agent.exe":         executable,
		"peerimeter-agent.NOTICES.txt": notices,
		"wireguard.dll":                dll,
	} {
		file, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func e2eSumLine(name string, contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func withTestEnv(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}

func corruptChecksumManifest(manifest string) string {
	lines := strings.Split(manifest, "\n")
	if len(lines) > 0 && len(lines[0]) >= 64 {
		lines[0] = strings.Repeat("0", 64) + lines[0][64:]
	}
	return strings.Join(lines, "\n")
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func executableName() string {
	if runtime.GOOS == "windows" {
		return "peerimeter-agent.exe"
	}
	return "peerimeter-agent"
}

func e2eReleaseArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return arch
	}
}

func waitForE2EVersion(t *testing.T, ctx context.Context, executable, caPath, expected string) {
	t.Helper()
	for {
		cmd := exec.CommandContext(ctx, executable, "version", "--json")
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+caPath, "NO_COLOR=1")
		output, err := cmd.Output()
		if err == nil {
			var result struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(output, &result) == nil && result.Version == expected {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("installed version did not become %s before timeout; last output=%s err=%v", expected, output, err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func waitForWindowsUpdateCleanup(t *testing.T, ctx context.Context, lockDir string) {
	t.Helper()
	for {
		entries, err := os.ReadDir(lockDir)
		if err == nil {
			pending := false
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".peerimeter-update-") {
					pending = true
					break
				}
			}
			if !pending {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(fmt.Errorf("Windows update staging was not cleaned up: %v", err))
		case <-time.After(250 * time.Millisecond):
		}
	}
}
