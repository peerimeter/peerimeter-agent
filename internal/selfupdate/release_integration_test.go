package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchIntegrationDownloadsAndVerifiesHTTPSRelease(t *testing.T) {
	for _, corruptSums := range []bool{false, true} {
		name := "valid checksums"
		if corruptSums {
			name = "checksum mismatch"
		}
		t.Run(name, func(t *testing.T) {
			binary := []byte("integration release binary")
			notices := []byte("integration notices")
			assetName := "peerimeter-agent-linux-x86_64"
			manifest := sumLine(assetName, binary) + sumLine(assetName+".NOTICES.txt", notices)
			if corruptSums {
				sum := sha256.Sum256(binary)
				manifest = strings.Replace(manifest, hex.EncodeToString(sum[:]), strings.Repeat("0", 64), 1)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/latest":
					_, _ = w.Write([]byte(`{"tag_name":"v2.4.1"}`))
				case "/download/v2.4.1/SHA256SUMS":
					_, _ = w.Write([]byte(manifest))
				case "/download/v2.4.1/" + assetName:
					_, _ = w.Write(binary)
				case "/download/v2.4.1/" + assetName + ".NOTICES.txt":
					_, _ = w.Write(notices)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			tag, files, err := fetchAt(context.Background(), server.Client(), "linux", "amd64", server.URL+"/latest", server.URL+"/download/")
			if corruptSums {
				if err == nil || !strings.Contains(err.Error(), "checksum verification failed") {
					t.Fatalf("expected checksum rejection, got tag=%q files=%v err=%v", tag, files, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tag != "v2.4.1" || string(files["peerimeter-agent"]) != string(binary) || string(files["peerimeter-agent.NOTICES.txt"]) != string(notices) {
				t.Fatalf("unexpected verified release: tag=%q files=%v", tag, files)
			}
		})
	}
}

func TestFetchIntegrationRejectsNonHTTPSReleaseBase(t *testing.T) {
	_, _, err := fetchAt(context.Background(), http.DefaultClient, "linux", "amd64", "https://example.test/latest", "http://example.test/download/")
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("accepted non-HTTPS release base: %v", err)
	}
}
