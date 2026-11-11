//go:build darwin

package service

import (
	"context"
	"encoding/xml"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestDarwinPlistPreservesArgumentsAndRestartPolicy(t *testing.T) {
	executable := "/Library/Peerimeter & Tools/peerimeter-agent"
	cfg := Config{ConfigPath: "/var/lib/peerimeter/<private>/service.json", StateDirectory: "/var/lib/peerimeter/state with spaces"}
	data, err := darwinPlist(executable, cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var values []string
	var inArray bool
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if token.Name.Local == "array" {
				inArray = true
			}
			if inArray && token.Name.Local == "string" {
				var value string
				if err := decoder.DecodeElement(&value, &token); err != nil {
					t.Fatal(err)
				}
				values = append(values, value)
			}
		case xml.EndElement:
			if token.Name.Local == "array" {
				inArray = false
			}
		}
	}
	want := []string{executable, "run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", serviceRuntime(cfg), "--config-dir", snapshotDirectory(cfg)}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("plist changed argument boundaries: %+v", values)
	}
	for _, required := range []string{"<key>RunAtLoad</key><true/>", "<key>SuccessfulExit</key><false/>", "<key>ThrottleInterval</key><integer>10</integer>"} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("missing launchd boot/restart policy %q", required)
		}
	}
}
func TestDarwinPlistRejectsControlCharacters(t *testing.T) {
	if _, err := darwinPlist("/bin/agent\nunsafe", Config{ConfigPath: "/tmp/config", StateDirectory: "/tmp/state"}); err == nil {
		t.Fatal("unsafe executable accepted")
	}
	if dispatched, err := Dispatch(context.Background(), func(context.Context) error { t.Fatal("unexpected foreground invocation"); return nil }); dispatched || err != nil {
		t.Fatal("launchd should use normal foreground execution")
	}
}

func TestDarwinReadOnlyRegistrationMatchesExactExecutable(t *testing.T) {
	executable := "/opt/Peerimeter Agent/bin/peerimeter-agent"
	plist, err := darwinPlist(executable, Config{ConfigPath: "/etc/peerimeter/service.json", StateDirectory: "/Library/Application Support/Peerimeter", RuntimeDirectory: "/var/run/peerimeter-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if owned, err := darwinRegistrationUsesExecutable(plist, executable); err != nil || !owned {
		t.Fatalf("own pre-inventory registration was not found: %v", err)
	}
	if owned, err := darwinRegistrationUsesExecutable(plist, executable+"-other"); err != nil || owned {
		t.Fatal("foreign executable matched launchd ownership")
	}
}

func TestDarwinReadOnlyProbeHonorsProgramOverCustomArgvZero(t *testing.T) {
	executable := "/opt/Peerimeter Agent/peerimeter-agent"
	plist := []byte(`<plist version="1.0"><dict><key>ProgramArguments</key><array><string>custom-argv-zero</string><string>run</string></array><key>Program</key><string>/opt/Peerimeter Agent/peerimeter-agent</string></dict></plist>`)
	if owned, err := darwinRegistrationUsesExecutable(plist, executable); err != nil || !owned {
		t.Fatal("Program was ignored after custom argv[0]", err)
	}
	duplicate := []byte(`<plist version="1.0"><dict><key>Program</key><string>/foreign</string><key>Program</key><string>/opt/Peerimeter Agent/peerimeter-agent</string></dict></plist>`)
	if owned, err := darwinRegistrationUsesExecutable(duplicate, executable); err == nil || owned {
		t.Fatal("duplicate executable definitions did not fail closed")
	}
}
