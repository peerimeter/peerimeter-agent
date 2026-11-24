//go:build darwin

package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const darwinServiceLabel = "com.peerimeter.agent"
const darwinServicePlist = "/Library/LaunchDaemons/" + darwinServiceLabel + ".plist"

// Dispatch is needed only by Windows SCM. launchd executes foreground run.
func Dispatch(context.Context, func(context.Context) error) (bool, error) { return false, nil }
func nativeSecureFiles(paths ...string) error                             { return nil }

func darwinPlist(executable string, cfg Config) ([]byte, error) {
	args := []string{executable, "daemon", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", serviceRuntime(cfg), "--config-dir", snapshotDirectory(cfg)}
	if cfg.Operator != "" {
		args = append(args, "--operator", cfg.Operator)
	}
	var out bytes.Buffer
	out.WriteString(xml.Header)
	out.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>" + darwinServiceLabel + "</string><key>ProgramArguments</key><array>")
	for _, arg := range args {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return nil, errors.New("invalid launchd service argument")
		}
		out.WriteString("<string>")
		if err := xml.EscapeText(&out, []byte(arg)); err != nil {
			return nil, errors.New("cannot encode launchd service arguments")
		}
		out.WriteString("</string>")
	}
	// Install writes the plist without bootstrapping it. launchd loads it at the
	// next system boot, or service start loads it immediately. bootout implements
	// an explicit stop without KeepAlive racing to restart the process.
	out.WriteString("</array><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>10</integer><key>ExitTimeOut</key><integer>20</integer><key>ProcessType</key><string>Background</string></dict></plist>\n")
	return out.Bytes(), nil
}
func darwinLaunchctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/bin/launchctl", args...).Run(); err != nil {
		return errors.New("launchctl operation failed; check system service registration and administrator privileges")
	}
	return nil
}
func darwinInstalled() error {
	info, err := os.Lstat(darwinServicePlist)
	if err != nil {
		return errors.New("Peerimeter launchd service is not installed")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("refusing to use an insecure or non-regular launchd service plist")
	}
	return nil
}

func nativeStatus() (Status, error) {
	info, err := os.Lstat(darwinServicePlist)
	if os.IsNotExist(err) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, errors.New("cannot inspect Peerimeter launchd service")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return Status{}, errors.New("refusing to use an insecure or non-regular launchd service plist")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+darwinServiceLabel).CombinedOutput()
	if err != nil && len(output) == 0 {
		return Status{}, errors.New("cannot inspect Peerimeter launchd service state")
	}
	return Status{Installed: true, Running: strings.Contains(string(output), "state = running")}, nil
}

func nativeManage(action string, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("system launchd service management requires root privileges")
	}
	target := "system/" + darwinServiceLabel
	switch action {
	case "install":
		executable, err := os.Executable()
		if err != nil {
			return errors.New("cannot locate agent executable")
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return errors.New("cannot resolve agent executable")
		}
		data, err := darwinPlist(executable, cfg)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(darwinServicePlist, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return errors.New("cannot install launchd plist; remove an existing Peerimeter service before reinstalling")
		}
		_, writeErr := f.Write(data)
		syncErr := f.Sync()
		closeErr := f.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			os.Remove(darwinServicePlist)
			return errors.New("cannot write launchd service plist")
		}
		// Explicitly enable boot activation even if an earlier service stop disabled
		// this label. Enabling alone does not start the service during installation.
		if err := darwinLaunchctl("enable", target); err != nil {
			os.Remove(darwinServicePlist)
			return err
		}
		return nil
	case "start":
		if err := darwinInstalled(); err != nil {
			return err
		}
		if darwinLaunchctl("print", target) == nil {
			return darwinLaunchctl("kickstart", target)
		}
		return darwinLaunchctl("bootstrap", "system", darwinServicePlist)
	case "stop":
		if err := darwinInstalled(); err != nil {
			return err
		}
		if darwinLaunchctl("print", target) != nil {
			return nil
		}
		return darwinLaunchctl("bootout", target)
	case "uninstall":
		if err := darwinInstalled(); err != nil {
			return err
		}
		if darwinLaunchctl("print", target) == nil {
			if err := darwinLaunchctl("bootout", target); err != nil {
				return err
			}
		}
		if err := os.Remove(darwinServicePlist); err != nil {
			return errors.New("cannot remove Peerimeter launchd plist")
		}
		return nil
	default:
		return fmt.Errorf("unsupported service action")
	}
}

func RemoveOwned(ctx context.Context, expectedExe string, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(darwinServicePlist); os.IsNotExist(err) {
		if darwinLaunchctl("print", "system/"+darwinServiceLabel) == nil {
			return errors.New("loaded launchd job has no verifiable owned plist")
		}
		return nil
	}
	if err := darwinInstalled(); err != nil {
		return err
	}
	data, err := os.ReadFile(darwinServicePlist)
	if err != nil {
		return err
	}
	plist, err := parseDarwinLaunchdPlist(data)
	if err != nil {
		return errors.New("cannot verify launchd service ownership")
	}
	if err := verifyDarwinServiceOwnership(plist, expectedExe, cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nativeManage("uninstall", cfg)
}

func verifyDarwinServiceOwnership(plist darwinLaunchdPlist, expectedExe string, cfg Config) error {
	if plist.Label != darwinServiceLabel {
		return errors.New("launchd label belongs to another installation")
	}
	executable := plist.Program
	arguments := append([]string(nil), plist.ProgramArguments...)
	if executable == "" {
		if len(arguments) == 0 {
			return errors.New("launchd registration does not expose an executable")
		}
		executable = arguments[0]
	} else if len(arguments) > 0 {
		// Program determines the executable even when argv[0] is customized.
		arguments[0] = expectedExe
	}
	if !filepath.IsAbs(executable) || !equalServicePath(executable, expectedExe) {
		return errors.New("launchd executable belongs to another installation")
	}
	return verifyServiceArguments(arguments, expectedExe, cfg)
}

func HasOwnedRegistration(ctx context.Context, expectedExe string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	data, err := os.ReadFile(darwinServicePlist)
	if os.IsNotExist(err) {
		if darwinLaunchctl("print", "system/"+darwinServiceLabel) == nil {
			return false, errors.New("a loaded launchd registration has no inspectable plist; program files were preserved")
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(data) > 65536 {
		return false, errors.New("launchd registration is oversized")
	}
	return darwinRegistrationUsesExecutable(data, expectedExe)
}
func darwinRegistrationUsesExecutable(data []byte, expectedExe string) (bool, error) {
	plist, err := parseDarwinLaunchdPlist(data)
	if err != nil {
		return false, errors.New("cannot inspect launchd executable registration")
	}
	executable := plist.Program
	if executable == "" && len(plist.ProgramArguments) > 0 {
		executable = plist.ProgramArguments[0]
	}
	if executable == "" || !filepath.IsAbs(executable) {
		return false, errors.New("launchd registration does not expose an unambiguous absolute executable")
	}
	return equalServicePath(executable, expectedExe), nil
}

type darwinLaunchdPlist struct {
	Label            string
	Program          string
	ProgramArguments []string
}

func parseDarwinLaunchdPlist(data []byte) (darwinLaunchdPlist, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return darwinLaunchdPlist{}, errors.New("launchd plist has no dictionary")
		}
		if err != nil {
			return darwinLaunchdPlist{}, err
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "dict" {
			return decodeDarwinLaunchdDictionary(decoder, start)
		}
	}
}

func decodeDarwinLaunchdDictionary(decoder *xml.Decoder, dictionary xml.StartElement) (darwinLaunchdPlist, error) {
	var plist darwinLaunchdPlist
	seen := make(map[string]bool)
	for {
		keyStart, err := nextLaunchdElement(decoder, dictionary.Name)
		if errors.Is(err, io.EOF) {
			return plist, nil
		}
		if err != nil {
			return darwinLaunchdPlist{}, err
		}
		var key string
		if err := decoder.DecodeElement(&key, &keyStart); err != nil {
			return darwinLaunchdPlist{}, err
		}
		if seen[key] {
			return darwinLaunchdPlist{}, errors.New("ambiguous duplicate launchd registration key")
		}
		seen[key] = true
		valueStart, err := nextLaunchdElement(decoder, dictionary.Name)
		if err != nil {
			return darwinLaunchdPlist{}, err
		}
		switch key {
		case "Label", "Program":
			if valueStart.Name.Local != "string" {
				return darwinLaunchdPlist{}, fmt.Errorf("invalid launchd %s registration", key)
			}
			var value string
			if err := decoder.DecodeElement(&value, &valueStart); err != nil {
				return darwinLaunchdPlist{}, err
			}
			if key == "Label" {
				plist.Label = value
			} else {
				plist.Program = value
			}
		case "ProgramArguments":
			if valueStart.Name.Local != "array" {
				return darwinLaunchdPlist{}, errors.New("invalid launchd ProgramArguments registration")
			}
			var args struct {
				Values []string `xml:"string"`
			}
			if err := decoder.DecodeElement(&args, &valueStart); err != nil {
				return darwinLaunchdPlist{}, err
			}
			plist.ProgramArguments = args.Values
		default:
			if err := decoder.Skip(); err != nil {
				return darwinLaunchdPlist{}, err
			}
		}
	}
}

func nextLaunchdElement(decoder *xml.Decoder, endElement xml.Name) (xml.StartElement, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		switch token := token.(type) {
		case xml.StartElement:
			return token, nil
		case xml.EndElement:
			if token.Name == endElement {
				return xml.StartElement{}, io.EOF
			}
		}
	}
}
