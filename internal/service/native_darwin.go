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
	args := []string{executable, "run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", serviceRuntime(cfg), "--config-dir", snapshotDirectory(cfg)}
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
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var arguments []string
	key := ""
	label := ""
	inArray := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("cannot verify launchd service ownership")
		}
		switch token := token.(type) {
		case xml.StartElement:
			switch token.Name.Local {
			case "key":
				if err := decoder.DecodeElement(&key, &token); err != nil {
					return err
				}
			case "array":
				inArray = key == "ProgramArguments"
			case "string":
				var value string
				if err := decoder.DecodeElement(&value, &token); err != nil {
					return err
				}
				if inArray {
					arguments = append(arguments, value)
				} else if key == "Label" {
					label = value
				}
			}
		case xml.EndElement:
			if token.Name.Local == "array" {
				inArray = false
			}
		}
	}
	if label != darwinServiceLabel {
		return errors.New("launchd label belongs to another installation")
	}
	if err := verifyServiceArguments(arguments, expectedExe, cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nativeManage("uninstall", cfg)
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
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	dictionary := 0
	key := ""
	seen := map[string]bool{}
	program := ""
	argumentZero := ""
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, errors.New("cannot inspect launchd executable registration")
		}
		switch token := token.(type) {
		case xml.StartElement:
			depth++
			if token.Name.Local == "dict" && dictionary == 0 {
				dictionary = depth
				continue
			}
			if depth != dictionary+1 {
				continue
			}
			if token.Name.Local == "key" {
				if err := decoder.DecodeElement(&key, &token); err != nil {
					return false, err
				}
				depth--
				if seen[key] {
					return false, errors.New("ambiguous duplicate launchd registration key")
				}
				seen[key] = true
				continue
			}
			if key == "Program" {
				if token.Name.Local != "string" {
					return false, errors.New("invalid launchd Program registration")
				}
				if err := decoder.DecodeElement(&program, &token); err != nil {
					return false, err
				}
				depth--
				key = ""
				continue
			}
			if key == "ProgramArguments" {
				if token.Name.Local != "array" {
					return false, errors.New("invalid launchd ProgramArguments registration")
				}
				var args struct {
					Values []string `xml:"string"`
				}
				if err := decoder.DecodeElement(&args, &token); err != nil {
					return false, err
				}
				depth--
				if len(args.Values) > 0 {
					argumentZero = args.Values[0]
				}
				key = ""
			}
		case xml.EndElement:
			depth--
		}
	}
	// launchd executes Program when present; argv[0] may deliberately differ.
	executable := program
	if executable == "" {
		executable = argumentZero
	}
	if executable == "" || !filepath.IsAbs(executable) {
		return false, errors.New("launchd registration does not expose an unambiguous absolute executable")
	}
	return equalServicePath(executable, expectedExe), nil
}
