//go:build darwin

package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
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
	args := []string{executable, "run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory}
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
