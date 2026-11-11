//go:build linux

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const linuxServiceName = "peerimeter-agent.service"
const linuxServicePath = "/etc/systemd/system/" + linuxServiceName
const linuxServiceMarker = "# Managed by peerimeter-agent; do not replace with an unrelated service.\n"

// Dispatch is used only by Windows' service dispatcher. Unix runs foreground
// under its native supervisor so signals reach the same runtime used by run.
func Dispatch(context.Context, func(context.Context) error) (bool, error) { return false, nil }
func nativeSecureFiles(...string) error                                   { return nil }

func linuxSystemdQuote(value string) string {
	// ExecStart uses systemd's own C-style quoting, environment expansion and
	// specifiers. It is never a shell command. Escape literal $ and % separately.
	return strings.ReplaceAll(strings.ReplaceAll(strconv.Quote(value), "$", "$$"), "%", "%%")
}
func linuxServiceUnit(executable string, cfg Config) ([]byte, error) {
	for _, path := range []string{executable, cfg.ConfigPath, cfg.StateDirectory, serviceRuntime(cfg)} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return nil, errors.New("systemd service paths must be absolute and contain no newlines or NUL")
		}
	}
	args := []string{linuxSystemdQuote(executable), "run", "--config", linuxSystemdQuote(cfg.ConfigPath), "--state-dir", linuxSystemdQuote(cfg.StateDirectory), "--runtime-dir", linuxSystemdQuote(serviceRuntime(cfg)), "--config-dir", linuxSystemdQuote(snapshotDirectory(cfg))}
	if cfg.Operator != "" {
		if len(cfg.Operator) > 256 || strings.TrimSpace(cfg.Operator) != cfg.Operator || strings.ContainsAny(cfg.Operator, "\x00\r\n") {
			return nil, errors.New("invalid systemd local operator identity")
		}
		args = append(args, "--operator", linuxSystemdQuote(cfg.Operator))
	}
	command := strings.Join(args, " ")
	unit := linuxServiceMarker + `[Unit]
Description=Peerimeter offline WireGuard agent
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
ExecStart=` + command + `
Restart=on-failure
RestartSec=3s
KillSignal=SIGTERM
TimeoutStopSec=20s
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`
	return []byte(unit), nil
}
func readLinuxService(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, errors.New("systemd service path is not a regular owned unit file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(contents), linuxServiceMarker) {
		return nil, errors.New("systemd unit belongs to another installation; refusing to modify it")
	}
	return contents, nil
}
func writeLinuxService(path string, contents []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".peerimeter-service-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}
func linuxSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	if err := cmd.Run(); err != nil {
		// Unit stdout/journal output is not copied into CLI errors; it may include
		// messages written by another process. journalctl remains available locally.
		return fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), err)
	}
	return nil
}
func nativeManage(action string, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("system service management requires root (run with sudo)")
	}
	if action == "install" {
		executable, err := os.Executable()
		if err != nil {
			return errors.New("cannot locate the installed agent executable")
		}
		contents, err := linuxServiceUnit(executable, cfg)
		if err != nil {
			return err
		}
		before, existed, err := installLinuxService(linuxServicePath, contents)
		if err != nil {
			return err
		}
		restore := func(cause error) error {
			var rollback error
			if existed {
				rollback = writeLinuxService(linuxServicePath, before)
			} else {
				rollback = os.Remove(linuxServicePath)
				_ = linuxSystemctl("disable", linuxServiceName)
			}
			reloadErr := linuxSystemctl("daemon-reload")
			return errors.Join(cause, rollback, reloadErr)
		}
		if err := linuxSystemctl("daemon-reload"); err != nil {
			return restore(err)
		}
		// Enable boot activation, but leave the first start as an explicit action.
		if err := linuxSystemctl("enable", linuxServiceName); err != nil {
			return restore(err)
		}
		return nil
	}
	if _, err := readLinuxService(linuxServicePath); err != nil {
		if action == "uninstall" && os.IsNotExist(err) {
			return nil
		}
		return err
	}
	switch action {
	case "start", "stop":
		return linuxSystemctl(action, linuxServiceName)
	case "uninstall":
		if err := linuxSystemctl("stop", linuxServiceName); err != nil {
			return err
		}
		if err := linuxSystemctl("disable", linuxServiceName); err != nil {
			return err
		}
		if err := os.Remove(linuxServicePath); err != nil {
			return err
		}
		// Protected config, identity, keys and chosen interface state are preserved.
		return linuxSystemctl("daemon-reload")
	default:
		return errors.New("unsupported Linux service action")
	}
}

func RemoveOwned(ctx context.Context, expectedExe string, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := readLinuxService(linuxServicePath)
	if os.IsNotExist(err) {
		if linuxSystemctl("is-active", "--quiet", linuxServiceName) == nil {
			return errors.New("active systemd service has no verifiable owned registration")
		}
		return nil
	}
	if err != nil {
		return err
	}
	expectedConfig := cfg.ConfigPath
	if expectedConfig == "" {
		expectedConfig = filepath.Join(snapshotDirectory(cfg), "service.json")
	}
	prefix := "ExecStart=" + linuxSystemdQuote(expectedExe) + " run --config " + linuxSystemdQuote(expectedConfig) + " --state-dir " + linuxSystemdQuote(cfg.StateDirectory)
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		if found || !strings.HasPrefix(line, prefix) {
			return errors.New("systemd service belongs to another installation")
		}
		found = true
		remainder := strings.TrimPrefix(line, prefix)
		runtimeFlag := " --runtime-dir " + linuxSystemdQuote(serviceRuntime(cfg))
		if strings.HasPrefix(remainder, runtimeFlag) {
			remainder = strings.TrimPrefix(remainder, runtimeFlag)
		} else if serviceRuntime(cfg) != cfg.StateDirectory {
			return errors.New("systemd runtime belongs to another installation")
		}
		configFlag := " --config-dir " + linuxSystemdQuote(snapshotDirectory(cfg))
		if strings.HasPrefix(remainder, configFlag) {
			remainder = strings.TrimPrefix(remainder, configFlag)
		}
		if remainder != "" && !strings.HasPrefix(remainder, " --operator ") {
			return errors.New("systemd service has unverifiable arguments")
		}
	}
	if !found {
		return errors.New("systemd executable registration is missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nativeManage("uninstall", cfg)
}

// installLinuxService refuses to repurpose even a Peerimeter-marked unit when
// its executable, layout or options differ. Marker ownership is not permission
// to take another installation's service registration.
func installLinuxService(path string, contents []byte) ([]byte, bool, error) {
	before, err := readLinuxService(path)
	if err == nil {
		if !bytes.Equal(before, contents) {
			return before, true, errors.New("existing Peerimeter systemd unit has different executable, paths or options; explicitly uninstall or migrate that service first")
		}
		return before, true, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}
	if err := writeLinuxService(path, contents); err != nil {
		return nil, false, fmt.Errorf("write systemd service: %w", err)
	}
	return nil, false, nil
}
