//go:build windows

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func runWindowsPmaCommand(ctx context.Context, command, caPath string) ([]byte, error) {
	commandLine := fmt.Sprintf(`powershell.exe -NoProfile -NonInteractive -Command "& '%s' version --json"`, strings.ReplaceAll(command, "'", "''"))
	cmd := exec.CommandContext(ctx, "powershell.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: commandLine}
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+caPath, "NO_COLOR=1")
	return cmd.CombinedOutput()
}
