//go:build windows

package cli

import "syscall"

func updateHelperProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00000200}
}
