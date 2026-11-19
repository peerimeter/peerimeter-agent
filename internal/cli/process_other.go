//go:build !windows

package cli

import "syscall"

func updateHelperProcessAttributes() *syscall.SysProcAttr {
	return nil
}
