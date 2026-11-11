//go:build windows

package logging

import (
	"os"

	"golang.org/x/sys/windows"
)

func enableTerminalColors(file *os.File) bool {
	handle := windows.Handle(file.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return false
	}
	return windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
