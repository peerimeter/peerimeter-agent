//go:build !windows

package logging

import "os"

func enableTerminalColors(*os.File) bool { return true }
