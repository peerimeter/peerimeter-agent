//go:build linux || darwin

package cli

import "os"

func enableTerminalColors(*os.File) bool { return true }
