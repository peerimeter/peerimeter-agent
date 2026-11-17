//go:build !windows

package cli

import "os"

func replaceConfigFile(source, destination string) error { return os.Rename(source, destination) }
