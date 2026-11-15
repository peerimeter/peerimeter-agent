//go:build windows

package service

import "os"

func acquireLegacyManagerLock(string) (*os.File, error) { return nil, nil }
