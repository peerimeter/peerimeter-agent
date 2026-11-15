//go:build windows

package service

import (
	"context"
	"os"
)

func acquireLegacyManagerLock(context.Context, string) (*os.File, error) { return nil, nil }
