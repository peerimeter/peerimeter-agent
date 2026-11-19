//go:build !windows

package cli

import (
	"context"
	"errors"
)

func runWindowsPmaCommand(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("Windows command runner called on a non-Windows platform")
}
