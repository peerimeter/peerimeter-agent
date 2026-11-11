// Package agent separates foreground lifetime from platform/service management.
package agent

import (
	"context"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"time"
)

func Run(ctx context.Context, backend platform.Backend, desired platform.Desired) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := backend.Start(ctx, desired)
	if err != nil {
		return err
	}
	<-ctx.Done()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.Close(cleanup); err != nil {
		return errors.Join(errors.New("native tunnel cleanup failed"), err)
	}
	return nil
}
