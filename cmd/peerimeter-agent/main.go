package main

import (
	"context"
	"github.com/peerimeter/peerimeter-agent/internal/cli"
	"github.com/peerimeter/peerimeter-agent/internal/service"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handled, err := service.Dispatch(ctx, func(ctx context.Context) error {
		if cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr) != 0 {
			return syscall.EINVAL
		}
		return nil
	})
	if handled {
		if err != nil {
			os.Exit(1)
		}
		return
	}
	os.Exit(cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
