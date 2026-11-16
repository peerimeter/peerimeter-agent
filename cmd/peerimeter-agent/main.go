package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/peerimeter/peerimeter-agent/internal/cli"
	"github.com/peerimeter/peerimeter-agent/internal/config"
	"github.com/peerimeter/peerimeter-agent/internal/logging"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

func main() {
	settings, err := config.LoadEnvironment()
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
	handler, err := logging.NewHandler(settings.LogFormat, os.Stderr)
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
	slog.SetDefault(slog.New(handler))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handled, err := service.Dispatch(ctx, func(ctx context.Context) error {
		if cli.ExecuteWithEnvironment(ctx, os.Args[1:], os.Stdout, os.Stderr, settings) != 0 {
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
	os.Exit(cli.ExecuteWithEnvironment(ctx, os.Args[1:], os.Stdout, os.Stderr, settings))
}
