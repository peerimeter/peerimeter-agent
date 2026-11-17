package main

import (
	"context"
	"io"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	settings, err := config.LoadEnvironment()
	if err != nil {
		_, _ = io.WriteString(stderr, err.Error()+"\n")
		return 2
	}
	handler, err := logging.NewHandler(settings.LogFormat, stderr)
	if err != nil {
		_, _ = io.WriteString(stderr, err.Error()+"\n")
		return 2
	}
	slog.SetDefault(slog.New(handler))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handled, err := service.Dispatch(ctx, func(ctx context.Context) error {
		if cli.ExecuteWithEnvironment(ctx, args, stdout, stderr, settings) != 0 {
			return syscall.EINVAL
		}
		return nil
	})
	if handled {
		if err != nil {
			return 1
		}
		return 0
	}
	return cli.ExecuteWithEnvironment(ctx, args, stdout, stderr, settings)
}
