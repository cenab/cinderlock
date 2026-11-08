package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/cenab/cinderlock/internal/cli"
	"github.com/cenab/cinderlock/internal/spec"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := cli.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		os.Exit(spec.ExitCode(err))
	}
}
