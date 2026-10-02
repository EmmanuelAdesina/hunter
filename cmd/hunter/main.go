// Command hunter monitors bug-bounty programs and alerts on opportunities that
// match a researcher's profile.
//
// The binary is a single-shot worker. GitHub Actions is the scheduler; there is
// no server, no daemon, and no listening socket. Each invocation performs one
// scan, records what it observed, optionally sends email, and exits.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/eadeshina/hunter/internal/cli"
)

// version is stamped at link time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// A cancelled context lets an in-flight HTTP request or state write abort
	// promptly when a workflow is cancelled or the machine is shutting down.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cli.SetVersion(version)
	os.Exit(cli.Run(ctx, cli.DefaultEnv()))
}
