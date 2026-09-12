// Command ssh-key-control is an SSH_ASKPASS program for macOS with a launch agent
// that lets ssh-agent confirm every use of a key through a dialog.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/alvnukov/ssh-key-control/internal/cli"
)

// version is set by the build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	// OpenSSH ends a notification prompt by sending SIGTERM; the context
	// makes the dialog close instead of the process dying mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	code := cli.Default(version).Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
