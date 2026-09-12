// Package launchd talks to launchd through launchctl: environment of the
// login session, bootstrapping of launch agents and their live state.
package launchd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ErrNotLoaded is returned for a service launchd does not know.
var ErrNotLoaded = errors.New("service is not loaded")

// Runner executes launchctl with the given arguments and returns its standard
// output. ExecRunner runs the real binary; tests script the answers.
type Runner interface {
	Run(ctx context.Context, args ...string) (string, error)
}

// ExitError is a launchctl run that ended with a non-zero status.
type ExitError struct {
	Args   []string
	Code   int
	Output string
}

func (e *ExitError) Error() string {
	msg := fmt.Sprintf("launchctl %s: exit status %d", strings.Join(e.Args, " "), e.Code)
	if e.Output != "" {
		msg += ": " + e.Output
	}
	return msg
}

// ExecRunner runs /bin/launchctl (or Path when set).
type ExecRunner struct {
	Path string
}

// Run implements Runner.
func (r ExecRunner) Run(ctx context.Context, args ...string) (string, error) {
	path := r.Path
	if path == "" {
		path = "/bin/launchctl"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.String(), &ExitError{
			Args:   args,
			Code:   exit.ExitCode(),
			Output: strings.TrimSpace(stderr.String() + stdout.String()),
		}
	}
	if err != nil {
		return "", fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// Domain is a launchd domain such as "gui/501".
type Domain string

// UserDomain is the GUI login session of the current user.
func UserDomain() Domain {
	return Domain("gui/" + strconv.Itoa(os.Getuid()))
}

// Service is the full name of a service in the domain.
func (d Domain) Service(label string) string {
	return string(d) + "/" + label
}

// Client issues launchctl commands against one domain.
type Client struct {
	Runner Runner
	Domain Domain
}

// Setenv sets a variable for every process launchd starts from now on in the domain.
func (c Client) Setenv(ctx context.Context, key, value string) error {
	_, err := c.Runner.Run(ctx, "setenv", key, value)
	return err
}

// Unsetenv removes a variable from the domain.
func (c Client) Unsetenv(ctx context.Context, key string) error {
	_, err := c.Runner.Run(ctx, "unsetenv", key)
	return err
}

// Getenv reads a variable of the domain. Unset variables read as "".
func (c Client) Getenv(ctx context.Context, key string) (string, error) {
	out, err := c.Runner.Run(ctx, "getenv", key)
	return strings.TrimSuffix(out, "\n"), err
}

// Bootstrap loads the launch agent described by plistPath into the domain.
func (c Client) Bootstrap(ctx context.Context, plistPath string) error {
	_, err := c.Runner.Run(ctx, "bootstrap", string(c.Domain), plistPath)
	return err
}

// Bootout unloads a service, stopping it if it runs. A service launchd does
// not know yields ErrNotLoaded.
func (c Client) Bootout(ctx context.Context, label string) error {
	_, err := c.Runner.Run(ctx, "bootout", c.Domain.Service(label))
	switch exitCode(err) {
	case 3: // ESRCH: no such process
		return ErrNotLoaded
	case 36: // EINPROGRESS: launchd is still tearing the service down
		return nil
	}
	return err
}

// Print describes a loaded service. An unknown one yields ErrNotLoaded.
func (c Client) Print(ctx context.Context, label string) (*Service, error) {
	out, err := c.Runner.Run(ctx, "print", c.Domain.Service(label))
	if exitCode(err) == 113 { // launchctl: "Could not find service"
		return nil, ErrNotLoaded
	}
	if err != nil {
		return nil, err
	}
	return ParsePrint(out)
}

func exitCode(err error) int {
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	return 0
}
