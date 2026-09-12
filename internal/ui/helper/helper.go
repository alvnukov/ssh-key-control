// Package helper drives the Swift user-interface helper: a separate process
// that shows dialogs and reads the keychain, spoken to over JSON lines.
//
// One helper process serves one askpass invocation. Requests go to its
// standard input, one JSON object per line; each answer comes back on its
// standard output the same way, in order.
package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// EnvVar names the helper executable explicitly; it wins over the search next to the program.
const EnvVar = "SSH_KEY_CONTROL_UI"

// Name is the file name of the helper executable.
const Name = "ssh-key-control-ui"

// Locate finds the helper: EnvVar, then libexec next to the running program's
// bin directory, then the program's own directory.
func Locate() (string, error) {
	if p := os.Getenv(EnvVar); p != "" {
		return p, nil
	}
	return LocateInstalled()
}

// LocateInstalled ignores EnvVar: a long-lived signing gate must not take UI
// programs from the environment, where any same-user process can set them.
func LocateInstalled() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return locateFrom(exe)
}

// locateFrom searches relative to the resolved path of the running program.
func locateFrom(exe string) (string, error) {
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "..", "libexec", Name),
		filepath.Join(dir, Name),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return filepath.Clean(c), nil
		}
	}
	return "", fmt.Errorf("%s not found next to %s (set %s)", Name, exe, EnvVar)
}

// request is one line sent to the helper.
type request struct {
	Activate    bool                   `json:"activate,omitempty"`
	Op          string                 `json:"op"`
	Title       string                 `json:"title,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Remember    *remember              `json:"remember,omitempty"`
	Placeholder string                 `json:"placeholder,omitempty"`
	Allow       string                 `json:"allow,omitempty"`
	Deny        string                 `json:"deny,omitempty"`
	Destination string                 `json:"destination,omitempty"`
	Decisions   []ui.TemporaryDecision `json:"decisions,omitempty"`
	Account     string                 `json:"account,omitempty"`
	Secret      string                 `json:"secret,omitempty"`
}

type remember struct {
	Label string `json:"label"`
}

// response is one line received from the helper.
type response struct {
	Change          *ui.DecisionChange `json:"change,omitempty"`
	OK              bool               `json:"ok"`
	Error           string             `json:"error,omitempty"`
	Answer          string             `json:"answer,omitempty"`
	Remember        bool               `json:"remember,omitempty"`
	Scope           *ui.GrantScope     `json:"scope,omitempty"`
	DurationMinutes json.RawMessage    `json:"durationMinutes,omitempty"`
}

// Error strings the helper uses for the conditions callers distinguish.
const (
	errCancelled = "cancelled"
	errNotFound  = "not-found"
	errDenied    = "denied"
)

// Client is a running helper process. It implements ui.Dialogs and ui.Keychain.
type Client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *strings.Builder
	mu     sync.Mutex
	once   sync.Once
	waited error
}

// Start launches the helper at path.
func Start(ctx context.Context, path string) (*Client, error) {
	cmd := exec.CommandContext(ctx, path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	c := &Client{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: &strings.Builder{}}
	cmd.Stderr = c.stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", path, err)
	}
	return c, nil
}

// Close ends the helper: its input is closed, which makes it exit, and its
// exit status is collected.
func (c *Client) Close() error {
	c.once.Do(func() {
		_ = c.stdin.Close()
		c.waited = c.cmd.Wait()
	})
	return c.waited
}

// call sends one request and reads its answer.
func (c *Client) call(req request) (response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	line, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		return response{}, c.failure(fmt.Errorf("write to helper: %w", err))
	}
	reply, err := c.stdout.ReadBytes('\n')
	if err != nil {
		return response{}, c.failure(fmt.Errorf("read from helper: %w", err))
	}
	var resp response
	decoder := json.NewDecoder(strings.NewReader(string(reply)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resp); err != nil {
		return response{}, errors.New("helper returned an invalid response")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return response{}, errors.New("helper returned an invalid response")
	}
	if resp.Scope != nil || resp.DurationMinutes != nil {
		if req.Op != "confirm" || !resp.OK {
			return response{}, errors.New("scope is only valid for an answered confirmation")
		}
		if resp.Scope != nil && resp.Answer == "yes" && resp.Scope.IsDenyDuration() {
			return response{}, errors.New("deny duration is not valid for an allowed confirmation")
		}
		if resp.Scope != nil && resp.Answer != "yes" && !resp.Scope.IsDenyDuration() {
			return response{}, errors.New("scope is only valid for an allowed confirmation")
		}
	}
	if resp.Change != nil && (req.Op != "manage-decisions" || !resp.OK) {
		return response{}, errors.New("decision change is only valid for the management window")
	}
	if !resp.OK {
		return resp, mapError(resp.Error)
	}
	return resp, nil
}

// failure wraps a transport error with whatever the helper wrote to stderr.
// A broken pipe means the helper is gone, so it is reaped first: Wait also
// finishes the goroutine that copies stderr, which makes the buffer complete
// and safe to read.
func (c *Client) failure(err error) error {
	_ = c.Close()
	if msg := strings.TrimSpace(c.stderr.String()); msg != "" {
		return fmt.Errorf("%w (helper: %s)", err, msg)
	}
	return err
}

func mapError(text string) error {
	switch text {
	case errCancelled:
		return ui.ErrCancelled
	case errNotFound:
		return ui.ErrNotFound
	case errDenied:
		return ui.ErrDenied
	case "":
		return errors.New("helper failed without a reason")
	}
	return errors.New(text)
}

// Secret implements ui.Dialogs.
func (c *Client) Secret(_ context.Context, req ui.SecretRequest) (ui.SecretAnswer, error) {
	r := request{Op: "secret", Title: req.Title, Message: req.Message}
	if req.Remember != nil {
		r.Remember = &remember{Label: req.Remember.Label}
	}
	resp, err := c.call(r)
	if err != nil {
		return ui.SecretAnswer{}, err
	}
	return ui.SecretAnswer{Secret: resp.Answer, Remember: resp.Remember}, nil
}

// Text implements ui.Dialogs.
func (c *Client) Text(_ context.Context, req ui.TextRequest) (string, error) {
	resp, err := c.call(request{Op: "text", Title: req.Title, Message: req.Message, Placeholder: req.Placeholder})
	if err != nil {
		return "", err
	}
	return resp.Answer, nil
}

// Confirm implements ui.Dialogs.
func (c *Client) Confirm(ctx context.Context, req ui.ConfirmRequest) (bool, error) {
	req.Destination = "" // Legacy callers cannot consume timed choices.
	answer, err := c.ConfirmScoped(ctx, req)
	return answer.Allowed, err
}

// ConfirmScoped implements ui.ScopedDialogs.
func (c *Client) ConfirmScoped(_ context.Context, req ui.ConfirmRequest) (ui.Confirmation, error) {
	resp, err := c.call(request{Op: "confirm", Title: req.Title, Message: req.Message, Allow: req.Allow, Deny: req.Deny, Destination: req.Destination})
	if err != nil {
		return ui.Confirmation{}, err
	}
	if resp.Answer != "yes" && resp.Answer != "no" {
		return ui.Confirmation{}, errors.New("unknown confirmation answer")
	}
	scope := ui.GrantOnce
	if resp.Scope != nil {
		scope = *resp.Scope
		if scope == "" {
			return ui.Confirmation{}, errors.New("empty confirmation scope")
		}
	}
	answer := ui.Confirmation{Allowed: resp.Answer == "yes", Scope: scope}
	custom := scope == ui.GrantCustom || scope == ui.DenyCustom
	if custom {
		if len(resp.DurationMinutes) == 0 || string(resp.DurationMinutes) == "null" ||
			json.Unmarshal(resp.DurationMinutes, &answer.DurationMinutes) != nil {
			return ui.Confirmation{}, errors.New("custom duration requires integer minutes")
		}
	} else if resp.DurationMinutes != nil {
		return ui.Confirmation{}, errors.New("minutes are only valid for a custom duration")
	}
	if _, _, err := answer.Lifetime(); err != nil {
		return ui.Confirmation{}, err
	}
	if req.Destination == "" && scope != ui.GrantOnce {
		return ui.Confirmation{}, errors.New("timed confirmation requires a destination")
	}
	return answer, nil
}

// Notify implements ui.Dialogs: the panel is shown at once and stays until
// ctx is done, after which the helper is closed so the panel disappears.
func (c *Client) Notify(ctx context.Context, req ui.NotifyRequest) error {
	if _, err := c.call(request{Op: "notify", Title: req.Title, Message: req.Message}); err != nil {
		return err
	}
	<-ctx.Done()
	_ = c.Close()
	return nil
}

// Get implements ui.Keychain.
func (c *Client) Get(_ context.Context, account string) (string, error) {
	resp, err := c.call(request{Op: "keychain.get", Account: account})
	if err != nil {
		return "", err
	}
	return resp.Answer, nil
}

// Set implements ui.Keychain.
func (c *Client) Set(_ context.Context, account, secret string) error {
	_, err := c.call(request{Op: "keychain.set", Account: account, Secret: secret})
	return err
}

// Delete implements ui.Keychain.
func (c *Client) Delete(_ context.Context, account string) error {
	_, err := c.call(request{Op: "keychain.delete", Account: account})
	return err
}
