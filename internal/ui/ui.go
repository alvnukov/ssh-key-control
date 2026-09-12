// Package ui defines what the askpass logic needs from the desktop: a few
// kinds of dialog and a place to remember secrets. The macOS implementation
// lives in a separate helper process (see package helper); tests use fakes.
package ui

import (
	"context"
	"errors"
)

var (
	// ErrCancelled is returned when the user dismisses a dialog.
	ErrCancelled = errors.New("cancelled by user")
	// ErrNotFound is returned by Keychain.Get when nothing is stored for the account.
	ErrNotFound = errors.New("no such keychain item")
	// ErrDenied is returned by Keychain.Get when the user refused the keychain access prompt.
	ErrDenied = errors.New("keychain access denied")
)

// RememberOption adds a "remember" checkbox to a secret dialog. The default
// state of the checkbox is the user's last choice, kept by the UI.
type RememberOption struct {
	Label string
}

// SecretRequest asks for a hidden text field.
type SecretRequest struct {
	Title    string
	Message  string
	Remember *RememberOption // nil: no checkbox
}

// SecretAnswer is what the user typed and whether they ticked the checkbox.
type SecretAnswer struct {
	Secret   string
	Remember bool
}

// TextRequest asks for a visible text field.
type TextRequest struct {
	Title       string
	Message     string
	Placeholder string
}

// ConfirmRequest asks a yes/no question. Deny is the default answer.
type ConfirmRequest struct {
	Title   string
	Message string
	Allow   string
	Deny    string
	// Destination enables timed choices only when nonempty.
	Destination string
}

// GrantScope is the lifetime selected for a confirmation: how long an
// approval (or, for the deny durations, a refusal) is remembered by the caller.
type GrantScope string

const (
	GrantOnce      GrantScope = "once"
	Grant5Minutes  GrantScope = "5m"
	Grant15Minutes GrantScope = "15m"
	GrantDay       GrantScope = "day" // Until the end of the local day.
	Deny5Minutes   GrantScope = "deny5m"
	Deny1Hour      GrantScope = "deny1h" // Kept for older helpers.
	Deny15Minutes  GrantScope = "deny15m"
	DenyDay        GrantScope = "denyday"
	GrantCustom    GrantScope = "custom"
	DenyCustom     GrantScope = "denycustom"
)

// IsDenyDuration reports whether the scope extends a refusal, not a grant.
func (s GrantScope) IsDenyDuration() bool {
	return s == Deny5Minutes || s == Deny1Hour || s == Deny15Minutes || s == DenyDay || s == DenyCustom
}

// Confirmation carries a decision; for a denial the Scope matters only when
// it is a deny duration, which the caller remembers as a standing refusal.
type Confirmation struct {
	Allowed         bool
	Scope           GrantScope
	DurationMinutes int // Only custom scopes; 1..1440. Zero means absent.
}

// ScopedDialogs offers confirmation lifetimes without changing legacy Dialogs.
// The UI reports choices only; it does not cache grants.
type ScopedDialogs interface {
	ConfirmScoped(ctx context.Context, req ConfirmRequest) (Confirmation, error)
}

// NotifyRequest shows a message with no answer, for example "touch your security key".
type NotifyRequest struct {
	Title   string
	Message string
}

// Dialogs shows dialogs to the user. Every method blocks until the dialog is
// closed; all of them return ErrCancelled when the user declines.
type Dialogs interface {
	Secret(ctx context.Context, req SecretRequest) (SecretAnswer, error)
	Text(ctx context.Context, req TextRequest) (string, error)
	Confirm(ctx context.Context, req ConfirmRequest) (bool, error)
	// Notify shows the message until ctx is done.
	Notify(ctx context.Context, req NotifyRequest) error
}

// Keychain stores secrets by account name (a key path or user@host).
type Keychain interface {
	Get(ctx context.Context, account string) (string, error)
	Set(ctx context.Context, account, secret string) error
	Delete(ctx context.Context, account string) error
}
