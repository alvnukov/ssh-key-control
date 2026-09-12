package askpass

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/alvnukov/ssh-key-control/internal/keys"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// DefaultAttempts is how many times a passphrase that can be checked against
// the key file is asked for before the last answer is handed to OpenSSH anyway.
const DefaultAttempts = 3

// Service answers prompts. It decides when to consult the keychain, when to
// store an answer and when to ask again; the dialogs themselves are behind ui.Dialogs.
type Service struct {
	Dialogs  ui.Dialogs
	Keychain ui.Keychain // nil: nothing is ever remembered
	// Verify checks a passphrase against a key file. nil: never check.
	Verify func(keyPath, passphrase string) keys.Verdict
	// Attempts overrides DefaultAttempts when positive.
	Attempts int
	// Log receives keychain problems that are not fatal. nil: discard.
	Log *log.Logger
}

// Answer returns what to print for OpenSSH. ui.ErrCancelled means the user declined.
func (s *Service) Answer(ctx context.Context, p Prompt) (string, error) {
	switch p.Kind {
	case Confirm:
		ok, err := s.Dialogs.Confirm(ctx, ui.ConfirmRequest{
			Title:   p.Title(),
			Message: p.Message(),
			Allow:   "Allow",
			Deny:    "Deny",
		})
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ui.ErrCancelled
		}
		return "yes", nil
	case Notify:
		return "", s.Dialogs.Notify(ctx, ui.NotifyRequest{Title: p.Title(), Message: p.Message()})
	case HostKey:
		return s.Dialogs.Text(ctx, ui.TextRequest{
			Title:       "Host key verification",
			Message:     p.Text,
			Placeholder: "yes, no or the fingerprint",
		})
	case Passphrase:
		return s.passphrase(ctx, p)
	case Password:
		return s.password(ctx, p)
	default:
		a, err := s.Dialogs.Secret(ctx, ui.SecretRequest{Title: p.Text})
		return a.Secret, err
	}
}

func (s *Service) passphrase(ctx context.Context, p Prompt) (string, error) {
	var note string
	if p.Retry {
		s.forget(ctx, p.Account)
		note = "OpenSSH rejected the previous passphrase."
	} else if secret, ok := s.lookup(ctx, p.Account); ok {
		if s.verify(p.Account, secret) != keys.Invalid {
			return secret, nil
		}
		s.forget(ctx, p.Account)
		note = "The passphrase remembered in your keychain was wrong and has been forgotten."
	}

	req := ui.SecretRequest{
		Title:    "Enter the passphrase for your SSH key",
		Remember: s.rememberOption(),
	}
	for attempt := 1; ; attempt++ {
		req.Message = passphraseMessage(p, note)
		a, err := s.Dialogs.Secret(ctx, req)
		if err != nil {
			return "", err
		}
		verdict := s.verify(p.Account, a.Secret)
		if verdict == keys.Invalid && attempt < s.attempts() {
			note = "Wrong passphrase."
			continue
		}
		if a.Remember && verdict != keys.Invalid {
			s.store(ctx, p.Account, a.Secret)
		}
		return a.Secret, nil
	}
}

func (s *Service) password(ctx context.Context, p Prompt) (string, error) {
	if secret, ok := s.lookup(ctx, p.Account); ok {
		return secret, nil
	}
	a, err := s.Dialogs.Secret(ctx, ui.SecretRequest{
		Title:    "Enter your SSH password",
		Message:  "Account: " + p.Account,
		Remember: s.rememberOption(),
	})
	if err != nil {
		return "", err
	}
	if a.Remember {
		s.store(ctx, p.Account, a.Secret)
	}
	return a.Secret, nil
}

func passphraseMessage(p Prompt, note string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Key: %s", p.Account)
	if p.ConfirmEachUse {
		b.WriteString("\nEvery use of the key will ask for your confirmation.")
	}
	if note != "" {
		b.WriteString("\n\n" + note)
	}
	return b.String()
}

func (s *Service) rememberOption() *ui.RememberOption {
	if s.Keychain == nil {
		return nil
	}
	return &ui.RememberOption{Label: "Remember in my keychain"}
}

func (s *Service) attempts() int {
	if s.Attempts > 0 {
		return s.Attempts
	}
	return DefaultAttempts
}

func (s *Service) verify(keyPath, passphrase string) keys.Verdict {
	if s.Verify == nil {
		return keys.Unverifiable
	}
	return s.Verify(keyPath, passphrase)
}

// lookup returns the remembered secret for account. A refused access prompt
// and a missing item both simply mean "ask the user".
func (s *Service) lookup(ctx context.Context, account string) (string, bool) {
	if s.Keychain == nil {
		return "", false
	}
	secret, err := s.Keychain.Get(ctx, account)
	switch {
	case err == nil:
		return secret, true
	case errors.Is(err, ui.ErrNotFound), errors.Is(err, ui.ErrDenied):
		return "", false
	default:
		s.logf("keychain lookup for %s: %v", account, err)
		return "", false
	}
}

func (s *Service) store(ctx context.Context, account, secret string) {
	if s.Keychain == nil {
		return
	}
	if err := s.Keychain.Set(ctx, account, secret); err != nil {
		s.logf("keychain store for %s: %v", account, err)
	}
}

func (s *Service) forget(ctx context.Context, account string) {
	if s.Keychain == nil {
		return
	}
	if err := s.Keychain.Delete(ctx, account); err != nil && !errors.Is(err, ui.ErrNotFound) {
		s.logf("keychain delete for %s: %v", account, err)
	}
}

func (s *Service) logf(format string, args ...any) {
	if s.Log == nil {
		return
	}
	s.Log.Printf(format, args...)
}

// Discard is a logger that drops everything, for callers that want no diagnostics.
var Discard = log.New(io.Discard, "", 0)
