package askpass

import (
	"context"
	"errors"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/keys"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// fakeDialogs answers Secret from a queue and records every request.
type fakeDialogs struct {
	secrets    []ui.SecretAnswer
	secretReqs []ui.SecretRequest
	textAnswer string
	textReqs   []ui.TextRequest
	confirm    bool
	confirmReq *ui.ConfirmRequest
	notifyReq  *ui.NotifyRequest
	err        error
}

func (f *fakeDialogs) Secret(_ context.Context, req ui.SecretRequest) (ui.SecretAnswer, error) {
	f.secretReqs = append(f.secretReqs, req)
	if f.err != nil {
		return ui.SecretAnswer{}, f.err
	}
	if len(f.secrets) == 0 {
		panic("unexpected Secret dialog")
	}
	a := f.secrets[0]
	f.secrets = f.secrets[1:]
	return a, nil
}

func (f *fakeDialogs) Text(_ context.Context, req ui.TextRequest) (string, error) {
	f.textReqs = append(f.textReqs, req)
	return f.textAnswer, f.err
}

func (f *fakeDialogs) Confirm(_ context.Context, req ui.ConfirmRequest) (bool, error) {
	f.confirmReq = &req
	return f.confirm, f.err
}

func (f *fakeDialogs) Notify(ctx context.Context, req ui.NotifyRequest) error {
	f.notifyReq = &req
	<-ctx.Done()
	return nil
}

type fakeKeychain struct {
	items   map[string]string
	getErr  error
	gets    []string
	stored  map[string]string
	deleted []string
}

func newFakeKeychain() *fakeKeychain {
	return &fakeKeychain{items: map[string]string{}, stored: map[string]string{}}
}

func (k *fakeKeychain) Get(_ context.Context, account string) (string, error) {
	k.gets = append(k.gets, account)
	if k.getErr != nil {
		return "", k.getErr
	}
	s, ok := k.items[account]
	if !ok {
		return "", ui.ErrNotFound
	}
	return s, nil
}

func (k *fakeKeychain) Set(_ context.Context, account, secret string) error {
	k.items[account] = secret
	k.stored[account] = secret
	return nil
}

func (k *fakeKeychain) Delete(_ context.Context, account string) error {
	k.deleted = append(k.deleted, account)
	if _, ok := k.items[account]; !ok {
		return ui.ErrNotFound
	}
	delete(k.items, account)
	return nil
}

// verifyAgainst treats one passphrase as right for every key.
func verifyAgainst(right string) func(string, string) keys.Verdict {
	return func(_, passphrase string) keys.Verdict {
		if passphrase == right {
			return keys.Valid
		}
		return keys.Invalid
	}
}

const key = "/Users/me/.ssh/id_ed25519"

func TestConfirm(t *testing.T) {
	p := Parse("Allow use of key id_ed25519?\nKey fingerprint SHA256:abc.", "confirm")
	for _, allow := range []bool{true, false} {
		d := &fakeDialogs{confirm: allow}
		s := &Service{Dialogs: d}
		got, err := s.Answer(context.Background(), p)
		if allow {
			if err != nil || got != "yes" {
				t.Errorf("allow: got %q, %v", got, err)
			}
		} else if !errors.Is(err, ui.ErrCancelled) {
			t.Errorf("deny: err = %v, want ErrCancelled", err)
		}
		if d.confirmReq.Title != "Allow use of key id_ed25519?" || d.confirmReq.Message != "Key fingerprint SHA256:abc." {
			t.Errorf("request = %+v", d.confirmReq)
		}
		if d.confirmReq.Deny != "Deny" || d.confirmReq.Allow != "Allow" {
			t.Errorf("buttons = %+v", d.confirmReq)
		}
	}
}

func TestNotifyEndsWithContext(t *testing.T) {
	d := &fakeDialogs{}
	s := &Service{Dialogs: d}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := s.Answer(ctx, Parse("Confirm user presence for key SHA256:abc", "none"))
	if err != nil || got != "" {
		t.Errorf("got %q, %v", got, err)
	}
	if d.notifyReq == nil || d.notifyReq.Title != "Confirm user presence for key SHA256:abc" {
		t.Errorf("request = %+v", d.notifyReq)
	}
}

func TestHostKeyPassesTextThrough(t *testing.T) {
	d := &fakeDialogs{textAnswer: "SHA256:abc"}
	s := &Service{Dialogs: d}
	prompt := "The authenticity of host 'h' can't be established.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? "
	got, err := s.Answer(context.Background(), Parse(prompt, ""))
	if err != nil || got != "SHA256:abc" {
		t.Fatalf("got %q, %v", got, err)
	}
	if len(d.textReqs) != 1 || d.textReqs[0].Message != Parse(prompt, "").Text {
		t.Errorf("requests = %+v", d.textReqs)
	}
}

func TestOtherIsNeverRemembered(t *testing.T) {
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "1234", Remember: true}}}
	k := newFakeKeychain()
	s := &Service{Dialogs: d, Keychain: k}
	got, err := s.Answer(context.Background(), Parse("Enter PIN for authenticator: ", ""))
	if err != nil || got != "1234" {
		t.Fatalf("got %q, %v", got, err)
	}
	if d.secretReqs[0].Remember != nil {
		t.Error("PIN dialog offered to remember")
	}
	if len(k.stored) != 0 || len(k.gets) != 0 {
		t.Errorf("keychain touched: %+v", k)
	}
}

func TestCancelledDialog(t *testing.T) {
	d := &fakeDialogs{err: ui.ErrCancelled}
	s := &Service{Dialogs: d, Keychain: newFakeKeychain()}
	_, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", ""))
	if !errors.Is(err, ui.ErrCancelled) {
		t.Errorf("err = %v", err)
	}
}

func TestPassphraseFromKeychain(t *testing.T) {
	k := newFakeKeychain()
	k.items[key] = "hunter2"
	d := &fakeDialogs{}
	s := &Service{Dialogs: d, Keychain: k, Verify: verifyAgainst("hunter2")}
	got, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", ""))
	if err != nil || got != "hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
	if len(d.secretReqs) != 0 {
		t.Error("dialog shown although the keychain had the passphrase")
	}
}

func TestPassphraseFromKeychainUnverifiable(t *testing.T) {
	k := newFakeKeychain()
	k.items[key] = "hunter2"
	s := &Service{Dialogs: &fakeDialogs{}, Keychain: k} // no Verify
	got, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", ""))
	if err != nil || got != "hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestWrongKeychainPassphraseIsForgotten(t *testing.T) {
	k := newFakeKeychain()
	k.items[key] = "stale"
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "fresh", Remember: true}}}
	s := &Service{Dialogs: d, Keychain: k, Verify: verifyAgainst("fresh")}
	got, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", ""))
	if err != nil || got != "fresh" {
		t.Fatalf("got %q, %v", got, err)
	}
	if len(k.deleted) != 1 || k.deleted[0] != key {
		t.Errorf("deleted = %v", k.deleted)
	}
	if k.stored[key] != "fresh" {
		t.Errorf("stored = %v", k.stored)
	}
	if msg := d.secretReqs[0].Message; msg != "Key: "+key+"\n\nThe passphrase remembered in your keychain was wrong and has been forgotten." {
		t.Errorf("message = %q", msg)
	}
}

func TestWrongTypedPassphraseIsAskedAgain(t *testing.T) {
	k := newFakeKeychain()
	d := &fakeDialogs{secrets: []ui.SecretAnswer{
		{Secret: "no", Remember: true},
		{Secret: "nope", Remember: true},
		{Secret: "yes", Remember: true},
	}}
	s := &Service{Dialogs: d, Keychain: k, Verify: verifyAgainst("yes")}
	got, err := s.Answer(context.Background(), Parse("Enter passphrase for "+key+" (will confirm each use): ", ""))
	if err != nil || got != "yes" {
		t.Fatalf("got %q, %v", got, err)
	}
	if len(d.secretReqs) != 3 {
		t.Fatalf("%d dialogs, want 3", len(d.secretReqs))
	}
	if d.secretReqs[0].Message != "Key: "+key+"\nEvery use of the key will ask for your confirmation." {
		t.Errorf("first message = %q", d.secretReqs[0].Message)
	}
	if d.secretReqs[1].Message != "Key: "+key+"\nEvery use of the key will ask for your confirmation.\n\nWrong passphrase." {
		t.Errorf("second message = %q", d.secretReqs[1].Message)
	}
	if k.stored[key] != "yes" || len(k.stored) != 1 {
		t.Errorf("stored = %v", k.stored)
	}
}

func TestWrongPassphraseOnLastAttemptIsNotStored(t *testing.T) {
	k := newFakeKeychain()
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "a", Remember: true}, {Secret: "b", Remember: true}}}
	s := &Service{Dialogs: d, Keychain: k, Verify: verifyAgainst("right"), Attempts: 2}
	got, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", ""))
	if err != nil || got != "b" {
		t.Fatalf("got %q, %v", got, err)
	}
	if len(k.stored) != 0 {
		t.Errorf("stored a wrong passphrase: %v", k.stored)
	}
}

func TestUnverifiablePassphraseIsStoredWhenAsked(t *testing.T) {
	k := newFakeKeychain()
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "sk", Remember: true}}}
	s := &Service{Dialogs: d, Keychain: k, Verify: func(string, string) keys.Verdict { return keys.Unverifiable }}
	if _, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", "")); err != nil {
		t.Fatal(err)
	}
	if k.stored[key] != "sk" {
		t.Errorf("stored = %v", k.stored)
	}
}

func TestRememberUnchecked(t *testing.T) {
	k := newFakeKeychain()
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "x", Remember: false}}}
	s := &Service{Dialogs: d, Keychain: k, Verify: verifyAgainst("x")}
	if _, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", "")); err != nil {
		t.Fatal(err)
	}
	if len(k.stored) != 0 {
		t.Errorf("stored = %v", k.stored)
	}
}

func TestRetryPromptForgetsWithoutLookup(t *testing.T) {
	k := newFakeKeychain()
	k.items[key] = "stale"
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "new"}}}
	s := &Service{Dialogs: d, Keychain: k}
	got, err := s.Answer(context.Background(), Parse("Bad passphrase, try again for "+key+": ", ""))
	if err != nil || got != "new" {
		t.Fatalf("got %q, %v", got, err)
	}
	if len(k.gets) != 0 {
		t.Error("looked up the keychain after OpenSSH rejected its content")
	}
	if len(k.deleted) != 1 {
		t.Errorf("deleted = %v", k.deleted)
	}
	if msg := d.secretReqs[0].Message; msg != "Key: "+key+"\n\nOpenSSH rejected the previous passphrase." {
		t.Errorf("message = %q", msg)
	}
}

func TestKeychainDeniedFallsBackToDialog(t *testing.T) {
	k := newFakeKeychain()
	k.getErr = ui.ErrDenied
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "typed"}}}
	s := &Service{Dialogs: d, Keychain: k}
	got, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", ""))
	if err != nil || got != "typed" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestKeychainFailureFallsBackToDialog(t *testing.T) {
	k := newFakeKeychain()
	k.getErr = errors.New("keychain exploded")
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "typed"}}}
	s := &Service{Dialogs: d, Keychain: k, Log: Discard}
	got, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", ""))
	if err != nil || got != "typed" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNoKeychainMeansNoCheckbox(t *testing.T) {
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "x", Remember: true}}}
	s := &Service{Dialogs: d}
	if _, err := s.Answer(context.Background(), Parse("Enter passphrase for key '"+key+"': ", "")); err != nil {
		t.Fatal(err)
	}
	if d.secretReqs[0].Remember != nil {
		t.Error("offered to remember without a keychain")
	}
}

func TestPassword(t *testing.T) {
	k := newFakeKeychain()
	d := &fakeDialogs{secrets: []ui.SecretAnswer{{Secret: "pw", Remember: true}}}
	s := &Service{Dialogs: d, Keychain: k}
	got, err := s.Answer(context.Background(), Parse("me@example.org's password: ", ""))
	if err != nil || got != "pw" {
		t.Fatalf("got %q, %v", got, err)
	}
	if k.stored["me@example.org"] != "pw" {
		t.Errorf("stored = %v", k.stored)
	}
	if d.secretReqs[0].Message != "Account: me@example.org" || d.secretReqs[0].Remember == nil {
		t.Errorf("request = %+v", d.secretReqs[0])
	}

	// Second time: no dialog.
	d2 := &fakeDialogs{}
	s2 := &Service{Dialogs: d2, Keychain: k}
	got, err = s2.Answer(context.Background(), Parse("(me@example.org) Password: ", ""))
	if err != nil || got != "pw" {
		t.Fatalf("second: got %q, %v", got, err)
	}
	if len(d2.secretReqs) != 0 {
		t.Error("dialog shown although the password was remembered")
	}
}
