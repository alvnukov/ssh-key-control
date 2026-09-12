// Package askpass implements the program side of OpenSSH's SSH_ASKPASS
// protocol: classify the prompt, get an answer from the user (or the keychain)
// and hand it back.
package askpass

import (
	"regexp"
	"strings"
)

// Kind is what OpenSSH is asking for.
type Kind int

const (
	// Other is any prompt not recognised below: a PIN, "Enter same passphrase
	// again", ssh-keygen questions. It gets a hidden field and is never remembered.
	Other Kind = iota
	// Passphrase is the passphrase of a private key file.
	Passphrase
	// Password is the password of a user on a host.
	Password
	// HostKey is the "continue connecting (yes/no/[fingerprint])?" question.
	HostKey
	// Confirm is ssh-agent asking whether a key may be used (SSH_ASKPASS_PROMPT=confirm).
	Confirm
	// Notify is a message with no answer, such as "touch your security key"
	// (SSH_ASKPASS_PROMPT=none).
	Notify
)

func (k Kind) String() string {
	switch k {
	case Passphrase:
		return "passphrase"
	case Password:
		return "password"
	case HostKey:
		return "host key"
	case Confirm:
		return "confirm"
	case Notify:
		return "notify"
	default:
		return "other"
	}
}

// Prompt is a classified OpenSSH prompt.
type Prompt struct {
	Kind Kind
	// Text is the prompt as OpenSSH passed it, surrounding whitespace removed.
	Text string
	// Account identifies what the secret belongs to: the key path for a
	// Passphrase, user@host for a Password. Empty for other kinds.
	Account string
	// Retry is set when OpenSSH says the previous answer was wrong. Only
	// ssh-add says so; ssh repeats the same prompt.
	Retry bool
	// ConfirmEachUse is set for `ssh-add -c`: the key will need confirmation on every use.
	ConfirmEachUse bool
}

var (
	// ssh: Enter passphrase for key '/home/me/.ssh/id_ed25519':
	keyPassphrase = regexp.MustCompile(`^Enter passphrase for key '(.+)':$`)
	// ssh-add: Enter passphrase for /home/me/.ssh/id_ed25519 (will confirm each use):
	//          Bad passphrase, try again for /home/me/.ssh/id_ed25519:
	addPassphrase = regexp.MustCompile(`^(Enter passphrase for|Bad passphrase, try again for) (.+?)( \(will confirm each use\))?:$`)
	// ssh: me@example.org's password:
	hostPassword = regexp.MustCompile(`^(.+?)'s password:$`)
	// ssh keyboard-interactive: (me@example.org) Password:
	interactive = regexp.MustCompile(`^\((.+?)\) (.+)$`)
	// the server's own wording of a password request
	passwordWord = regexp.MustCompile(`(?i)password:?$`)
)

// Parse classifies text, the prompt OpenSSH passed as the only argument.
// hint is the value of SSH_ASKPASS_PROMPT, which ssh-agent sets to "confirm"
// and ssh to "none" when no answer is expected.
func Parse(text, hint string) Prompt {
	p := Prompt{Text: strings.TrimSpace(text)}
	switch {
	case strings.EqualFold(hint, "confirm"):
		p.Kind = Confirm
		return p
	case strings.EqualFold(hint, "none"):
		p.Kind = Notify
		return p
	}

	if m := keyPassphrase.FindStringSubmatch(p.Text); m != nil {
		p.Kind, p.Account = Passphrase, m[1]
		return p
	}
	if m := addPassphrase.FindStringSubmatch(p.Text); m != nil {
		p.Kind, p.Account = Passphrase, m[2]
		p.Retry = strings.HasPrefix(m[1], "Bad")
		p.ConfirmEachUse = m[3] != ""
		return p
	}
	if m := hostPassword.FindStringSubmatch(p.Text); m != nil {
		p.Kind, p.Account = Password, m[1]
		return p
	}
	if m := interactive.FindStringSubmatch(p.Text); m != nil {
		p.Account = m[1]
		if passwordWord.MatchString(m[2]) {
			p.Kind = Password
		}
		return p
	}
	if strings.Contains(p.Text, "(yes/no") {
		p.Kind = HostKey
		return p
	}
	return p
}

// Title and Message split a two-line prompt such as ssh-agent's
// "Allow use of key foo?\nKey fingerprint SHA256:...": the first line is the
// question, the rest the details.
func (p Prompt) Title() string {
	title, _, _ := strings.Cut(p.Text, "\n")
	return strings.TrimSpace(title)
}

// Message is the part of the prompt after its first line.
func (p Prompt) Message() string {
	_, rest, _ := strings.Cut(p.Text, "\n")
	return strings.TrimSpace(rest)
}
