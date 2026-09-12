// Package keys checks passphrases against private key files, so that a wrong
// passphrase is never stored and a stale one is noticed before OpenSSH sees it.
package keys

import (
	"crypto/x509"
	"errors"
	"os"

	"golang.org/x/crypto/ssh"
)

// Verdict is the result of Verify.
type Verdict int

const (
	// Unverifiable means the file could not be read or the format is not
	// understood (for example a FIDO "sk-" key); the passphrase may still be right.
	Unverifiable Verdict = iota
	// Valid means the passphrase decrypts the key.
	Valid
	// Invalid means the key is understood and the passphrase does not decrypt it.
	Invalid
)

func (v Verdict) String() string {
	switch v {
	case Valid:
		return "valid"
	case Invalid:
		return "invalid"
	default:
		return "unverifiable"
	}
}

// Verify reports whether passphrase decrypts the private key stored at path.
func Verify(path, passphrase string) Verdict {
	data, err := os.ReadFile(path)
	if err != nil {
		return Unverifiable
	}
	if passphrase == "" {
		// An empty passphrase decrypts nothing; it is wrong exactly when the key is encrypted.
		var missing *ssh.PassphraseMissingError
		if _, err := ssh.ParseRawPrivateKey(data); errors.As(err, &missing) {
			return Invalid
		}
		return Unverifiable
	}
	_, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(passphrase))
	switch {
	case err == nil:
		return Valid
	case errors.Is(err, x509.IncorrectPasswordError):
		return Invalid
	default:
		return Unverifiable
	}
}
