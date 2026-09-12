package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerify(t *testing.T) {
	encrypted := writeKey(t, "correct horse")
	plain := writeKey(t, "")

	tests := []struct {
		name       string
		path       string
		passphrase string
		want       Verdict
	}{
		{"right passphrase", encrypted, "correct horse", Valid},
		{"wrong passphrase", encrypted, "battery staple", Invalid},
		{"empty passphrase", encrypted, "", Invalid},
		{"unencrypted key", plain, "anything", Unverifiable},
		{"missing file", filepath.Join(t.TempDir(), "nope"), "x", Unverifiable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Verify(tt.path, tt.passphrase); got != tt.want {
				t.Errorf("Verify(%q) = %v, want %v", tt.passphrase, got, tt.want)
			}
		})
	}
}

func TestVerifyGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Verify(path, "x"); got != Unverifiable {
		t.Errorf("got %v, want unverifiable", got)
	}
}
