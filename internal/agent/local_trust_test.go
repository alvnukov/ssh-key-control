package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type localAuth struct {
	Session               []byte
	Message               byte
	User, Service, Method string
	Signed                byte
	Algorithm             string
	Key                   []byte
	Rest                  []byte `ssh:"rest"`
}

func localFixture(t *testing.T, trust func() bool, confirm func(context.Context, SigningRequest) (bool, error)) (*protectedConnection, ssh.Signer, ssh.Signer, localAuth) {
	t.Helper()
	makeKey := func() (ed25519.PrivateKey, ssh.Signer) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
		return private, signer
	}
	private, key := makeKey()
	_, host := makeKey()
	p := NewProtected(confirm)
	if err := p.keyring.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	c := &protectedConnection{owner: p, ctx: context.Background(), trustedLocal: trust}
	session := []byte("local verified test exchange")
	signature, err := host.Sign(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	bind := ssh.Marshal(struct {
		Host, Session, Signature []byte
		Forward                  byte
	}{host.PublicKey().Marshal(), session, ssh.Marshal(signature), 0})
	if _, err := c.Extension("session-bind@openssh.com", bind); err != nil {
		t.Fatal(err)
	}
	auth := localAuth{session, 50, "alice", "ssh-connection", "publickey", 1, key.PublicKey().Type(), key.PublicKey().Marshal(), nil}
	return c, key, host, auth
}

func TestLocalTrustOrdinaryContext(t *testing.T) {
	for _, tc := range []struct {
		name            string
		trust           bool
		change          func(*protectedConnection, *localAuth)
		wantDestination bool
	}{
		{"attested direct client", true, func(*protectedConnection, *localAuth) {}, true},
		{"untrusted direct claimant", false, func(*protectedConnection, *localAuth) {}, false},
		{"missing binding", true, func(c *protectedConnection, _ *localAuth) { c.binding = nil }, false},
		{"wrong session", true, func(_ *protectedConnection, a *localAuth) { a.Session = []byte("other") }, false},
		{"wrong key", true, func(_ *protectedConnection, a *localAuth) { a.Key = []byte("other") }, false},
		{"wrong service", true, func(_ *protectedConnection, a *localAuth) { a.Service = "other" }, false},
		{"missing user", true, func(_ *protectedConnection, a *localAuth) { a.User = "" }, false},
		{"wrong algorithm", true, func(_ *protectedConnection, a *localAuth) { a.Algorithm = "other" }, false},
		{"trailing fields", true, func(_ *protectedConnection, a *localAuth) { a.Rest = []byte{0} }, false},
		{"not authentication", true, func(_ *protectedConnection, a *localAuth) { a.Message = 51 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got SigningRequest
			c, key, host, auth := localFixture(t, func() bool { return tc.trust }, func(_ context.Context, r SigningRequest) (bool, error) {
				got = r
				return false, nil
			})
			tc.change(c, &auth)
			if signature, err := c.Sign(key.PublicKey(), ssh.Marshal(auth)); err == nil || signature != nil {
				t.Fatal("denial produced a signature")
			}
			if tc.wantDestination {
				if got.User != "alice" || got.HostKey != ssh.FingerprintSHA256(host.PublicKey()) {
					t.Fatalf("missing exact destination: %+v", got)
				}
			} else if got.User != "" || got.HostKey != "" {
				t.Fatalf("invalid context acquired destination authority: %+v", got)
			}
		})
	}
}

func TestLocalTrustLossDuringApprovalDeniesSignature(t *testing.T) {
	trusted := true
	c, key, _, auth := localFixture(t, func() bool { return trusted }, func(context.Context, SigningRequest) (bool, error) {
		trusted = false
		return true, nil
	})
	if signature, err := c.Sign(key.PublicKey(), ssh.Marshal(auth)); err == nil || signature != nil {
		t.Fatal("peer lost attestation while waiting, but received a signature")
	}
}

func TestLocalTrustDoesNotRescueForwardedOrRepeatedBinding(t *testing.T) {
	for _, forwarding := range []byte{0, 1} {
		called := false
		c, key, host, auth := localFixture(t, func() bool { return true }, func(context.Context, SigningRequest) (bool, error) {
			called = true
			return true, nil
		})
		signature, err := host.Sign(rand.Reader, auth.Session)
		if err != nil {
			t.Fatal(err)
		}
		if forwarding == 1 {
			c.binding = nil
		} // first binding claims forwarding
		bind := ssh.Marshal(struct {
			Host, Session, Signature []byte
			Forward                  byte
		}{host.PublicKey().Marshal(), auth.Session, ssh.Marshal(signature), forwarding})
		if _, err := c.Extension("session-bind@openssh.com", bind); err == nil {
			t.Fatal("forwarded/repeated binding accepted")
		}
		if signature, err := c.Sign(key.PublicKey(), ssh.Marshal(auth)); err == nil || signature != nil || called {
			t.Fatal("trusted local client bypassed binding rejection")
		}
	}
}
