package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	protected "github.com/alvnukov/ssh-key-control/internal/agent"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// stated is everything a signing request says about the key and where the
// signature is going. It leaves out Caller, which is a live kernel lookup
// rather than part of the request, and which makes the struct uncomparable.
func stated(req protected.SigningRequest) [4]string {
	return [4]string{req.Fingerprint, req.Comment, req.User, req.HostKey}
}

type protectedRecorder struct {
	mu       sync.Mutex
	requests []protected.SigningRequest
	allow    bool
	err      error
}

func (r *protectedRecorder) confirm(_ context.Context, req protected.SigningRequest) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	return r.allow, r.err
}

func (r *protectedRecorder) recorded() []protected.SigningRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]protected.SigningRequest(nil), r.requests...)
}

func protectedClient(t *testing.T, p *protected.Protected) sshagent.ExtendedAgent {
	t.Helper()
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, server) }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Protected.Serve did not stop")
		}
	})
	return sshagent.NewClient(client)
}

func protectedKey(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer
}

func TestProtectedEverySignatureRequiresConfirmation(t *testing.T) {
	for _, constrained := range []bool{false, true} {
		for _, outcome := range []struct {
			name  string
			allow bool
			err   error
		}{
			{name: "denied"},
			{name: "allowed", allow: true},
			{name: "callback error", allow: true, err: errors.New("confirmation unavailable")},
		} {
			t.Run(outcome.name+map[bool]string{false: "/unconstrained", true: "/constrained"}[constrained], func(t *testing.T) {
				rec := &protectedRecorder{allow: outcome.allow, err: outcome.err}
				client := protectedClient(t, protected.NewProtected(rec.confirm))
				key, signer := protectedKey(t)
				const comment = "alice@trusted.example SHA256:not-the-key"
				if err := client.Add(sshagent.AddedKey{PrivateKey: key, Comment: comment, ConfirmBeforeUse: constrained}); err != nil {
					t.Fatal(err)
				}
				data := []byte("arbitrary unbound data")
				for range 2 {
					sig, err := client.Sign(signer.PublicKey(), data)
					if outcome.allow && outcome.err == nil {
						if err != nil {
							t.Fatal(err)
						}
						if err := signer.PublicKey().Verify(data, sig); err != nil {
							t.Fatal(err)
						}
					} else if err == nil || sig != nil {
						t.Fatal("denial produced a signature")
					}
				}
				requests := rec.recorded()
				if len(requests) != 2 {
					t.Fatalf("got %d confirmations, want 2", len(requests))
				}
				want := protected.SigningRequest{Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Comment: comment}
				for _, req := range requests {
					if stated(req) != stated(want) {
						t.Errorf("request = %+v, want %+v", req, want)
					}
				}
			})
		}
	}
}

func protectedBinding(t *testing.T, host ssh.Signer, session []byte, forwarded bool) []byte {
	t.Helper()
	sig, err := host.Sign(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(&struct {
		HostKey, SessionID, Signature []byte
		Forwarded                     bool
	}{host.PublicKey().Marshal(), session, ssh.Marshal(sig), forwarded})
}

type protectedAuth struct {
	SessionID             []byte
	Message               byte
	User, Service, Method string
	HasSignature          bool
	Algorithm             string
	PublicKey             []byte
	Rest                  []byte `ssh:"rest"`
}

func protectedUserauth(key ssh.PublicKey, session []byte) protectedAuth {
	return protectedAuth{SessionID: session, Message: 50, User: "alice", Service: "ssh-connection", Method: "publickey", HasSignature: true, Algorithm: key.Type(), PublicKey: key.Marshal()}
}

func TestProtectedVerifiedDestination(t *testing.T) {
	for _, hostbound := range []bool{false, true} {
		t.Run(map[bool]string{false: "publickey", true: "hostbound"}[hostbound], func(t *testing.T) {
			rec := &protectedRecorder{allow: true}
			p := protected.NewProtected(rec.confirm)
			client := protectedClient(t, p)
			key, signer := protectedKey(t)
			_, host := protectedKey(t)
			session := []byte("verified SSH exchange hash")
			if err := client.Add(sshagent.AddedKey{PrivateKey: key, Comment: "key label"}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Extension("session-bind@openssh.com", protectedBinding(t, host, session, false)); err != nil {
				t.Fatal(err)
			}
			auth := protectedUserauth(signer.PublicKey(), session)
			if hostbound {
				auth.Method = "publickey-hostbound-v00@openssh.com"
				auth.Rest = ssh.Marshal(&struct{ HostKey []byte }{host.PublicKey().Marshal()})
			}
			data := ssh.Marshal(&auth)
			for range 2 {
				sig, err := client.Sign(signer.PublicKey(), data)
				if err != nil {
					t.Fatal(err)
				}
				if err := signer.PublicKey().Verify(data, sig); err != nil {
					t.Fatal(err)
				}
			}
			requests := rec.recorded()
			want := protected.SigningRequest{Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Comment: "key label", User: "alice", HostKey: ssh.FingerprintSHA256(host.PublicKey())}
			if !hostbound {
				want.User, want.HostKey = "", ""
			}
			if len(requests) != 2 {
				t.Fatalf("got %d callbacks", len(requests))
			}
			for _, req := range requests {
				if stated(req) != stated(want) {
					t.Errorf("request = %+v, want %+v", req, want)
				}
			}
			// Keys are shared, but destination authority must not cross connections.
			other := protectedClient(t, p)
			if _, err := other.Sign(signer.PublicKey(), data); err != nil {
				t.Fatal(err)
			}
			last := rec.recorded()[2]
			if last.User != "" || last.HostKey != "" {
				t.Fatalf("binding leaked across connections: %+v", last)
			}
		})
	}
}

func TestProtectedUnknownContextAlwaysConfirms(t *testing.T) {
	key, signer := protectedKey(t)
	_, host := protectedKey(t)
	_, other := protectedKey(t)
	session := []byte("authenticated session")
	for _, tc := range []struct {
		name   string
		change func(*protectedAuth)
	}{
		{"different session", func(a *protectedAuth) { a.SessionID = []byte("another session") }},
		{"missing session", func(a *protectedAuth) { a.SessionID = nil }},
		{"wrong message", func(a *protectedAuth) { a.Message = 51 }},
		{"empty user", func(a *protectedAuth) { a.User = "" }},
		{"wrong service", func(a *protectedAuth) { a.Service = "ssh-userauth" }},
		{"wrong method", func(a *protectedAuth) { a.Method = "password" }},
		{"unsigned probe", func(a *protectedAuth) { a.HasSignature = false }},
		{"wrong algorithm", func(a *protectedAuth) { a.Algorithm = ssh.KeyAlgoRSA }},
		{"wrong public key", func(a *protectedAuth) { a.PublicKey = other.PublicKey().Marshal() }},
		{"trailing bytes", func(a *protectedAuth) { a.Rest = []byte{0} }},
		{"hostbound missing host", func(a *protectedAuth) { a.Rest = nil }},
		{"hostbound wrong host", func(a *protectedAuth) {
			a.Method = "publickey-hostbound-v00@openssh.com"
			a.Rest = ssh.Marshal(&struct{ Host []byte }{other.PublicKey().Marshal()})
		}},
		{"hostbound trailing bytes", func(a *protectedAuth) {
			a.Method = "publickey-hostbound-v00@openssh.com"
			a.Rest = append(ssh.Marshal(&struct{ Host []byte }{host.PublicKey().Marshal()}), 0)
		}},
		{"oversized context", func(a *protectedAuth) { a.User = string(make([]byte, 65<<10)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &protectedRecorder{}
			client := protectedClient(t, protected.NewProtected(rec.confirm))
			if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Extension("session-bind@openssh.com", protectedBinding(t, host, session, false)); err != nil {
				t.Fatal(err)
			}
			// A scoped request must not leave stale authority behind.
			auth := protectedUserauth(signer.PublicKey(), session)
			auth.Method = "publickey-hostbound-v00@openssh.com"
			auth.Rest = ssh.Marshal(&struct{ HostKey []byte }{host.PublicKey().Marshal()})
			if _, err := client.Sign(signer.PublicKey(), ssh.Marshal(&auth)); err == nil {
				t.Fatal("denial ignored")
			}
			tc.change(&auth)
			for _, data := range [][]byte{ssh.Marshal(&auth), []byte("not userauth"), nil} {
				if sig, err := client.Sign(signer.PublicKey(), data); err == nil || sig != nil {
					t.Fatal("generic denial ignored")
				}
			}
			requests := rec.recorded()
			if len(requests) != 4 {
				t.Fatalf("got %d confirmations, want 4", len(requests))
			}
			if requests[0].User != "alice" || requests[0].HostKey != ssh.FingerprintSHA256(host.PublicKey()) {
				t.Fatalf("missing initial scope: %+v", requests[0])
			}
			for _, req := range requests[1:] {
				if req.User != "" || req.HostKey != "" {
					t.Errorf("forged destination: %+v", req)
				}
			}
		})
	}
}

func TestProtectedInvalidBindingTaintsConnection(t *testing.T) {
	key, signer := protectedKey(t)
	_, host := protectedKey(t)
	_, otherHost := protectedKey(t)
	session := []byte("session signed by server")
	valid := protectedBinding(t, host, session, false)
	badSignature := append([]byte(nil), valid...)
	badSignature[len(badSignature)-2] ^= 1
	badBoolean := append([]byte(nil), valid...)
	badBoolean[len(badBoolean)-1] = 2
	var forged struct {
		HostKey, SessionID, Signature []byte
		Forwarded                     bool
	}
	if err := ssh.Unmarshal(valid, &forged); err != nil {
		t.Fatal(err)
	}
	forged.SessionID = []byte("not the signed session")
	wrongSession := ssh.Marshal(&forged)
	forged.SessionID = session
	forged.HostKey = otherHost.PublicKey().Marshal()
	for _, tc := range []struct {
		name      string
		contents  []byte
		bindFirst bool
	}{
		{"bad signature", badSignature, false},
		{"wrong signed session", wrongSession, false},
		{"wrong signing host", ssh.Marshal(&forged), false},
		{"malformed", []byte{0xff, 0xff, 0xff, 0xff}, false},
		{"truncated", valid[:len(valid)-1], false},
		{"trailing data", append(append([]byte(nil), valid...), 0), false},
		{"empty session", protectedBinding(t, host, nil, false), false},
		{"oversized session", protectedBinding(t, host, make([]byte, 129), false), false},
		{"oversized binding", make([]byte, 65<<10), false},
		{"forwarded", protectedBinding(t, host, session, true), false},
		{"invalid boolean", badBoolean, false},
		{"duplicate", valid, true},
		{"conflicting host", protectedBinding(t, otherHost, session, false), true},
		{"conflicting session", protectedBinding(t, host, []byte("second session"), false), true},
		{"forwarding chain", protectedBinding(t, otherHost, []byte("next hop"), true), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &protectedRecorder{allow: true}
			p := protected.NewProtected(rec.confirm)
			client := protectedClient(t, p)
			if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
				t.Fatal(err)
			}
			if tc.bindFirst {
				if _, err := client.Extension("session-bind@openssh.com", valid); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := client.Extension("session-bind@openssh.com", tc.contents); err == nil {
				t.Fatal("invalid binding accepted")
			}
			if _, err := client.Extension("session-bind@openssh.com", valid); err == nil {
				t.Fatal("tainted connection rebound")
			}
			auth := protectedUserauth(signer.PublicKey(), session)
			for _, data := range [][]byte{ssh.Marshal(&auth), []byte("generic")} {
				if sig, err := client.Sign(signer.PublicKey(), data); err == nil || sig != nil {
					t.Fatal("tainted connection signed")
				}
			}
			if len(rec.recorded()) != 0 {
				t.Fatal("tainted binding reached confirmation")
			}
			// Taint, like authenticated scope, is connection-local.
			clean := protectedClient(t, p)
			if _, err := clean.Sign(signer.PublicKey(), []byte("generic")); err != nil {
				t.Fatal(err)
			}
			requests := rec.recorded()
			if len(requests) != 1 || requests[0].HostKey != "" || requests[0].User != "" {
				t.Fatalf("unexpected clean context: %+v", requests)
			}
		})
	}
}

func TestProtectedFlagsAndClientSignersCannotBypassGate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "deny", true: "allow"}[allow], func(t *testing.T) {
			rec := &protectedRecorder{allow: allow}
			p := protected.NewProtected(rec.confirm)
			// Protected itself exposes no Agent (and hence no raw Signers).
			if _, ok := any(p).(sshagent.Agent); ok {
				t.Fatal("Protected exposes raw agent methods")
			}
			client := protectedClient(t, p)
			if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
				t.Fatal(err)
			}
			data := []byte("RSA payload")
			for _, tc := range []struct {
				flag      sshagent.SignatureFlags
				algorithm string
			}{
				{sshagent.SignatureFlagRsaSha256, ssh.KeyAlgoRSASHA256},
				{sshagent.SignatureFlagRsaSha512, ssh.KeyAlgoRSASHA512},
			} {
				sig, err := client.SignWithFlags(signer.PublicKey(), data, tc.flag)
				if !allow {
					if err == nil || sig != nil {
						t.Fatal("flags bypassed denial")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if sig.Format != tc.algorithm {
					t.Fatalf("signature format %q, want %q", sig.Format, tc.algorithm)
				}
				if err := signer.PublicKey().Verify(data, sig); err != nil {
					t.Fatal(err)
				}
			}
			// NewClient.Signers creates protocol-backed signers, never exports
			// private keys. Saving one must not save a confirmation decision.
			signers, err := client.Signers()
			if err != nil {
				t.Fatal(err)
			}
			if len(signers) != 1 {
				t.Fatalf("got %d signers", len(signers))
			}
			for range 2 {
				sig, err := signers[0].Sign(rand.Reader, data)
				if allow {
					if err != nil {
						t.Fatal(err)
					}
					if err := signer.PublicKey().Verify(data, sig); err != nil {
						t.Fatal(err)
					}
				} else if err == nil || sig != nil {
					t.Fatal("client signer bypassed denial")
				}
			}
			if got := len(rec.recorded()); got != 4 {
				t.Fatalf("got %d confirmations, want 4", got)
			}
		})
	}
}

func TestProtectedRejectsUnsupportedConstraintsAndNilConfirmation(t *testing.T) {
	client := protectedClient(t, protected.NewProtected(nil))
	key, signer := protectedKey(t)
	if err := client.Add(sshagent.AddedKey{PrivateKey: key, ConfirmBeforeUse: true, ConstraintExtensions: []sshagent.ConstraintExtension{{ExtensionName: "restrict-destination-v00@openssh.com"}}}); err == nil {
		t.Fatal("unsupported restriction silently dropped")
	}
	keys, err := client.List()
	if err != nil || len(keys) != 0 {
		t.Fatalf("rejected key was added: %v, %v", keys, err)
	}
	if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	if sig, err := client.Sign(signer.PublicKey(), []byte("data")); err == nil || sig != nil {
		t.Fatal("nil callback allowed signing")
	}
}

func TestProtectedLockUnlockLifetimeAndRemoval(t *testing.T) {
	rec := &protectedRecorder{allow: true}
	p := protected.NewProtected(rec.confirm)
	client := protectedClient(t, p)
	other := protectedClient(t, p)
	key, signer := protectedKey(t)
	if err := client.Add(sshagent.AddedKey{PrivateKey: key, ConfirmBeforeUse: true}); err != nil {
		t.Fatal(err)
	}
	if err := other.Lock([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if keys, err := client.List(); err != nil || len(keys) != 0 {
		t.Fatalf("locked list = %v, %v", keys, err)
	}
	if _, err := client.Sign(signer.PublicKey(), []byte("data")); err == nil {
		t.Fatal("locked agent signed")
	}
	if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err == nil {
		t.Fatal("locked agent accepted key")
	}
	if err := client.Remove(signer.PublicKey()); err == nil {
		t.Fatal("locked agent removed key")
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("locked agent removed all keys")
	}
	if err := client.Unlock([]byte("wrong")); err == nil {
		t.Fatal("wrong password unlocked agent")
	}
	if err := client.Unlock([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(signer.PublicKey(), []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := other.Remove(signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(signer.PublicKey(), []byte("data")); err == nil {
		t.Fatal("removed key signed")
	}
	if err := client.Add(sshagent.AddedKey{PrivateKey: key, ConfirmBeforeUse: true, LifetimeSecs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(signer.PublicKey(), []byte("data")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		keys, err := other.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key lifetime was dropped")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := client.Sign(signer.PublicKey(), []byte("data")); err == nil {
		t.Fatal("expired key signed")
	}
	if got := len(rec.recorded()); got != 2 {
		t.Fatalf("got %d confirmations, want 2 successful signing requests", got)
	}
	if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	if err := other.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if keys, err := client.List(); err != nil || len(keys) != 0 {
		t.Fatalf("removed keys = %v, %v", keys, err)
	}
}

func TestProtectedLockDuringConfirmationPreventsSignature(t *testing.T) {
	var locker sshagent.ExtendedAgent
	p := protected.NewProtected(func(context.Context, protected.SigningRequest) (bool, error) {
		return true, locker.Lock([]byte("secret"))
	})
	locker = protectedClient(t, p)
	client := protectedClient(t, p)
	key, signer := protectedKey(t)
	if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	if sig, err := client.Sign(signer.PublicKey(), []byte("data")); err == nil || sig != nil {
		t.Fatal("lock during confirmation ignored")
	}
}

func TestProtectedCancellationStopsServeAndConfirmation(t *testing.T) {
	for _, signing := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "confirming"}[signing], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			p := protected.NewProtected(func(ctx context.Context, _ protected.SigningRequest) (bool, error) {
				close(entered)
				<-ctx.Done()
				// Even a callback that approves after cancellation cannot sign.
				return true, nil
			})
			server, conn := net.Pipe()
			defer conn.Close()
			done := make(chan error, 1)
			go func() { done <- p.Serve(ctx, server) }()
			result := make(chan error, 1)
			if signing {
				client := sshagent.NewClient(conn)
				key, signer := protectedKey(t)
				if err := client.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
					t.Fatal(err)
				}
				go func() { _, err := client.Sign(signer.PublicKey(), []byte("data")); result <- err }()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("callback not reached")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("Serve ignored cancellation")
			}
			if signing {
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("canceled request signed")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("client still blocked")
				}
			}
		})
	}
}
