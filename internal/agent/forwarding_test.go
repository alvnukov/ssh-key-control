package agent_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	protected "github.com/alvnukov/ssh-key-control/internal/agent"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// These tests use the agent socket protocol, including the binding boolean and
// failure replies, rather than calling the connection implementation directly.
func forwardedFixture(t *testing.T, hops int, rec *protectedRecorder) (sshagent.ExtendedAgent, ssh.Signer, ssh.Signer, protectedAuth, []string) {
	t.Helper()
	client := protectedClient(t, protected.NewProtected(rec.confirm))
	private, key := protectedKey(t)
	if err := client.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	var fingerprints []string
	var terminal ssh.Signer
	var session []byte
	for i := 0; i <= hops; i++ {
		_, host := protectedKey(t)
		session = []byte(fmt.Sprintf("exchange %d", i))
		if _, err := client.Extension("session-bind@openssh.com", protectedBinding(t, host, session, i < hops)); err != nil {
			t.Fatal(err)
		}
		if i < hops {
			fingerprints = append(fingerprints, ssh.FingerprintSHA256(host.PublicKey()))
		} else {
			terminal = host
		}
	}
	auth := protectedUserauth(key.PublicKey(), session)
	auth.Method = "publickey-hostbound-v00@openssh.com"
	auth.Rest = ssh.Marshal(struct{ HostKey []byte }{terminal.PublicKey().Marshal()})
	return client, key, terminal, auth, fingerprints
}

func TestForwardedHostboundWireRoundtrip(t *testing.T) {
	for _, hops := range []int{1, 2, 15} {
		t.Run(fmt.Sprint(hops), func(t *testing.T) {
			rec := &protectedRecorder{allow: true}
			client, key, host, auth, fingerprints := forwardedFixture(t, hops, rec)
			for range 2 {
				data := ssh.Marshal(auth)
				sig, err := client.SignWithFlags(key.PublicKey(), data, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := key.PublicKey().Verify(data, sig); err != nil {
					t.Fatal(err)
				}
			}
			requests := rec.recorded()
			if len(requests) != 2 {
				t.Fatalf("each forwarded signature needs approval; got %d", len(requests))
			}
			for _, req := range requests {
				if !req.Forwarded || req.Caller != nil || req.User != auth.User || req.HostKey != ssh.FingerprintSHA256(host.PublicKey()) || strings.Join(req.ForwardedHosts, " ") != strings.Join(fingerprints, " ") {
					t.Fatalf("wrong terminal or caller attribution: %+v", req)
				}
			}
		})
	}
}

func TestForwardedAuthRequiresExactHostboundTerminal(t *testing.T) {
	for _, name := range []string{"ordinary", "generic", "wrong session", "wrong host", "wrong key", "empty user", "wrong service", "wrong message", "wrong algorithm", "unsigned", "invalid signed boolean", "truncated", "trailing", "oversized"} {
		t.Run(name, func(t *testing.T) {
			rec := &protectedRecorder{allow: true}
			client, key, _, auth, _ := forwardedFixture(t, 1, rec)
			switch name {
			case "ordinary":
				auth.Method, auth.Rest = "publickey", nil
			case "wrong session":
				auth.SessionID = []byte("exchange 0")
			case "wrong host":
				_, other := protectedKey(t)
				auth.Rest = ssh.Marshal(struct{ HostKey []byte }{other.PublicKey().Marshal()})
			case "wrong key":
				auth.PublicKey = []byte("other key")
			case "empty user":
				auth.User = ""
			case "wrong service":
				auth.Service = "other"
			case "wrong message":
				auth.Message = 51
			case "wrong algorithm":
				auth.Algorithm = "other"
			case "unsigned":
				auth.HasSignature = false
			case "trailing":
				auth.Rest = append(auth.Rest, 0)
			}
			data := ssh.Marshal(auth)
			switch name {
			case "generic":
				data = []byte("generic signing")
			case "invalid signed boolean":
				// The signed flag follows SID, message, user, service and method.
				offset := len(ssh.Marshal(struct {
					Session               []byte
					Message               byte
					User, Service, Method string
				}{auth.SessionID, auth.Message, auth.User, auth.Service, auth.Method}))
				data[offset] = 2
			case "truncated":
				data = data[:len(data)-1]
			case "oversized":
				data = make([]byte, 65<<10)
			}
			if sig, err := client.Sign(key.PublicKey(), data); err == nil || sig != nil || len(rec.recorded()) != 0 {
				t.Fatal("invalid forwarded authentication reached approval or signing")
			}
		})
	}
}

func TestForwardingIncompleteAndInvalidChainsCannotSign(t *testing.T) {
	for _, name := range []string{"incomplete", "duplicate", "post terminal", "hop limit", "bad signature", "invalid flag", "trailing", "aggregate bytes"} {
		t.Run(name, func(t *testing.T) {
			rec := &protectedRecorder{allow: true}
			client := protectedClient(t, protected.NewProtected(rec.confirm))
			private, key := protectedKey(t)
			if err := client.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
				t.Fatal(err)
			}
			_, host := protectedKey(t)
			if name == "aggregate bytes" {
				cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, Permissions: ssh.Permissions{Extensions: map[string]string{"padding": strings.Repeat("x", 35<<10)}}}
				if err := cert.SignCert(rand.Reader, host); err != nil {
					t.Fatal(err)
				}
				var err error
				host, err = ssh.NewCertSigner(cert, host)
				if err != nil {
					t.Fatal(err)
				}
			}
			first := protectedBinding(t, host, []byte("first"), name != "post terminal")
			if _, err := client.Extension("session-bind@openssh.com", first); err != nil {
				t.Fatal(err)
			}
			invalid := protectedBinding(t, host, []byte("terminal"), false)
			switch name {
			case "duplicate":
				invalid = first
			case "hop limit":
				for i := 1; i < 16; i++ {
					if _, err := client.Extension("session-bind@openssh.com", protectedBinding(t, host, []byte(fmt.Sprint(i)), true)); err != nil {
						t.Fatal(err)
					}
				}
			case "bad signature":
				invalid[len(invalid)-2] ^= 1
			case "invalid flag":
				invalid[len(invalid)-1] = 2
			case "trailing":
				invalid = append(invalid, 0)
			}
			if name != "incomplete" {
				if _, err := client.Extension("session-bind@openssh.com", invalid); err == nil {
					t.Fatal("invalid binding accepted")
				}
				if _, err := client.Extension("session-bind@openssh.com", protectedBinding(t, host, []byte("recovery"), false)); err == nil {
					t.Fatal("invalid connection recovered")
				}
			}
			auth := protectedUserauth(key.PublicKey(), []byte("first"))
			auth.Method = "publickey-hostbound-v00@openssh.com"
			auth.Rest = ssh.Marshal(struct{ HostKey []byte }{host.PublicKey().Marshal()})
			for _, data := range [][]byte{ssh.Marshal(auth), bytes.Repeat([]byte{1}, 8)} {
				if sig, err := client.Sign(key.PublicKey(), data); err == nil || sig != nil || len(rec.recorded()) != 0 {
					t.Fatal("incomplete or invalid chain reached confirmation")
				}
			}
		})
	}
}

func TestForwardedHostboundDenialCannotSign(t *testing.T) {
	rec := &protectedRecorder{allow: false}
	client, key, _, auth, _ := forwardedFixture(t, 1, rec)
	if sig, err := client.Sign(key.PublicKey(), ssh.Marshal(auth)); err == nil || sig != nil || len(rec.recorded()) != 1 {
		t.Fatal("forwarded denial did not gate signing")
	}
}
