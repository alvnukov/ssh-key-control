package agent

import (
	"bytes"
	"context"
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// SigningRequest identifies the key and, only for authenticated userauth data,
// its destination. HostKey is the SHA256 fingerprint of the verified server
// public key, never a hostname. Empty User and HostKey mean generic signing.
// Comment is untrusted metadata, not an identity or destination.
type SigningRequest struct {
	Fingerprint, Comment, User, HostKey string
}

// Protected owns an in-memory keyring with no ungated signing interface.
// All connections share keys, lifetimes and lock state, but not destinations.
type Protected struct {
	keyring        sshagent.ExtendedAgent
	confirm        func(context.Context, SigningRequest) (bool, error)
	openManagement func() error
}

// NewProtected creates an agent that requires confirm for every signature.
// It does not cache approvals: any explicit destination lease belongs in the
// callback, which must treat empty destination fields as generic signing.
// A nil callback denies all signing. The callback may run concurrently for
// different connections and should honor its context.
func NewProtected(confirm func(context.Context, SigningRequest) (bool, error)) *Protected {
	return &Protected{keyring: sshagent.NewKeyring().(sshagent.ExtendedAgent), confirm: confirm}
}

// ManageDecisionsExtension only opens a local UI. No authority-changing data
// or snapshots are accepted or returned on the agent socket.
const ManageDecisionsExtension = "manage-decisions@ssh-key-control"

func NewProtectedWithManagement(confirm func(context.Context, SigningRequest) (bool, error), open func() error) *Protected {
	p := NewProtected(confirm)
	p.openManagement = open
	return p
}

// Serve serves one connection until disconnection or cancellation, closing conn
// on return. Only the per-connection wrapper is exposed to the agent protocol.
func (p *Protected) Serve(ctx context.Context, conn net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	transport := &packetTransport{Conn: conn, ctx: ctx, packets: make(chan []byte, 1)}
	done := make(chan struct{})
	go transport.receive(cancel, done)
	defer func() { cancel(); conn.Close(); <-done }()
	return sshagent.ServeAgent(&protectedConnection{owner: p, ctx: ctx,
		trustedLocal: func() bool { return trustedLocalSSH(conn) },
	}, transport)
}

// ServeAgent dispatches requests serially, so binding state belongs solely to
// this connection and needs no shared lock.
type protectedConnection struct {
	owner        *Protected
	ctx          context.Context
	binding      *protectedBinding
	tainted      bool
	trustedLocal func() bool
}

type protectedBinding struct {
	hostKey   ssh.PublicKey
	sessionID []byte
}

// ServeAgent caps wire packets at 16 MiB. Apply a tighter bound before parsing
// destination evidence, and retain at most one bounded session ID and host key.
const maxProtectedContextBytes = 64 << 10

var _ sshagent.ExtendedAgent = (*protectedConnection)(nil)

func (c *protectedConnection) List() ([]*sshagent.Key, error) { return c.owner.keyring.List() }
func (c *protectedConnection) Add(key sshagent.AddedKey) error {
	if len(key.ConstraintExtensions) != 0 {
		return errors.New("agent: unsupported constraint extensions")
	}
	// Confirmation is enforced unconditionally by this wrapper, not keyring.
	key.ConfirmBeforeUse = false
	return c.owner.keyring.Add(key)
}
func (c *protectedConnection) Remove(key ssh.PublicKey) error { return c.owner.keyring.Remove(key) }
func (c *protectedConnection) RemoveAll() error               { return c.owner.keyring.RemoveAll() }
func (c *protectedConnection) Lock(passphrase []byte) error   { return c.owner.keyring.Lock(passphrase) }
func (c *protectedConnection) Unlock(passphrase []byte) error {
	return c.owner.keyring.Unlock(passphrase)
}
func (c *protectedConnection) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("agent: exporting signers is forbidden")
}
func (c *protectedConnection) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}
func (c *protectedConnection) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	if c.tainted {
		return nil, errors.New("agent: invalid session binding")
	}
	if c.owner.confirm == nil {
		return nil, errors.New("agent: confirmation unavailable")
	}
	keys, err := c.List()
	if err != nil {
		return nil, err
	}
	for _, candidate := range keys {
		if !bytes.Equal(candidate.Blob, key.Marshal()) {
			continue
		}
		actual, err := ssh.ParsePublicKey(candidate.Blob)
		if err != nil {
			return nil, err
		}
		req := SigningRequest{Fingerprint: ssh.FingerprintSHA256(actual), Comment: candidate.Comment}
		var localOnly bool
		req.User, req.HostKey, localOnly = c.destination(actual, data)
		allowed, err := c.owner.confirm(c.ctx, req)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, errors.New("agent: signing denied")
		}
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}
		// A peer may exit or change while the dialog is open. Never use a
		// local-only decision after its original process loses attestation.
		if localOnly && (c.trustedLocal == nil || !c.trustedLocal()) {
			return nil, errors.New("agent: local SSH client is no longer trusted")
		}
		// The private keyring rechecks lock state and lifetime after confirmation.
		return c.owner.keyring.SignWithFlags(actual, data, flags)
	}
	return nil, errors.New("agent: key unavailable")
}

// Only a single direct, nonforwarded binding is supported. Any malformed,
// forwarded or additional binding (even a duplicate) permanently forbids
// signing on this connection. We deliberately do not interpret binding chains.
func (c *protectedConnection) Extension(name string, contents []byte) ([]byte, error) {
	if name == ManageDecisionsExtension {
		if len(contents) != 0 || c.tainted || c.binding != nil || c.owner.openManagement == nil {
			return nil, sshagent.ErrExtensionUnsupported
		}
		return nil, c.owner.openManagement()
	}
	if name != "session-bind@openssh.com" {
		return nil, sshagent.ErrExtensionUnsupported
	}
	if c.tainted || c.binding != nil {
		c.tainted = true
		return nil, errors.New("agent: repeated session binding")
	}
	c.tainted = true // Fail closed even if a later valid binding is attempted.
	if len(contents) > maxProtectedContextBytes {
		return nil, errors.New("agent: session binding too large")
	}
	var wire struct {
		HostKey, SessionID, Signature []byte
		Forwarding                    byte
	}
	if err := ssh.Unmarshal(contents, &wire); err != nil {
		return nil, err
	}
	if wire.Forwarding != 0 || len(wire.SessionID) == 0 || len(wire.SessionID) > 128 {
		return nil, errors.New("agent: unsupported session binding")
	}
	host, err := ssh.ParsePublicKey(wire.HostKey)
	if err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(wire.Signature, &sig); err != nil {
		return nil, err
	}
	if err := host.Verify(wire.SessionID, &sig); err != nil {
		return nil, err
	}
	c.binding = &protectedBinding{hostKey: host, sessionID: bytes.Clone(wire.SessionID)}
	c.tainted = false
	return nil, nil
}

// destination extracts authority only from a complete, matching userauth
// payload. All other data stays generic; a previous scoped request grants no
// authority to a subsequent request on the same connection.
func (c *protectedConnection) destination(key ssh.PublicKey, data []byte) (string, string, bool) {
	if c.binding == nil || len(data) > maxProtectedContextBytes {
		return "", "", false
	}
	var auth struct {
		SessionID             []byte
		Message               byte
		User, Service, Method string
		HasSignature          byte
		Algorithm             string
		PublicKey             []byte
		Rest                  []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data, &auth); err != nil {
		return "", "", false
	}
	if !bytes.Equal(auth.SessionID, c.binding.sessionID) || auth.Message != 50 ||
		auth.User == "" || auth.Service != "ssh-connection" || auth.HasSignature != 1 ||
		!bytes.Equal(auth.PublicKey, key.Marshal()) || !protectedAuthAlgorithm(key.Type(), auth.Algorithm) {
		return "", "", false
	}
	switch auth.Method {
	// Hostbound userauth is destination-bound even for an untrusted client.
	// Ordinary publickey is accepted only from an attested local OS SSH
	// client, using its verified, direct session binding.
	case "publickey-hostbound-v00@openssh.com":
		var bound struct{ HostKey []byte }
		if err := ssh.Unmarshal(auth.Rest, &bound); err != nil {
			return "", "", false
		}
		if !bytes.Equal(bound.HostKey, c.binding.hostKey.Marshal()) {
			return "", "", false
		}
	case "publickey":
		if len(auth.Rest) != 0 || c.trustedLocal == nil || !c.trustedLocal() {
			return "", "", false
		}
		return auth.User, ssh.FingerprintSHA256(c.binding.hostKey), true
	default:
		return "", "", false
	}
	return auth.User, ssh.FingerprintSHA256(c.binding.hostKey), false
}

func protectedAuthAlgorithm(keyType, algorithm string) bool {
	if keyType == algorithm {
		return true
	}
	switch keyType {
	case ssh.KeyAlgoRSA:
		return algorithm == ssh.KeyAlgoRSASHA256 || algorithm == ssh.KeyAlgoRSASHA512
	case ssh.CertAlgoRSAv01:
		return algorithm == ssh.CertAlgoRSASHA256v01 || algorithm == ssh.CertAlgoRSASHA512v01
	}
	return false
}
