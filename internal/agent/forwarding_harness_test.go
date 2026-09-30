package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	protected "github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// scopedHarnessDialogs stands in for the standard scoped UI boundary. It allows
// one forwarded signature at a time and records each request for assertions.
type scopedHarnessDialogs struct {
	mu       sync.Mutex
	requests []ui.ConfirmRequest
}

func (d *scopedHarnessDialogs) Confirm(_ context.Context, req ui.ConfirmRequest) (bool, error) {
	return false, fmt.Errorf("legacy confirmation called for %q", req.Title)
}

func (d *scopedHarnessDialogs) ConfirmScoped(_ context.Context, req ui.ConfirmRequest) (ui.Confirmation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, req)
	if req.OnceOnly {
		return ui.Confirmation{Allowed: true, Scope: ui.GrantOnce}, nil
	}
	return ui.Confirmation{Allowed: true, Scope: ui.Grant15Minutes}, nil
}

func (d *scopedHarnessDialogs) snapshot() []ui.ConfirmRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]ui.ConfirmRequest(nil), d.requests...)
}

// This joins the real Protected agent protocol to the production Authorizer,
// while replacing only the human UI with a deterministic, one-shot dialog.
func TestForwardingConfirmationHarnessUsesProductionGateAndOnceScope(t *testing.T) {
	dialogs := &scopedHarnessDialogs{}
	authorizer := confirmation.New(dialogs, time.Now)
	protectedAgent := protected.NewProtected(func(ctx context.Context, req protected.SigningRequest) (bool, error) {
		destination := &confirmation.Destination{User: req.User, Host: req.HostKey, HostKey: req.HostKey}
		if req.Forwarded {
			return authorizer.AuthorizeForwarded(ctx, req.Fingerprint, req.Comment, destination, req.ForwardedHosts)
		}
		return authorizer.Authorize(ctx, req.Fingerprint, req.Comment, destination, req.Caller)
	})
	client := protectedClient(t, protectedAgent)
	private, key := protectedKey(t)
	if err := client.Add(sshagent.AddedKey{PrivateKey: private, Comment: "temporary forwarding harness key"}); err != nil {
		t.Fatal(err)
	}

	_, hop := protectedKey(t)
	_, terminal := protectedKey(t)
	fingerprint := ssh.FingerprintSHA256(key.PublicKey())
	destination := &confirmation.Destination{User: "harness-user", Host: "loopback-test", HostKey: ssh.FingerprintSHA256(terminal.PublicKey())}
	// Seed a broader direct lease for the same key, user and terminal host.
	// A forwarded request must still go to its one-shot dialog.
	if allowed, err := authorizer.Authorize(context.Background(), fingerprint, "temporary forwarding harness key", destination, nil); err != nil || !allowed {
		t.Fatalf("seed direct decision: allowed=%v err=%v", allowed, err)
	}

	firstSession, terminalSession := []byte("harness hop session"), []byte("harness terminal session")
	if _, err := client.Extension("session-bind@openssh.com", protectedBinding(t, hop, firstSession, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Extension("session-bind@openssh.com", protectedBinding(t, terminal, terminalSession, false)); err != nil {
		t.Fatal(err)
	}
	userauth := protectedUserauth(key.PublicKey(), terminalSession)
	userauth.User = destination.User
	userauth.Method = "publickey-hostbound-v00@openssh.com"
	userauth.Rest = ssh.Marshal(struct{ HostKey []byte }{terminal.PublicKey().Marshal()})
	data := ssh.Marshal(userauth)
	for range 2 {
		sig, err := client.SignWithFlags(key.PublicKey(), data, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := key.PublicKey().Verify(data, sig); err != nil {
			t.Fatalf("verify harness signature: %v", err)
		}
	}

	// The unbound method on a forwarded connection is rejected before the UI.
	unbound := userauth
	unbound.Method = "publickey"
	unbound.Rest = nil
	if sig, err := client.SignWithFlags(key.PublicKey(), ssh.Marshal(unbound), 0); err == nil || sig != nil {
		t.Fatal("forwarded ordinary publickey request unexpectedly signed")
	}

	requests := dialogs.snapshot()
	if len(requests) != 3 { // one direct lease prompt plus two forwarded prompts
		t.Fatalf("confirmation count = %d, want 3", len(requests))
	}
	if requests[0].OnceOnly || requests[0].Destination != "harness-user @ loopback-test" {
		t.Fatalf("direct prompt was not scoped as expected: %+v", requests[0])
	}
	for i, req := range requests[1:] {
		if !req.OnceOnly || req.Destination != "harness-user @ "+destination.HostKey || req.Boundary != 0 {
			t.Fatalf("forwarded prompt %d is not destination-bound and one-shot: %+v", i, req)
		}
	}
	if len(authorizer.TemporaryDecisions()) != 1 {
		t.Fatalf("forwarded signatures altered direct leases: got %d decisions, want 1", len(authorizer.TemporaryDecisions()))
	}
}

// This opt-in macOS test replaces the remote Docker endpoints with two
// unprivileged, loopback-only OpenSSH servers. All identity material and
// configuration live under one 0700 temporary directory.
func TestLocalOpenSSHTwoHopForwardingHarness(t *testing.T) {
	if os.Getenv("SSH_KEY_CONTROL_RUN_LOCAL_SSHD_HARNESS") != "1" {
		t.Skip("set SSH_KEY_CONTROL_RUN_LOCAL_SSHD_HARNESS=1 to run isolated local sshd hops")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("local sshd harness is for the macOS production agent")
	}
	if os.Geteuid() == 0 {
		t.Fatal("refusing to run local sshd harness as root")
	}
	sshd, err := exec.LookPath("/usr/sbin/sshd")
	if err != nil {
		t.Fatal("macOS sshd unavailable:", err)
	}
	sshPath, err := exec.LookPath("/usr/bin/ssh")
	if err != nil {
		t.Fatal("macOS ssh unavailable:", err)
	}
	userBytes, err := exec.Command("/usr/bin/id", "-un").Output()
	if err != nil {
		t.Fatal(err)
	}
	user := strings.TrimSpace(string(userBytes))
	if user == "" || strings.ContainsAny(user, " \t\r\n") {
		t.Fatalf("unexpected current user %q", user)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(home, ".ssh")
	if info, err := os.Stat(sshDir); err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		t.Fatalf("refusing unsafe or missing SSH config directory %s: %v", sshDir, err)
	}
	dir, err := os.MkdirTemp(sshDir, "skc-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	_, keyPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keySigner, err := ssh.NewSignerFromKey(keyPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, err := ssh.MarshalPrivateKey(keyPrivate, "temporary forwarding test identity")
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(dir, "identity")
	if err := writeHarnessFile(identityPath, pem.EncodeToMemory(privatePEM), 0600); err != nil {
		t.Fatal(err)
	}
	publicPath := identityPath + ".pub"
	if err := writeHarnessFile(publicPath, ssh.MarshalAuthorizedKey(keySigner.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}

	firstPrivate, firstHost := harnessHostKey(t)
	secondPrivate, secondHost := harnessHostKey(t)
	firstPort, secondPort := harnessAvailablePort(t), harnessAvailablePort(t)
	if firstPort == secondPort {
		secondPort = harnessAvailablePort(t)
	}
	authorized := ssh.MarshalAuthorizedKey(keySigner.PublicKey())
	startHarnessSSHD(t, sshd, dir, "first", user, firstPort, firstPrivate, authorized)
	startHarnessSSHD(t, sshd, dir, "second", user, secondPort, secondPrivate, authorized)

	knownHosts := filepath.Join(dir, "known_hosts")
	known := fmt.Sprintf("[127.0.0.1]:%d %s[127.0.0.1]:%d %s", firstPort,
		ssh.MarshalAuthorizedKey(firstHost.PublicKey()), secondPort, ssh.MarshalAuthorizedKey(secondHost.PublicKey()))
	if err := writeHarnessFile(knownHosts, []byte(known), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "ssh_config")
	configText := fmt.Sprintf("Host hop-one\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s\n IdentitiesOnly yes\n PubkeyAuthentication host-bound\n PreferredAuthentications publickey\n StrictHostKeyChecking yes\n UserKnownHostsFile %s\n GlobalKnownHostsFile /dev/null\n UpdateHostKeys no\n ControlMaster no\n ControlPath none\n ControlPersist no\n ProxyJump none\n ProxyCommand none\n\n"+
		"Host hop-two\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s\n IdentitiesOnly yes\n PubkeyAuthentication host-bound\n PreferredAuthentications publickey\n StrictHostKeyChecking yes\n UserKnownHostsFile %s\n GlobalKnownHostsFile /dev/null\n UpdateHostKeys no\n ControlMaster no\n ControlPath none\n ControlPersist no\n ProxyJump none\n ProxyCommand none\n",
		firstPort, user, publicPath, knownHosts, secondPort, user, publicPath, knownHosts)
	if err := writeHarnessFile(config, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}

	dialogs := &scopedHarnessDialogs{}
	authorizer := confirmation.New(dialogs, time.Now)
	protectedAgent := protected.NewProtected(func(ctx context.Context, req protected.SigningRequest) (bool, error) {
		destination := &confirmation.Destination{User: req.User, Host: req.HostKey, HostKey: req.HostKey}
		if req.Forwarded {
			return authorizer.AuthorizeForwarded(ctx, req.Fingerprint, req.Comment, destination, req.ForwardedHosts)
		}
		return authorizer.Authorize(ctx, req.Fingerprint, req.Comment, destination, req.Caller)
	})
	socket := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- protected.ServeListener(agentCtx, listener, protectedAgent) }()
	t.Cleanup(func() {
		stopAgent()
		_ = listener.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("stop protected agent: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("protected agent did not stop")
		}
	})
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		t.Fatal("connect isolated agent socket:", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := sshagent.NewClient(conn).Add(sshagent.AddedKey{PrivateKey: keyPrivate, Comment: "temporary forwarding test identity"}); err != nil {
		t.Fatal("add ephemeral key to isolated agent:", err)
	}

	// Seed a direct hop-two lease. Forwarded auth to the same destination must
	// still invoke the one-shot dialog instead of consuming this cached lease.
	secondDestination := &confirmation.Destination{User: user, Host: "hop-two", HostKey: ssh.FingerprintSHA256(secondHost.PublicKey())}
	if allowed, err := authorizer.Authorize(context.Background(), ssh.FingerprintSHA256(keySigner.PublicKey()), "temporary forwarding test identity", secondDestination, nil); err != nil || !allowed {
		t.Fatalf("seed direct lease: allowed=%v err=%v", allowed, err)
	}

	localEnv := append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	sshPrefix := quoteHarness(sshPath) + " -F " + quoteHarness(config) + " -A"
	remoteUnbound := sshPrefix + " -o PubkeyAuthentication=unbound hop-two printf UNBOUND_SHOULD_NOT_RUN"
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 30*time.Second)
	first := exec.CommandContext(firstCtx, sshPath, "-F", config, "-A", "hop-one", remoteUnbound)
	first.Env = localEnv
	firstOutput, err := first.CombinedOutput()
	cancelFirst()
	if err == nil || strings.Contains(string(firstOutput), "UNBOUND_SHOULD_NOT_RUN") {
		t.Fatalf("unbound second hop unexpectedly succeeded: err=%v\n%s", err, firstOutput)
	}
	if prompts := dialogs.snapshot(); len(prompts) != 2 { // direct seed and direct hop-one auth only
		t.Fatalf("unbound second hop reached the approval UI: got %d prompts, want 2", len(prompts))
	}

	remoteBound := sshPrefix + " hop-two printf FORWARDED_HOP_OK"
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 30*time.Second)
	second := exec.CommandContext(secondCtx, sshPath, "-F", config, "-A", "hop-one", remoteBound)
	second.Env = localEnv
	secondOutput, err := second.CombinedOutput()
	cancelSecond()
	if err != nil {
		t.Fatalf("hostbound two-hop ssh failed: %v\n%s", err, secondOutput)
	}
	if !strings.Contains(string(secondOutput), "FORWARDED_HOP_OK") {
		t.Fatalf("second-hop SSH did not return success marker: %s", secondOutput)
	}
	requests := dialogs.snapshot()
	if len(requests) != 3 {
		t.Fatalf("hostbound forwarded request did not prompt exactly once: got %d prompts, want 3 total", len(requests))
	}
	forwarded := requests[2]
	if !forwarded.OnceOnly || forwarded.Destination != user+" @ "+ssh.FingerprintSHA256(secondHost.PublicKey()) || !strings.Contains(forwarded.Message, ssh.FingerprintSHA256(firstHost.PublicKey())) {
		t.Fatalf("forwarded prompt lost destination/path or once-only scope: %+v", forwarded)
	}
}

func harnessHostKey(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
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

func harnessAvailablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func startHarnessSSHD(t *testing.T, sshd, dir, name, user string, port int, hostPrivate ed25519.PrivateKey, authorized []byte) {
	t.Helper()
	hostBlock, err := ssh.MarshalPrivateKey(hostPrivate, "temporary "+name+" host key")
	if err != nil {
		t.Fatal(err)
	}
	hostKey := filepath.Join(dir, name+"_hostkey")
	if err := writeHarnessFile(hostKey, pem.EncodeToMemory(hostBlock), 0600); err != nil {
		t.Fatal(err)
	}
	authorizedPath := filepath.Join(dir, name+"_authorized_keys")
	if err := writeHarnessFile(authorizedPath, authorized, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, name+"_sshd_config")
	configText := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nStrictModes yes\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nPermitRootLogin no\nAllowUsers %s\nAllowAgentForwarding yes\nAllowTcpForwarding no\nX11Forwarding no\nUsePAM no\nUseDNS no\nPrintMotd no\nPermitUserEnvironment no\nLogLevel VERBOSE\n",
		port, hostKey, filepath.Join(dir, name+".pid"), authorizedPath, user)
	if err := writeHarnessFile(configPath, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(sshd, "-t", "-f", configPath).CombinedOutput(); err != nil {
		t.Fatalf("sshd -t %s failed, no daemon started: %v\n%s", name, err, output)
	}
	cmd := exec.Command(sshd, "-D", "-e", "-f", configPath)
	var output harnessLockedBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start unprivileged loopback sshd %s: %v", name, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Errorf("sshd %s did not stop", name)
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("sshd %s did not listen on loopback; output: %s", name, output.String())
}

type harnessLockedBuffer struct {
	mu    sync.Mutex
	value strings.Builder
}

func (b *harnessLockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.value.Write(data)
}

func (b *harnessLockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.value.String()
}

func writeHarnessFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func quoteHarness(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
