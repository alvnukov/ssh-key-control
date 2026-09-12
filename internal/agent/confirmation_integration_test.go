package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// TestConfirmationIntegration exercises real OpenSSH binaries, not launchd or
// the installed askpass/UI. Every key, configuration file and socket is private
// to the test. The second login cannot fall back to the disk private key.
func TestConfirmationIntegration(t *testing.T) {
	runConfirmationIntegration(t, "publickey", false, "")
}

// Deny ends the login attempt: with the managed publickey-only setting, ssh
// must not fall back to password or any other authentication method.
func TestConfirmationDenialEndsAttempt(t *testing.T) {
	runConfirmationIntegration(t, "publickey,password", false, "")
}

// Password hosts still work with an explicit per-invocation override.
func TestConfirmationPasswordOnlyControl(t *testing.T) {
	runConfirmationIntegration(t, "password", false, "-oPreferredAuthentications=password")
}

func TestProtectedSSHIntegration(t *testing.T) {
	for _, methods := range []string{"publickey", "publickey,password", "password"} {
		override := ""
		if methods == "password" {
			override = "-oPreferredAuthentications=password"
		}
		t.Run(methods, func(t *testing.T) { runConfirmationIntegration(t, methods, true, override) })
	}
}

func runConfirmationIntegration(t *testing.T, authentications string, useProtected bool, passwordOverride string) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires local OpenSSH subprocesses")
	}
	for _, binary := range []string{"/usr/bin/ssh", "/usr/bin/ssh-agent"} {
		if info, err := os.Stat(binary); err != nil || info.Mode()&0111 == 0 {
			t.Skipf("requires executable %s", binary)
		}
	}
	// Keep the Unix socket below Darwin's sockaddr_un path limit. Do not run
	// this test in parallel: Setenv is restored by testing's cleanup.
	t.Setenv("TMPDIR", "/tmp")
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	write := func(name string, data []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	newKey := func() (ssh.Signer, ed25519.PrivateKey) {
		t.Helper()
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return signer, key
	}
	clientSigner, privateKey := newKey()
	hostSigner, _ := newKey()
	// Keep the key comment distinct from the host alias so a substring match
	// cannot mistake the key's label for host context in the confirm argument.
	block, err := ssh.MarshalPrivateKey(privateKey, "fixture-key-comment")
	if err != nil {
		t.Fatal(err)
	}
	identity := write("identity", pem.EncodeToMemory(block), 0600)
	write("identity.pub", ssh.MarshalAuthorizedKey(clientSigner.PublicKey()), 0600)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() == "confirmation-test" && bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("only the generated test key is authorized")
		},
	}
	// A fresh fixture password is used only by the password-only control. It is
	// never taken from the environment, printed, or offered by the denial case.
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password := fmt.Sprintf("%x", passwordBytes)
	var passwordAttempts atomic.Int32
	if strings.Contains(authentications, "password") {
		serverConfig.PasswordCallback = func(meta ssh.ConnMetadata, supplied []byte) (*ssh.Permissions, error) {
			passwordAttempts.Add(1)
			if meta.User() == "confirmation-test" && string(supplied) == password {
				return nil, nil
			}
			return nil, errors.New("only the generated test password is authorized")
		}
	}
	if authentications == "password" {
		serverConfig.PublicKeyCallback = nil
	}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var authenticated atomic.Int32
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Sequential connections suffice here; deadlines bound even failed
			// authentication and unfinished session/channel requests.
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			func() {
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return // A denied second authentication is expected.
				}
				defer server.Close()
				authenticated.Add(1)
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "sessions only")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						var command struct{ Command string }
						ok := request.Type == "exec" && ssh.Unmarshal(request.Payload, &command) == nil && command.Command == "exit 0"
						_ = request.Reply(ok, nil)
						if ok {
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.Close()
							// Let OpenSSH acknowledge channel closure and disconnect.
							// Closing TCP here races its final write on Linux.
							_ = server.Wait()
							return
						}
					}
					_ = channel.Close()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serverDone:
		case <-time.After(11 * time.Second):
			t.Error("loopback SSH server did not stop within its connection deadline")
		}
	})

	socket := filepath.Join(dir, "a")
	promptLog := write("prompts", nil, 0600)
	// NUL-delimited kind/argument pairs preserve the full fixture-only prompt,
	// including embedded newlines. OpenSSH leaves SSH_ASKPASS_PROMPT unset for
	// passwords, so label those by the fixture prompt rather than losing kind.
	askpass := write("askpass", []byte(`#!/bin/sh
kind="${SSH_ASKPASS_PROMPT-}"
case "$1" in
  *password:*) kind=password ;;
esac
printf '%s\000%s\000' "$kind" "$1" >> "$CONFIRMATION_PROMPT_LOG"
if [ "$kind" = password ] && [ -n "${CONFIRMATION_TEST_PASSWORD-}" ]; then
  printf '%s\n' "$CONFIRMATION_TEST_PASSWORD"
  exit 0
fi
exit 1
`), 0700)
	// An allowlist avoids inherited agent, askpass, keychain and SSH settings.
	env := []string{
		"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=" + dir, "TMPDIR=" + dir,
		"SSH_AUTH_SOCK=" + socket, "SSH_ASKPASS=" + askpass,
		"SSH_ASKPASS_REQUIRE=force", "CONFIRMATION_PROMPT_LOG=" + promptLog,
	}
	if useProtected {
		ln, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		protected := agent.NewProtected(func(_ context.Context, req agent.SigningRequest) (bool, error) {
			// The Go test server supports ordinary publickey, not hostbound:
			// this must remain a one-shot request with no reusable destination.
			if req.HostKey != "" || req.User != "" || req.Fingerprint != ssh.FingerprintSHA256(clientSigner.PublicKey()) {
				t.Errorf("ordinary publickey acquired destination authority: %+v", req)
			}
			f, err := os.OpenFile(promptLog, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				return false, err
			}
			defer f.Close()
			_, err = fmt.Fprintf(f, "confirm\x00%s @ 127.0.0.1; key %s; server %s\x00", req.User, req.Fingerprint, req.HostKey)
			return false, err
		})
		done := make(chan error, 1)
		go func() { done <- agent.ServeListener(ctx, ln, protected) }()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("protected agent did not stop")
			}
		})
	} else {
		var agentOutput bytes.Buffer
		agentCommand := exec.CommandContext(ctx, "/usr/bin/ssh-agent", "-D", "-a", socket)
		agentCommand.Env = env
		agentCommand.Dir = dir
		agentCommand.Stdout = &agentOutput
		agentCommand.Stderr = &agentOutput
		agentCommand.WaitDelay = time.Second
		if err := agentCommand.Start(); err != nil {
			t.Fatal(err)
		}
		agentDone := make(chan error, 1)
		go func() { agentDone <- agentCommand.Wait() }()
		t.Cleanup(func() {
			_ = agentCommand.Process.Kill()
			select {
			case <-agentDone:
				t.Logf("isolated ssh-agent output:\n%s", agentOutput.String())
			case <-time.After(3 * time.Second):
				t.Error("isolated ssh-agent did not exit after kill")
			}
		})
	}
	var agentConn net.Conn
	readyDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(readyDeadline) && ctx.Err() == nil {
		agentConn, err = net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if agentConn == nil {
		t.Fatalf("isolated ssh-agent socket was not ready: %v", err)
	}
	t.Cleanup(func() { _ = agentConn.Close() })
	agentClient := sshagent.NewClient(agentConn)
	identities := func() []*sshagent.Key {
		t.Helper()
		if err := agentConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		keys, err := agentClient.List()
		if err != nil {
			t.Fatalf("list isolated agent identities: %v", err)
		}
		return keys
	}
	if keys := identities(); len(keys) != 0 {
		t.Fatalf("new isolated agent already contains %d identities", len(keys))
	}

	port := listener.Addr().(*net.TCPAddr).Port
	knownHosts := write("known_hosts", []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))), 0600)
	passwordAuthentication, batchMode := "no", "yes"
	if strings.Contains(authentications, "password") {
		passwordAuthentication, batchMode = "yes", "no"
	}
	config := write("config", []byte(fmt.Sprintf(`Host isolated-confirmation
    HostName 127.0.0.1
    Port %d
    User confirmation-test
    IdentityFile %q
    IdentityAgent %q
    IdentitiesOnly yes
    PreferredAuthentications %s
    PasswordAuthentication %s
    KbdInteractiveAuthentication no
    BatchMode %s
    NumberOfPasswordPrompts 3
    ControlMaster no
    ControlPath none
    ControlPersist no
    ProxyCommand none
    ProxyJump none
    StrictHostKeyChecking yes
    UserKnownHostsFile %q
    GlobalKnownHostsFile /dev/null
    UpdateHostKeys no
    ConnectTimeout 3
    ConnectionAttempts 1
    RequestTTY no
    IgnoreUnknown UseKeychain
    UseKeychain no
`, port, identity, filepath.Join(dir, "stale-agent"), authentications, passwordAuthentication, batchMode, knownHosts)), 0600)
	if err := agent.PublishSocket(filepath.Join(dir, "ssh-key-control.sock"), socket); err != nil {
		t.Fatal(err)
	}
	if err := (sshconfig.ManagedConfig{Path: config}).Install(); err != nil {
		t.Fatalf("install managed config in temporary directory: %v", err)
	}
	runSSH := func() ([]byte, error) {
		t.Helper()
		commandCtx, stop := context.WithTimeout(ctx, 8*time.Second)
		defer stop()
		args := []string{"-v", "-F", config}
		if passwordOverride != "" {
			args = append(args, passwordOverride)
		}
		command := exec.CommandContext(commandCtx, "/usr/bin/ssh", append(args, "isolated-confirmation", "exit 0")...)
		command.Env = append(append([]string{}, env...), "SSH_AUTH_SOCK="+filepath.Join(dir, "stale-agent"))
		if authentications == "password" {
			command.Env = append(command.Env, "CONFIRMATION_TEST_PASSWORD="+password)
		}
		command.Dir = dir
		command.WaitDelay = time.Second
		output, err := command.CombinedOutput()
		if commandCtx.Err() != nil {
			t.Fatalf("SSH connection timed out: %v\n%s", commandCtx.Err(), output)
		}
		return output, err
	}
	readPrompts := func() (confirmations, passwords int) {
		t.Helper()
		data, err := os.ReadFile(promptLog)
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Split(string(data), "\x00")
		if len(fields)%2 != 1 || fields[len(fields)-1] != "" {
			t.Fatalf("malformed fixture prompt log: %q", data)
		}
		for i := 0; i < len(fields)-1; i += 2 {
			kind, argument := fields[i], fields[i+1]
			t.Logf("askpass kind=%q raw argument=%q", kind, argument)
			switch kind {
			case "confirm":
				confirmations++
				t.Logf("confirm host availability: alias=%t loopback=%t", strings.Contains(argument, "isolated-confirmation"), strings.Contains(argument, "127.0.0.1"))
			case "password":
				passwords++
				if authentications != "password" && confirmations == 0 {
					t.Error("password prompt preceded confirmation denial")
				}
			default:
				t.Errorf("unexpected askpass prompt kind %q: %q", kind, argument)
			}
		}
		t.Logf("prompt counts: confirm=%d password=%d; server password attempts=%d authenticated=%d", confirmations, passwords, passwordAttempts.Load(), authenticated.Load())
		return confirmations, passwords
	}
	if authentications == "password" {
		output, err := runSSH()
		confirmations, passwords := readPrompts()
		if err != nil {
			t.Fatalf("password-only control failed: %v\n%s", err, output)
		}
		if confirmations != 0 || passwords != 1 || passwordAttempts.Load() != 1 || authenticated.Load() != 1 {
			t.Fatal("password-only control must authenticate once using only its generated test password")
		}
		if keys := identities(); len(keys) != 0 {
			t.Fatalf("password-only control unexpectedly added %d agent identities", len(keys))
		}
		return
	}
	if output, err := runSSH(); err != nil {
		t.Fatalf("initial disk-key login failed: %v\n%s", err, output)
	}
	keys := identities()
	if len(keys) != 1 || !bytes.Equal(keys[0].Blob, clientSigner.PublicKey().Marshal()) {
		t.Fatalf("automatic key addition missing or unexpected: got %d identities; want only generated key", len(keys))
	}
	// Leave the public identity available for IdentitiesOnly matching, but no
	// private disk key that could turn a denied agent signature into success.
	if err := os.Remove(identity); err != nil {
		t.Fatal(err)
	}
	write("prompts", nil, 0600) // Observe only the second connection.
	output, secondErr := runSSH()
	confirmations, passwords := readPrompts()
	if confirmations == 0 {
		t.Fatalf("NO CONFIRMATION after automatic key add: second SSH error=%v\n%s", secondErr, output)
	}
	var exitErr *exec.ExitError
	// The managed block restricts ssh to publickey, so a denied key ends the
	// attempt; the server's own advertisement may still list both methods.
	deniedSignal := bytes.Contains(output, []byte("Permission denied (publickey)")) ||
		bytes.Contains(output, []byte("Permission denied (password,publickey)"))
	if !errors.As(secondErr, &exitErr) || exitErr.ExitCode() != 255 || !deniedSignal {
		t.Fatalf("denied confirmation did not cause authentication failure: error=%v\n%s", secondErr, output)
	}
	if got := authenticated.Load(); got != 1 {
		t.Fatalf("server accepted %d authentications; want only the initial disk-key login", got)
	}
	if keys := identities(); len(keys) != 1 || !bytes.Equal(keys[0].Blob, clientSigner.PublicKey().Marshal()) {
		t.Fatal("generated identity disappeared from agent after denied confirmation")
	}
	t.Logf("automatic add retained generated identity; denial failed authentication (exit 255); agent refusal signal=%t", bytes.Contains(output, []byte("agent refused operation")))
	wantPasswords := 0
	if passwords != wantPasswords {
		t.Fatalf("after key denial got %d password prompts, want %d\n%s", passwords, wantPasswords, output)
	}
}
