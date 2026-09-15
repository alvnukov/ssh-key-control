package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// keyAgent is the protected agent as these commands see it: something on the
// managed socket that can be asked what it holds and told to let go.
type keyAgent struct{ keyring sshagent.Agent }

// serveAgent puts a keyring on the socket the commands dial. The socket lives
// in a short directory of its own: a Unix socket path is limited to about a
// hundred characters, which a test's own temporary directory can exceed.
func serveAgent(t *testing.T, sshConfig string) *keyAgent {
	t.Helper()
	held := &keyAgent{keyring: sshagent.NewKeyring()}
	listener, err := net.Listen("unix", filepath.Join(filepath.Dir(sshConfig), "ssh-key-control.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = sshagent.ServeAgent(held.keyring, conn)
			}()
		}
	}()
	return held
}

func (k *keyAgent) fingerprints(t *testing.T) []string {
	t.Helper()
	loaded, err := k.keyring.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found []string
	for _, key := range loaded {
		found = append(found, ssh.FingerprintSHA256(key))
	}
	return found
}

// keyFile writes a private key where OpenSSH would keep one, and answers with
// its fingerprint so a test can say which key it means.
func keyFile(t *testing.T, dir, name, passphrase string) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block := &pem.Block{}
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(private, name)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(private, name, []byte(passphrase))
	}
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey())
}

// sshDir replaces the harness's config path with one short enough to hold a
// socket, and reports the directory the keys and the socket live in.
func sshDir(t *testing.T, h *harness) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "skc")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h.app.SSHConfig = filepath.Join(dir, "config")
	return dir
}

// loader stands in for ssh-add and records what it was told to do with which
// environment, because that environment is what sends the passphrase prompt to
// our own dialog instead of to whatever terminal happens to be attached.
type loader struct {
	env, paths []string
	calls      int
	output     string
	err        error
}

func (l *loader) install(h *harness) {
	h.app.SSHAdd = func(_ context.Context, env, paths []string) (string, error) {
		l.calls++
		l.env, l.paths = env, paths
		return l.output, l.err
	}
}

func (l *loader) value(name string) string {
	for _, entry := range l.env {
		if key, value, ok := strings.Cut(entry, "="); ok && key == name {
			return value
		}
	}
	return ""
}

func TestKeysNeedsToBeToldWhetherToLoadOrUnload(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"keys"}, {"keys", "reload"}, {"keys", "load", "--all"}} {
		if code := h.run(args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
}

func TestKeysListNamesEveryKeyTheAgentHolds(t *testing.T) {
	h := newHarness(t)
	sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	if code := h.run("keys", "list"); code != ExitOK || !strings.Contains(h.out.String(), "no keys") {
		t.Fatalf("empty agent: %d, %q", code, h.out.String())
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: &private, Comment: "work"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if code := h.run("keys", "list"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	line := h.out.String()
	if !strings.Contains(line, held.fingerprints(t)[0]) || !strings.Contains(line, "work") {
		t.Errorf("list = %q, want the fingerprint and the comment", line)
	}
}

func TestKeysListReportsAnAgentThatIsNotRunningRatherThanFailing(t *testing.T) {
	h := newHarness(t)
	sshDir(t, h)
	// The menu asks this every time it opens; a stopped agent is an answer.
	if code := h.run("keys", "list", "--json"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	var listing keyListing
	if err := json.Unmarshal([]byte(h.out.String()), &listing); err != nil {
		t.Fatalf("decode %q: %v", h.out.String(), err)
	}
	if listing.Available || len(listing.Keys) != 0 {
		t.Errorf("listing = %+v, want an unavailable agent holding nothing", listing)
	}
	held := serveAgent(t, h.app.SSHConfig)
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	_ = held.keyring.Add(sshagent.AddedKey{PrivateKey: &private, Comment: "work"})
	if code := h.run("keys", "list", "--json"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if err := json.Unmarshal([]byte(h.out.String()), &listing); err != nil {
		t.Fatalf("decode %q: %v", h.out.String(), err)
	}
	if !listing.Available || len(listing.Keys) != 1 || listing.Keys[0].Fingerprint != held.fingerprints(t)[0] {
		t.Errorf("listing = %+v, want the one key the agent holds", listing)
	}
	if listing.Keys[0].Comment != "work" || !strings.Contains(listing.Keys[0].Algorithm, "ed25519") {
		t.Errorf("entry = %+v, want the comment and the algorithm", listing.Keys[0])
	}
}

func TestKeysLoadSendsThePassphrasePromptToOurOwnDialog(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	serveAgent(t, h.app.SSHConfig)
	keyFile(t, dir, "id_ed25519", "secret")
	// Nothing a caller exported may redirect where the passphrase is typed.
	h.env["SSH_ASKPASS"] = "/tmp/impostor"
	h.env["SSH_AUTH_SOCK"] = "/tmp/someone-elses-agent"
	h.env["HOME"] = "/Users/me"
	h.env["DISPLAY"] = ":0"
	run := &loader{output: "Identity added: " + filepath.Join(dir, "id_ed25519")}
	run.install(h)
	if code := h.run("keys", "load"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if run.value("SSH_ASKPASS") != exe {
		t.Errorf("SSH_ASKPASS = %q, want this program", run.value("SSH_ASKPASS"))
	}
	if run.value("SSH_ASKPASS_REQUIRE") != "force" {
		t.Errorf("SSH_ASKPASS_REQUIRE = %q, want the dialog even from a terminal", run.value("SSH_ASKPASS_REQUIRE"))
	}
	if want := filepath.Join(dir, "ssh-key-control.sock"); run.value("SSH_AUTH_SOCK") != want {
		t.Errorf("SSH_AUTH_SOCK = %q, want the protected agent at %q", run.value("SSH_AUTH_SOCK"), want)
	}
	if run.value("HOME") != "/Users/me" || run.value("DISPLAY") != "" {
		t.Errorf("environment = %v, want only what loading a key needs", run.env)
	}
	if out := h.out.String(); !strings.Contains(out, "Identity added") {
		t.Errorf("output = %q, want what ssh-add said", out)
	}
}

func TestKeysLoadOffersOnlyTheKeysTheAgentDoesNotAlreadyHold(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	keyFile(t, dir, "id_ed25519", "")
	keyFile(t, dir, "id_work", "")
	// Everything else in ~/.ssh is not a key and is not offered as one.
	for name, body := range map[string]string{
		"id_ed25519.pub": "ssh-ed25519 AAAA nobody\n",
		"known_hosts":    "example.com ssh-ed25519 AAAA\n",
		"config":         "Host *\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := &loader{}
	run.install(h)
	if code := h.run("keys", "load"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if len(run.paths) != 2 {
		t.Fatalf("offered %v, want both private keys and nothing else", run.paths)
	}
	// Loading what is already there would ask for its passphrase for nothing,
	// which is exactly what pressing a menu item twice must not do.
	data, err := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: key, Comment: "id_ed25519"}); err != nil {
		t.Fatal(err)
	}
	if code := h.run("keys", "load"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if len(run.paths) != 1 || filepath.Base(run.paths[0]) != "id_work" {
		t.Errorf("offered %v, want only the key the agent lacks", run.paths)
	}
	// With nothing left to load, ssh-add is not run at all.
	if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: mustKey(t, filepath.Join(dir, "id_work")), Comment: "id_work"}); err != nil {
		t.Fatal(err)
	}
	before := run.calls
	if code := h.run("keys", "load"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if run.calls != before {
		t.Errorf("ssh-add ran %d more times with nothing to load", run.calls-before)
	}
	if out := h.out.String(); !strings.Contains(out, "already holds 2") {
		t.Errorf("output = %q, want what the agent already holds", out)
	}
}

func mustKey(t *testing.T, path string) interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// An encrypted key keeps its public half in the clear, so a key already in the
// agent is recognised without ever asking for its passphrase.
func TestKeysLoadSkipsALoadedKeyWithoutAskingForItsPassphrase(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	keyFile(t, dir, "id_ed25519", "secret")
	data, err := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.ParseRawPrivateKeyWithPassphrase(data, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: key, Comment: "id_ed25519"}); err != nil {
		t.Fatal(err)
	}
	run := &loader{}
	run.install(h)
	if code := h.run("keys", "load"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if run.calls != 0 {
		t.Errorf("ssh-add ran for a key the agent already holds: %v", run.paths)
	}
}

func TestKeysLoadTakesTheKeyFilesItIsGiven(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	serveAgent(t, h.app.SSHConfig)
	keyFile(t, dir, "id_ed25519", "")
	elsewhere := filepath.Join(t.TempDir(), "deploy")
	keyFile(t, filepath.Dir(elsewhere), "deploy", "")
	run := &loader{}
	run.install(h)
	if code := h.run("keys", "load", elsewhere); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if len(run.paths) != 1 || run.paths[0] != elsewhere {
		t.Errorf("offered %v, want only the key that was named", run.paths)
	}
	if code := h.run("keys", "load", filepath.Join(dir, "missing")); code == ExitOK {
		t.Errorf("a key that is not there was loaded anyway: %q", h.out.String())
	}
}

func TestKeysLoadSaysSoWhenThereIsNothingToLoad(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	serveAgent(t, h.app.SSHConfig)
	run := &loader{}
	run.install(h)
	if code := h.run("keys", "load"); code != ExitFailure || !strings.Contains(h.err.String(), dir) {
		t.Errorf("empty directory: %d, %q", code, h.err.String())
	}
	if run.calls != 0 {
		t.Errorf("ssh-add ran with no keys to load")
	}
}

func TestKeysLoadReportsWhatSSHAddSaidWhenItFails(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	serveAgent(t, h.app.SSHConfig)
	keyFile(t, dir, "id_ed25519", "secret")
	run := &loader{output: "Bad passphrase, try again", err: errSSHAdd}
	run.install(h)
	if code := h.run("keys", "load"); code != ExitFailure {
		t.Fatalf("exit %d, want a failure", code)
	}
	if !strings.Contains(h.out.String(), "Bad passphrase") {
		t.Errorf("output = %q, want what ssh-add said", h.out.String())
	}
}

func TestKeysLoadCannotRunWithoutAnAgentToLoadInto(t *testing.T) {
	h := newHarness(t)
	sshDir(t, h)
	run := &loader{}
	run.install(h)
	if code := h.run("keys", "load"); code != ExitFailure || !strings.Contains(h.err.String(), "unavailable") {
		t.Errorf("no agent: %d, %q", code, h.err.String())
	}
	if run.calls != 0 {
		t.Errorf("ssh-add ran with no agent to load into")
	}
}

func TestKeysUnloadTakesEveryKeyBackOut(t *testing.T) {
	h := newHarness(t)
	sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	for _, comment := range []string{"work", "home"} {
		_, private, _ := ed25519.GenerateKey(rand.Reader)
		if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: &private, Comment: comment}); err != nil {
			t.Fatal(err)
		}
	}
	if code := h.run("keys", "unload"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if out := h.out.String(); !strings.Contains(out, "removed 2") {
		t.Errorf("output = %q, want how many keys were removed", out)
	}
	if left := held.fingerprints(t); len(left) != 0 {
		t.Errorf("the agent still holds %v", left)
	}
	if code := h.run("keys", "unload"); code != ExitOK || !strings.Contains(h.out.String(), "no keys") {
		t.Errorf("second unload: %d, %q", code, h.out.String())
	}
}

// listing is what the key window reads: one row per key this Mac knows about.
func listing(t *testing.T, h *harness, args ...string) keyListing {
	t.Helper()
	if code := h.run(append([]string{"keys", "list", "--json"}, args...)...); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	var found keyListing
	if err := json.Unmarshal([]byte(h.out.String()), &found); err != nil {
		t.Fatalf("decode %q: %v", h.out.String(), err)
	}
	return found
}

func rowFor(t *testing.T, found keyListing, path string) keyEntry {
	t.Helper()
	for _, row := range found.Keys {
		if row.Path == path {
			return row
		}
	}
	t.Fatalf("no row for %s in %+v", path, found.Keys)
	return keyEntry{}
}

// legacyKeyFile writes a key in the format OpenSSH used before it had one of
// its own: encrypted end to end, with no public half to read out of it.
func legacyKeyFile(t *testing.T, dir, name string) string {
	t.Helper()
	body := make([]byte, 128)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF",
		},
		Bytes: body,
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// publicHalfFile writes the public half OpenSSH leaves beside a key it made,
// and answers with the fingerprint and the private half behind it.
func publicHalfFile(t *testing.T, path, comment string) (string, interface{}) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " " + comment + "\n"
	if err := os.WriteFile(path+".pub", []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), &private
}

// The window shows one list: every key this Mac has, and whether the agent
// holds it. A key that is both on disk and in the agent is one row, not two.
func TestKeysListShowsWhatIsLoadedBesideWhatCouldBe(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	loaded := keyFile(t, dir, "id_ed25519", "")
	idle := keyFile(t, dir, "id_work", "secret")
	if err := held.keyring.Add(sshagent.AddedKey{
		PrivateKey: mustKey(t, filepath.Join(dir, "id_ed25519")), Comment: "id_ed25519"}); err != nil {
		t.Fatal(err)
	}
	// A key put into the agent by something else is shown too: it can be
	// unloaded here even though no file of ours is behind it.
	_, elsewhere, _ := ed25519.GenerateKey(rand.Reader)
	if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: &elsewhere, Comment: "yubikey"}); err != nil {
		t.Fatal(err)
	}
	found := listing(t, h)
	if !found.Available || len(found.Keys) != 3 {
		t.Fatalf("listing = %+v, want both key files and the key held on its own", found)
	}
	if row := rowFor(t, found, filepath.Join(dir, "id_ed25519")); !row.Loaded || row.Fingerprint != loaded || row.Encrypted {
		t.Errorf("loaded key = %+v, want it named, marked loaded and needing no passphrase", row)
	}
	if row := rowFor(t, found, filepath.Join(dir, "id_work")); row.Loaded || row.Fingerprint != idle || !row.Encrypted {
		t.Errorf("idle key = %+v, want it named, not loaded and needing a passphrase", row)
	}
	orphan := rowFor(t, found, "")
	if !orphan.Loaded || orphan.Comment != "yubikey" || orphan.Fingerprint == "" {
		t.Errorf("key held without a file = %+v, want it listed as loaded", orphan)
	}
	// The plain listing says the same thing in one line per key.
	if code := h.run("keys", "list"); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "in agent") || !strings.Contains(out, "not loaded") || !strings.Contains(out, "yubikey") {
		t.Errorf("list = %q, want each key and whether the agent holds it", out)
	}
}

// A key does not have to live in ~/.ssh. The ones the SSH config names are
// meant to be used, and the ones a person adds by hand were chosen outright.
func TestKeysListFindsKeysNamedInTheConfigAndGivenByHand(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	serveAgent(t, h.app.SSHConfig)
	home := t.TempDir()
	h.env["HOME"] = home
	elsewhere := t.TempDir()
	keyFile(t, home, "from-config", "")
	keyFile(t, elsewhere, "by-hand", "")
	config := "Host work\n  IdentityFile ~/from-config\n  IdentityFile ~/from-config.pub\n" +
		"# IdentityFile ~/commented-out\nHost *\n  IdentityAgent " + dir + "/ssh-key-control.sock\n"
	if err := os.WriteFile(h.app.SSHConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	byHand := filepath.Join(elsewhere, "by-hand")
	found := listing(t, h, byHand)
	paths := map[string]bool{}
	for _, row := range found.Keys {
		paths[row.Path] = true
	}
	if !paths[filepath.Join(home, "from-config")] {
		t.Errorf("listing = %+v, want the key the SSH config names", found.Keys)
	}
	if !paths[byHand] {
		t.Errorf("listing = %+v, want the key given on the command line", found.Keys)
	}
	if len(found.Keys) != 2 {
		t.Errorf("listing = %+v, want only the two keys that exist", found.Keys)
	}
}

// The public half OpenSSH leaves beside a key names it without its passphrase,
// which is the only way to say anything about a key in the older format.
func TestKeysListNamesAnEncryptedKeyFromThePublicHalfBesideIt(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	path := legacyKeyFile(t, dir, "zz.pem")
	fingerprint, private := publicHalfFile(t, path, "deploy key")
	row := rowFor(t, listing(t, h), path)
	if row.Fingerprint != fingerprint || row.Comment != "deploy key" || !row.Encrypted || row.Loaded {
		t.Errorf("row = %+v, want it named from the public half and not loaded", row)
	}
	if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: private, Comment: path}); err != nil {
		t.Fatal(err)
	}
	found := listing(t, h)
	if len(found.Keys) != 1 {
		t.Fatalf("listing = %+v, want one row for one key", found.Keys)
	}
	if row := rowFor(t, found, path); !row.Loaded || row.Fingerprint != fingerprint {
		t.Errorf("row = %+v, want the same key marked loaded", row)
	}
}

// Without a public half there is nothing to compute from the file, so the name
// ssh-add gives the key it read is the only link back to it.
func TestKeysListRecognisesALoadedKeyItCannotReadByTheNameSSHAddGaveIt(t *testing.T) {
	h := newHarness(t)
	dir := sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	path := legacyKeyFile(t, dir, "zz.pem")
	if row := rowFor(t, listing(t, h), path); row.Fingerprint != "" || !row.Encrypted || row.Loaded {
		t.Errorf("row = %+v, want an unnamed key that is not loaded", row)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: &private, Comment: path}); err != nil {
		t.Fatal(err)
	}
	found := listing(t, h)
	if len(found.Keys) != 1 {
		t.Fatalf("listing = %+v, want the file and the key it was loaded from as one row", found.Keys)
	}
	if row := rowFor(t, found, path); !row.Loaded || row.Fingerprint == "" {
		t.Errorf("row = %+v, want it loaded and named by what the agent holds", row)
	}
}

func TestKeysUnloadTakesOutOnlyTheKeyItIsGiven(t *testing.T) {
	h := newHarness(t)
	sshDir(t, h)
	held := serveAgent(t, h.app.SSHConfig)
	for _, comment := range []string{"work", "home"} {
		_, private, _ := ed25519.GenerateKey(rand.Reader)
		if err := held.keyring.Add(sshagent.AddedKey{PrivateKey: &private, Comment: comment}); err != nil {
			t.Fatal(err)
		}
	}
	going := held.fingerprints(t)[0]
	if code := h.run("keys", "unload", going); code != ExitOK {
		t.Fatalf("exit %d: %q", code, h.err.String())
	}
	if out := h.out.String(); !strings.Contains(out, "removed 1 key") {
		t.Errorf("output = %q, want the one key it took out", out)
	}
	left := held.fingerprints(t)
	if len(left) != 1 || left[0] == going {
		t.Errorf("the agent holds %v, want only the key that was not named", left)
	}
	// Asking for a key the agent does not hold leaves the agent as it is: the
	// state asked for is the state it is already in.
	if code := h.run("keys", "unload", going); code != ExitOK || !strings.Contains(h.out.String(), "does not hold") {
		t.Errorf("unloading a key that is gone: %d, %q", code, h.out.String())
	}
	if len(held.fingerprints(t)) != 1 {
		t.Errorf("the agent lost a key nobody named")
	}
}
