package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// SSHAdd is OpenSSH's own key loader. Loading a key means decrypting it, which
// means passphrases, remembered secrets, hardware tokens and every key format
// OpenSSH grew over the years; none of that is worth reimplementing here.
const SSHAdd = "/usr/bin/ssh-add"

// A private key file is a few kilobytes. Anything larger in ~/.ssh is something
// else, and is not read.
const maxKeyFileBytes = 1 << 20

// errSSHAdd is what a key that would not load looks like. ssh-add has already
// said why on its own output, which is passed through rather than restated.
var errSSHAdd = errors.New("ssh-add could not load every key")

// keysUsage is the second word of the command, because a key is either put into
// the agent or taken out of it, and both are worth naming.
const keysUsage = "keys takes load, unload or list"

func (a *App) keys(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return &usageError{keysUsage}
	}
	switch args[0] {
	case "load":
		return a.loadKeys(ctx, args[1:])
	case "unload":
		return a.unloadKeys(ctx, args[1:])
	case "list":
		return a.listKeys(ctx, args[1:])
	}
	return &usageError{keysUsage}
}

// agentKeys dials the protected agent. Every keys command needs it: the agent
// is the only place these keys live, and it holds them in memory alone.
func (a *App) agentKeys(ctx context.Context) (sshagent.ExtendedAgent, net.Conn, error) {
	if a.SSHConfig == "" {
		return nil, nil, errors.New("cannot determine the home directory")
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", (sshconfig.ManagedConfig{Path: a.SSHConfig}).SocketPath())
	if err != nil {
		return nil, nil, errors.New("the protected SSH agent is unavailable")
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return sshagent.NewClient(conn), conn, nil
}

// keyListing is what the key window reads: one row per key this Mac knows
// about, whether the agent holds it or it is only a file on disk. Fingerprints,
// comments and paths are public; nothing secret leaves the agent, which cannot
// export a key at all.
type keyListing struct {
	Available bool       `json:"available"`
	Keys      []keyEntry `json:"keys"`
}

type keyEntry struct {
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	Comment     string `json:"comment"`
	// Path is the key file this row can be loaded from. Empty means the agent
	// holds a key whose file is not among the ones we know about.
	Path      string `json:"path"`
	Loaded    bool   `json:"loaded"`
	Encrypted bool   `json:"encrypted"`
}

func (a *App) listKeys(ctx context.Context, args []string) error {
	asJSON := false
	var extra []string
	for _, arg := range args {
		if arg == "--json" {
			asJSON = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return &usageError{"keys list takes key files and --json"}
		}
		extra = append(extra, arg)
	}
	listing := keyListing{Keys: []keyEntry{}}
	var held []*sshagent.Key
	client, conn, err := a.agentKeys(ctx)
	if err == nil {
		defer conn.Close()
		if held, err = client.List(); err != nil {
			return err
		}
		listing.Available = true
	}
	listing.Keys = a.keyRows(held, extra)
	if asJSON {
		return json.NewEncoder(a.Stdout).Encode(listing)
	}
	if !listing.Available {
		// The keys on disk are still worth listing: they are what could be
		// loaded once the agent is back.
		fmt.Fprintln(a.Stdout, "the protected SSH agent is not running")
	}
	if len(listing.Keys) == 0 {
		fmt.Fprintln(a.Stdout, "no keys in the agent and no key files found")
		return nil
	}
	for _, key := range listing.Keys {
		state := "not loaded"
		if key.Loaded {
			state = "in agent"
		}
		fmt.Fprintf(a.Stdout, "%-10s %s %s %s\n", state, orDash(key.Fingerprint), orDash(key.Algorithm), key.where())
	}
	return nil
}

// where names the key the way a person would: by the file it lives in, falling
// back to the comment the agent knows it by.
func (e keyEntry) where() string {
	if e.Path == "" {
		return e.Comment
	}
	if e.Comment != "" && e.Comment != e.Path && e.Comment != filepath.Base(e.Path) {
		return e.Path + " (" + e.Comment + ")"
	}
	return e.Path
}

// keyRows merges what the agent holds with the key files this Mac has, so one
// list answers both questions the key window asks: what is loaded, and what
// could be loaded. A key file the agent already holds is one row, not two.
func (a *App) keyRows(held []*sshagent.Key, extra []string) []keyEntry {
	agentKeys := make([]*sshagent.Key, 0, len(held))
	seen := make(map[string]bool, len(held))
	for _, key := range held {
		fingerprint := ssh.FingerprintSHA256(key)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		agentKeys = append(agentKeys, key)
	}
	used := make([]bool, len(agentKeys))
	rows := []keyEntry{}
	for _, path := range candidateKeyFiles(a.SSHConfig, a.Getenv("HOME"), extra) {
		data, err := readKeyFile(path)
		if err != nil {
			continue
		}
		row := keyEntry{Path: path, Encrypted: isEncrypted(data)}
		if public, comment, ok := publicKeyFor(path, data); ok {
			row.Fingerprint = ssh.FingerprintSHA256(public)
			row.Algorithm = public.Type()
			row.Comment = comment
		}
		for index, key := range agentKeys {
			if used[index] || !matches(row, key, path) {
				continue
			}
			used[index] = true
			row.Loaded = true
			row.Fingerprint = ssh.FingerprintSHA256(key)
			row.Algorithm = key.Format
			row.Comment = key.Comment
			break
		}
		rows = append(rows, row)
	}
	for index, key := range agentKeys {
		if used[index] {
			continue
		}
		rows = append(rows, keyEntry{
			Fingerprint: ssh.FingerprintSHA256(key),
			Algorithm:   key.Format,
			Comment:     key.Comment,
			Loaded:      true,
		})
	}
	return rows
}

// matches decides whether an agent key came from this key file. A fingerprint
// settles it. The older encrypted formats keep no public half in the clear, so
// nothing can be computed from the file without its passphrase; for those,
// ssh-add's own habit of naming a key after the file it read is the only link
// there is, and it is used only when there is no fingerprint to go by.
func matches(row keyEntry, key *sshagent.Key, path string) bool {
	if row.Fingerprint != "" {
		return row.Fingerprint == ssh.FingerprintSHA256(key)
	}
	return key.Comment == path || key.Comment == filepath.Base(path)
}

// candidateKeyFiles is every key this Mac could load: the ones OpenSSH would
// find in ~/.ssh, the ones named by IdentityFile in its config, and the ones
// the person added by hand. Only files that really are private keys survive.
func candidateKeyFiles(sshConfig, home string, extra []string) []string {
	dir := filepath.Dir(sshConfig)
	if home == "" {
		home = filepath.Dir(dir)
	}
	seen := map[string]bool{}
	found := []string{}
	for _, list := range [][]string{privateKeyFiles(dir), identityFiles(sshConfig, dir, home), extra} {
		for _, path := range list {
			path = filepath.Clean(path)
			if seen[path] || !filepath.IsAbs(path) {
				continue
			}
			seen[path] = true
			if data, err := readKeyFile(path); err == nil && isPrivateKey(data) {
				found = append(found, path)
			}
		}
	}
	sort.Strings(found)
	return found
}

// identityFiles reads the IdentityFile lines out of the SSH config. A key named
// there is one the person means to use, even when it lives outside ~/.ssh.
func identityFiles(configPath, dir, home string) []string {
	data, err := readKeyFile(configPath)
	if err != nil {
		return nil
	}
	var found []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, value, ok := strings.Cut(strings.ReplaceAll(line, "=", " "), " ")
		if !ok || !strings.EqualFold(keyword, "IdentityFile") {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"`)
		if value == "" || strings.HasSuffix(value, ".pub") {
			continue
		}
		switch {
		case value == "~":
			value = home
		case strings.HasPrefix(value, "~/"):
			value = filepath.Join(home, value[2:])
		case strings.HasPrefix(value, "%d/"):
			value = filepath.Join(home, value[3:])
		case !filepath.IsAbs(value):
			value = filepath.Join(dir, value)
		}
		found = append(found, value)
	}
	return found
}

// unloadKeys takes keys back out of the agent: the ones named by fingerprint,
// or every one of them when nothing is named. A key that is already gone is not
// a failure — the agent is in the state that was asked for.
func (a *App) unloadKeys(ctx context.Context, args []string) error {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			return &usageError{"keys unload takes key fingerprints"}
		}
	}
	client, conn, err := a.agentKeys(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	loaded, err := client.List()
	if err != nil {
		return err
	}
	if len(loaded) == 0 {
		fmt.Fprintln(a.Stdout, "the agent holds no keys")
		return nil
	}
	if len(args) == 0 {
		if err := client.RemoveAll(); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "removed %d %s from the agent\n", len(loaded), plural(len(loaded), "key", "keys"))
		return nil
	}
	removed := 0
	for _, wanted := range args {
		var target *sshagent.Key
		for _, key := range loaded {
			if ssh.FingerprintSHA256(key) == wanted {
				target = key
				break
			}
		}
		if target == nil {
			fmt.Fprintf(a.Stdout, "the agent does not hold %s\n", wanted)
			continue
		}
		if err := client.Remove(target); err != nil {
			return err
		}
		removed++
	}
	fmt.Fprintf(a.Stdout, "removed %d %s from the agent\n", removed, plural(removed, "key", "keys"))
	return nil
}

// loadKeys hands ssh-add the keys that are not in the agent yet. Keys already
// loaded are left alone: re-adding one buys nothing and would ask for its
// passphrase again, which is exactly what a menu item must not do when pressed
// twice.
func (a *App) loadKeys(ctx context.Context, args []string) error {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			return &usageError{"keys load takes key files, not options"}
		}
	}
	client, conn, err := a.agentKeys(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	loaded, err := client.List()
	if err != nil {
		return err
	}
	// Loading can take as long as a passphrase takes to type; the connection
	// carries a deadline and has nothing left to say, so it goes now.
	conn.Close()
	held := make(map[string]bool, len(loaded))
	for _, key := range loaded {
		held[ssh.FingerprintSHA256(key)] = true
	}
	candidates := args
	if len(candidates) == 0 {
		candidates = privateKeyFiles(filepath.Dir(a.SSHConfig))
		if len(candidates) == 0 {
			return fmt.Errorf("no private keys in %s", filepath.Dir(a.SSHConfig))
		}
	}
	wanted := make([]string, 0, len(candidates))
	for _, path := range candidates {
		data, err := readKeyFile(path)
		if err != nil {
			if len(args) != 0 {
				return err
			}
			continue
		}
		if public, _, ok := publicKeyFor(path, data); ok && held[ssh.FingerprintSHA256(public)] {
			continue
		}
		wanted = append(wanted, path)
	}
	if len(wanted) == 0 {
		fmt.Fprintf(a.Stdout, "the agent already holds %d %s\n", len(loaded), plural(len(loaded), "key", "keys"))
		return nil
	}
	output, err := a.runSSHAdd(ctx, wanted)
	if out := strings.TrimSpace(output); out != "" {
		fmt.Fprintln(a.Stdout, out)
	}
	if err != nil {
		return err
	}
	return a.reportHeld(ctx)
}

// reportHeld says what the agent holds now, so the window that shows this says
// what was achieved and not only what was attempted.
func (a *App) reportHeld(ctx context.Context) error {
	client, conn, err := a.agentKeys(ctx)
	if err != nil {
		return nil
	}
	defer conn.Close()
	held, err := client.List()
	if err != nil {
		return nil
	}
	fmt.Fprintf(a.Stdout, "the agent holds %d %s\n", len(held), plural(len(held), "key", "keys"))
	return nil
}

// runSSHAdd runs ssh-add against our socket, with this program as its askpass,
// so a passphrase is typed into the same dialog as everywhere else and can be
// remembered in the same keychain. The environment is built rather than
// inherited: nothing a caller exported may redirect the passphrase prompt.
func (a *App) runSSHAdd(ctx context.Context, paths []string) (string, error) {
	if a.SSHAdd == nil {
		return "", errors.New("loading keys is unavailable")
	}
	exe, err := a.Executable()
	if err != nil {
		return "", err
	}
	home := a.Getenv("HOME")
	if home == "" {
		home = filepath.Dir(filepath.Dir(a.SSHConfig))
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		agent.EnvAuthSock + "=" + (sshconfig.ManagedConfig{Path: a.SSHConfig}).SocketPath(),
		agent.EnvAskpass + "=" + exe,
		agent.EnvRequire + "=" + agent.RequireForce,
	}
	if tmp := a.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	return a.SSHAdd(ctx, env, paths)
}

// execSSHAdd runs the real ssh-add with no terminal to fall back to, so the
// passphrase can only be typed into the dialog.
func execSSHAdd(ctx context.Context, env, paths []string) (string, error) {
	cmd := exec.CommandContext(ctx, SSHAdd, paths...)
	cmd.Env = env
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	text := out.String()
	if err != nil {
		if len(text) > 0 {
			return text, errSSHAdd
		}
		return text, fmt.Errorf("ssh-add: %w", err)
	}
	return text, nil
}

// privateKeyFiles lists the private keys sitting in the SSH directory, the
// place OpenSSH itself looks. A public half, a known_hosts file or a socket is
// not a key, and neither is anything without a private key header.
func privateKeyFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var found []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() || strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := readKeyFile(path)
		if err != nil || !isPrivateKey(data) {
			continue
		}
		found = append(found, path)
	}
	sort.Strings(found)
	return found
}

func readKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a key file", path)
	}
	if info.Size() > maxKeyFileBytes {
		return nil, fmt.Errorf("%s is too large to be a key file", path)
	}
	return os.ReadFile(path)
}

func isPrivateKey(data []byte) bool {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	return bytes.HasPrefix(line, []byte("-----BEGIN ")) && bytes.HasSuffix(bytes.TrimSpace(line), []byte("PRIVATE KEY-----"))
}

// isEncrypted reports whether loading this key will ask for a passphrase, which
// is what decides whether loading it at login can happen without anyone there.
func isEncrypted(data []byte) bool {
	_, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	return errors.As(err, &missing)
}

// publicKeyFor names a key without its passphrase. The public half beside it is
// the first place to look: OpenSSH writes one for every key it generates, and
// it carries the comment as well. Failing that, the key file itself gives up
// its public half — the OPENSSH format keeps it in the clear, and an
// unencrypted key carries it outright.
func publicKeyFor(path string, data []byte) (ssh.PublicKey, string, bool) {
	if beside, err := readKeyFile(path + ".pub"); err == nil {
		if public, comment, _, _, err := ssh.ParseAuthorizedKey(beside); err == nil {
			return public, comment, true
		}
	}
	if public, ok := publicHalf(data); ok {
		return public, "", true
	}
	return nil, "", false
}

// publicHalf reports the public key of a private key file when it can be had
// without a passphrase. An older encrypted format yields nothing, and such a
// key is simply offered to ssh-add again.
func publicHalf(data []byte) (ssh.PublicKey, bool) {
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer.PublicKey(), true
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) && missing.PublicKey != nil {
		return missing.PublicKey, true
	}
	return nil, false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
