package confirmation

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func hostFixtureKey(t *testing.T, seed byte) ssh.PublicKey {
	t.Helper()
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{seed}), ed25519.SeedSize))).Public())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func hostFixtureFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKnownHostNamesPlain(t *testing.T) {
	key := hostFixtureKey(t, 1)
	entry := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	path := hostFixtureFile(t, "known_hosts", "z.example,a.example "+entry+" misleading-comment\na.example,[server.example]:2222 "+entry+"\n")
	config := hostFixtureFile(t, "config", "")
	if got := KnownHostNames(ssh.FingerprintSHA256(key), path, config); got != "[server.example]:2222, a.example, z.example" {
		t.Fatalf("names = %q", got)
	}
	if got := KnownHostNames(ssh.FingerprintSHA256(hostFixtureKey(t, 2)), path, config); got != "" {
		t.Fatalf("mismatched key names = %q", got)
	}
}

func TestKnownHostNamesHashed(t *testing.T) {
	key := hostFixtureKey(t, 1)
	entry := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	for _, tc := range []struct{ name, host, config, want string }{
		{"hostname", "real.example", "Host shortcut\n HostName real.example\n", "real.example"},
		{"literal alias", "shortcut", "Host shortcut other\n", "shortcut"},
		{"unknown", "hidden.example", "Host unrelated\n", ""},
		{"default port", "real.example", "Host shortcut\n HostName real.example\n Port 22\n", "real.example"},
		{"explicit default port", "real.example", "Host [real.example]:22\n", "real.example"},
		{"custom port", "[real.example]:2222", "Host shortcut\n HostName real.example\n Port 2222\n", "[real.example]:2222"},
		{"wildcard", "*.example", "Host *.example\n", ""},
		{"token", "%h.example", "Host shortcut\n HostName %h.example\n", ""},
		{"negated", "!hidden.example", "Host !hidden.example\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := hostFixtureFile(t, "known_hosts", knownhosts.HashHostname(tc.host)+" "+entry+"\n")
			config := hostFixtureFile(t, "config", tc.config)
			if got := KnownHostNames(ssh.FingerprintSHA256(key), path, config); got != tc.want {
				t.Fatalf("names = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKnownHostNamesExclusionsAndErrors(t *testing.T) {
	key := hostFixtureKey(t, 1)
	entry := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	good := "ok.example " + entry + "\n"
	for _, tc := range []struct{ name, hosts, config, want string }{
		{"revoked and CA", "@revoked revoked.example " + entry + "\n@cert-authority ca.example " + entry + "\n" + good, "", "ok.example"},
		{"unsafe names", "evil\x1b.example,bidi\u202e.example,*.example,!no.example " + entry + "\n" + good, "", "ok.example"},
		{"malformed known hosts", good + "broken\n", "", "ok.example"},
		{"long known hosts line", good + "#" + strings.Repeat("x", 65536), "", ""},
		{"large known hosts file", good + strings.Repeat("#\n", 2<<20), "", ""},
		{"long config line", good, "#" + strings.Repeat("x", 65536), ""},
		{"large config file", good, strings.Repeat("#\n", 2<<20) + "#", ""},
		{"all hashed names and deduplication", knownhosts.HashHostname("b.example") + " " + entry + "\n" + knownhosts.HashHostname("a.example") + " " + entry + "\na.example " + entry + "\n", "Host a.example b.example a.example\n", "a.example, b.example"},
		{"hashed key mismatch", knownhosts.HashHostname("a.example") + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostFixtureKey(t, 2)))) + "\n", "Host a.example\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts := hostFixtureFile(t, "known_hosts", tc.hosts)
			config := hostFixtureFile(t, "config", tc.config)
			if got := KnownHostNames(ssh.FingerprintSHA256(key), hosts, config); got != tc.want {
				t.Fatalf("names = %q, want %q", got, tc.want)
			}
		})
	}
	hosts := hostFixtureFile(t, "known_hosts", good)
	missing := filepath.Join(t.TempDir(), "missing")
	if got := KnownHostNames(ssh.FingerprintSHA256(key), missing, ""); got != "" {
		t.Fatalf("missing known hosts: %q", got)
	}
	if got := KnownHostNames(ssh.FingerprintSHA256(key), hosts, missing); got != "" {
		t.Fatalf("missing config: %q", got)
	}
	if got := KnownHostNames(ssh.FingerprintSHA256(key), hosts, ""); got != "ok.example" {
		t.Fatalf("no config: %q", got)
	}
	if got := KnownHostNames("", hosts, ""); got != "" {
		t.Fatalf("empty fingerprint: %q", got)
	}
}
