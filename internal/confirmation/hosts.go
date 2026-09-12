package confirmation

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const hostFileLimit = 4 << 20
const hostLineLimit = 64 << 10

// KnownHostNames returns informational known names for an already verified server
// hostkey. It does not identify the requested alias, establish certificate trust,
// or authorize anything. Only the explicitly supplied public files are read.
func KnownHostNames(fingerprint string, knownHostsPath, configPath string) string {
	if fingerprint == "" {
		return ""
	}
	data, err := readHostFile(knownHostsPath)
	if err != nil {
		return ""
	}
	var candidates []string
	if configPath != "" {
		config, err := readHostFile(configPath)
		if err != nil {
			return ""
		}
		candidates, err = configuredHostCandidates(config)
		if err != nil {
			return ""
		}
	}
	names := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), hostLineLimit)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil {
			return ""
		}
		if marker != "" || ssh.FingerprintSHA256(key) != fingerprint {
			continue
		}
		for _, host := range hosts {
			if strings.HasPrefix(host, "|") {
				for _, candidate := range candidates {
					if matchesHostHash(host, candidate) {
						names[candidate] = true
					}
				}
			} else if safeHostName(host) {
				names[host] = true
			}
		}
	}
	if scanner.Err() != nil {
		return ""
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return strings.Join(result, ", ")
}

func readHostFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, hostFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > hostFileLimit {
		return nil, io.ErrShortBuffer
	}
	return data, nil
}

// Reject rather than strip unsafe characters: stripping could invent a name.
func safeHostName(name string) bool {
	if name == "" || strings.ContainsAny(name, "|*?!%,\"'\\#$") {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

// Config supplies only guesses to check against hashes, never evidence of a
// binding. Includes are not followed and tokens are not expanded.
func configuredHostCandidates(data []byte) ([]string, error) {
	directives, err := sshconfig.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	candidates := make(map[string]bool)
	var block []string
	port, globalPort := "22", "22"
	global := true
	flush := func() {
		for _, name := range block {
			if !safeHostName(name) {
				continue
			}
			candidates[knownhosts.Normalize(name)] = true
			if _, _, err := net.SplitHostPort(name); err != nil {
				candidates[knownhosts.Normalize(net.JoinHostPort(name, port))] = true
			}
		}
	}
	for _, d := range directives {
		value, _, _ := strings.Cut(d.Value, "#")
		value = strings.TrimSpace(value)
		switch d.Key {
		case "host", "match":
			flush()
			block = nil
			global = false
			port = globalPort
			if d.Key == "host" {
				block = append(block, strings.Fields(value)...)
			}
		case "hostname":
			block = append(block, value)
		case "port":
			n, err := strconv.Atoi(value)
			if err == nil && n > 0 && n <= 65535 {
				port = strconv.Itoa(n)
				if global {
					globalPort = port
				}
			}
		}
	}
	flush()
	result := make([]string, 0, len(candidates))
	for name := range candidates {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func matchesHostHash(encoded, name string) bool {
	parts := strings.Split(encoded, "|")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "1" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != sha1.Size {
		return false
	}
	digest, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(digest) != sha1.Size {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	_, _ = mac.Write([]byte(name))
	return hmac.Equal(mac.Sum(nil), digest)
}
