// Package sshconfig reads ssh_config(5) far enough to spot settings that
// defeat an askpass dialog or an agent with per-use confirmation.
package sshconfig

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Directive is one keyword line of a configuration file.
type Directive struct {
	Line int
	// Key is the keyword in lower case.
	Key string
	// Value is the rest of the line, trimmed, with surrounding quotes removed.
	Value string
	// Scope is the Host or Match line the directive belongs to, "" at top level.
	Scope string
}

// DefaultPath is the user's own configuration file.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// Parse reads directives from r. Unknown keywords are kept; the caller decides
// what matters. Include directives are reported but not followed.
func Parse(r io.Reader) ([]Directive, error) {
	var out []Directive
	scope := ""
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value := split(line)
		if key == "" {
			continue
		}
		if key == "host" || key == "match" {
			scope = strings.TrimSpace(sc.Text())
		}
		out = append(out, Directive{Line: n, Key: key, Value: value, Scope: scope})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// split separates "Key value", "Key=value" and "Key = value".
func split(line string) (key, value string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key = strings.ToLower(line[:i])
	value = strings.TrimLeft(line[i:], " \t")
	value = strings.TrimPrefix(value, "=")
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return key, value
}

// Warning is a setting that gets in the way, with the line it lives on.
type Warning struct {
	Line  int
	Scope string
	Text  string
}

func (w Warning) String() string {
	where := fmt.Sprintf("line %d", w.Line)
	if w.Scope != "" {
		where += ", " + w.Scope
	}
	return fmt.Sprintf("%s (%s)", w.Text, where)
}

// Check returns what in ds will keep the dialog or the confirmations from appearing.
func Check(ds []Directive) []Warning {
	var out []Warning
	warn := func(d Directive, text string) {
		out = append(out, Warning{Line: d.Line, Scope: d.Scope, Text: text})
	}
	for _, d := range ds {
		v := strings.ToLower(d.Value)
		switch d.Key {
		case "usekeychain":
			if v == "yes" {
				warn(d, "UseKeychain yes: ssh takes passphrases from the keychain by itself, so no dialog appears and keys loaded this way are used without confirmation; remove it")
			}
		case "addkeystoagent":
			field, _, _ := strings.Cut(v, " ")
			switch field {
			case "confirm":
			case "no":
				warn(d, "AddKeysToAgent no: keys are not automatically added with confirmation; an earlier matching value overrides later confirm directives")
			default:
				warn(d, fmt.Sprintf("AddKeysToAgent %s: keys are added to the agent without per-use confirmation; use \"AddKeysToAgent confirm\"", d.Value))
			}
		case "identityagent":
			switch v {
			case "none":
				warn(d, "IdentityAgent none: ssh uses no agent at all here")
			case "ssh_auth_sock", "$ssh_auth_sock":
			default:
				warn(d, fmt.Sprintf("IdentityAgent %s: ssh talks to that agent instead of the installed one", d.Value))
			}
		case "include":
			warn(d, fmt.Sprintf("Include %s: not checked; look there for the same settings", d.Value))
		}
	}
	return out
}

// CheckFile reads and checks one file. A missing file yields no warnings.
func CheckFile(path string) ([]Warning, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ds, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Our exact global prefix wins before all Host/Match/Include settings.
	// Only suppress overridden directives when ownership is unambiguous.
	c := ManagedConfig{Path: path}
	if owned, err := c.owned(data); err == nil && owned > 0 {
		current, _ := c.prefix()
		routesAgent := strings.HasPrefix(string(data), current)
		filtered := ds[:0]
		for _, d := range ds {
			if d.Key == "addkeystoagent" || (routesAgent && d.Key == "identityagent") {
				continue
			}
			filtered = append(filtered, d)
		}
		ds = filtered
	}
	return Check(ds), nil
}
