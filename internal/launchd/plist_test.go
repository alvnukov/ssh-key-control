package launchd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarshalPlist(t *testing.T) {
	job := Job{
		Label:              "io.example.agent",
		ProgramArguments:   []string{"/usr/local/bin/ssh-key-control", "agent"},
		RunAtLoad:          true,
		KeepAliveOnFailure: true,
		ThrottleInterval:   10,
		EnableTransactions: true,
		EnvironmentVariables: map[string]string{
			"SSH_ASKPASS_REQUIRE": "force",
			"SSH_ASKPASS":         "/usr/local/bin/ssh-key-control",
		},
		SecureSocket: &SecureSocket{Name: "Listeners", Key: "SSH_KEY_CONTROL_AGENT_SOCKET"},
	}
	got, err := job.MarshalPlist()
	if err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>io.example.agent</string>
		<key>ProgramArguments</key>
		<array>
			<string>/usr/local/bin/ssh-key-control</string>
			<string>agent</string>
		</array>
		<key>RunAtLoad</key>
		<true/>
		<key>KeepAlive</key>
		<dict>
			<key>SuccessfulExit</key>
			<false/>
		</dict>
		<key>ThrottleInterval</key>
		<integer>10</integer>
		<key>EnableTransactions</key>
		<true/>
		<key>EnvironmentVariables</key>
		<dict>
			<key>SSH_ASKPASS</key>
			<string>/usr/local/bin/ssh-key-control</string>
			<key>SSH_ASKPASS_REQUIRE</key>
			<string>force</string>
		</dict>
		<key>Sockets</key>
		<dict>
			<key>Listeners</key>
			<dict>
				<key>SecureSocketWithKey</key>
				<string>SSH_KEY_CONTROL_AGENT_SOCKET</string>
			</dict>
		</dict>
	</dict>
</plist>
`
	if string(got) != want {
		t.Errorf("plist:\n%s\nwant:\n%s", got, want)
	}
	lintPlist(t, got)
}

func TestMarshalPlistMinimal(t *testing.T) {
	got, err := Job{Label: "x", ProgramArguments: []string{"/bin/true"}}.MarshalPlist()
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"RunAtLoad", "KeepAlive", "ThrottleInterval", "EnableTransactions", "EnvironmentVariables", "Sockets"} {
		if strings.Contains(string(got), absent) {
			t.Errorf("minimal plist contains %s", absent)
		}
	}
	lintPlist(t, got)
}

func TestMarshalPlistAlwaysKeepAlive(t *testing.T) {
	got, err := (Job{Label: "x", ProgramArguments: []string{"/bin/true"}, KeepAlive: true}).MarshalPlist()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "<key>KeepAlive</key>\n\t\t<true/>") {
		t.Errorf("always keepalive missing:\n%s", got)
	}
}

func TestMarshalPlistEscapes(t *testing.T) {
	got, err := Job{Label: "a&b", ProgramArguments: []string{"/Applications/<x>/bin", "<true></true>", "<false></false>"}, RunAtLoad: true}.MarshalPlist()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "<string>a&amp;b</string>") || !strings.Contains(string(got), "&lt;x&gt;") {
		t.Errorf("not escaped:\n%s", got)
	}
	for _, literal := range []string{"&lt;true&gt;&lt;/true&gt;", "&lt;false&gt;&lt;/false&gt;"} {
		if !strings.Contains(string(got), literal) {
			t.Errorf("boolean-like string was changed: %s\n%s", literal, got)
		}
	}
	lintPlist(t, got)
}

func TestMarshalPlistRejectsIncomplete(t *testing.T) {
	if _, err := (Job{ProgramArguments: []string{"/bin/true"}}).MarshalPlist(); err == nil {
		t.Error("no label: expected an error")
	}
	if _, err := (Job{Label: "x"}).MarshalPlist(); err == nil {
		t.Error("no program: expected an error")
	}
	if _, err := (Job{Label: "x", ProgramArguments: []string{"/bin/true"}, KeepAliveOnFailure: true}).MarshalPlist(); err == nil {
		t.Error("failure-only keepalive without run-at-load: expected an error")
	}
	if _, err := (Job{Label: "x", ProgramArguments: []string{"/bin/true"}, ThrottleInterval: -1}).MarshalPlist(); err == nil {
		t.Error("negative throttle interval: expected an error")
	}
	if _, err := (Job{Label: "x", ProgramArguments: []string{"/bin/true"}, RunAtLoad: true, KeepAlive: true, KeepAliveOnFailure: true}).MarshalPlist(); err == nil {
		t.Error("conflicting keepalive policies: expected an error")
	}
}

// lintPlist checks general plist syntax; launchd's XPC parser is stricter.
func lintPlist(t *testing.T, data []byte) {
	t.Helper()
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		t.Skip("plutil not available")
	}
	path := filepath.Join(t.TempDir(), "job.plist")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(plutil, "-lint", path).CombinedOutput(); err != nil {
		t.Errorf("plutil -lint: %v\n%s", err, out)
	}
}
