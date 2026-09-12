package launchd

import (
	"strings"
	"testing"
)

func TestNativeSocketAcceptsOnlySystemJobSocket(t *testing.T) {
	good, err := ParsePrint(appleAgent)
	if err != nil {
		t.Fatal(err)
	}
	if path, err := nativeSocket(good, "gui/501/com.openssh.ssh-agent"); err != nil || path != "/var/run/com.apple.launchd.yR1H3s4Jb5/Listeners" {
		t.Fatalf("%s %v", path, err)
	}
	for _, change := range []struct{ old, new string }{
		{systemAgentPlist, "/Users/test/Library/LaunchAgents/com.openssh.ssh-agent.plist"},
		{"/usr/bin/ssh-agent", "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control"},
		{"com.apple.launchd.yR1H3s4Jb5/Listeners", "other/Listeners"},
		{"secure key = SSH_AUTH_SOCK", "secure key = OTHER_SOCKET"},
	} {
		parsed, err := ParsePrint(strings.ReplaceAll(appleAgent, change.old, change.new))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = nativeSocket(parsed, "gui/501/com.openssh.ssh-agent"); err == nil {
			t.Errorf("accepted replacement %q", change.new)
		}
	}
	if _, err = nativeSocket(good, "gui/999/com.openssh.ssh-agent"); err == nil {
		t.Fatal("accepted different user domain")
	}
}
