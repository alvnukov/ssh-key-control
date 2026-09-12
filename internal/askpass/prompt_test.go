package askpass

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		text string
		hint string
		want Prompt
	}{
		{
			name: "ssh key passphrase",
			text: "Enter passphrase for key '/Users/me/.ssh/id_ed25519': ",
			want: Prompt{Kind: Passphrase, Account: "/Users/me/.ssh/id_ed25519"},
		},
		{
			name: "ssh key passphrase with spaces and quotes in the path",
			text: "Enter passphrase for key '/Users/me/my keys/it's mine': ",
			want: Prompt{Kind: Passphrase, Account: "/Users/me/my keys/it's mine"},
		},
		{
			name: "ssh-add passphrase",
			text: "Enter passphrase for /Users/me/.ssh/id_ed25519: ",
			want: Prompt{Kind: Passphrase, Account: "/Users/me/.ssh/id_ed25519"},
		},
		{
			name: "ssh-add -c passphrase",
			text: "Enter passphrase for /Users/me/.ssh/id_ed25519 (will confirm each use): ",
			want: Prompt{Kind: Passphrase, Account: "/Users/me/.ssh/id_ed25519", ConfirmEachUse: true},
		},
		{
			name: "ssh-add retry",
			text: "Bad passphrase, try again for /Users/me/.ssh/id_ed25519: ",
			want: Prompt{Kind: Passphrase, Account: "/Users/me/.ssh/id_ed25519", Retry: true},
		},
		{
			name: "ssh-add -c retry",
			text: "Bad passphrase, try again for id_rsa (will confirm each use): ",
			want: Prompt{Kind: Passphrase, Account: "id_rsa", Retry: true, ConfirmEachUse: true},
		},
		{
			name: "password",
			text: "me@example.org's password: ",
			want: Prompt{Kind: Password, Account: "me@example.org"},
		},
		{
			name: "keyboard-interactive password",
			text: "(me@example.org) Password: ",
			want: Prompt{Kind: Password, Account: "me@example.org"},
		},
		{
			name: "keyboard-interactive one-time code",
			text: "(me@example.org) Verification code: ",
			want: Prompt{Kind: Other, Account: "me@example.org"},
		},
		{
			name: "host key",
			text: "The authenticity of host 'example.org (192.0.2.1)' can't be established.\nED25519 key fingerprint is SHA256:abc.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ",
			want: Prompt{Kind: HostKey},
		},
		{
			name: "host key, old wording",
			text: "Are you sure you want to continue connecting (yes/no)? ",
			want: Prompt{Kind: HostKey},
		},
		{
			name: "agent confirmation",
			text: "Allow use of key id_ed25519?\nKey fingerprint SHA256:abc.",
			hint: "confirm",
			want: Prompt{Kind: Confirm},
		},
		{
			name: "agent confirmation ignores the text",
			text: "Enter passphrase for key '/x': ",
			hint: "confirm",
			want: Prompt{Kind: Confirm},
		},
		{
			name: "notification",
			text: "Confirm user presence for key ED25519-SK SHA256:abc",
			hint: "none",
			want: Prompt{Kind: Notify},
		},
		{
			name: "hint is case-insensitive",
			text: "x",
			hint: "CONFIRM",
			want: Prompt{Kind: Confirm},
		},
		{
			name: "pin",
			text: "Enter PIN for ED25519-SK key /Users/me/.ssh/id_ed25519_sk: ",
			want: Prompt{Kind: Other},
		},
		{
			name: "ssh-keygen",
			text: "Enter same passphrase again: ",
			want: Prompt{Kind: Other},
		},
		{
			name: "bare passphrase",
			text: "Enter passphrase: ",
			want: Prompt{Kind: Other},
		},
		{
			name: "empty",
			text: "",
			want: Prompt{Kind: Other},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.text, tt.hint)
			got.Text = "" // compared separately
			if got != tt.want {
				t.Errorf("Parse(%q, %q)\n got %+v\nwant %+v", tt.text, tt.hint, got, tt.want)
			}
		})
	}
}

func TestParseKeepsTrimmedText(t *testing.T) {
	p := Parse("  Enter passphrase for key '/k':  \n", "")
	if p.Text != "Enter passphrase for key '/k':" {
		t.Errorf("Text = %q", p.Text)
	}
}

func TestTitleAndMessage(t *testing.T) {
	p := Parse("Allow use of key id_ed25519?\nKey fingerprint SHA256:abc.", "confirm")
	if p.Title() != "Allow use of key id_ed25519?" {
		t.Errorf("Title = %q", p.Title())
	}
	if p.Message() != "Key fingerprint SHA256:abc." {
		t.Errorf("Message = %q", p.Message())
	}
	single := Parse("Confirm user presence", "none")
	if single.Title() != "Confirm user presence" || single.Message() != "" {
		t.Errorf("single line: %q / %q", single.Title(), single.Message())
	}
}

func TestKindString(t *testing.T) {
	for k, want := range map[Kind]string{Other: "other", Passphrase: "passphrase", Password: "password", HostKey: "host key", Confirm: "confirm", Notify: "notify"} {
		if k.String() != want {
			t.Errorf("%d.String() = %q, want %q", k, k.String(), want)
		}
	}
}
