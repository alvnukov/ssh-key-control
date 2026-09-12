# SSH Key Control

The macOS interface follows the system's preferred languages: Russian and
English are included, with English as the fallback. Restart the app after
changing the language in macOS. Menus, settings, history and standard approval
labels are localized; SSH-provided prompts and raw command diagnostics remain
verbatim. Fingerprints, key comments, usernames and paths are never translated.

The new name preserves existing settings, Keychain integration, launch agent
identifiers, the `ssh-key-control` command and the historical data directory. The local Git history is retained in
[alvnukov/ssh-key-control](https://github.com/alvnukov/ssh-key-control).
See [release readiness](docs/release-readiness.md) for remaining distribution requirements.

Native macOS dialogs for OpenSSH, and an `ssh-agent` that can show them.

`ssh`, `ssh-add` and `ssh-keygen` ask for passphrases, passwords, host-key
decisions and `ssh-add -c` confirmations through a standard alert instead of
the terminal. Passphrases can be remembered in the login keychain, and every
read from it goes through the system's own access prompt.

The second half is the point of this project. Confirmation prompts for keys
added with `ssh-add -c` (or `AddKeysToAgent confirm`) are shown by
`ssh-agent`, not by `ssh`. On macOS 26 the built-in agent is a system service
that launchd keeps apart from variables set with `launchctl setenv`, so it can
never find an askpass program and confirmations silently fail. `ssh-key-control
install` registers a per-user launch agent that owns the agent socket, exports
`SSH_AUTH_SOCK`, `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE` to your login
session and runs its own agent in its place, so every signature can ask you.
Everything started after that, terminals and GUI apps alike, talks to an agent
that requires your approval.

Requires macOS 13 or later. Building needs Go 1.25 and Xcode 15 (or the
Command Line Tools).

## Install

### DMG (drag to Applications)

Build with `make dmg`. The image is `build/SSH-Key-Control-<architecture>.dmg`,
with a SHA-256 checksum beside it. It contains the app, an Applications link
and installation instructions. This build targets the current Mac's architecture.

1. Open the DMG and drag **SSH Key Control.app** onto **Applications**.
2. Eject the image and open the app from Applications.
3. Choose **Set Up SSH Agent…** from the menu bar and click **Enable / Update Agent**.

The app includes the agent and confirmation helper; no Homebrew, terminal setup
or administrator access is needed. Setup changes SSH routing for your account
using the existing installer and its configuration backup. It never approves a
key or destination. Setup refuses to run from a disk image, Downloads or App
Translocation; `/Applications` and `~/Applications` are supported.

After replacing the app, run **Enable / Update Agent** again. This restarts the
agent and clears in-memory keys and temporary approvals. SSH can reload keys;
keys added only through `ssh-add` must be added again. Keep the app at the same
location while enabled.

Before deleting the app, use **Remove Agent Setup…**. Removing setup stops
launchd supervision, restores the system agent and removes
managed SSH settings; Keychain entries and history are preserved. If you disabled
Apple's agent, restore it in Advanced settings and complete any requested logout
before removing the protected agent. Removal refuses to proceed while the system
agent's startup is disabled or its status cannot be verified.

Local builds are ad-hoc signed. To prepare a public download, use
`make dmg SIGN_IDENTITY="Developer ID Application: …"`, then submit the DMG
with `xcrun notarytool submit <image.dmg> --keychain-profile <profile> --wait`
and staple the accepted ticket with `xcrun stapler staple <image.dmg>`.
Recompute the checksum after stapling. Credentials and notarization are not
part of the default build. See Apple's [distribution guidance](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution).
A locally verified ad-hoc signature does not establish Gatekeeper acceptance
of a downloaded build.

### From source

Source is published at [alvnukov/ssh-key-control](https://github.com/alvnukov/ssh-key-control).
Download DMGs from [Releases](https://github.com/alvnukov/ssh-key-control/releases).
No Homebrew tap is published; the included formula is a reference recipe.
Clone the repository, then build:

```sh
git clone https://github.com/alvnukov/ssh-key-control.git
cd ssh-key-control
make install                 # ~/.local/bin and ~/.local/libexec; no sudo
export PATH="$HOME/.local/bin:$PATH"
ssh-key-control install
```

`make install` defaults to `~/.local` and copies `bin/ssh-key-control`,
`libexec/ssh-key-control-ui` and the app under `Applications`. Add `~/.local/bin` to your
shell's `PATH` configuration to keep the command available in new terminals.
Override the destination with `make install PREFIX=/path/to/prefix`; use the
same `PREFIX` for `make uninstall`. The CLI finds its helper in the adjacent
`libexec` directory, so no helper override is needed.

`ssh-key-control install` configures `~/.ssh/config` for automatic key loading with
per-use confirmation, writes
`~/Library/LaunchAgents/io.github.alvnukov.ssh-key-control.plist`, loads it and waits
until the agent is running and the variables are exported. Existing SSH settings
are backed up before modification; no manual `ssh-add` step is required for keys
loaded by `ssh`. Run it as yourself, never with `sudo`.

SSH is routed to this agent by the managed `IdentityAgent` setting, including
from existing terminals with a stale `SSH_AUTH_SOCK`. Quit and reopen the terminal
to update other programs that use that variable directly, such as `ssh-add`.

### Check that it works

```sh
ssh-key-control doctor
ssh your-host               # use one of your usual SSH destinations
```

When SSH first loads an encrypted key from disk, the dialog asks for its
passphrase. The key is automatically added to the agent with confirmation
required. Subsequent agent signatures show Allow/Deny. Return and keypad Enter
perform the highlighted action (Deny by default). The “Return / Enter” selector
changes this preference for future dialogs; choosing Allow always means one
signature, never a timed grant. Escape always denies.
The initial disk-based signature and reuse of an already-open SSH connection
(such as ControlMaster multiplexing) do not require an agent signature and
therefore do not show that confirmation.

## Menu bar app

Open `build/SSH Key Control.app` after `make`, or run `make install-app` to copy it
to `~/Applications`. The app uses an original terminal-key icon and runs in the
menu bar without a Dock icon. Enabling agent setup registers both the SSH agent
and the menu bar app with launchd. Unexpected exits restart with throttling.
**Quit SSH Key Control** stays stopped until the next login or setup update,
while the SSH agent remains running.

- **Security History…** (⌘Y): approval-gate decisions, timestamps, full signing-key
  and server-key fingerprints, SSH username, scope and expiry at the time of the
  decision. Search and filters distinguish refusals, unverified destinations and
  remembered decisions.
- **Settings…** (⌘,): Return/Enter action, the initial Keychain checkbox, and
  the current launchd supervision policy for the menu bar app.
- **Advanced**: keep 1, 7 or 30 days and at most 250, 1,000 or 5,000 events;
  inspect this build's security policy.

Settings apply without restarting the agent. Retention limits hide older events
on refresh and prune the stored file on the next recorded event. History records
are private local metadata under
`~/Library/Application Support/SSH Key Control/history.json` (0600 inside a 0700
directory). The settings file lives beside it. Passwords, key comments, signed
payloads and shell commands are excluded.

History starts only after the updated agent is installed and started.
An approval is **not proof of a successful signature or SSH login**. Requests
rejected before reaching the approval gate are not included in this journal.
The journal is never a source of authorization and is not tamper-evident against
processes running as the same user. The app reads it; it cannot create a grant.

`make install` also packages the companion under `$(APPDIR)`, which defaults to
`~/Applications`.
`make install-app APPDIR=/chosen/folder` installs just the companion at a chosen
location. Supervision requires `/Applications` or `~/Applications`; if the app
moves, run **Enable / Update Agent** again. Remove agent setup before deleting
the app.

## Disabling Apple's SSH agent

In **Settings → Advanced → System SSH agent**, turn on **Disable Apple's SSH
agent**. This explicitly authorizes changing `com.openssh.ssh-agent` for your
user: disable automatic loading, then attempt to unload the existing job.
The protected SSH Key Control agent must already be running.

macOS may allow the startup change but refuse unloading a system job while SIP
is enabled. The switch then means **startup disabled**, not **agent stopped**.
The app shows the actual loaded/running state and asks you to:

1. Save your work.
2. Choose **Apple menu → Log Out**, then sign in again (or restart the Mac).
3. Open Advanced settings and press **Check Status**. Only a disabled **and
   unloaded** service is reported as disabled. A remaining loaded service is
   still capable of activation; the app does not declare success.

To restore the system agent, turn the setting **off**. The app enables its
startup and attempts to load it. If it remains unloaded, sign out and in again.
Restore it **before** removing the SSH Key Control agent or deleting the app.

If the app has already been removed, run this recovery command as your own user,
then log out and in:

```sh
/bin/launchctl enable "gui/$(id -u)/com.openssh.ssh-agent"
```

The command restores startup policy only; it does not alter keys or Keychain
items. This setting does not disable SIP, modify system files, or prevent a
process from launching a separate agent or reading a private key it can access.
Apple's OpenSSH Keychain entries are separate from this app's `ssh-key-control`
entries and are not removed by this setting.

## Commands

| Command | What it does |
| --- | --- |
| `ssh-key-control install [--require force\|prefer]` | configure automatic key confirmation and launchd supervision; an installed app bundle adds menu supervision |
| `ssh-key-control uninstall` | remove managed SSH settings and launchd jobs; restore the system agent socket |
| `ssh-key-control status` | the agent, menu supervision, executable availability, socket and login-session variables |
| `ssh-key-control doctor` | check the installation, this shell and `~/.ssh/config`; exit 1 when the installation is broken |
| `ssh-key-control forget <account>...` | delete a remembered passphrase (the key path) or password (`user@host`) |
| `ssh-key-control <prompt>` | answer one prompt; OpenSSH runs this, you never do |

`--require force` (default) sends every prompt to the dialog, even from a
terminal. `--require prefer` uses the dialog only where there is no terminal;
agent confirmations always come as a dialog because the agent has none.

## How it works

OpenSSH runs the program named by `SSH_ASKPASS` with the prompt as the only
argument, reads the answer from its standard output and treats exit status 1
as "declined". `SSH_ASKPASS_PROMPT` tells confirmations (`confirm`) and
notifications (`none`) apart from questions.

| OpenSSH asks for | Dialog | Remembered |
| --- | --- | --- |
| key passphrase (`ssh`, `ssh-add`) | hidden field with *Remember in my keychain* | yes |
| password (`user@host's password:`) | hidden field with *Remember in my keychain* | yes |
| host key (`continue connecting?`) | text field: `yes`, `no` or the fingerprint | no |
| confirmation (`ssh-add -c`) | Deny / Allow, configurable Return (default Deny) | no |
| notification (touch the security key) | floating panel, closes when OpenSSH is done | no |
| anything else (PIN, `ssh-keygen`) | hidden field | no |

A remembered passphrase is checked against the key file before it is used and
deleted when it no longer opens the key or when OpenSSH reports it as wrong,
so a rotated passphrase never causes a loop of failed attempts.

Three executables are involved. `ssh-key-control` (Go) parses the prompt, talks to
the keychain and to launchd, and holds all the logic. `ssh-key-control-ui`
(Swift) shows the dialogs and reads the keychain; it is started by
`ssh-key-control` for one prompt at a time and speaks JSON lines on its standard
input and output. It is looked up in `../libexec` next to `ssh-key-control`, or
wherever `SSH_KEY_CONTROL_UI` points. `ssh-key-control-menubar` owns the status icon,
settings and history windows.

The signing launch agent is `io.github.alvnukov.ssh-key-control`. launchd creates the
socket (`SecureSocketWithKey`) and starts `ssh-key-control agent`, which activates
that socket, publishes the stable link, exports the variables with
`launchctl setenv` and then serves the agent protocol itself; every signature
is checked before it is issued. The plist is plain XML; `ssh-key-control status`
shows what launchd has. Setup from an installed app also registers
`io.github.alvnukov.ssh-key-control.menubar`. launchd keeps the agent running and
restarts the menu after unsuccessful exits, both with a bounded launch rate; a
successful menu exit records deliberate Quit.

## Every signature asks

The agent keeps the keys in memory and no client can opt out of the approval
dialog: adding a key without `-c` still requires Allow for each signature, for
any program — terminal, script or anything else running as your user. The
dialog names the key and, when a verified session binding matches a hostbound
user-authentication request, the remote user and the server's exact host-key
fingerprint with its known_hosts names. Ordinary publickey authentication and
requests without this evidence require one-time approval; they cannot create
or reuse a timed grant. The server key must be part of the signed request.
A hostname or SSH config alias never grants access to all keys of a server. Allow approves exactly one signature; the menu next to it can
grant 5 minutes, 15 minutes or the rest of the local day for that key, that
remote user and that server identity. Grants live only in the agent's memory
and vanish when it restarts. The Deny menu can silence the same exact
key/server-fingerprint/user combination for 5 minutes or 1 hour.
Forwarded or repeated session bindings are rejected; agent forwarding and
multi-hop binding chains are currently unsupported.

Disconnected clients cancel their pending dialog and queued approval; a late
answer cannot create a grant. The service accepts at most 64 concurrent
connections, limits incoming packets to 256 KiB and permits one queued packet
per connection. Excess connections or pipelining are closed. A partially sent
packet and a blocked reply have a 5-second deadline; idle connections and
human approval have no such deadline. These are transport bounds, not a
guarantee against denial of service by programs running as the same user.

Deny ends the connection attempt: the managed
configuration restricts `ssh` to publickey authentication, so no password or
other method is tried afterwards. Password-only hosts still work with an
explicit override, e.g. `ssh -oPreferredAuthentications=password host`.

Two things this cannot cover: the first signature of a key read from disk
before it reaches the agent, and anything a program running as your user can
already read or change on its own (files, this configuration, the agent
socket).

## `~/.ssh/config`

`ssh-key-control install` prepends a marked block with `AddKeysToAgent confirm` and
`IdentityAgent` pointing to `~/.ssh/ssh-key-control.sock`. The agent refreshes this
stable symlink to its launchd-created socket on every start; the installer also
publishes it before reporting success. This prevents an old terminal environment
from silently selecting the system agent. OpenSSH uses the first value, so
existing `AddKeysToAgent` and `IdentityAgent` settings are retained but overridden.
All other Host/Match sections and comments remain intact below the block.
Reinstallation does not duplicate it; an unchanged older confirmation-only block
is upgraded in place. Uninstall removes the managed block and socket link, never
the socket target.

Before changing an existing file, installation saves a private backup at
`~/.ssh/config.ssh-key-control.bak`; an existing backup is never overwritten.
Writes are atomic. A symlink or a modified managed block causes an error rather
than an unsafe overwrite. Uninstall removes only the exact managed block,
retaining your other settings, later edits and the backup.

SSH configuration is prepared before loading the agent. If loading fails, the
managed settings remain for a retry or `ssh-key-control uninstall`; the error is not
reported as a successful installation.

Other settings are not forcibly replaced: `UseKeychain yes` lets SSH retrieve
the passphrase itself, and command-line options or an alternate `ssh -F`
configuration can override these defaults. The managed block restricts ssh
to publickey authentication so Deny ends the attempt; password hosts work
with an explicit per-invocation override. `ssh-key-control doctor` reports
potentially conflicting directives, including `AddKeysToAgent no` before
`confirm`; it recognises its own global block and does not warn about settings
that the block overrides. It is not a full evaluation of OpenSSH's Host/Match
rules.

## Keychain

Items are generic passwords with service `ssh-key-control` and the key path (or
`user@host`) as the account, in the login keychain. They are visible in
Keychain Access, and `ssh-key-control forget` removes them.

The *Remember in my keychain* checkbox starts ticked and keeps its last state:

```sh
defaults write io.github.alvnukov.ssh-key-control rememberInKeychain -bool false
```

## Security

- Keychain items are created with an access list that trusts no application.
  macOS asks "ssh-key-control-ui wants to use your confidential information" on
  every read. Choose **Allow**, not **Always Allow**; with the latter any
  process that can run the helper can read the passphrase silently. **Deny**
  simply brings up the passphrase dialog.
- The API that creates such access lists, `SecAccessCreate`, is deprecated
  without a replacement for file-based keychains. It works on current macOS
  and is used on purpose.
- The passphrase passes through the memory of both executables and OpenSSH's
  standard input; neither Go nor Swift guarantees wiping it afterwards.
- Both executables are ad-hoc signed and not notarised. Gatekeeper does not
  apply to programs that are never opened from the Finder.
- `ssh-key-control agent` holds added keys in its own memory and checks every
  signature before it is issued; private key bytes pass through this process
  while it runs, and its own compromises are the same-user trust boundary.

## Uninstall

```sh
ssh-key-control uninstall        # remove launchd jobs, restore the system agent socket
make uninstall
```

Managed SSH settings are removed without restoring an old backup over later
edits. The backup and remembered keychain passphrases remain until you delete
them. If you edited the managed block itself, uninstall refuses to remove it
or unload the agent until that conflict is resolved.

## Troubleshooting

`ssh-key-control doctor` covers most of this. `ok` lines are fine, `warn` lines
concern this shell or your config, `FAIL` means the installation is broken.

**The terminal asks instead of a dialog.** This shell was started before the
agent: open a new terminal window. `launchctl getenv SSH_AUTH_SOCK` shows what
new programs will get.

**No confirmation dialog for a key added with `ssh-add -c`.** The key was
added to a different agent, or the agent was started without `SSH_ASKPASS`.
`ssh-key-control status` shows the agent's socket and the login session's
`SSH_AUTH_SOCK`; they must match. `ssh-add -l` in a fresh terminal lists what
the right agent holds.

**The dialog appears behind the terminal.** Terminal's *Secure Keyboard Entry*
keeps other applications from taking focus. Click the dialog, or turn the
option off.

**`ssh-key-control install` says the helper is missing.** `ssh-key-control-ui` must be
in `libexec` next to `bin/ssh-key-control`, or named by `SSH_KEY_CONTROL_UI`.

## Development

```
cmd/ssh-key-control        entry point
internal/askpass       prompt parsing and the answer flow
internal/keys          passphrase check against the key file
internal/ui            dialog and keychain interfaces; ui/helper drives ssh-key-control-ui
internal/launchd       launchctl client, `launchctl print` parser, plist writer
internal/agent         the launch agent job and `ssh-key-control agent`
internal/install       install, uninstall and status against launchd
internal/sshconfig     ~/.ssh/config management, parser and checks
internal/cli           commands and output
ui/                    SwiftPM package: the dialogs and the keychain
```

```sh
make            # build/bin/ssh-key-control, build/libexec/ssh-key-control-ui
make test       # go test -race ./... and swift test
make check      # gofmt and go vet
```

The Go side is tested against fakes for launchd, the file system and the
helper, so the tests never touch launchd, the keychain or the screen. The
Swift tests cover the wire protocol and request dispatch; the dialogs
themselves are checked by hand.

## License

[MIT](LICENSE).
