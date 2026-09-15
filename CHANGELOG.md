# Changelog

## Unreleased

Initial version.

- Use SSH Key Control consistently for product executables, service identifiers,
  preferences, data paths, package metadata, the app, and the DMG.
- Follow macOS language preferences with Russian and English UI resources,
  including menus, settings, history and standard approval dialogs.
- Refuse agent removal when Apple's fallback service is disabled or its status
  cannot be verified, without partially removing the managed SSH configuration.

- Self-contained drag-to-Applications DMG with a native agent setup window.
- Explicit Advanced setting to disable or restore Apple's per-user SSH service;
  distinguish pending SIP-blocked changes from a fully unloaded service, with
  logout, verification and recovery instructions.

- Native menu bar companion with an original terminal-key icon, General and
  Advanced settings, launchd crash recovery with deliberate Quit semantics, and
  a searchable security history.
- Bounded private decision history with exact fingerprints, decision source,
  scope and expiry. The UI has no authority to create approvals.
- Read-only `status --json` for the companion; the SSH agent runs independently.

- Cancel pending and queued confirmations when clients disconnect; do not
  retain grants from cancelled answers.
- Bound concurrent agent connections, frame sizes, pipelining and partial I/O.
- Require hostbound signed server identity for timed grants and denials;
  ordinary publickey requests remain one-shot.
- Show the calling process chain in the confirmation dialog and tie a timed
  decision to the ancestor it is drawn at, so it covers that program and
  everything it starts instead of every program running as this user. A refusal
  obeys the same line: it silences the program it was drawn at — and everything
  started from it, with no further dialog and no notification — instead of the
  user's own next connection, and outranks approvals held below it. A refusal
  that could not be attached to any program answers one request and is gone.
  Temporary Decisions lists and revokes by program.
- Manage keys from the menu bar: one item says how many keys the agent holds
  and opens a window listing every key this Mac knows about — the private keys
  in `~/.ssh`, the `IdentityFile` entries of `~/.ssh/config`, files added by
  hand, and keys the agent holds whose file is not here. A switch per row loads
  that one key or takes it back out, a checkbox marks a key to be loaded when
  the menu bar app starts (only into an agent holding nothing, and saying so
  when it has no remembered passphrase), and each row shows whether its
  passphrase is in the keychain and can forget it. Backed by
  `ssh-key-control keys load|unload|list`, which now lists the keys on disk
  beside the ones in the agent and unloads by fingerprint. Loading runs
  OpenSSH's `ssh-add` against the protected socket with this program as its
  `SSH_ASKPASS`, skips the keys the agent already holds, and waits as long as a
  passphrase takes to type.
- Configurable Return/keypad Enter action with a visible matching default;
  Escape always denies.
- Do not include malformed UI responses in errors, which could expose secrets.

- `ssh-key-control <prompt>`: answers OpenSSH prompts with native dialogs.
  Passphrases and passwords can be remembered in the login keychain;
  `ssh-add -c` confirmations default to Deny; host-key questions get a text
  field; security-key notifications close when OpenSSH is done.
- `ssh-key-control install`: registers a launch agent that owns the
  `SSH_AUTH_SOCK` socket, exports `SSH_AUTH_SOCK`, `SSH_ASKPASS` and
  `SSH_ASKPASS_REQUIRE` to the login session and serves its own agent that
  requires approval for every signature, with per-server time grants and
  Deny ending the connection attempt.
- `ssh-key-control uninstall`, `status`, `doctor` and `forget`.
- Homebrew formula and Makefile.
