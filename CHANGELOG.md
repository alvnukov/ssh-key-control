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
