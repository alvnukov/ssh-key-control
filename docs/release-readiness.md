# SSH Key Control: release readiness

Status: source preparation for the first tag-driven release. No published build,
tag, signature, notarization, or attestation is claimed by this document.

## Branding and compatibility

The app, DMG, executables, Go module, launchd labels, bundle identifier,
preferences suite, history directory, package metadata, and public repository
all use SSH Key Control. The reference Homebrew formula points to the public
repository; no tap is published.

The public source contains no previous product identifiers. An existing local
installation requires the explicit private migration in `name-migration.md`;
the current installer must not use a new service identifier to bypass a denied
Login Items decision.

## Language

The UI follows macOS preferred languages. Russian and English catalogs ship in
both the app and standalone helper installation; unsupported languages fall
back to English. Quit and reopen the app after changing macOS language settings.
Approval wire values, fingerprints, key comments, paths and account names remain
unchanged. OpenSSH-supplied prompts and command diagnostics are preserved verbatim.

The relocation test compiles the actual localization resolver and places it
beside copied product resources in app and standalone layouts. Its SwiftPM
fallback fails deliberately, so a passing test cannot depend on a development
checkout. It checks Russian, English and unsupported-language fallback.

## Local verification

- Go race tests and vet pass, including fail-closed uninstall preflight.
- Swift tests pass, including lifecycle approval guards, catalog parity,
  formatting arguments, opaque security data, Return/Escape behavior, and
  native settings.
- `make dmg` verifies executable and bundle structure, both language resources,
  and image integrity. A public release still requires the signing and manual
  checks below.
- Run `bash scripts/test-localization.sh "build/SSH Key Control.app"`
  to verify relocated resources. CI runs this after building the image.

## Before public release

- Obtain a Developer ID signing identity; sign, notarize and staple the release,
  then regenerate the checksum. No signing identity was available locally.
- Exercise download/Gatekeeper, drag installation, upgrade and removal on a
  clean Mac. Verify Intel separately before offering an Intel image.
- Complete a real logout/login test for Apple's service disable and restore.
  SIP can leave a disabled service running until logout. Never report that state
  as fully disabled. Do not remove the protected agent until fallback is restored.
- The initial tag is v0.1.0. Tag publication is blocked by source security,
  native tests and DMG verification on both architectures, and CodeQL findings.
  A tag must match the committed app version and refer to a commit on main.
  Developer ID and clean-Mac manual validation remain separate distribution gates.

## Security boundary

Approvals are scoped to exact key fingerprint, verified server-key fingerprint
and SSH user. Plain publickey requests permit one signature only; server names
never grant access to all server fingerprints. Localization does not alter
authorization logic.

Disabling Apple's launchd service is not a prohibition on all agent processes.
Processes with access to private key files or Keychain may use other paths.
History is local informational evidence, not a tamper-proof audit log or a list
of completed SSH logins. See SECURITY.md and README for the threat model; tests
are not a proof of complete security.
