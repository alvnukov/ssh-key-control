# Security policy

Report suspected vulnerabilities privately using GitHub's **Report a
vulnerability** option on this repository's Security page. Include the affected
version, a minimal reproduction using disposable keys and the expected security
boundary. Do not publish real private keys, passwords or live server details.

The current release line is 0.1.x. Fixes will be published as new version tags;
older development snapshots are unsupported.

## What the application protects

The agent gates signing operations. Persistent decisions require the exact
signing-key fingerprint, verified host-key fingerprint and SSH username.
Unverified destinations receive at most one signature per approval.

Disabling Apple's launchd service does not prevent arbitrary processes from
starting another agent or reading accessible private keys. Local history is
informational and may be modified by processes running as the same user.

CI runs secret scanning, dependency vulnerability checks, Go/Swift CodeQL,
static analysis, race tests, native regression tests, parser fuzzing and
packaged-artifact checks. These checks reduce risk; they do not constitute a
formal proof of security, independent audit or Apple notarization.
