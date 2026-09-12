# Release verification

The first release is v0.1.0, matching the committed app version. Publication is
triggered by a version tag on main and requires all jobs in `.github/workflows/ci.yml`.

## Required automated gates

- Full Git-history secret scan, module verification and tidy check, workflow lint.
- Go vet, staticcheck, reachable dependency vulnerability scanning and CodeQL.
- Go race tests and bounded packet/session-binding parser fuzzing.
- Swift tests with warnings as errors and Objective-C static analysis.
- Native Apple Silicon and Intel builds, read-only DMG mounting, checksum,
  architecture, version, code-signature and relocated RU/EN resource validation.
- Binary vulnerability scan and GitHub artifact attestations before publication.

## Distribution limits

The current release uses ad-hoc signatures, without Developer ID or Apple
notarization. Git commit/tag signatures and GitHub attestations establish source
and build provenance; they do not establish Gatekeeper acceptance. Clean-Mac
Gatekeeper, macOS 13 compatibility and Intel hardware smoke tests remain manual
checks beyond the CI macOS 15 runners. No universal binary is claimed.

## Product boundaries

Timed Allow and Deny decisions require the exact signing-key fingerprint,
verified host-key fingerprint and SSH username. Unverified requests allow only
one-time decisions. The default-on Apple-agent monitor removes detected keys
from that agent's memory and sends system notifications; polling permits use
before detection. It does not modify private files, Keychain, Apple's launch
policy or macOS protections. History is local informational evidence, not a
tamper-proof log or proof of a completed SSH login.

Known previous managed SSH-config prefixes can be migrated explicitly with a
private backup; unknown or modified prefixes remain protected from overwrite.
The original install backup is retained across removal and reinstallation.
Tests are evidence for these contracts, not a proof of complete security.
