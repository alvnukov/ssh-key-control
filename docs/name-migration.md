# Migrating previous managed SSH settings

The setup window recognizes a small, explicit set of previous managed prefixes
at the start of `~/.ssh/config`. It offers migration only after recognizing the
exact prefix. The same operation is available as `ssh-key-control migrate-config`.

Migration saves the full original config as
`~/.ssh/config.ssh-key-control.migration.bak`, replaces only the recognized prefix,
preserves the remaining contents and permissions, then repairs the current
installation. An existing migration backup must match the input exactly and is
never overwritten. The ordinary `.ssh-key-control.bak` retains the first install
backup across later edits and reinstallations.

Unknown, modified, displaced or repeated managed markers are not overwritten.
Setup provides the config location and an action to open it for manual review.
This prevents migration from interpreting user-written rules as owned settings.

This operation migrates SSH configuration only. It does not copy or remove old
Keychain entries, history, private keys or unrelated application bundles. It does
not change macOS protection or Apple's agent startup policy. Existing Login Items
approval requirements remain in force; renaming a service is not an approval bypass.
