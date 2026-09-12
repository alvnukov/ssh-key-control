# Private one-time name migration contract

Releases created after the product-name cleanup intentionally contain no previous
product identifiers. Upgrading an existing installation therefore requires a
one-time local migrator whose previous paths, labels, defaults domain, Keychain
service, and SSH configuration markers come from a verified private backup.
Those values must not be reconstructed by guessing or hidden in the public tree.

The migrator must run only after the user explicitly starts it and must satisfy
this sequence:

1. Perform a read-only preflight. Resolve the two previous launch-agent plists,
   their exact labels and executables, and check both with
   `SMAppService.statusForLegacyPlist`. Abort while either status is
   `requiresApproval`, `notFound`, or `notRegistered`. A previous Login Items
   denial must be changed by the user in macOS Settings before migration; a new
   label must never be used to bypass that decision.
2. Verify that every source file and directory is owned by the current user,
   has the expected type, and is not a symlink. Create a private, mode-preserving
   backup before changing anything.
3. Copy the complete application-support directory into
   `~/Library/Application Support/SSH Key Control` without interpreting the
   journal or policy payload. This preserves exact key and server fingerprints,
   SSH users, decisions, retention settings, and history ordering.
4. Copy the known defaults keys into the new defaults domains without changing
   their values. Copy each known Keychain generic-password item to service
   `ssh-key-control` with the same account, secret data, accessibility, and
   access-control attributes. Do not delete the source item at this stage.
5. Replace the previous SSH managed block only when it is byte-exact and at the
   beginning of the file. Write the current `ssh-key-control` block and socket
   path atomically, preserve unrelated SSH configuration and file modes, and
   abort on modified, displaced, or duplicate markers.
6. Confirm the renamed app bundle and all three executables are already present.
   After a final explicit user confirmation, boot out both previous jobs and
   verify both labels are absent before allowing either current job to start.
   Keep a rollback path that restores the previous plists and configuration if
   the current installation does not become healthy.
7. Open SSH Key Control and require the user to choose **Enable / Update Agent**.
   Do not bootstrap current labels from the migrator. If macOS reports
   `requiresApproval` for either current Login Item, stop and direct the user to
   Login Items; do not retry under another identifier.
8. Declare success only when lifecycle health reports the expected executable
   paths, one running protected agent, one supervised menu process, the exact
   socket link, managed SSH configuration, and matching login-session variables.
   Delete the previous plist files only after this check. Retain the private data
   backup and source Keychain items until the user separately approves cleanup.

The current public installer also refuses an unknown managed SSH block instead
of prepending a second block. That failure is the signal to run this migrator,
not a reason to weaken ownership checks.
