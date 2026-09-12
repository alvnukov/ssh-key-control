#!/bin/bash
# Exercise the real localization resolver in relocated app/CLI layouts,
# with no SwiftPM build-tree fallback. No GUI, agent or user preference changes.
set -euo pipefail
app_path="${1:?built app required}"
resource_name=ssh-key-control-ui_SSHKeyControlUI.bundle
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/Probe.app/Contents/MacOS" "$temporary/Probe.app/Contents/Resources" "$temporary/libexec"
cp "$app_path/Contents/Info.plist" "$temporary/Probe.app/Contents/Info.plist"
ditto "$app_path/Contents/Resources/$resource_name" "$temporary/Probe.app/Contents/Resources/$resource_name"
ditto "$app_path/Contents/Resources/$resource_name" "$temporary/libexec/$resource_name"
cat > "$temporary/main.swift" <<'SWIFT'
import Foundation

extension Bundle {
    // Using the generated SwiftPM fallback is a packaging failure here.
    static var module: Bundle { fatalError("Unexpected build-tree fallback") }
}

let expected = CommandLine.arguments[1]
guard L10n.string("Deny") == expected else {
    fatalError("Incorrect preferred language")
}
guard L10n.resources.bundlePath.hasPrefix(Bundle.main.bundleURL.path) else {
    fatalError("Resources loaded outside the relocated product")
}
print("Localized product: " + expected)
SWIFT
xcrun swiftc ui/Sources/SSHKeyControlUI/Localization.swift "$temporary/main.swift" -o "$temporary/libexec/probe"
cp "$temporary/libexec/probe" "$temporary/Probe.app/Contents/MacOS/ssh-key-control-menubar"
for executable in "$temporary/libexec/probe" "$temporary/Probe.app/Contents/MacOS/ssh-key-control-menubar"; do
    "$executable" Отклонить -AppleLanguages '(ru-RU)'
    "$executable" Deny -AppleLanguages '(en-GB)'
    "$executable" Deny -AppleLanguages '(ja)'
done
