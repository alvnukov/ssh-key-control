#!/bin/bash
set -euo pipefail
image_path="${1:?DMG required}"
expected_version="${2:?version required}"
image_directory="$(cd "$(dirname "$image_path")" && pwd)"
image_name="$(basename "$image_path")"
(cd "$image_directory" && shasum -a 256 -c "$image_name.sha256")
mount_directory="$(mktemp -d)"
attached=false
cleanup() {
    if [ "$attached" = true ]; then hdiutil detach "$mount_directory" -quiet; fi
    rmdir "$mount_directory"
}
trap cleanup EXIT
hdiutil attach "$image_directory/$image_name" -readonly -nobrowse -mountpoint "$mount_directory" -quiet
attached=true
app="$mount_directory/SSH Key Control.app"
test "$(readlink "$mount_directory/Applications")" = /Applications
codesign --verify --deep --strict "$app"
plutil -lint "$app/Contents/Info.plist"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")" = "$expected_version"
test "$("$app/Contents/MacOS/ssh-key-control" --version)" = "ssh-key-control $expected_version"
for binary in ssh-key-control ssh-key-control-ui ssh-key-control-menubar; do
    test "$(lipo -archs "$app/Contents/MacOS/$binary")" = "$(uname -m)"
done
bash scripts/test-localization.sh "$app"
