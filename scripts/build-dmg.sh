#!/bin/bash
# Build a compressed, read-only drag-to-Applications image without Finder automation.
set -euo pipefail
app_path="${1:?app bundle required}"
dmg_path="${2:?output DMG required}"
sign_identity="${3:--}"
test -d "$app_path"
for executable in ssh-key-control ssh-key-control-ui ssh-key-control-menubar; do
    test -x "$app_path/Contents/MacOS/$executable"
    /usr/bin/codesign --verify --strict "$app_path/Contents/MacOS/$executable"
done
for language in en ru; do
    test -f "$app_path/Contents/Resources/ssh-key-control-ui_SSHKeyControlUI.bundle/$language.lproj/Localizable.strings"
done
/usr/bin/codesign --verify --strict "$app_path"
mkdir -p "$(dirname "$dmg_path")"
stage_dir="$(mktemp -d "$(dirname "$dmg_path")/.dmg-stage.XXXXXX")"
trap 'rm -rf "$stage_dir"' EXIT
mkdir "$stage_dir/payload"
/usr/bin/ditto "$app_path" "$stage_dir/payload/SSH Key Control.app"
ln -s /Applications "$stage_dir/payload/Applications"
/usr/bin/ditto ui/App/Install.txt "$stage_dir/payload/Install.txt"
# Give HFS+/GPT explicit headroom: automatic sizing can produce an invalid
# small image for this payload. Unused space is compressed in the final UDZO.
payload_kib=$(/usr/bin/du -sk "$stage_dir/payload" | /usr/bin/awk '{print $1}')
image_mib=$(( (payload_kib + 1023) / 1024 * 2 + 32 ))
if [ "$image_mib" -lt 64 ]; then image_mib=64; fi
/usr/bin/hdiutil create -volname "SSH Key Control" -srcfolder "$stage_dir/payload" \
    -size "${image_mib}m" -fs HFS+ -format UDZO -ov "$stage_dir/image.dmg"
if [ "$sign_identity" != "-" ]; then
    /usr/bin/codesign --sign "$sign_identity" --timestamp "$stage_dir/image.dmg"
fi
/usr/bin/hdiutil verify "$stage_dir/image.dmg"
mv -f "$stage_dir/image.dmg" "$dmg_path"
(cd "$(dirname "$dmg_path")" && /usr/bin/shasum -a 256 "$(basename "$dmg_path")" > "$(basename "$dmg_path").sha256")
