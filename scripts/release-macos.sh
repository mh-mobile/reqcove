#!/bin/bash
# Build the macOS (Apple silicon) binary on this Mac, sign it with a Developer
# ID, notarize it, and add it to the draft release that the release workflow
# made for the tag. The signing key never leaves the keychain.
#
#   scripts/release-macos.sh v0.1.0
#
# Needs: a "Developer ID Application" identity in the keychain, and notary
# credentials stored with
#   xcrun notarytool store-credentials reqcove-notary --apple-id … --team-id …
set -euo pipefail
version=${1:?usage: release-macos.sh vX.Y.Z}
identity=${REQCOVE_SIGN_IDENTITY:-Developer ID Application}
profile=${REQCOVE_NOTARY_PROFILE:-reqcove-notary}
cd "$(dirname "$0")/.."
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$version^{commit}")" ] || { echo "check out $version first" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "uncommitted or untracked files: the build must be exactly $version" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
name=reqcove_${version#v}_darwin_arm64
mkdir -p "$work/$name"
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X main.version=$version" -o "$work/$name/reqcove" ./cmd/reqcove
codesign --force --options runtime --timestamp --sign "$identity" "$work/$name/reqcove"
codesign --verify --strict "$work/$name/reqcove"

# Notarize. A bare binary cannot be stapled; Gatekeeper looks the ticket up online.
ditto -c -k "$work/$name/reqcove" "$work/notarize.zip"
# notarytool exits 0 for Invalid and Rejected too; only Accepted goes on.
xcrun notarytool submit "$work/notarize.zip" --keychain-profile "$profile" --wait --output-format json > "$work/notary.json"
status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "$work/notary.json")
if [ "$status" != "Accepted" ]; then
  id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("id",""))' "$work/notary.json")
  echo "notarization: $status" >&2
  [ -n "$id" ] && xcrun notarytool log "$id" --keychain-profile "$profile" >&2
  exit 1
fi

go run github.com/google/go-licenses/v2@v2.0.1 save ./cmd/reqcove --save_path="$work/$name/third_party_licenses"
cp "$(go list -m -f '{{.Dir}}' tailscale.com)/PATENTS" "$work/$name/third_party_licenses/tailscale.com/"
cp LICENSE README.md README.ja.md "$work/$name/"
tar -C "$work" -czf "$work/$name.tar.gz" "$name"

# Add it to the draft, with its checksum.
gh release download "$version" --pattern checksums.txt --dir "$work"
(cd "$work" && shasum -a 256 "$name.tar.gz" >> checksums.txt)
gh release upload "$version" "$work/$name.tar.gz" "$work/checksums.txt" --clobber
echo "added $name.tar.gz to the draft release $version"
