#!/usr/bin/env bash
# Build clipveil.app: a dockless, ad-hoc-signed agent bundle.
# Signing the bundle gives clipveil its own TCC identity, so macOS attributes
# Accessibility permission to "clipveil" instead of whatever terminal launched it.
set -euo pipefail
cd "$(dirname "$0")/.."

BUNDLE_ID="engineer.sqa.clipveil"
APP="dist/clipveil.app"

echo "==> cargo build --release"
cargo build --release

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp dist/Info.plist "$APP/Contents/Info.plist"
cp target/release/clipveil "$APP/Contents/MacOS/clipveil"

echo "==> ad-hoc code signing"
codesign --force --sign - --identifier "$BUNDLE_ID" "$APP"
codesign --verify --verbose "$APP"

echo "==> done: $APP"
codesign -dvv "$APP" 2>&1 | grep -E "Identifier|Signature|CDHash" || true
