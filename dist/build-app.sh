#!/usr/bin/env bash
# Build clipveil.app: a dockless, code-signed agent bundle.
# Signing the bundle gives clipveil its own TCC identity, so macOS attributes
# Accessibility permission to "clipveil" instead of whatever terminal launched it.
# Defaults to ad-hoc signing for CI/releases; local development can set
# CODESIGN_IDENTITY to a stable certificate name such as clipveil-dev.
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

echo "==> code signing with identity: ${CODESIGN_IDENTITY:--}"
codesign --force --sign "${CODESIGN_IDENTITY:--}" --identifier "$BUNDLE_ID" "$APP"
codesign --verify --verbose "$APP"

echo "==> done: $APP"
codesign -dvv "$APP" 2>&1 | grep -E "Identifier|Signature|CDHash" || true
