#!/usr/bin/env bash
# Install clipveil.app to ~/Applications and start it at login via a LaunchAgent.
# Running under launchd (not your terminal) is what makes Accessibility attach to
# clipveil itself — so you can revoke your terminal's Accessibility access.
set -euo pipefail
cd "$(dirname "$0")/.."

APP_SRC="dist/clipveil.app"
LABEL="engineer.sqa.clipveil"
DEST="$HOME/Applications"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"

[ -d "$APP_SRC" ] || { echo "Build first: dist/build-app.sh"; exit 1; }

echo "==> installing app to $DEST/clipveil.app"
mkdir -p "$DEST"
rm -rf "$DEST/clipveil.app"
cp -R "$APP_SRC" "$DEST/clipveil.app"

echo "==> stopping any running instance"
launchctl unload "$PLIST" 2>/dev/null || true
pkill -x clipveil 2>/dev/null || true

echo "==> writing LaunchAgent $PLIST"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${DEST}/clipveil.app/Contents/MacOS/clipveil</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/clipveil.err.log</string>
    <key>StandardOutPath</key>
    <string>/tmp/clipveil.out.log</string>
</dict>
</plist>
PL

echo "==> loading LaunchAgent"
launchctl load "$PLIST"

echo
echo "Installed. clipveil is running and will start at login."
echo "Next: System Settings > Privacy & Security > Accessibility — enable 'clipveil'."
echo "Then you can safely turn OFF Accessibility for your terminal."
