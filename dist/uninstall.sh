#!/usr/bin/env bash
set -euo pipefail
LABEL="engineer.sqa.clipveil"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
pkill -x clipveil 2>/dev/null || true
rm -rf "$HOME/Applications/clipveil.app"
echo "clipveil uninstalled (LaunchAgent removed, app deleted)."
echo "Remove its Accessibility entry manually in System Settings if you wish."
