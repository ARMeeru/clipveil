clipveil detects and redacts API keys, access tokens, credentials, JWTs, and private keys before paste.

## Install

```sh
mkdir -p ~/Applications
unzip clipveil-*-macos-arm64.zip -d ~/Applications
xattr -dr com.apple.quarantine ~/Applications/clipveil.app
open ~/Applications/clipveil.app
```

Then grant **System Settings → Privacy & Security → Accessibility → clipveil** so it can synthesize the paste keystroke.

> Apple Silicon (arm64) only. The app is ad-hoc signed, not notarized, so clearing the quarantine attribute with the `xattr` step is required after download.
