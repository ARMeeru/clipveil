# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-07-06

### Added
- Optional TOML config at `${XDG_CONFIG_HOME:-~/.config}/clipveil/config.toml`:
  configurable hotkey, paste/modifier delays, and custom or disabled detection
  patterns. Applies to both the agent and the `scan`/`redact` CLI.
- `cargo audit` (RustSec) in CI and Dependabot for dependency security.
- Tag-triggered release automation (build, sign, checksum, publish).
- Stable dev code-signing via `CODESIGN_IDENTITY` so Accessibility survives rebuilds.
- CONTRIBUTING.md and ARCHITECTURE.md.

### Changed
- Detection precision: a Shannon-entropy gate on generic `password=`/`token=`/`api_key=`
  matches cuts false positives without touching provider-specific patterns.
- After a redacted paste, the original is restored only if the pasteboard is unchanged
  (guarded by change count) — never clobbering a newer copy or resurrecting the secret.
- Refactored the agent's smart-paste decision into a pure, unit-tested layer.

[0.1.1]: https://github.com/ARMeeru/clipveil/releases/tag/v0.1.1

## [0.1.0] - 2026-07-04

### Added
- **Cmd+Shift+V** global hotkey. On a secret-carrying clipboard it shows a native
  **Paste Redacted / Paste Plain** dialog; otherwise it pastes normally. Plain
  Cmd+V is never intercepted.
- Detection for 18 secret classes: GitHub (classic + fine-grained PAT), GitLab,
  OpenAI, Stripe, AWS access keys, Google API + OAuth, Slack (bot/app/webhook),
  Discord, Telegram, SendGrid, npm, JWTs, Bearer headers, PEM private keys, and
  generic `password=` / `token=` / `api_key=` assignments.
- CLI subcommands: `scan` (exit 1 on secret), `redact`, and `run` (the agent).
- Dockless, ad-hoc-signed `.app` bundle with a launch-at-login installer.
- Startup Accessibility preflight that warns when the permission is missing.
- 22 automated tests (unit + integration corpus + CLI) and a QA report.

[0.1.0]: https://github.com/ARMeeru/clipveil/releases/tag/v0.1.0
