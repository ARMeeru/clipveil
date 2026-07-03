# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
