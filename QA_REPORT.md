# clipveil QA Report — v0.1.0 (2026-07-03)

All checks are versioned in the repo and reproducible with a single command:

```sh
cargo test
```

## Suite

| Location | Tests | Covers |
|----------|-------|--------|
| `src/detect.rs` (unit) | 12 | pattern-level detection, overlap merge, label preference |
| `tests/detection.rs` (integration) | 6 | full corpus over the public API (below) |
| `tests/cli.rs` (end-to-end) | 4 | `scan`/`redact` via the built binary, exit codes, stdin |

The integration corpus (`tests/detection.rs`) asserts over:

- **25 positive cases** — every supported token type is detected and redacted.
- **7 false-positive controls** — UUID, git SHA, IP, prose, file paths, plain
  numbers, and a bare base64 blob all stay clean.
- **UTF-8 edge cases** — 🔑 emoji, accented `café`, and CJK 秘密 adjacent to a
  secret redact without panicking (byte-offset slicing stays on char
  boundaries because regex runs in Unicode mode).
- **Boundary spans** — secrets at the very start and end of input.
- **Overlap** — a `Bearer` + JWT overlap collapses to a single redaction span.
- **Large input** — a token embedded in a multi-thousand-line log is still found.

## Performance

A 196 KB payload with an embedded token scans in **~8 ms**. The lazy DFA is
linear in input size, so large pastes stay imperceptible — the reason `regex`
was chosen over `regex-lite` (see README → Footprint).

## Coverage

GitHub (classic + fine-grained PAT), GitLab PAT, OpenAI, Stripe, AWS access key,
Google API key, Google OAuth, Slack (bot, app, webhook), Discord bot token,
Telegram bot token, SendGrid, npm, JWT, Bearer headers, PEM private-key blocks,
and generic `password=` / `token=` / `api_key=` assignments.

## Manual GUI check

The Paste Plain / Paste Redacted dialog is verified by hand using
`samples/secret-samples.txt` (all fake values). It can't be automated here
because macOS hides the agent's window from screen-capture tooling — a
deliberate privacy property, and the reason clipveil's own dialog is invisible
to automation.

## Result

**Full suite passes: 22/22.** Run `cargo test` to reproduce.
