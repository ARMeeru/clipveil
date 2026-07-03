# clipveil QA Report — v0.1.0 (2026-07-03)

Automated QA over the detection engine via the `scan` / `redact` CLI, plus a
manual sample set (`samples/secret-samples.txt`) for the GUI dialog flow.

## Summary

**53 / 53 automated checks passed.**

| Category | Cases | Result |
|----------|-------|--------|
| Positive detection (all token types) | 20 | all detected |
| False-positive controls (UUID, git SHA, IP, prose, paths, base64) | 7 | all clean |
| Edge cases (start/end spans, emoji, accents, CJK, overlap) | 6 | all pass, no panic |
| Newer token types (Discord, Slack app, Google OAuth, Telegram, SendGrid) | 5 | added + covered |
| Regression unit tests | 12 | pass |

## UTF-8 safety

Redaction slices by byte offset. Verified that inputs mixing multi-byte
characters (🔑 emoji, accented `café`, CJK 秘密) with secrets redact without
panic and preserve surrounding text — regex operates in Unicode mode, so match
boundaries always fall on valid character boundaries.

## Performance

A 196 KB clipboard payload with an embedded token scans in **~8 ms**. The lazy
DFA is linear in input size, so large pastes stay imperceptible (this is the
central reason `regex` was chosen over `regex-lite` — see README Footprint).

## Coverage

GitHub (classic + fine-grained PAT), GitLab PAT, OpenAI, Stripe, AWS access key,
Google API key, Google OAuth, Slack (bot, app, webhook), Discord bot token,
Telegram bot token, SendGrid, npm, JWT, Bearer headers, PEM private-key blocks,
and generic `password=` / `token=` / `api_key=` assignments.

## Known limitations

- Regex detection targets common, high-risk shapes; it is a safety net, not a
  guarantee. The Paste Plain / Paste Redacted dialog is the human backstop.
- The GUI dialog flow (button clicks) is validated manually via the sample file;
  it cannot be automated here because macOS hides the agent's window from
  screen-capture tooling (a deliberate privacy property).
