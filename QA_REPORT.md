# clipveil QA Report — v0.1.2 (2026-07-15)

All checks are versioned in the repo and reproducible with a single command
(and run in both feature lanes — full agent and pure library):

```sh
cargo test                        # --all-features
cargo test --no-default-features  # pure library only
```

## Suite — 68 tests

| Location | Tests | Covers |
|----------|-------|--------|
| `src/detect.rs` (unit) | 31 | pattern detection, overlap/label merge, config-aware `Scanner`, Shannon-entropy gate |
| `src/config.rs` (unit) | 15 | TOML parsing, hotkey parser, defaults, graceful fallback |
| `src/agent_plan.rs` (unit) | 7 | pure smart-paste decision plan + restore guard |
| `tests/detection.rs` (integration) | 11 | full corpus over the public API |
| `tests/cli.rs` (end-to-end) | 4 | `scan`/`redact` via the built binary, exit codes, stdin |

## Detection corpus (`tests/detection.rs`)

- **Positives** — every supported token type is detected and redacted.
- **False-positive controls** — UUID, git SHA, IP, prose, file paths, plain
  numbers, and a bare base64 blob stay clean; low-entropy generic assignments
  (`password=password`, `token=changeme`) are filtered by the entropy gate.
- **UTF-8 edge cases** — 🔑 emoji, accented `café`, CJK 秘密 adjacent to a secret
  redact without panicking (regex runs in Unicode mode, so byte-offset slicing
  stays on character boundaries).
- **Boundary spans** — secrets at the very start and end of input.
- **Overlap** — a `Bearer` + JWT overlap collapses to a single redaction span.
- **Large input** — a token in a multi-thousand-line log is still found.

## New in 0.1.2

- **Focus-settle before prompted pastes** (`agent_plan.rs`): both prompted plans
  (Plain and Redacted) now assert a `Wait(paste_settle_ms)` **before**
  `SendPaste` — the regression that made Paste Plain beep instead of pasting is
  locked down by the exact-plan tests. Verified live on macOS 26: both dialog
  buttons paste correctly and the redacted path still restores the original.
- **Dependency bumps** (`regex` 1.13, `toml` 1.1): full suite passes in both
  feature lanes after the `toml` 0.8 → 1.1 major bump; config parsing, fallback,
  and hotkey tests are unchanged. `cargo tree -d` confirms zero duplicate crate
  versions on macOS.

## New in 0.1.1

- **Config** (`config.rs`): TOML parsing, the `"cmd+shift+v"`-style hotkey
  parser, and graceful fallback (missing/invalid file → defaults, no panic).
  Custom (`[detection.extra]`) and disabled (`[detection].disable`) patterns are
  exercised through the `Scanner` in both the agent and the CLI.
- **Precision** (`detect.rs`): the Shannon-entropy gate on `generic_secret`
  filters low-entropy assignments while keeping real high-entropy values — the
  **full corpus passes with zero positive regressions**.
- **Decision layer** (`agent_plan.rs`): the pure `plan()` is asserted for all
  four branches (no-secret / Plain / Redacted / Cancel), and `should_restore`
  covers the change-count restore guard (restore only when the clipboard is
  unchanged).

## Performance

A 196 KB payload with an embedded token scans in **~8 ms**. The lazy DFA is
linear in input size, so large pastes stay imperceptible — the reason `regex`
was chosen over `regex-lite` (see README → Footprint).

## Detection coverage

GitHub (classic + fine-grained PAT), GitLab, OpenAI, Stripe, AWS access key,
Google API key + OAuth, Slack (bot, app, webhook), Discord, Telegram, SendGrid,
npm, JWT, Bearer headers, PEM private-key blocks, generic `password=` /
`token=` / `api_key=` assignments (entropy-gated), plus any user-configured
custom patterns.

## Manual / live checks

The Cmd+Shift+V → Paste Redacted → guarded-restore flow can't run in CI (macOS
hides the agent's window from screen-capture tooling — a deliberate privacy
property). It is verified by hand on each runtime-affecting change using
`samples/secret-samples.txt` (all fake values): the redacted paste lands and the
original is restored only when the clipboard is unchanged.

## Result

**Full suite passes: 68/68**, in both feature lanes. Run `cargo test` to reproduce.
