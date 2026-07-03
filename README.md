# clipveil

**Veil secrets in your clipboard before you paste them.**

A tiny (~1 MB), zero-runtime macOS agent for people who copy from a terminal and
paste into an LLM, a chat, or a doc — and occasionally forget that the thing they
just copied contains a live GitHub token, AWS key, or private key.

`clipveil` binds a single hotkey — **Cmd+Shift+V**. When you press it:

- If the clipboard has **no** secret, it just pastes. Nothing changes.
- If it **does**, a native dialog appears:

  > ⚠️ Secret detected in clipboard: `github_token`
  > **[ Paste Redacted ]  [ Paste Plain ]**

  Pick **Paste Plain** to drop the real value where you actually need it (an
  `.env`, a config, a `curl`). Pick **Paste Redacted** to paste a masked copy —
  ideal for LLM prompts and bug reports. Your real clipboard is restored
  afterwards either way.

Your normal **Cmd+V** is never touched.

---

## Why it exists

Existing "secure clipboard managers" redact secrets in their *saved history* —
the thing you actually paste is untouched. clipveil redacts the **paste itself**,
at the moment you paste, with a choice. All detection runs locally; nothing ever
leaves your machine.

## Install

Requires the Rust toolchain (`rustup`) and macOS.

```sh
git clone <your-repo-url> clipveil
cd clipveil
cargo build --release
cp target/release/clipveil /usr/local/bin/
```

### Grant Accessibility permission (one time)

Synthesizing the paste keystroke requires Accessibility access. The first time
clipveil tries to paste, macOS will prompt — or add it manually:

**System Settings → Privacy & Security → Accessibility → +** and add
`clipveil` (or the terminal you launch it from).

Without this, detection and the dialog still work, but the final paste keystroke
is silently dropped by macOS.

clipveil checks this at startup and prints a warning if the permission is
missing, so you won't be left guessing why a paste didn't land.

## Usage

```sh
clipveil run          # start the agent (default). Binds Cmd+Shift+V.
clipveil scan         # scan piped stdin or the clipboard; exit 1 if a secret is found
clipveil redact       # print a redacted copy of piped stdin or the clipboard
clipveil version
clipveil help
```

The `scan` / `redact` subcommands make clipveil useful in scripts and pre-commit
hooks too:

```sh
pbpaste | clipveil scan            # "am I about to paste a secret?"
cat prod.env | clipveil redact     # masked copy for sharing
git diff | clipveil scan || echo "secret in staged changes!"
```

## Run at login

Copy the provided launch agent and load it:

```sh
cp dist/com.clipveil.agent.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.clipveil.agent.plist
```

## What it detects

GitHub tokens (classic + fine-grained PAT), GitLab PATs, OpenAI keys, Stripe
keys, AWS access key IDs, Google API keys, Slack tokens & webhooks, npm tokens,
JWTs, `Authorization: Bearer` headers, PEM private-key blocks, and generic
`password=` / `token=` / `api_key=` assignments.

Detection favors safety over precision: it would rather flag a false positive
(which you dismiss with **Paste Plain**) than leak a real secret. Patterns live
in [`src/detect.rs`](src/detect.rs) — add your own in one line.

## How it works

```
Cmd+Shift+V ──▶ read clipboard ──▶ detect::has_secret?
                                     │
                        no ──────────┤────────── yes
                        │            │            │
                   paste as-is       │      native dialog
                                     │       ┌────┴─────┐
                                   Plain   Redacted   Cancel
                                     │        │          │
                                  paste   set redacted   nothing
                                          clipboard,
                                          paste,
                                          restore original
```

- Global hotkey via Carbon `RegisterEventHotKey` (no Accessibility needed).
- Dialog via native AppKit (`rfd`).
- Paste synthesized via `enigo` (needs Accessibility).
- Detection is pure regex — fully unit-tested, no I/O.

## Known limitations (v1)

- The paste is a synthetic **Cmd+V**, so the target app must accept a normal
  paste. There's a small focus-settle delay after the dialog closes; very fast
  successive pastes may need a beat.
- Regex detection can't catch every possible secret shape. It covers the common,
  high-risk ones. Treat it as a safety net, not a guarantee.

## Development

```sh
cargo test --no-default-features    # fast: detection core only
cargo clippy --all-features -- -D warnings
cargo build --release
```

## License

MIT — see [LICENSE](LICENSE).
