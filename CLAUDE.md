# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

clipveil is a macOS agent that veils secrets in your clipboard before you paste them. It binds Cmd+Shift+V; when the clipboard holds a secret it offers Paste Redacted / Paste Plain, otherwise it pastes normally. All detection runs locally.

## Build, test, lint

```sh
cargo test                        # full test suite (default features = agent)
cargo test --no-default-features  # fast lane: pure library only, no GUI stack
cargo clippy --all-features -- -D warnings
cargo fmt --all -- --check
cargo build --release
```

Run a single test:
```sh
cargo test test_name
cargo test --test detection        # a specific integration test file
```

Build and run the agent locally:
```sh
./dist/build-app.sh                # builds + assembles + signs clipveil.app
./dist/install.sh                  # installs to ~/Applications
```

Stable dev signing (avoids re-granting Accessibility each rebuild):
```sh
export CODESIGN_IDENTITY=clipveil-dev
./dist/build-app.sh
```

## Architecture

One Cargo package, two crates:

**Library (`src/lib.rs`)** — pure, cross-platform, no OS/GUI deps. Testable with `--no-default-features`.
- `detect.rs` — regex pattern set, config-aware `Scanner`, `redact`/`scan`/`summary`, Shannon-entropy gate for `generic_secret` (threshold 2.8)
- `agent_plan.rs` — pure decision layer: `plan(clipboard, choice) -> Vec<Action>` plus `should_restore(..)`. No side effects.
- `config.rs` — TOML config loader, hotkey string parser. Config at `${XDG_CONFIG_HOME:-~/.config}/clipveil/config.toml`.

**Binary (`src/main.rs`)** — macOS agent + CLI, behind the `agent` feature flag.
- `agent.rs` — dockless NSApplication, Carbon global hotkey, rfd dialog, Accessibility preflight, executor that runs `agent_plan` actions against real clipboard/input APIs.
- `paste.rs` — clipboard read/write (arboard), synthetic Cmd+V (enigo), modifier-release wait.

Design rule: detection logic and decisions are pure and unit-tested. The side-effecting shell (`agent.rs` executor, `paste.rs`) is intentionally untested.

## Feature flags

- `agent` (default) — full macOS agent (rfd, enigo, global-hotkey, objc2-app-kit, ...)
- `clipboard` — clipboard access for scan/redact
- No default features — pure library only (regex + config)

## Key conventions

- **Never commit a contiguous secret-shaped literal.** Assemble test fixtures from parts with the `asm(&[...])` helper. GitHub push-protection blocks real-looking tokens.
- Overlapping findings merge into one span; the most specific kind label wins (rank: vendor-specific > bearer_token > generic_secret).
- `generic_secret` matches pass a Shannon-entropy gate on the value portion — low-entropy assignments like `password=password` are filtered out.
- Config files never panic: missing/invalid config falls back to defaults with a stderr warning.
- Conventional commit subjects: `<type>: <summary>` (feat|fix|ci|docs|refactor|chore). Squash merge PRs.
- Rust edition 2024 (rustc >= 1.85).

## Ponytail — lazy senior dev mode

Before writing any code, stop at the first rung that holds:

1. Does this need to be built at all? (YAGNI)
2. Does it already exist in this codebase? Reuse the helper, util, or pattern that's already here.
3. Does the standard library already do this? Use it.
4. Does a native platform feature cover it? Use it.
5. Does an already-installed dependency solve it? Use it.
6. Can this be one line? Make it one line.
7. Only then: write the minimum code that works.

The ladder runs after you understand the problem, not instead of it: read the task and the code it touches, trace the real flow end to end, then climb.

Bug fix = root cause, not symptom. Grep every caller of the function you touch and fix the shared function once.

Rules:
- No abstractions that weren't explicitly requested.
- No new dependency if it can be avoided.
- Deletion over addition. Boring over clever. Fewest files possible.
- Shortest working diff wins, but only once you understand the problem.
- Pick the edge-case-correct option when two stdlib approaches are the same size.
- Mark intentional simplifications with a `ponytail:` comment naming the ceiling and upgrade path.

Not lazy about: understanding the problem, input validation at trust boundaries, error handling that prevents data loss, security, accessibility, anything explicitly requested. Non-trivial logic leaves ONE runnable check behind (an assert-based self-check or one small test file; no frameworks, no fixtures).
