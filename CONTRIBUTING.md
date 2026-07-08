# Contributing to clipveil

Thanks for your interest. clipveil is a small macOS agent that redacts secrets in
your clipboard before you paste them. This guide covers building, testing, and
the pull-request workflow.

## Prerequisites

- macOS on Apple Silicon (arm64)
- Rust (stable, edition 2024 — rustc ≥ 1.85), via [rustup](https://rustup.rs)
- Xcode Command Line Tools (for `codesign`, linking AppKit)

## Build & test

The crate is split into a cross-platform **library** (detection, decision logic,
config) and a macOS **binary** (the agent). Tests run in two lanes:

```sh
cargo test                        # everything (default = agent feature)
cargo test --no-default-features  # fast: pure library only, no GUI stack
cargo clippy --all-features -- -D warnings
cargo fmt --all -- --check
cargo build --release
```

CI runs `fmt · clippy · test` plus a `cargo audit` job on every push and PR.
Please make sure `cargo fmt`, `cargo clippy -- -D warnings`, and both test lanes
pass before opening a PR — clippy in particular tracks the latest stable, which
can flag lints an older local toolchain misses (`rustup update stable`).

## Running the agent locally

```sh
./dist/build-app.sh        # builds + assembles + signs clipveil.app
./dist/install.sh          # installs to ~/Applications, starts it at login
```

Then grant **System Settings → Privacy & Security → Accessibility → clipveil**.

### Stable dev signing (skip the re-grant treadmill)

Ad-hoc signing changes the code hash every rebuild, so macOS asks you to
re-grant Accessibility each time. Create a self-signed **Code Signing**
certificate named `clipveil-dev` in your login keychain (Keychain Access →
Certificate Assistant → Create a Certificate, type *Code Signing*), then:

```sh
export CODESIGN_IDENTITY=clipveil-dev
./dist/build-app.sh
```

The grant is then keyed to the certificate, not the code hash, so it survives
rebuilds. CI and releases stay ad-hoc (unset `CODESIGN_IDENTITY`).

## Pull-request workflow

`main` is protected: PRs required, CI must pass, and commits must be signed.

1. Branch off the latest `main`: `git checkout -b <type>/<slug>`
   (`feat|fix|ci|docs|refactor|chore`).
2. Keep each PR focused on one concern. Conventional commit subjects
   (`<type>: <summary>`), body explains *why*.
3. Reference the issue in the PR body: `Closes #<n>`.
4. Ensure all checks pass, open the PR against `main`, and let it be reviewed
   before merging. Prefer **squash merge** to keep `main` linear.

## Code & test conventions

- Match existing style; `rustfmt` is authoritative.
- The detection core is pure and cross-platform — keep GUI/OS calls in the
  binary's thin shell (`agent.rs`, `paste.rs`).
- **Never commit a contiguous secret-shaped literal** — assemble test fixtures
  from parts with the `asm(&[...])` helper. GitHub push-protection will block
  real-looking tokens, and it's the exact anti-pattern this tool exists to
  prevent.
- Engineering conventions — commit format, squash-merge, and the `ponytail:`
  rule for marking intentional simplifications with their ceiling and upgrade
  path — live in [CLAUDE.md](CLAUDE.md), followed by both AI coding agents and
  human contributors.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
