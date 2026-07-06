# Architecture

clipveil binds a hotkey (default **Cmd+Shift+V**); when the clipboard holds a
secret it offers **Paste Redacted / Paste Plain**, otherwise it pastes normally.
All detection runs locally — nothing leaves the machine.

## Crate layout: library + binary

The project is one package with two crates:

- **Library (`clipveil`)** — pure, cross-platform, no OS/GUI dependencies. This
  is what the fast `--no-default-features` test lane exercises.
  - `detect` — regex pattern set, the config-aware `Scanner`, `redact`/`scan`/
    `summary`, and the Shannon-entropy gate for `generic_secret`.
  - `agent_plan` — the pure decision layer: `plan(clipboard, choice) -> Vec<Action>`
    plus `should_restore(..)`. Contains no side effects.
  - `config` — loads the optional TOML config and parses the hotkey string.
- **Binary (`clipveil`)** — the macOS agent + CLI, behind the `agent` feature.
  - `main.rs` — CLI dispatch: `run` (agent), `scan`, `redact`.
  - `agent.rs` — the macOS shell: a dockless (`.Accessory`) `NSApplication`
    running the Cocoa loop, the Carbon global hotkey, the `rfd` dialog, the
    Accessibility preflight, and the **executor** that runs an `agent_plan`
    action list against the real clipboard/input APIs.
  - `paste.rs` — clipboard read/write (`arboard`), synthetic Cmd+V (`enigo`),
    and the modifier-release wait.

Detection logic and decisions are pure and unit-tested; only the thin
side-effecting shell (`agent.rs` executor, `paste.rs`) is untested — by design.

## Detection

`Scanner` holds an effective pattern set = built-in patterns, minus any kinds
disabled in config, plus any `[detection.extra]` patterns. `scan` returns
non-overlapping, merged `Finding` spans (specific labels preferred over the
broad `generic_secret`). Generic matches additionally pass a Shannon-entropy
gate (threshold 2.8) so low-entropy assignments like `password=password` don't
false-positive, while real high-entropy values still match. Both the agent and
the CLI (`scan`/`redact`) use a config-built `Scanner`.

## The smart-paste flow

```
Cmd+Shift+V ─▶ read clipboard ─▶ needs_prompt?
                                    │
                        no ─────────┤───────── yes
                        │           │           │
                     plan()      dialog: Redacted / Plain / Cancel
                        │           │
                        ▼           ▼
                 execute(Vec<Action>) on the real APIs
```

`plan()` returns an ordered, side-effect-free list of `Action`s
(`WaitForModifiersReleased`, `SetClipboard`, `SendPaste`, `Wait`,
`RestoreIfUnchanged`). The executor runs them. After a redacted paste, the
original is restored **only if** the pasteboard `changeCount` is unchanged since
the redacted write — so a newer copy is never clobbered and the secret is never
resurrected over it. (`changeCount` tracks writes, not reads, so a pathologically
slow target reading after restore is a known, unsolved edge.)

## macOS specifics

- The global hotkey uses Carbon `RegisterEventHotKey`, whose events dispatch to
  the *application* event target — a bare CLI has no such identity, so the agent
  promotes itself to a dockless `NSApplication` and runs the Cocoa loop.
- Synthesizing the paste keystroke needs **Accessibility** permission; a startup
  preflight (`AXIsProcessTrustedWithOptions`) warns when it's missing.
- Signing gives the app its own TCC identity. Releases are ad-hoc signed; local
  dev can use a stable self-signed cert (`CODESIGN_IDENTITY`) so the grant
  survives rebuilds. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Configuration

`${XDG_CONFIG_HOME:-~/.config}/clipveil/config.toml` (all fields optional; a
missing or invalid file falls back to defaults with a warning, never a panic):
hotkey binding, `paste_settle_ms`, `modifier_wait_timeout_ms`, and
`[detection]` (`disable` built-in kinds, `[detection.extra]` custom patterns).
See `dist/config.example.toml`.

## Feature flags

- `agent` (default) → the full macOS agent (`rfd`, `enigo`, `global-hotkey`,
  `objc2-app-kit`, …).
- `clipboard` → clipboard access for `scan`/`redact`.
- No default features → the pure library only (regex + config), which is why the
  detection and decision layers are testable without a display.

## CI & release

- `.github/workflows/ci.yml` — fmt · clippy · test + `cargo audit`, on macOS.
- `.github/workflows/release.yml` — on a `v*` tag: build, sign, package, and
  publish the zip + raw binary + checksums; `workflow_dispatch` runs a build-only
  dry run.
- Dependabot keeps Cargo + Actions dependencies current.
