//! Pure decision layer for one smart-paste operation.

use std::time::Duration;

use crate::detect::Scanner;

// ── Timing (overridable via config) ────────────────────────────────────────

/// Default settle delay: give the target a short window to read the redacted
/// clipboard. Pasteboard change counts track writes, not reads, so a
/// pathologically slow target that reads after restoration remains a known,
/// unsolved edge.
pub const DEFAULT_PASTE_SETTLE_MS: u64 = 250;

/// Default modifier-wait timeout: how long we block waiting for physical
/// modifier keys to release before giving up.
pub const DEFAULT_MODIFIER_WAIT_TIMEOUT_MS: u64 = 1000;

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteChoice {
    Plain,
    Redacted,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    WaitForModifiersReleased,
    SetClipboard(String),
    SendPaste,
    Wait(Duration),
    RestoreIfUnchanged(String),
}

// ── Logic ──────────────────────────────────────────────────────────────────

pub fn needs_prompt(scanner: &Scanner, clipboard: &str) -> bool {
    !clipboard.is_empty() && scanner.has_secret(clipboard)
}

pub fn should_restore(captured_change_count: isize, current_change_count: isize) -> bool {
    captured_change_count == current_change_count
}

pub fn plan(
    scanner: &Scanner,
    clipboard: &str,
    choice: PasteChoice,
    settle_ms: u64,
) -> Vec<Action> {
    if !needs_prompt(scanner, clipboard) {
        return vec![Action::WaitForModifiersReleased, Action::SendPaste];
    }

    // Both prompted arms wait before SendPaste: the chooser dialog has just
    // closed and macOS re-activates the target app asynchronously. Pasting
    // before focus lands leaves the keystroke with no responder (error beep).
    match choice {
        PasteChoice::Plain => vec![
            Action::WaitForModifiersReleased,
            Action::Wait(Duration::from_millis(settle_ms)),
            Action::SendPaste,
        ],
        PasteChoice::Redacted => vec![
            Action::SetClipboard(scanner.redact(clipboard)),
            Action::WaitForModifiersReleased,
            Action::Wait(Duration::from_millis(settle_ms)),
            Action::SendPaste,
            Action::Wait(Duration::from_millis(settle_ms)),
            Action::RestoreIfUnchanged(clipboard.to_string()),
        ],
        PasteChoice::Cancel => Vec::new(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(parts: &[&str]) -> String {
        parts.concat()
    }

    fn secret_clipboard() -> String {
        format!(
            "prefix {} suffix",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        )
    }

    #[test]
    fn no_secret_pastes_without_prompt() {
        let clipboard = "ordinary clipboard text";
        let scanner = Scanner::default();

        assert!(!needs_prompt(&scanner, clipboard));
        assert_eq!(
            plan(
                &scanner,
                clipboard,
                PasteChoice::Cancel,
                DEFAULT_PASTE_SETTLE_MS
            ),
            vec![Action::WaitForModifiersReleased, Action::SendPaste]
        );
    }

    #[test]
    fn plain_pastes_existing_clipboard() {
        let clipboard = secret_clipboard();
        let scanner = Scanner::default();

        assert!(needs_prompt(&scanner, &clipboard));
        assert_eq!(
            plan(
                &scanner,
                &clipboard,
                PasteChoice::Plain,
                DEFAULT_PASTE_SETTLE_MS
            ),
            vec![
                Action::WaitForModifiersReleased,
                Action::Wait(Duration::from_millis(250)),
                Action::SendPaste,
            ]
        );
    }

    #[test]
    fn redacted_replaces_pastes_and_restores_clipboard() {
        let clipboard = secret_clipboard();
        let scanner = Scanner::default();

        assert!(needs_prompt(&scanner, &clipboard));
        assert_eq!(
            plan(
                &scanner,
                &clipboard,
                PasteChoice::Redacted,
                DEFAULT_PASTE_SETTLE_MS
            ),
            vec![
                Action::SetClipboard("prefix [REDACTED:github_token] suffix".to_string()),
                Action::WaitForModifiersReleased,
                Action::Wait(Duration::from_millis(250)),
                Action::SendPaste,
                Action::Wait(Duration::from_millis(250)),
                Action::RestoreIfUnchanged(clipboard),
            ]
        );
    }

    #[test]
    fn cancel_does_nothing() {
        let clipboard = secret_clipboard();
        let scanner = Scanner::default();

        assert!(needs_prompt(&scanner, &clipboard));
        assert_eq!(
            plan(
                &scanner,
                &clipboard,
                PasteChoice::Cancel,
                DEFAULT_PASTE_SETTLE_MS
            ),
            Vec::new()
        );
    }

    #[test]
    fn restores_when_clipboard_is_unchanged() {
        assert!(should_restore(42, 42));
    }

    #[test]
    fn skips_restore_when_clipboard_changed() {
        assert!(!should_restore(42, 43));
    }

    #[test]
    fn custom_settle_ms_is_respected() {
        let clipboard = secret_clipboard();
        let scanner = Scanner::default();
        let actions = plan(&scanner, &clipboard, PasteChoice::Redacted, 500);
        assert!(actions.contains(&Action::Wait(Duration::from_millis(500))));
        assert!(!actions.contains(&Action::Wait(Duration::from_millis(250))));
    }
}
