//! Pure decision layer for one smart-paste operation.

use std::time::Duration;

use clipveil::detect;

const RESTORE_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasteChoice {
    Plain,
    Redacted,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    WaitForModifiersReleased,
    SetClipboard(String),
    SendPaste,
    Wait(Duration),
    Restore(String),
}

pub(crate) fn needs_prompt(clipboard: &str) -> bool {
    !clipboard.is_empty() && detect::has_secret(clipboard)
}

pub(crate) fn plan(clipboard: &str, choice: PasteChoice) -> Vec<Action> {
    if !needs_prompt(clipboard) {
        return vec![Action::WaitForModifiersReleased, Action::SendPaste];
    }

    match choice {
        PasteChoice::Plain => vec![Action::WaitForModifiersReleased, Action::SendPaste],
        PasteChoice::Redacted => vec![
            Action::SetClipboard(detect::redact(clipboard)),
            Action::WaitForModifiersReleased,
            Action::SendPaste,
            Action::Wait(RESTORE_DELAY),
            Action::Restore(clipboard.to_string()),
        ],
        PasteChoice::Cancel => Vec::new(),
    }
}

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

        assert!(!needs_prompt(clipboard));
        assert_eq!(
            plan(clipboard, PasteChoice::Cancel),
            vec![Action::WaitForModifiersReleased, Action::SendPaste]
        );
    }

    #[test]
    fn plain_pastes_existing_clipboard() {
        let clipboard = secret_clipboard();

        assert!(needs_prompt(&clipboard));
        assert_eq!(
            plan(&clipboard, PasteChoice::Plain),
            vec![Action::WaitForModifiersReleased, Action::SendPaste]
        );
    }

    #[test]
    fn redacted_replaces_pastes_and_restores_clipboard() {
        let clipboard = secret_clipboard();

        assert!(needs_prompt(&clipboard));
        assert_eq!(
            plan(&clipboard, PasteChoice::Redacted),
            vec![
                Action::SetClipboard("prefix [REDACTED:github_token] suffix".to_string()),
                Action::WaitForModifiersReleased,
                Action::SendPaste,
                Action::Wait(Duration::from_millis(250)),
                Action::Restore(clipboard),
            ]
        );
    }

    #[test]
    fn cancel_does_nothing() {
        let clipboard = secret_clipboard();

        assert!(needs_prompt(&clipboard));
        assert_eq!(plan(&clipboard, PasteChoice::Cancel), Vec::new());
    }
}
