//! Clipboard I/O and synthetic paste. All OS-touching side effects live here.

#[cfg(feature = "clipboard")]
use arboard::Clipboard;

/// Read the current clipboard text (empty string if it holds no text).
#[cfg(feature = "clipboard")]
pub fn read_clipboard() -> Result<String, String> {
    let mut cb = Clipboard::new().map_err(|e| e.to_string())?;
    match cb.get_text() {
        Ok(t) => Ok(t),
        // No text on the clipboard is not an error for our purposes.
        Err(_) => Ok(String::new()),
    }
}

/// Overwrite the clipboard with `s`.
#[cfg(feature = "clipboard")]
pub fn write_clipboard(s: &str) -> Result<(), String> {
    let mut cb = Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(s.to_string()).map_err(|e| e.to_string())
}

/// Synthesize Cmd+V into the frontmost application.
///
/// Requires Accessibility permission (System Settings → Privacy & Security →
/// Accessibility). Without it, macOS silently drops the synthetic keystrokes.
#[cfg(feature = "agent")]
pub fn send_cmd_v() -> Result<(), String> {
    use enigo::{Direction, Enigo, Key, Keyboard, Settings};
    let mut enigo = Enigo::new(&Settings::default()).map_err(|e| e.to_string())?;
    enigo.key(Key::Meta, Direction::Press).map_err(|e| e.to_string())?;
    enigo.key(Key::Unicode('v'), Direction::Click).map_err(|e| e.to_string())?;
    enigo.key(Key::Meta, Direction::Release).map_err(|e| e.to_string())?;
    Ok(())
}
