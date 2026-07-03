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

/// Block until the physical modifier keys (Cmd/Shift/Option/Ctrl) are released,
/// or a timeout elapses.
///
/// The global hotkey fires on key-*down*, so at that instant the user is still
/// holding Cmd+Shift. Synthesizing Cmd+V while Shift is physically down yields a
/// polluted chord (not a clean paste). We wait for the hardware state to clear
/// first. Reads the HID-level flags so it reflects real keys, not synthetic ones.
#[cfg(feature = "agent")]
pub fn wait_for_modifiers_released() {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceFlagsState(state_id: u32) -> u64;
    }
    // kCGEventSourceStateHIDSystemState = 1 (actual hardware key state)
    const HID_STATE: u32 = 1;
    // CGEventFlags masks: shift | control | alternate | command
    const MOD_MASK: u64 = 0x0002_0000 | 0x0004_0000 | 0x0008_0000 | 0x0010_0000;

    let start = std::time::Instant::now();
    loop {
        let flags = unsafe { CGEventSourceFlagsState(HID_STATE) };
        if flags & MOD_MASK == 0 {
            break;
        }
        if start.elapsed() >= std::time::Duration::from_millis(1000) {
            break; // give up after 1s; the user is genuinely holding a key
        }
        std::thread::sleep(std::time::Duration::from_millis(8));
    }
}
