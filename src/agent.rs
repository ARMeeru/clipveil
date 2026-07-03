//! Resident agent: binds Cmd+Shift+V, and on a secret-carrying clipboard shows
//! a "Paste Plain / Paste Redacted" chooser before letting the paste through.
//!
//! Design notes (macOS specifics):
//! * The global hotkey is a Carbon `RegisterEventHotKey`, which needs a running
//!   CFRunLoop on the main thread to dispatch. We run that loop here.
//! * The hotkey callback fires ON the main thread, which is exactly where AppKit
//!   (the rfd dialog) and event synthesis must happen.

use std::thread;
use std::time::Duration;

use global_hotkey::{
    hotkey::{Code, HotKey, Modifiers},
    GlobalHotKeyEvent, GlobalHotKeyManager,
};

use crate::detect;
use crate::paste;

/// Small delay so focus can return to the target app after the dialog closes
/// (and before we synthesize the paste).
const FOCUS_SETTLE: Duration = Duration::from_millis(150);
/// Delay before restoring the original clipboard after a redacted paste.
const RESTORE_DELAY: Duration = Duration::from_millis(250);

pub fn run() -> Result<(), String> {
    let manager = GlobalHotKeyManager::new().map_err(|e| e.to_string())?;
    // Cmd+Shift+V. SUPER maps to Command on macOS.
    let hotkey = HotKey::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::KeyV);
    manager
        .register(hotkey)
        .map_err(|e| format!("could not register Cmd+Shift+V: {e}"))?;

    let target_id = hotkey.id();

    // Fires on the main thread while the run loop below is pumping.
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        if event.id == target_id
            && event.state == global_hotkey::HotKeyState::Pressed
        {
            handle_smart_paste();
        }
    }));

    eprintln!("clipveil: watching Cmd+Shift+V. Press Ctrl+C to quit.");
    run_loop();
    Ok(())
}

/// Core flow for one Cmd+Shift+V press.
fn handle_smart_paste() {
    let clip = match paste::read_clipboard() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("clipveil: clipboard read failed: {e}");
            return;
        }
    };

    // Nothing sensitive — behave like an ordinary paste.
    if clip.is_empty() || !detect::has_secret(&clip) {
        let _ = paste::send_cmd_v();
        return;
    }

    match ask_user(&clip) {
        PasteChoice::Plain => {
            // Clipboard already holds the real value; just paste.
            thread::sleep(FOCUS_SETTLE);
            let _ = paste::send_cmd_v();
        }
        PasteChoice::Redacted => {
            let redacted = detect::redact(&clip);
            let original = clip.clone();
            if paste::write_clipboard(&redacted).is_ok() {
                thread::sleep(FOCUS_SETTLE);
                let _ = paste::send_cmd_v();
                // Put the real value back so legitimate uses still work.
                thread::sleep(RESTORE_DELAY);
                let _ = paste::write_clipboard(&original);
            }
        }
        PasteChoice::Cancel => { /* do nothing */ }
    }
}

enum PasteChoice {
    Plain,
    Redacted,
    Cancel,
}

/// Native two-button chooser describing what was found.
fn ask_user(clip: &str) -> PasteChoice {
    use rfd::{MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};

    let summary = detect::summary(clip);
    let kinds: Vec<String> = summary
        .iter()
        .map(|(k, n)| if *n > 1 { format!("{k} ×{n}") } else { k.to_string() })
        .collect();

    let body = format!(
        "Secret detected in clipboard:\n{}\n\nPaste the real value, or a redacted copy?",
        kinds.join(", ")
    );

    let result = MessageDialog::new()
        .set_level(MessageLevel::Warning)
        .set_title("clipveil — secret detected")
        .set_description(body)
        .set_buttons(MessageButtons::OkCancelCustom(
            "Paste Redacted".to_string(),
            "Paste Plain".to_string(),
        ))
        .show();

    match result {
        MessageDialogResult::Custom(label) if label == "Paste Redacted" => PasteChoice::Redacted,
        MessageDialogResult::Custom(label) if label == "Paste Plain" => PasteChoice::Plain,
        _ => PasteChoice::Cancel,
    }
}

/// Run the main-thread CFRunLoop so the Carbon hotkey can dispatch.
#[cfg(target_os = "macos")]
fn run_loop() {
    use core_foundation::runloop::CFRunLoop;
    CFRunLoop::run_current();
}

#[cfg(not(target_os = "macos"))]
fn run_loop() {
    // Non-macOS fallback: block forever; global-hotkey has its own backend loop.
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
