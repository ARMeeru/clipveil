//! Resident agent: binds Cmd+Shift+V, and on a secret-carrying clipboard shows
//! a "Paste Plain / Paste Redacted" chooser before letting the paste through.
//!
//! Design notes (macOS specifics):
//! * The global hotkey is a Carbon `RegisterEventHotKey`, whose events are
//!   delivered to the *application* event target. A bare CLI process has no
//!   application identity with the window server, so it would register the
//!   hotkey but never receive events. We therefore promote the process to a
//!   real (but dockless, `.Accessory`) NSApplication and run the Cocoa event
//!   loop, which pumps the Carbon hotkey events to global-hotkey's handler.
//! * The hotkey callback fires ON the main thread, which is exactly where
//!   AppKit (the rfd dialog) and event synthesis must happen.

use std::thread;
use std::time::Duration;

use global_hotkey::{
    hotkey::{Code, HotKey, Modifiers},
    GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
};

use clipveil::detect;
use crate::paste;

/// Delay before restoring the original clipboard after a redacted paste.
const RESTORE_DELAY: Duration = Duration::from_millis(250);

/// Ask macOS whether this process may synthesize input (Accessibility). Passing
/// the prompt option surfaces the system "grant access" dialog the first time.
#[cfg(target_os = "macos")]
fn accessibility_trusted() -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::{CFString, CFStringRef};

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
        static kAXTrustedCheckOptionPrompt: CFStringRef;
    }

    unsafe {
        let key = CFString::wrap_under_get_rule(kAXTrustedCheckOptionPrompt);
        let value = CFBoolean::true_value();
        let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);
        AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef())
    }
}

#[cfg(target_os = "macos")]
pub fn run() -> Result<(), String> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

    let mtm = MainThreadMarker::new().ok_or("clipveil agent must run on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    // Dockless background app that can still own the global hotkey and dialogs.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    if !accessibility_trusted() {
        eprintln!("clipveil: Accessibility permission is not granted yet.");
        eprintln!("          Detection and the dialog work, but the paste keystroke will be dropped.");
        eprintln!("          Grant it in System Settings > Privacy & Security > Accessibility");
        eprintln!("          (enable the terminal/app you launch clipveil from), then restart clipveil.");
    }

    let manager = GlobalHotKeyManager::new().map_err(|e| e.to_string())?;
    let hotkey = HotKey::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::KeyV);
    manager
        .register(hotkey)
        .map_err(|e| format!("could not register Cmd+Shift+V: {e}"))?;
    let target_id = hotkey.id();

    // Fires on the main thread while the Cocoa run loop below is pumping.
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        if event.id == target_id && event.state == HotKeyState::Pressed {
            handle_smart_paste();
        }
    }));

    eprintln!("clipveil: watching Cmd+Shift+V. Press Ctrl+C to quit.");
    // Runs the Cocoa event loop; blocks until the process is signalled.
    // `manager` stays in scope for the whole run, keeping the hotkey registered.
    app.run();
    drop(manager);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn run() -> Result<(), String> {
    Err("clipveil's agent is only supported on macOS".into())
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
        paste::wait_for_modifiers_released();
        let _ = paste::send_cmd_v();
        return;
    }

    match ask_user(&clip) {
        PasteChoice::Plain => {
            paste::wait_for_modifiers_released();
            let _ = paste::send_cmd_v();
        }
        PasteChoice::Redacted => {
            let redacted = detect::redact(&clip);
            let original = clip.clone();
            if paste::write_clipboard(&redacted).is_ok() {
                paste::wait_for_modifiers_released();
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
