//! Resident agent: binds a configurable hotkey (default Cmd+Shift+V), and on a
//! secret-carrying clipboard shows a "Paste Plain / Paste Redacted" chooser
//! before letting the paste through.
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

use global_hotkey::{
    GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
    hotkey::{Code, HotKey, Modifiers},
};

use crate::paste;
use clipveil::{
    agent_plan::{self, Action, PasteChoice},
    config,
    detect::Scanner,
};

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

// ── Per-process singleton state ────────────────────────────────────────────
// The hotkey callback receives no context, so we store the config-derived
// values in a thread-local that is written once before the event loop starts.

std::thread_local! {
    static AGENT_STATE: std::cell::RefCell<Option<AgentState>> =
        const { std::cell::RefCell::new(None) };
}

struct AgentState {
    scanner: Scanner,
    settle_ms: u64,
    modifier_timeout_ms: u64,
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
        eprintln!(
            "          Detection and the dialog work, but the paste keystroke will be dropped."
        );
        eprintln!("          Grant it in System Settings > Privacy & Security > Accessibility");
        eprintln!(
            "          (enable the terminal/app you launch clipveil from), then restart clipveil."
        );
    }

    // ── Load configuration ────────────────────────────────────────────
    let cfg = config::load();
    let (mods, code) = config::parse_hotkey(&cfg.hotkey).unwrap_or_else(|e| {
        eprintln!("clipveil: warning: {e} — falling back to cmd+shift+v");
        (Modifiers::SUPER | Modifiers::SHIFT, Code::KeyV)
    });

    let scanner = Scanner::new(Some(&cfg.detection));

    AGENT_STATE.with(|s| {
        *s.borrow_mut() = Some(AgentState {
            scanner,
            settle_ms: cfg.paste_settle_ms,
            modifier_timeout_ms: cfg.modifier_wait_timeout_ms,
        });
    });

    // ── Hotkey ────────────────────────────────────────────────────────
    let manager = GlobalHotKeyManager::new().map_err(|e| e.to_string())?;
    let hotkey = HotKey::new(Some(mods), code);
    let id = hotkey.id();
    manager
        .register(hotkey)
        .map_err(|e| format!("could not register hotkey: {e}"))?;

    // Fires on the main thread while the Cocoa run loop below is pumping.
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        if event.id == id && event.state == HotKeyState::Pressed {
            handle_smart_paste();
        }
    }));

    let desc = hotkey_desc(mods, code);
    eprintln!("clipveil: watching {desc}. Press Ctrl+C to quit.");
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

/// Core flow for one hotkey press.
fn handle_smart_paste() {
    let clip = match paste::read_clipboard() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("clipveil: clipboard read failed: {e}");
            return;
        }
    };

    let (_choice, actions) = AGENT_STATE.with(|s| {
        let state = s.borrow();
        let state = state.as_ref().expect("agent state not initialised");
        let choice = if agent_plan::needs_prompt(&state.scanner, &clip) {
            ask_user(&clip, &state.scanner)
        } else {
            PasteChoice::Plain
        };
        let actions = agent_plan::plan(&state.scanner, &clip, choice, state.settle_ms);
        (choice, actions)
    });

    execute(actions);
}

/// Execute a side-effect-free plan against the macOS clipboard and input APIs.
fn execute(actions: Vec<Action>) {
    use objc2_app_kit::NSPasteboard;

    let mut redacted_change_count = None;
    for action in actions {
        match action {
            Action::WaitForModifiersReleased => {
                let timeout = AGENT_STATE.with(|s| {
                    s.borrow()
                        .as_ref()
                        .map(|st| st.modifier_timeout_ms)
                        .unwrap_or(agent_plan::DEFAULT_MODIFIER_WAIT_TIMEOUT_MS)
                });
                paste::wait_for_modifiers_released(timeout);
            }
            Action::SetClipboard(text) => {
                if paste::write_clipboard(&text).is_err() {
                    return;
                }
                redacted_change_count = Some(NSPasteboard::generalPasteboard().changeCount());
            }
            Action::SendPaste => {
                let _ = paste::send_cmd_v();
            }
            Action::Wait(delay) => thread::sleep(delay),
            Action::RestoreIfUnchanged(original) => {
                let current_change_count = NSPasteboard::generalPasteboard().changeCount();
                if redacted_change_count.is_some_and(|captured| {
                    agent_plan::should_restore(captured, current_change_count)
                }) {
                    let _ = paste::write_clipboard(&original);
                }
            }
        }
    }
}

/// Build a human-readable hotkey description for the startup banner.
fn hotkey_desc(mods: Modifiers, code: Code) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if mods.contains(Modifiers::SUPER) {
        parts.push("Cmd");
    }
    if mods.contains(Modifiers::SHIFT) {
        parts.push("Shift");
    }
    if mods.contains(Modifiers::CONTROL) {
        parts.push("Ctrl");
    }
    if mods.contains(Modifiers::ALT) {
        parts.push("Opt");
    }
    let key_str = format!("{code:?}");
    parts.push(&key_str);
    parts.join("+")
}

/// Native two-button chooser describing what was found.
fn ask_user(clip: &str, scanner: &Scanner) -> PasteChoice {
    use rfd::{MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};

    let summary = scanner.summary(clip);
    let kinds: Vec<String> = summary
        .iter()
        .map(|(k, n)| {
            if *n > 1 {
                format!("{k} ×{n}")
            } else {
                k.to_string()
            }
        })
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
