//! Optional TOML configuration file.
//!
//! Loaded from `${XDG_CONFIG_HOME:-~/.config}/clipveil/config.toml`.
//! Every field is optional; a missing file, missing field, or invalid file
//! falls back to current defaults after a stderr warning — never panics.

use std::collections::HashMap;
use std::path::PathBuf;

use keyboard_types::{Code, Modifiers};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Config shape
// ---------------------------------------------------------------------------

fn default_hotkey() -> String {
    "cmd+shift+v".into()
}

fn default_settle_ms() -> u64 {
    250
}

fn default_modifier_timeout_ms() -> u64 {
    1000
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClipveilConfig {
    /// Global hotkey binding, e.g. "cmd+shift+v". Parsed case-insensitively.
    #[serde(default = "default_hotkey")]
    pub hotkey: String,

    /// Milliseconds to wait after pasting redacted content before restoring
    /// the original clipboard.
    #[serde(default = "default_settle_ms")]
    pub paste_settle_ms: u64,

    /// Maximum milliseconds to block waiting for physical modifier keys
    /// (Cmd/Shift/Option/Ctrl) to be released before giving up.
    #[serde(default = "default_modifier_timeout_ms")]
    pub modifier_wait_timeout_ms: u64,

    #[serde(default)]
    pub detection: DetectionConfig,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    /// Built-in pattern kinds to disable, e.g. ["generic_secret"].
    #[serde(default)]
    pub disable: Vec<String>,

    /// Extra custom patterns: label → regex string.
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Hotkey parser
// ---------------------------------------------------------------------------

/// Parse a hotkey string like `"cmd+shift+v"` into a `(Modifiers, Code)` pair.
///
/// Tokens are case-insensitive and separated by `+`. The last token is treated
/// as the key; all preceding tokens are modifiers.
///
/// Recognised modifier tokens:
///   `cmd` | `command` | `super` → `Modifiers::SUPER`
///   `shift`                     → `Modifiers::SHIFT`
///   `ctrl` | `control`          → `Modifiers::CONTROL`
///   `alt`  | `option`           → `Modifiers::ALT`
///
/// The key token is resolved via [`Code::from_str`] (e.g. `"v"`, `"KeyV"`,
/// `"Escape"`, `"F1"`, …).
pub fn parse_hotkey(s: &str) -> Result<(Modifiers, Code), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty hotkey string".into());
    }

    let parts: Vec<&str> = s.split('+').map(|p| p.trim()).collect();
    if parts.len() < 2 {
        return Err(format!(
            "hotkey '{s}' must contain at least one modifier and a key, e.g. 'cmd+shift+v'"
        ));
    }

    let (mod_tokens, key_token) = parts.split_at(parts.len() - 1);
    let key_str = key_token[0];

    let mut mods = Modifiers::empty();
    for tok in mod_tokens {
        match tok.to_lowercase().as_str() {
            "cmd" | "command" | "super" => mods.insert(Modifiers::SUPER),
            "shift" => mods.insert(Modifiers::SHIFT),
            "ctrl" | "control" => mods.insert(Modifiers::CONTROL),
            "alt" | "option" => mods.insert(Modifiers::ALT),
            other => return Err(format!("unknown modifier '{other}' in hotkey '{s}'")),
        }
    }

    let code: Code = normalize_key(key_str)
        .parse()
        .map_err(|_| format!("unknown key '{key_str}' in hotkey '{s}'"))?;

    Ok((mods, code))
}

/// Normalise a user-supplied key token to a form [`Code::from_str`] accepts.
///
/// `keyboard-types` expects exact case-sensitive variant names (e.g. `"KeyV"`,
/// `"Escape"`). Users write `"v"`, `"V"`, `"escape"` — this bridges the gap.
fn normalize_key(raw: &str) -> String {
    // Single ASCII letter → "Key<UPPER>"
    if raw.len() == 1 && raw.as_bytes()[0].is_ascii_alphabetic() {
        let upper = raw.as_bytes()[0].to_ascii_uppercase() as char;
        return format!("Key{upper}");
    }
    // Common aliases (lowercase → PascalCase variant name)
    let candidate = match raw.to_lowercase().as_str() {
        "esc" | "escape" => "Escape",
        "enter" | "return" => "Enter",
        "space" => "Space",
        "tab" => "Tab",
        "backspace" => "Backspace",
        "delete" | "del" => "Delete",
        "up" | "arrowup" => "ArrowUp",
        "down" | "arrowdown" => "ArrowDown",
        "left" | "arrowleft" => "ArrowLeft",
        "right" | "arrowright" => "ArrowRight",
        "home" => "Home",
        "end" => "End",
        "pageup" => "PageUp",
        "pagedown" => "PageDown",
        "capslock" => "CapsLock",
        "numlock" => "NumLock",
        "scrolllock" => "ScrollLock",
        "printscreen" | "prtsc" => "PrintScreen",
        "insert" | "ins" => "Insert",
        "pause" => "Pause",
        "contextmenu" | "menu" => "ContextMenu",
        other => {
            // Try PascalCase: "keyv" → "KeyV", "f1" → "F1"
            let pascal = pascal_case(other);
            // Also try "Key" + uppercase first letter for things like "keyv"
            if pascal.starts_with("Key") || pascal.starts_with('F') && pascal.len() <= 4 {
                return pascal;
            }
            // Fall through: return as-is and let from_str try it
            return pascal;
        }
    };
    candidate.into()
}

/// Quick PascalCase conversion: "keyv" → "KeyV", "arrowup" → "ArrowUp"
fn pascal_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut upper_next = true;
    for c in s.chars() {
        if c == '_' || c == '-' || c == ' ' {
            upper_next = true;
            continue;
        }
        if upper_next {
            result.push(c.to_ascii_uppercase());
            upper_next = false;
        } else {
            result.push(c.to_ascii_lowercase());
        }
    }
    result
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

/// Compute the config file path respecting `XDG_CONFIG_HOME`.
fn config_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(dir).join("clipveil").join("config.toml")
    } else {
        #[allow(deprecated)]
        let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".config").join("clipveil").join("config.toml")
    }
}

/// Load the optional configuration file.
///
/// * If the file does not exist → return defaults silently.
/// * If it exists but is invalid TOML → warn to stderr, return defaults.
/// * If it exists and parses but the hotkey string is invalid → warn, return
///   defaults (with the hotkey reset to `"cmd+shift+v"`).
///
/// **Never panics**.
pub fn load() -> ClipveilConfig {
    let path = config_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ClipveilConfig::default(),
        Err(e) => {
            eprintln!(
                "clipveil: warning: could not read config '{}': {e}",
                path.display()
            );
            return ClipveilConfig::default();
        }
    };

    let mut cfg: ClipveilConfig = match toml::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "clipveil: warning: invalid config '{}': {e}",
                path.display()
            );
            return ClipveilConfig::default();
        }
    };

    // Validate the hotkey string early so the agent gets a clean fallback.
    if let Err(e) = parse_hotkey(&cfg.hotkey) {
        eprintln!(
            "clipveil: warning: bad hotkey in config '{}': {e}",
            path.display()
        );
        cfg.hotkey = default_hotkey();
    }

    cfg
}

impl Default for ClipveilConfig {
    fn default() -> Self {
        Self {
            hotkey: default_hotkey(),
            paste_settle_ms: default_settle_ms(),
            modifier_wait_timeout_ms: default_modifier_timeout_ms(),
            detection: DetectionConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_hotkey ──────────────────────────────────────────────────

    #[test]
    fn parse_cmd_shift_v() {
        let (mods, code) = parse_hotkey("cmd+shift+v").unwrap();
        assert!(mods.contains(Modifiers::SUPER));
        assert!(mods.contains(Modifiers::SHIFT));
        assert_eq!(code, Code::KeyV);
    }

    #[test]
    fn parse_case_insensitive() {
        let (mods, code) = parse_hotkey("CMD+SHIFT+V").unwrap();
        assert!(mods.contains(Modifiers::SUPER));
        assert!(mods.contains(Modifiers::SHIFT));
        assert_eq!(code, Code::KeyV);
    }

    #[test]
    fn parse_ctrl_alt_escape() {
        let (mods, code) = parse_hotkey("ctrl+alt+escape").unwrap();
        assert!(mods.contains(Modifiers::CONTROL));
        assert!(mods.contains(Modifiers::ALT));
        assert_eq!(code, Code::Escape);
    }

    #[test]
    fn parse_command_option_key_a() {
        let (mods, code) = parse_hotkey("command+option+a").unwrap();
        assert!(mods.contains(Modifiers::SUPER));
        assert!(mods.contains(Modifiers::ALT));
        assert_eq!(code, Code::KeyA);
    }

    #[test]
    fn parse_super_control_f5() {
        let (mods, code) = parse_hotkey("super+control+F5").unwrap();
        assert!(mods.contains(Modifiers::SUPER));
        assert!(mods.contains(Modifiers::CONTROL));
        assert_eq!(code, Code::F5);
    }

    #[test]
    fn unknown_modifier_is_error() {
        assert!(parse_hotkey("win+v").is_err());
    }

    #[test]
    fn unknown_key_is_error() {
        assert!(parse_hotkey("cmd+shift+ZZZ").is_err());
    }

    #[test]
    fn empty_string_is_error() {
        assert!(parse_hotkey("").is_err());
    }

    #[test]
    fn no_modifier_is_error() {
        assert!(parse_hotkey("v").is_err());
    }

    // ── defaults ──────────────────────────────────────────────────────

    #[test]
    fn default_config_has_expected_values() {
        let cfg = ClipveilConfig::default();
        assert_eq!(cfg.hotkey, "cmd+shift+v");
        assert_eq!(cfg.paste_settle_ms, 250);
        assert_eq!(cfg.modifier_wait_timeout_ms, 1000);
        assert!(cfg.detection.disable.is_empty());
        assert!(cfg.detection.extra.is_empty());
    }

    // ── TOML round-trip ───────────────────────────────────────────────

    #[test]
    fn empty_toml_is_all_defaults() {
        let cfg: ClipveilConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.hotkey, "cmd+shift+v");
        assert_eq!(cfg.paste_settle_ms, 250);
    }

    #[test]
    fn partial_toml_overrides_fields() {
        let toml_str = r#"
hotkey = "ctrl+alt+space"
paste_settle_ms = 500
"#;
        let cfg: ClipveilConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.hotkey, "ctrl+alt+space");
        assert_eq!(cfg.paste_settle_ms, 500);
        assert_eq!(cfg.modifier_wait_timeout_ms, 1000); // default
    }

    #[test]
    fn detection_disable_and_extra_parse() {
        let toml_str = r#"
[detection]
disable = ["generic_secret", "bearer_token"]

[detection.extra]
acme_key = "acme_[A-Za-z0-9]{32}"
custom = "mysecret-[0-9a-f]{16}"
"#;
        let cfg: ClipveilConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.detection.disable.len(), 2);
        assert!(cfg.detection.disable.contains(&"generic_secret".into()));
        assert!(cfg.detection.disable.contains(&"bearer_token".into()));
        assert_eq!(cfg.detection.extra.len(), 2);
        assert_eq!(
            cfg.detection.extra.get("acme_key").unwrap(),
            "acme_[A-Za-z0-9]{32}"
        );
        assert_eq!(
            cfg.detection.extra.get("custom").unwrap(),
            "mysecret-[0-9a-f]{16}"
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let toml_str = r#"
hotkey = "cmd+shift+v"
bogus_field = 42
"#;
        let result: Result<ClipveilConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_toml_is_rejected() {
        let result: Result<ClipveilConfig, _> = toml::from_str("not valid {{{");
        assert!(result.is_err());
    }
}
