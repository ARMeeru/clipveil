//! Secret detection & redaction core.
//!
//! Pure logic: no clipboard, no GUI, no OS calls. This is the part that is
//! fully unit-tested and the part that actually keeps your tokens out of an
//! LLM prompt. Everything else in clipveil is plumbing around this module.

use regex::Regex;
use std::sync::LazyLock;

use crate::config::DetectionConfig;

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A single detected secret and its byte span within the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
}

// ---------------------------------------------------------------------------
// Built-in patterns
// ---------------------------------------------------------------------------

/// Ordered list of (label, pattern). Order matters only for readability;
/// overlaps are resolved by span, not by list position.
static PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    let raw: &[(&'static str, &str)] = &[
        // Private key blocks — redact the WHOLE block, header to footer.
        (
            "private_key",
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        ),
        // GitHub fine-grained PAT
        ("github_pat", r"github_pat_[0-9a-zA-Z_]{22,255}"),
        // GitHub classic tokens: ghp_ gho_ ghu_ ghs_ ghr_
        ("github_token", r"gh[pousr]_[0-9A-Za-z]{36,255}"),
        // GitLab PAT
        ("gitlab_pat", r"glpat-[0-9A-Za-z_\-]{20}"),
        // OpenAI keys (sk- and sk-proj-)
        ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
        // Stripe secret/restricted keys
        ("stripe_key", r"[rs]k_(?:live|test)_[0-9a-zA-Z]{16,}"),
        // AWS access key IDs
        (
            "aws_access_key",
            r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b",
        ),
        // Google API key
        ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
        // Slack tokens
        ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        // Slack incoming webhook
        (
            "slack_webhook",
            r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{40,}",
        ),
        // npm token
        ("npm_token", r"npm_[0-9A-Za-z]{36}"),
        // Discord bot token (id.timestamp.hmac)
        (
            "discord_token",
            r"[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}",
        ),
        // Slack app-level token
        ("slack_app_token", r"xapp-[0-9A-Za-z\-]{10,}"),
        // Google OAuth access token
        ("google_oauth", r"ya29\.[A-Za-z0-9_\-]{20,}"),
        // Telegram bot token
        ("telegram_token", r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"),
        // SendGrid API key
        (
            "sendgrid_key",
            r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{40,}",
        ),
        // JSON Web Token
        (
            "jwt",
            r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        ),
        // Authorization: Bearer <token>
        ("bearer_token", r"(?i)bearer\s+[A-Za-z0-9._~+/\-]{20,}=*"),
        // Generic key=value secret assignments
        (
            "generic_secret",
            r#"(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|auth[_\-]?token)["']?\s*[:=]\s*["']?[^\s"']{8,}"#,
        ),
    ];
    raw.iter()
        .map(|(k, p)| (*k, Regex::new(p).expect("invalid built-in regex")))
        .collect()
});

// ---------------------------------------------------------------------------
// Rank helpers (overlap resolution)
// ---------------------------------------------------------------------------

/// Rank a kind by specificity. Specific vendor tokens beat the broad
/// generic/`bearer` catch-alls when they overlap, so the dialog shows the most
/// informative label.
fn rank(kind: &str) -> u8 {
    match kind {
        "generic_secret" => 0,
        "bearer_token" => 1,
        _ => 2,
    }
}

/// Is `cand` a better label than `cur` for an overlapping cluster?
fn better_label(cand: &Finding, cur: &Finding) -> bool {
    let (rc, rk) = (rank(cand.kind), rank(cur.kind));
    if rc != rk {
        rc > rk
    } else {
        (cand.end - cand.start) > (cur.end - cur.start)
    }
}

// ---------------------------------------------------------------------------
// Shannon entropy (used for generic_secret gating)
// ---------------------------------------------------------------------------

/// Byte-level Shannon entropy. Returns 0.0 for empty input; max is ~8.0 for
/// uniformly-distributed random bytes.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / n;
        h -= p * p.log2();
    }
    h
}

/// Minimum Shannon entropy a generic-secret *value* must have to be flagged.
///
/// Empirically tuned:
///   "password"         ≈ 2.75  → below threshold, rejected ✓
///   "changeme"         ≈ 2.75  → below threshold, rejected ✓
///   "SuperSecret123"   ≈ 3.18  → above threshold, flagged ✓
///   "0123456789abcdef"  = 4.0   → above threshold, flagged ✓
///
/// ponytail: ceiling — one global f64 threshold. Upgrade path: per-kind
/// thresholds or a calibrated model if a vendor token slips past this gate.
const ENTROPY_THRESHOLD: f64 = 2.8;

/// Extract the value portion of a `generic_secret` match.
///
/// The regex captures `key=value` / `key: value` style assignments. This
/// function strips the key, separator, and any surrounding quotes so only the
/// actual secret value remains for entropy analysis.
fn extract_generic_value(full_match: &str) -> Option<&str> {
    let sep_pos = full_match.find(['=', ':'])?;
    let value = full_match[sep_pos + 1..].trim();
    // Strip surrounding quotes
    let value = value.strip_prefix('"').unwrap_or(value);
    let value = value.strip_suffix('"').unwrap_or(value);
    let value = value.strip_prefix('\'').unwrap_or(value);
    let value = value.strip_suffix('\'').unwrap_or(value);
    let value = value.trim();
    if value.is_empty() { None } else { Some(value) }
}

// ---------------------------------------------------------------------------
// Core scan logic (shared by free functions and Scanner)
// ---------------------------------------------------------------------------

/// Return every secret span in `text`, merged so no two spans overlap. Each
/// merged span is labelled with the most specific kind it contains.
///
/// This is the single implementation used by both the free function and
/// `Scanner::scan`. The entropy gate for `generic_secret` is applied here.
fn scan_with(patterns: &[(&'static str, Regex)], text: &str) -> Vec<Finding> {
    let mut raw: Vec<Finding> = Vec::new();
    for (kind, re) in patterns {
        for m in re.find_iter(text) {
            // Entropy gate: skip only low-entropy generic_secret matches.
            // If we can't extract a value, keep the match (fail open).
            if *kind == "generic_secret"
                && extract_generic_value(m.as_str())
                    .is_some_and(|value| shannon_entropy(value.as_bytes()) < ENTROPY_THRESHOLD)
            {
                continue;
            }
            raw.push(Finding {
                kind,
                start: m.start(),
                end: m.end(),
            });
        }
    }
    // Earliest first; for equal starts, longest first.
    raw.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut merged: Vec<Finding> = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let cl_start = raw[i].start;
        let mut cl_end = raw[i].end;
        let mut best = raw[i].clone();
        let mut j = i + 1;
        while j < raw.len() && raw[j].start < cl_end {
            if raw[j].end > cl_end {
                cl_end = raw[j].end;
            }
            if better_label(&raw[j], &best) {
                best = raw[j].clone();
            }
            j += 1;
        }
        merged.push(Finding {
            kind: best.kind,
            start: cl_start,
            end: cl_end,
        });
        i = j;
    }
    merged
}

// ---------------------------------------------------------------------------
// Free functions (backward-compatible — use built-in patterns)
// ---------------------------------------------------------------------------

/// Return every secret span in `text`.
pub fn scan(text: &str) -> Vec<Finding> {
    scan_with(&PATTERNS, text)
}

/// Cheap yes/no: does `text` contain anything secret-shaped?
///
/// Delegates to [`scan`] so the entropy gate for `generic_secret` is applied
/// consistently — a low-entropy generic assignment returns `false`.
pub fn has_secret(text: &str) -> bool {
    !scan(text).is_empty()
}

/// Replace every detected secret with a `[REDACTED:<kind>]` marker.
pub fn redact(text: &str) -> String {
    let findings = scan_with(&PATTERNS, text);
    redact_from(text, &findings)
}

// ---------------------------------------------------------------------------
// Scanner (config-aware)
// ---------------------------------------------------------------------------

/// A configurable secret scanner.
///
/// Unlike the free functions (which always use the built-in pattern set),
/// `Scanner` can be constructed from a [`DetectionConfig`], giving the
/// caller control over which built-in kinds are disabled and what extra
/// custom patterns are added.
pub struct Scanner {
    patterns: Vec<(&'static str, Regex)>,
}

impl Scanner {
    /// Build a scanner from an optional detection configuration.
    ///
    /// * `None` or an empty config → behaves identically to the free functions.
    /// * `disable` entries are matched by kind name. Built-in patterns whose
    ///   label appears in `disable` are removed.
    /// * `extra` entries are compiled as [`Regex`]; any that fail to compile
    ///   are silently skipped.
    pub fn new(config: Option<&DetectionConfig>) -> Self {
        let mut patterns: Vec<(&'static str, Regex)> = PATTERNS.clone();

        if let Some(cfg) = config {
            // Remove disabled kinds
            if !cfg.disable.is_empty() {
                patterns.retain(|(kind, _)| !cfg.disable.iter().any(|d| d == kind));
            }

            // Add extra patterns
            for (label, re_str) in &cfg.extra {
                match Regex::new(re_str) {
                    Ok(re) => {
                        // ponytail: ceiling — Scanner owns 'static labels via leak;
                        // safe because both call sites build one Scanner per process.
                        // Upgrade path: swap Finding.kind to Cow<'static, str> if a
                        // long-lived caller ever builds many Scanners.
                        let leaked: &'static str = Box::leak(label.clone().into_boxed_str());
                        patterns.push((leaked, re));
                    }
                    Err(e) => {
                        eprintln!("clipveil: warning: skipping custom pattern '{label}': {e}");
                    }
                }
            }
        }

        Self { patterns }
    }

    /// Scan `text` using this scanner's effective pattern set.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        scan_with(&self.patterns, text)
    }

    /// Cheap yes/no: does `text` contain anything secret-shaped?
    ///
    /// Delegates to [`Self::scan`] so the entropy gate for `generic_secret` is
    /// applied consistently.
    pub fn has_secret(&self, text: &str) -> bool {
        !self.scan(text).is_empty()
    }

    /// Replace every detected secret with a `[REDACTED:<kind>]` marker.
    pub fn redact(&self, text: &str) -> String {
        let findings = self.scan(text);
        redact_from(text, &findings)
    }

    /// Distinct secret kinds present, with counts.
    /// ponytail: ceiling — O(kinds²) linear scan; kinds stays tiny in practice.
    /// Upgrade path: HashMap<&'static str, usize> if kind cardinality ever grows.
    pub fn summary(&self, text: &str) -> Vec<(&'static str, usize)> {
        let mut counts: Vec<(&'static str, usize)> = Vec::new();
        for f in self.scan(text) {
            if let Some(entry) = counts.iter_mut().find(|(k, _)| *k == f.kind) {
                entry.1 += 1;
            } else {
                counts.push((f.kind, 1));
            }
        }
        counts
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new(None)
    }
}

// ---------------------------------------------------------------------------
// Shared redaction helper
// ---------------------------------------------------------------------------

fn redact_from(text: &str, findings: &[Finding]) -> String {
    if findings.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for f in findings {
        out.push_str(&text[cursor..f.start]);
        out.push_str(&format!("[REDACTED:{}]", f.kind));
        cursor = f.end;
    }
    out.push_str(&text[cursor..]);
    out
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a token from parts so no secret-shaped literal ever appears
    /// contiguously in source — keeps secret scanners quiet on our own fixtures.
    fn asm(parts: &[&str]) -> String {
        parts.concat()
    }

    // ── shannon_entropy ────────────────────────────────────────────────

    #[test]
    fn entropy_empty_is_zero() {
        assert!((shannon_entropy(b"") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn entropy_single_byte_is_zero() {
        assert!((shannon_entropy(b"aaaa") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn entropy_uniform_256_is_eight() {
        let data: Vec<u8> = (0..=255).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 0.01, "expected ~8.0, got {h}");
    }

    #[test]
    fn entropy_mixed_card() {
        // "SuperSecret123" — manually verified: should be ~3.18
        let h = shannon_entropy(b"SuperSecret123");
        assert!(h > 3.0 && h < 3.4, "expected ~3.18, got {h}");
    }

    #[test]
    fn entropy_low_for_repetitive() {
        // "password" should be well below threshold
        let h = shannon_entropy(b"password");
        assert!(h < ENTROPY_THRESHOLD, "expected < 2.8, got {h}");
    }

    #[test]
    fn entropy_for_changeme_below_threshold() {
        let h = shannon_entropy(b"changeme");
        assert!(h < ENTROPY_THRESHOLD, "expected < 2.8, got {h}");
    }

    // ── extract_generic_value ──────────────────────────────────────────

    #[test]
    fn extracts_value_after_equals() {
        assert_eq!(
            extract_generic_value("password=SuperSecret123"),
            Some("SuperSecret123")
        );
    }

    #[test]
    fn extracts_value_after_colon_with_space() {
        assert_eq!(
            extract_generic_value("api_key: 0123456789abcdef"),
            Some("0123456789abcdef")
        );
    }

    #[test]
    fn strips_double_quotes() {
        assert_eq!(
            extract_generic_value("token=\"abc123def456\""),
            Some("abc123def456")
        );
    }

    #[test]
    fn strips_single_quotes() {
        assert_eq!(
            extract_generic_value("password='s3cret!!'"),
            Some("s3cret!!")
        );
    }

    // ── entropy gate on generic_secret ─────────────────────────────────

    #[test]
    fn low_entropy_generic_is_filtered() {
        // "password=password" — the value "password" has low entropy
        let findings = scan("password=password");
        assert!(
            findings.is_empty(),
            "low-entropy generic should be filtered, got {findings:?}"
        );
    }

    #[test]
    fn high_entropy_generic_is_still_detected() {
        // Use a high-entropy value
        let value = "Xp2kQ9vLm5nR3sT8wY1aB6cD0eF4gH7j";
        let text = format!("token={value}");
        let findings = scan(&text);
        assert!(
            findings.iter().any(|f| f.kind == "generic_secret"),
            "high-entropy generic should be detected, got {findings:?}"
        );
    }

    #[test]
    fn token_changeme_is_filtered() {
        let findings = scan("token=changeme");
        assert!(
            findings.is_empty(),
            "token=changeme should be filtered, got {findings:?}"
        );
    }

    // ── existing detection tests (unchanged) ───────────────────────────

    #[test]
    fn detects_github_classic_token() {
        let t = format!(
            "export TOKEN={}",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        );
        assert!(has_secret(&t));
        assert_eq!(scan(&t).len(), 1);
        assert_eq!(scan(&t)[0].kind, "github_token");
    }

    #[test]
    fn detects_github_fine_grained_pat() {
        let t = asm(&[
            "github_pat_",
            "11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
        ]);
        assert!(has_secret(&t));
    }

    #[test]
    fn detects_aws_access_key() {
        let t = format!("aws_access_key_id = {}", asm(&["AKIA", "IOSFODNN7EXAMPLE"]));
        assert!(scan(&t).iter().any(|x| x.kind == "aws_access_key"));
    }

    #[test]
    fn detects_openai_key() {
        let t = format!(
            "OPENAI_API_KEY={}",
            asm(&["sk-proj-", "abcdefghijklmnopqrstuvwxyz1234567890"])
        );
        assert!(
            scan(&t)
                .iter()
                .any(|x| x.kind == "openai_key" || x.kind == "generic_secret")
        );
    }

    #[test]
    fn detects_jwt() {
        let t = format!(
            "auth {}",
            asm(&[
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                ".",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
                ".",
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            ])
        );
        assert!(
            scan(&t)
                .iter()
                .any(|x| x.kind == "jwt" || x.kind == "bearer_token")
        );
    }

    #[test]
    fn detects_private_key_block_whole() {
        let begin = asm(&["-----BEGIN OPENSSH ", "PRIVATE KEY-----"]);
        let end = asm(&["-----END OPENSSH ", "PRIVATE KEY-----"]);
        let t = format!("before\n{begin}\nb3BlbnNzaC1rZXk\nMORELINES\n{end}\nafter");
        let out = redact(&t);
        assert!(out.contains("[REDACTED:private_key]"));
        assert!(!out.contains("b3BlbnNzaC1rZXk"));
        assert!(out.starts_with("before"));
        assert!(out.ends_with("after"));
    }

    #[test]
    fn redacts_and_preserves_surrounding_text() {
        let t = format!(
            "run with {} now",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        );
        assert_eq!(redact(&t), "run with [REDACTED:github_token] now");
    }

    #[test]
    fn clean_text_is_untouched() {
        let t = "the quick brown fox jumps over the lazy dog 12345";
        assert!(!has_secret(t));
        assert_eq!(redact(t), t);
    }

    #[test]
    fn overlapping_bearer_and_jwt_merge_to_one_span() {
        let t = format!(
            "Authorization: Bearer {}",
            asm(&[
                "eyJhbGciOiJIUzI1NiJ9",
                ".",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
                ".",
                "abcDEFghiJKLmnoPQRstuVWXyz1234567890"
            ])
        );
        assert_eq!(scan(&t).len(), 1);
        assert_eq!(redact(&t).matches("[REDACTED").count(), 1);
    }

    #[test]
    fn multiple_distinct_secrets_all_redacted() {
        let t = format!(
            "k1 {} and k2 {} end",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"]),
            asm(&["AKIA", "IOSFODNN7EXAMPLE"])
        );
        let out = redact(&t);
        assert!(out.contains("[REDACTED:github_token]"));
        assert!(out.contains("[REDACTED:aws_access_key]"));
        assert_eq!(out.matches("[REDACTED").count(), 2);
    }

    #[test]
    fn detects_newer_token_types() {
        let cases: [(String, &str); 5] = [
            (
                asm(&[
                    "MTk4NjIyNDgzNDcxOTI1MjQ4",
                    ".",
                    "GBTk9x",
                    ".",
                    "abcdefghijklmnopqrstuvwxyzABCDEF012ab",
                ]),
                "discord_token",
            ),
            (
                asm(&["xapp-", "1-A0123ABCD-1234567890-abcdef0123456789"]),
                "slack_app_token",
            ),
            (
                asm(&["ya29.", "a0AfH6SMBxExampleExampleExampleExampleExample"]),
                "google_oauth",
            ),
            (
                asm(&["1234567890", ":", "AAExampleExampleExampleExampleExample01"]),
                "telegram_token",
            ),
            (
                asm(&[
                    "SG.",
                    "abcdefghijklmnopqrstuv",
                    ".",
                    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
                ]),
                "sendgrid_key",
            ),
        ];
        for (tok, kind) in &cases {
            assert!(
                scan(tok).iter().any(|f| f.kind == *kind),
                "{kind} not detected"
            );
        }
    }

    #[test]
    fn summary_counts_kinds() {
        let t = format!(
            "{} {}",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"]),
            asm(&["ghp_", "zyxwvutsrqponmlkjihgfedcba9876543210"])
        );
        let s = Scanner::default().summary(&t);
        assert_eq!(s.iter().find(|(k, _)| *k == "github_token").unwrap().1, 2);
    }

    // ── Scanner ────────────────────────────────────────────────────────

    #[test]
    fn scanner_default_matches_free_functions() {
        let t = format!(
            "export TOKEN={}",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        );
        let scanner = Scanner::default();
        assert!(scanner.has_secret(&t));
        assert_eq!(scanner.scan(&t).len(), 1);
    }

    #[test]
    fn scanner_disable_removes_kind() {
        let cfg = DetectionConfig {
            disable: vec!["github_token".into(), "generic_secret".into()],
            ..Default::default()
        };
        let scanner = Scanner::new(Some(&cfg));
        let t = format!(
            "export TOKEN={}",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        );
        // Both github_token and generic_secret are disabled, so no match.
        assert!(!scanner.has_secret(&t));
        assert!(scanner.scan(&t).is_empty());
    }

    #[test]
    fn scanner_extra_adds_custom_pattern() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("acme_key".into(), r"acme_[A-Za-z0-9]{32}".into());
        let cfg = DetectionConfig {
            extra,
            ..Default::default()
        };
        let scanner = Scanner::new(Some(&cfg));
        let t = format!(
            "key={}",
            asm(&["acme_", "0123456789abcdefghijABCDEFGHIJ01"])
        );
        assert!(scanner.has_secret(&t));
        assert!(scanner.scan(&t).iter().any(|f| f.kind == "acme_key"));
    }

    #[test]
    fn scanner_disable_and_extra_compose() {
        let cfg = DetectionConfig {
            disable: vec!["generic_secret".into()],
            extra: {
                let mut m = std::collections::HashMap::new();
                m.insert("mysecret".into(), r"mysecret_[A-Za-z0-9]{16}".into());
                m
            },
            ..Default::default()
        };
        let scanner = Scanner::new(Some(&cfg));

        // generic_secret should be disabled
        assert!(!scanner.has_secret("password=SuperSecret123"));

        // github_token should still work
        let gh = format!(
            "export T={}",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        );
        assert!(scanner.has_secret(&gh));

        // custom pattern should work
        let custom = format!("key={}", asm(&["mysecret_", "abcdefghij01234567"]));
        assert!(scanner.has_secret(&custom));
    }

    #[test]
    fn scanner_bad_regex_is_skipped() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("bad".into(), r"[invalid".into());
        let cfg = DetectionConfig {
            extra,
            ..Default::default()
        };
        let scanner = Scanner::new(Some(&cfg));
        // Should not have added the bad pattern; still works with built-ins
        let t = format!(
            "export TOKEN={}",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        );
        assert!(scanner.has_secret(&t));
    }

    #[test]
    fn scanner_none_config_is_same_as_default() {
        let s1 = Scanner::new(None);
        let s2 = Scanner::default();
        let t = format!(
            "export TOKEN={}",
            asm(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])
        );
        assert_eq!(s1.has_secret(&t), s2.has_secret(&t));
    }
}
