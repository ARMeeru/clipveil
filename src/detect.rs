//! Secret detection & redaction core.
//!
//! Pure logic: no clipboard, no GUI, no OS calls. This is the part that is
//! fully unit-tested and the part that actually keeps your tokens out of an
//! LLM prompt. Everything else in clipveil is plumbing around this module.

use once_cell::sync::Lazy;
use regex::Regex;

/// A single detected secret and its byte span within the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
}

/// Ordered list of (label, pattern). Order matters only for readability;
/// overlaps are resolved by span, not by list position.
static PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
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
        ("aws_access_key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b"),
        // Google API key
        ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
        // Slack tokens
        ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        // Slack incoming webhook
        ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{40,}"),
        // npm token
        ("npm_token", r"npm_[0-9A-Za-z]{36}"),
        // Discord bot token (id.timestamp.hmac)
        ("discord_token", r"[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}"),
        // Slack app-level token
        ("slack_app_token", r"xapp-[0-9A-Za-z\-]{10,}"),
        // Google OAuth access token
        ("google_oauth", r"ya29\.[A-Za-z0-9_\-]{20,}"),
        // Telegram bot token
        ("telegram_token", r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"),
        // SendGrid API key
        ("sendgrid_key", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{40,}"),
        // JSON Web Token
        ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
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

/// Return every secret span in `text`, merged so no two spans overlap. Each
/// merged span is labelled with the most specific kind it contains.
pub fn scan(text: &str) -> Vec<Finding> {
    let mut raw: Vec<Finding> = Vec::new();
    for (kind, re) in PATTERNS.iter() {
        for m in re.find_iter(text) {
            raw.push(Finding { kind, start: m.start(), end: m.end() });
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
        merged.push(Finding { kind: best.kind, start: cl_start, end: cl_end });
        i = j;
    }
    merged
}

/// Cheap yes/no: does `text` contain anything secret-shaped?
pub fn has_secret(text: &str) -> bool {
    PATTERNS.iter().any(|(_, re)| re.is_match(text))
}

/// Replace every detected secret with a `[REDACTED:<kind>]` marker.
pub fn redact(text: &str) -> String {
    let findings = scan(text);
    if findings.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for f in &findings {
        out.push_str(&text[cursor..f.start]);
        out.push_str(&format!("[REDACTED:{}]", f.kind));
        cursor = f.end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Distinct secret kinds present, with counts — used to describe findings
/// in the paste dialog.
pub fn summary(text: &str) -> Vec<(&'static str, usize)> {
    let mut counts: Vec<(&'static str, usize)> = Vec::new();
    for f in scan(text) {
        if let Some(entry) = counts.iter_mut().find(|(k, _)| *k == f.kind) {
            entry.1 += 1;
        } else {
            counts.push((f.kind, 1));
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_github_classic_token() {
        let t = "export TOKEN=REDACTED_TEST_TOKEN";
        assert!(has_secret(t));
        assert_eq!(scan(t).len(), 1);
        assert_eq!(scan(t)[0].kind, "github_token");
    }

    #[test]
    fn detects_github_fine_grained_pat() {
        let t = "REDACTED_TEST_TOKEN";
        assert!(has_secret(t));
    }

    #[test]
    fn detects_aws_access_key() {
        let t = "aws_access_key_id = REDACTED_TEST_TOKEN";
        let f = scan(t);
        assert!(f.iter().any(|x| x.kind == "aws_access_key"));
    }

    #[test]
    fn detects_openai_key() {
        let t = "OPENAI_API_KEY=REDACTED_TEST_TOKEN";
        assert!(scan(t).iter().any(|x| x.kind == "openai_key" || x.kind == "generic_secret"));
    }

    #[test]
    fn detects_jwt() {
        let t = "auth REDACTED_TEST_JWT";
        assert!(scan(t).iter().any(|x| x.kind == "jwt" || x.kind == "bearer_token"));
    }

    #[test]
    fn detects_private_key_block_whole() {
        let t = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nMORELINES\n-----END OPENSSH PRIVATE KEY-----\nafter";
        let out = redact(t);
        assert!(out.contains("[REDACTED:private_key]"));
        assert!(!out.contains("b3BlbnNzaC1rZXk"));
        assert!(out.starts_with("before"));
        assert!(out.ends_with("after"));
    }

    #[test]
    fn redacts_and_preserves_surrounding_text() {
        let t = "run with REDACTED_TEST_TOKEN now";
        let out = redact(t);
        assert_eq!(out, "run with [REDACTED:github_token] now");
    }

    #[test]
    fn clean_text_is_untouched() {
        let t = "the quick brown fox jumps over the lazy dog 12345";
        assert!(!has_secret(t));
        assert_eq!(redact(t), t);
    }

    #[test]
    fn overlapping_bearer_and_jwt_merge_to_one_span() {
        let t = "Authorization: Bearer REDACTED_TEST_JWT";
        let f = scan(t);
        // The two patterns overlap; they must collapse into a single redaction span.
        assert_eq!(f.len(), 1);
        let out = redact(t);
        assert_eq!(out.matches("[REDACTED").count(), 1);
    }

    #[test]
    fn multiple_distinct_secrets_all_redacted() {
        let t = "k1 REDACTED_TEST_TOKEN and k2 REDACTED_TEST_TOKEN end";
        let out = redact(t);
        assert!(!out.contains("ghp_"));
        assert!(!out.contains("REDACTED_TEST_TOKEN"));
        assert_eq!(out.matches("[REDACTED").count(), 2);
    }

    #[test]
    fn detects_newer_token_types() {
        let cases = [
            ("REDACTED_TEST_TOKEN", "discord_token"),
            ("REDACTED_TEST_TOKEN", "slack_app_token"),
            ("REDACTED_TEST_TOKEN", "google_oauth"),
            ("REDACTED_TEST_TOKENle01", "telegram_token"),
            ("REDACTED_TEST_TOKEN", "sendgrid_key"),
        ];
        for (tok, kind) in cases {
            let found = scan(tok);
            assert!(found.iter().any(|f| f.kind == kind), "{kind} not detected in {tok}");
        }
    }

    #[test]
    fn summary_counts_kinds() {
        let t = "REDACTED_TEST_TOKEN REDACTED_TEST_TOKEN";
        let s = summary(t);
        assert_eq!(s.iter().find(|(k, _)| *k == "github_token").unwrap().1, 2);
    }
}
