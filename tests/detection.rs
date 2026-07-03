//! Integration corpus for the detection engine. This is the versioned,
//! reproducible source of the QA numbers — run with `cargo test`.
//!
//! Tokens are assembled from parts via `asm(..)` so no secret-shaped literal is
//! ever committed to the repo (keeps secret scanners quiet on our own fixtures).

use clipveil::detect::{has_secret, redact, scan};

const A36: &str = "0123456789abcdefghijABCDEFGHIJ012345"; // 36 chars

/// Join parts at runtime; the full token never appears contiguously in source.
fn asm(parts: &[&str]) -> String {
    parts.concat()
}

fn positives() -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("github classic ghp", format!("run ghp_{A36} now"), "github_token"),
        ("github gho", format!("gho_{A36}"), "github_token"),
        ("github ghs", format!("ghs_{A36}"), "github_token"),
        ("github fine PAT", asm(&["github_pat_", "11ABCDEFGHIJ0123456789_abcdefghijKLMNOPQRSTUV"]), "github_pat"),
        ("gitlab pat", asm(&["glpat-", "ABCDEFghij0123456789"]), "gitlab_pat"),
        ("openai sk-", format!("key {}", asm(&["sk-", "abcdefghijklmnopqrstuvwx0123"])), "openai_key"),
        ("openai sk-proj", asm(&["sk-proj-", "abcdefghijklmnop0123456789"]), "openai_key"),
        ("stripe sk_live", asm(&["sk_live_", "0123456789abcdefABCDEF01"]), "stripe_key"),
        ("stripe rk_live", asm(&["rk_live_", "0123456789abcdefABCDEF01"]), "stripe_key"),
        ("aws AKIA", format!("aws_key={}", asm(&["AKIA", "IOSFODNN7EXAMPLE"])), "aws_access_key"),
        ("aws ASIA", asm(&["ASIA", "Y34FZKBOKMUTVV7A"]), "aws_access_key"),
        ("google api key", asm(&["AIza", "SyD-ExampleExampleExampleExample123"]), "google_api_key"),
        ("google oauth", asm(&["ya29.", "a0AfH6SMBxExampleExampleExampleExampleExample"]), "google_oauth"),
        ("slack bot xoxb", asm(&["xoxb-", "1234567890-abcdefFGHIJ12345"]), "slack_token"),
        ("slack app xapp", asm(&["xapp-", "1-A0123ABCD-1234567890-abcdef0123456789"]), "slack_app_token"),
        ("slack webhook", asm(&["https://hooks.slack.com/services/", "T00000000/B11111111/abcdefghijklmnopqrstuvwx"]), "slack_webhook"),
        ("discord bot", asm(&["MTk4NjIyNDgzNDcxOTI1MjQ4", ".", "GBTk9x", ".", "abcdefghijklmnopqrstuvwxyzABCDEF012ab"]), "discord_token"),
        ("telegram bot", asm(&["1234567890", ":", "AAExampleExampleExampleExampleExample01"]), "telegram_token"),
        ("sendgrid key", asm(&["SG.", "abcdefghijklmnopqrstuv", ".", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"]), "sendgrid_key"),
        ("npm token", format!("npm_{A36}"), "npm_token"),
        ("jwt", format!("tok {}", asm(&["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"])), "jwt"),
        ("bearer", asm(&["Authorization: Bearer ", "abcdefghijklmnopqrstuvwxyz0123456789"]), "bearer_token"),
        ("generic password", "password=SuperSecret123".into(), "generic_secret"),
        ("generic api_key", "api_key: 0123456789abcdef".into(), "generic_secret"),
        ("private key", format!("x\n{}\nMIIBOwIBAAJBAK\nQ2F0\n{}\ny", asm(&["-----BEGIN RSA ", "PRIVATE KEY-----"]), asm(&["-----END RSA ", "PRIVATE KEY-----"])), "private_key"),
    ]
}

fn negatives() -> Vec<(&'static str, &'static str)> {
    vec![
        ("uuid", "id 550e8400-e29b-41d4-a716-446655440000"),
        ("git sha", "commit 9cb24bcf1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d done"),
        ("ip address", "server 192.168.1.100 port 8080"),
        ("prose token", "a token of trust and the secret of life is love"),
        ("file path", "/usr/local/bin/clipveil and ~/.cargo/env"),
        ("hex/nums", "color a1b2c3 value 42 count 1000000"),
        ("base64 blob", "data SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q="),
    ]
}

#[test]
fn positives_are_detected_and_redacted() {
    for (name, text, kind) in positives() {
        let found = scan(&text);
        assert!(found.iter().any(|f| f.kind == kind), "[{name}] expected {kind}, got {found:?}");
        assert!(redact(&text).contains("[REDACTED:"), "[{name}] redact produced no marker");
    }
}

#[test]
fn negatives_are_clean() {
    for (name, text) in negatives() {
        assert!(!has_secret(text), "[{name}] false positive: {:?}", scan(text));
        assert_eq!(redact(text), text, "[{name}] clean text was altered");
    }
}

#[test]
fn utf8_edge_cases_do_not_panic_and_preserve_context() {
    let cases = [
        format!("🔑 leaked ghp_{A36} done"),
        "clé api_key=abcdefgh12345 café".to_string(),
        format!("秘密 ghp_{A36} 秘密"),
    ];
    for text in cases {
        assert!(has_secret(&text));
        let red = redact(&text); // must not panic on multi-byte boundaries
        assert!(red.contains("[REDACTED:"));
    }
}

#[test]
fn secrets_at_string_boundaries() {
    let start = format!("ghp_{A36} trailing");
    let end = format!("leading ghp_{A36}");
    assert!(redact(&start).starts_with("[REDACTED:github_token]"));
    assert!(redact(&end).ends_with("[REDACTED:github_token]"));
}

#[test]
fn overlapping_bearer_jwt_collapse_to_one_span() {
    let t = format!("Authorization: Bearer {}", asm(&["eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0In0", ".", "abcDEFghiJKLmnoPQRstuVWXyz1234567890"]));
    assert_eq!(scan(&t).len(), 1);
    assert_eq!(redact(&t).matches("[REDACTED").count(), 1);
}

#[test]
fn large_input_still_detects() {
    let mut big = "some log line here\n".repeat(7000);
    big.push_str(&format!("ghp_{A36}\n"));
    assert!(has_secret(&big));
}
