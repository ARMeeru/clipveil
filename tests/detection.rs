//! Integration corpus for the detection engine. This is the versioned,
//! reproducible source of the QA numbers — run with `cargo test`.

use clipveil::detect::{has_secret, redact, scan};

const A36: &str = "0123456789abcdefghijABCDEFGHIJ012345"; // 36 chars

fn positives() -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("github classic ghp", format!("run ghp_{A36} now"), "github_token"),
        ("github gho", format!("gho_{A36}"), "github_token"),
        ("github ghs", format!("ghs_{A36}"), "github_token"),
        ("github fine PAT", "REDACTED_TEST_TOKEN".into(), "github_pat"),
        ("gitlab pat", "REDACTED_TEST_TOKEN".into(), "gitlab_pat"),
        ("openai sk-", "key REDACTED_TEST_TOKEN".into(), "openai_key"),
        ("openai sk-proj", "REDACTED_TEST_TOKEN".into(), "openai_key"),
        ("stripe sk_live", "REDACTED_TEST_TOKEN".into(), "stripe_key"),
        ("stripe rk_live", "REDACTED_TEST_TOKEN".into(), "stripe_key"),
        ("aws AKIA", "aws_key=REDACTED_TEST_TOKEN".into(), "aws_access_key"),
        ("aws ASIA", "REDACTED_TEST_TOKEN".into(), "aws_access_key"),
        ("google api key", "REDACTED_TEST_TOKEN".into(), "google_api_key"),
        ("google oauth", "REDACTED_TEST_TOKEN".into(), "google_oauth"),
        ("slack bot xoxb", "REDACTED_TEST_TOKEN".into(), "slack_token"),
        ("slack app xapp", "REDACTED_TEST_TOKEN".into(), "slack_app_token"),
        ("slack webhook", "https://hooks.example.invalid/x".into(), "slack_webhook"),
        ("discord bot", "REDACTED_TEST_TOKEN".into(), "discord_token"),
        ("telegram bot", "REDACTED_TEST_TOKENle01".into(), "telegram_token"),
        ("sendgrid key", "REDACTED_TEST_TOKEN".into(), "sendgrid_key"),
        ("npm token", format!("npm_{A36}"), "npm_token"),
        ("jwt", "tok REDACTED_TEST_JWT".into(), "jwt"),
        ("bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789".into(), "bearer_token"),
        ("generic password", "password=SuperSecret123".into(), "generic_secret"),
        ("generic api_key", "api_key: 0123456789abcdef".into(), "generic_secret"),
        ("private key", "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAK\nQ2F0\n-----END RSA PRIVATE KEY-----\ny".into(), "private_key"),
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
        // redaction must remove the raw secret marker where applicable
        let red = redact(&text);
        assert!(red.contains("[REDACTED:"), "[{name}] redact produced no marker");
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
        assert!(red.is_char_boundary(0));
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
    let t = "Authorization: Bearer REDACTED_TEST_JWT";
    assert_eq!(scan(t).len(), 1);
    assert_eq!(redact(t).matches("[REDACTED").count(), 1);
}

#[test]
fn large_input_still_detects() {
    let mut big = "some log line here\n".repeat(7000);
    big.push_str(&format!("ghp_{A36}\n"));
    assert!(has_secret(&big));
}
