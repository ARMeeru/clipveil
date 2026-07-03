//! End-to-end CLI tests. Shell out to the built binary and drive it via stdin,
//! so these run regardless of the clipboard/agent features.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &str) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_clipveil"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn clipveil");
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn scan_exits_1_and_names_kind_on_secret() {
    let tok = ["ghp_", "0123456789abcdefghijABCDEFGHIJ012345"].concat();
    let (code, out) = run(&["scan"], &format!("export T={tok}\n"));
    assert_eq!(code, 1, "scan should exit 1 when a secret is present");
    assert!(out.contains("github_token"), "scan output: {out}");
}

#[test]
fn scan_exits_0_and_reports_clean_on_safe_text() {
    let (code, out) = run(&["scan"], "just a normal log line, nothing secret\n");
    assert_eq!(code, 0);
    assert!(out.to_lowercase().contains("clean"), "scan output: {out}");
}

#[test]
fn redact_replaces_secret_on_stdout() {
    let jwt = ["eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiJ4In0", ".", "abcDEFghiJKLmnoPQRstuVWXyz1234567890"].concat();
    let (code, out) = run(&["redact"], &format!("curl -H 'Authorization: Bearer {jwt}'\n"));
    assert_eq!(code, 0);
    assert!(out.contains("[REDACTED:"), "redact output: {out}");
    assert!(out.contains("[REDACTED:"), "expected redaction marker: {out}");
}

#[test]
fn redact_passes_clean_text_through_unchanged() {
    let input = "hello world 12345\n";
    let (code, out) = run(&["redact"], input);
    assert_eq!(code, 0);
    assert_eq!(out, input);
}
