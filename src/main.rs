//! clipveil — veil secrets in your clipboard before you paste them.

use clipveil::detect;

#[cfg(feature = "clipboard")]
mod paste;

#[cfg(feature = "agent")]
mod agent;

use std::io::{IsTerminal, Read};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("run");

    match cmd {
        "run" => cmd_run(),
        "scan" => cmd_scan(),
        "redact" => cmd_redact(),
        "version" | "--version" | "-V" => {
            println!("clipveil {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("clipveil: unknown command '{other}'\n");
            print_help();
            std::process::exit(2);
        }
    }
}

/// Input source: piped stdin if present, otherwise the clipboard.
fn read_input() -> Result<String, String> {
    if !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        return Ok(buf);
    }
    read_clipboard_or_hint()
}

#[cfg(feature = "clipboard")]
fn read_clipboard_or_hint() -> Result<String, String> {
    paste::read_clipboard()
}

#[cfg(not(feature = "clipboard"))]
fn read_clipboard_or_hint() -> Result<String, String> {
    Err("no input piped and this build has no clipboard support".into())
}

/// `clipveil scan` — report findings; exit 1 if any secret is present.
fn cmd_scan() {
    let text = match read_input() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("clipveil: {e}");
            std::process::exit(2);
        }
    };
    let summary = detect::summary(&text);
    if summary.is_empty() {
        println!("clean — no secrets detected");
        return;
    }
    println!("SECRETS DETECTED:");
    for (kind, n) in &summary {
        println!("  {kind} ({n})");
    }
    std::process::exit(1);
}

/// `clipveil redact` — print the redacted text to stdout.
fn cmd_redact() {
    let text = match read_input() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("clipveil: {e}");
            std::process::exit(2);
        }
    };
    print!("{}", detect::redact(&text));
}

#[cfg(feature = "agent")]
fn cmd_run() {
    if let Err(e) = agent::run() {
        eprintln!("clipveil: agent failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "agent"))]
fn cmd_run() {
    eprintln!("clipveil: this build was compiled without the 'agent' feature");
    std::process::exit(1);
}

fn print_help() {
    println!(
        r#"clipveil {ver} — veil secrets in your clipboard before you paste

USAGE:
    clipveil [COMMAND]

COMMANDS:
    run       Start the resident agent (default). Binds Cmd+Shift+V and
              prompts Paste Plain / Paste Redacted when a secret is found.
    scan      Report secrets in piped stdin or the clipboard. Exit 1 if found.
    redact    Print a redacted copy of piped stdin or the clipboard.
    version   Print version.
    help      Show this help.

EXAMPLES:
    clipveil run
    pbpaste | clipveil scan
    cat secrets.env | clipveil redact
"#,
        ver = env!("CARGO_PKG_VERSION")
    );
}
