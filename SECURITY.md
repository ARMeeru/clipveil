# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

- Preferred: GitHub → **Security** tab → **Report a vulnerability** (private
  advisory).
- Or email: **asifur.rahaman@meeru.dev**

Please include a description, reproduction steps, and the affected version.
You can expect an initial response within a few days.

## Scope & design notes

clipveil is a local macOS agent. It has **no network access** — all secret
detection runs on-device, and no clipboard content ever leaves your machine.
That said, responsible disclosure of anything that could cause a secret to leak
(for example a redaction bypass, or a pattern that fails to match a real token
class) is very welcome.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
