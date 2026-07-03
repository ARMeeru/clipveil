# Samples

A local file `secret-samples.txt` (git-ignored) holds **fake** tokens for
manually exercising the Cmd+Shift+V dialog. It is intentionally not committed:
it contains secret-shaped strings that would trip secret scanners, and shipping
realistic-looking tokens in a public repo is exactly the habit clipveil exists
to break.

To recreate it, copy any assembled fixture from `tests/detection.rs` (the
`positives()` list) onto its own line and paste with Cmd+Shift+V.
