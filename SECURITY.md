# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository
instead. You can expect an initial response within 7 days.

## Security review notes

- All external input (log lines, CLI arguments) is treated as untrusted and validated.
- No `eval`/`exec`, no `shell=True`, no deserialization of untrusted data.
- Least privilege: runs as an unprivileged (dynamic) user; only outbound TLS connections.
- TLS verification is always on; the webhook URL is treated as a secret and redacted.
- CI runs ruff (incl. flake8-bandit rules), Bandit, pip-audit and a gitleaks secret
  scan on every push and pull request; GitHub Actions are pinned to commit SHAs and
  run with `contents: read` only.
