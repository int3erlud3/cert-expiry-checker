# cert-expiry-checker

[![CI](https://github.com/int3erlud3/cert-expiry-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/int3erlud3/cert-expiry-checker/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```text
              _                    _
   __ ___ _ _| |_ ___ _____ ___ __(_)_ _ _  _
  / _/ -_) '_|  _|___/ -_) \ / '_ \ | '_| || |
  \__\___|_|  \__|   \___/_\_\ .__/_|_|  \_, |
                             |_|         |__/
      _           _
   __| |_  ___ __| |_____ _ _
  / _| ' \/ -_) _| / / -_) '_|
  \__|_||_\___\__|_\_\___|_|

+====================================================================+
|  CERT EXPIRY CHECKER  ::  TLS Certificate Expiry Monitor           |
+--------------------------------------------------------------------+
|  Catch expiring certificates before your users do                  |
|  v1.0.0  -  Bastion Ops Toolkit  -  by int3erlud3                  |
+====================================================================+
```

Check TLS certificates of many hosts in parallel, warn before they expire and
optionally post a summary to a chat webhook (Slack, Mattermost, Teams, …).
Standard library only – no runtime dependencies.

## Features

- `host` or `host:port` targets from the command line and/or a file
- Full certificate **and** hostname verification (TLS ≥ 1.2); expired, self-signed or
  mismatched certificates are reported as `CRITICAL`, unreachable hosts as `UNKNOWN`
- Configurable warning/critical thresholds in days
- Parallel checks with timeouts
- Output as **table** (sorted by urgency) or **JSON**
- Optional webhook notification; the URL is read from the environment, never from
  arguments or files in the repository
- Monitoring-friendly exit codes: `0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN / usage error

## Installation

```bash
git clone https://github.com/int3erlud3/cert-expiry-checker.git
cd cert-expiry-checker
python3 -m venv .venv && . .venv/bin/activate
pip install .
```

## Usage

```bash
cert-expiry-checker example.com www.wikipedia.org mail.example.org:465

cert-expiry-checker -i examples/domains.txt --warn 30 --crit 14 -f json

# Notify a webhook when something needs attention
export CERT_EXPIRY_WEBHOOK_URL='https://hooks.slack.com/services/...'   # keep out of shell history/repo
cert-expiry-checker -i /etc/cert-expiry-checker/domains.txt --notify
```

Example output:

```text
STATUS    HOST                                      DAYS  EXPIRES (UTC)        DETAILS
--------------------------------------------------------------------------------------
CRITICAL  expired.badssl.com:443                       -  -                    verification failed: certificate has expired
UNKNOWN   localhost:1                                  -  -                    ConnectionRefusedError: [Errno 111] Connection refused
WARNING   www.wikipedia.org:443                       26  2026-11-03 19:15:40  CN=*.wikipedia.org issuer=Let's Encrypt
OK        example.com:443                             78  2026-12-25 22:56:35  CN=example.com issuer=SSL Corporation
```

A systemd service + timer example is in [`examples/`](examples/).

## Configuration

| Option / variable | Default | Description |
|---|---|---|
| `targets` | – | `host` or `host:port` (port default 443) |
| `-i, --input FILE` | – | One target per line, `#` comments allowed |
| `-w, --warn DAYS` | `30` | WARNING if fewer days left |
| `-c, --crit DAYS` | `14` | CRITICAL if fewer days left |
| `-f, --format` | `table` | `table` or `json` |
| `-t, --timeout SEC` | `10` | Connect/handshake timeout (0–120) |
| `--workers N` | `8` | Parallel checks (1–32) |
| `--notify` | off | POST a summary when status is not OK |
| `--notify-always` | off | With `--notify`: also when everything is OK |
| `CERT_EXPIRY_WEBHOOK_URL` | – | Webhook URL (**https only**), see `.env.example` |
| `--no-banner` / `NO_BANNER=1` | off | Suppress the startup banner (shown on a terminal only) |

## Startup banner

Part of the **Bastion Ops Toolkit**. When run interactively, `cert-expiry-checker` prints the
banner shown above to **stderr** – only if stderr is a terminal and never together with `--format json`. Pipes,
cron jobs, systemd units and monitoring agents see exactly the same output and exit
codes as before. Disable it with `--no-banner` or `NO_BANNER=1`; `--help` and
`--version` show it on a terminal too.

## Development

```bash
make venv && make lint test security   # ruff, pytest (network mocked), bandit, pip-audit
make scan                               # gitleaks secret scan (needs Docker)
```

## Security notes

- Certificate verification is **never disabled**; there is intentionally no
  `--insecure` flag. Verification failures are findings, not errors to suppress.
- The webhook URL is a secret: it is taken only from the environment, must be
  `https://`, and is redacted from error messages. Use a root-only `EnvironmentFile`
  (see example unit) instead of putting it on the command line.
- Targets are validated (RFC 1123 hostnames, port range) and the number of targets is
  capped; only treat the target list as trusted operator input (the tool connects to
  whatever hosts it is given).
- Runs unprivileged; the example unit uses `DynamicUser=yes` and systemd sandboxing.

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
