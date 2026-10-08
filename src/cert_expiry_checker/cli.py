"""Command line interface for cert-expiry-checker."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .banner import maybe_print_banner, maybe_print_banner_for_info
from .checker import EXIT_CODES, Result, Target, check_all, overall_status, parse_target
from .notify import WEBHOOK_ENV, WebhookError, build_payload, send, webhook_url_from_env

MAX_TARGETS = 500


def _days(value: str) -> int:
    if not value.isdigit() or int(value) > 3650:
        raise argparse.ArgumentTypeError("must be an integer between 0 and 3650")
    return int(value)


def _timeout(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        seconds = -1.0
    if not 0 < seconds <= 120:
        raise argparse.ArgumentTypeError("must be a number of seconds between 0 and 120")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cert-expiry-checker",
        description="Check TLS certificate expiry for hosts (host or host:port).",
        epilog=f"Webhook URL is read from the {WEBHOOK_ENV} environment variable.",
    )
    p.add_argument("targets", nargs="*", help="host or host:port (default port 443)")
    p.add_argument("-i", "--input", type=Path, help="file with one host[:port] per line (# comments)")
    p.add_argument("-w", "--warn", type=_days, default=30, help="warning threshold in days (default 30)")
    p.add_argument("-c", "--crit", type=_days, default=14, help="critical threshold in days (default 14)")
    p.add_argument("-f", "--format", choices=("table", "json"), default="table")
    p.add_argument("-t", "--timeout", type=_timeout, default=10.0, help="connect timeout in seconds")
    p.add_argument("--workers", type=int, default=8, choices=range(1, 33), metavar="1-32")
    p.add_argument("--notify", action="store_true", help=f"send a webhook to ${WEBHOOK_ENV} on problems")
    p.add_argument("--notify-always", action="store_true", help="with --notify: also send when all OK")
    p.add_argument(
        "--no-banner", action="store_true", help="do not print the startup banner (or set NO_BANNER=1)"
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def load_targets(args: argparse.Namespace) -> list[Target]:
    raw = list(args.targets)
    if args.input:
        raw += [ln.split("#", 1)[0] for ln in args.input.read_text(encoding="utf-8").splitlines()]
    targets = list(dict.fromkeys(parse_target(r) for r in raw if r.strip()))
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"too many targets (max {MAX_TARGETS})")
    return targets


def render_table(results: list[Result]) -> str:
    header = f"{'STATUS':<9} {'HOST':<40} {'DAYS':>5}  {'EXPIRES (UTC)':<20} DETAILS"
    rows = [header, "-" * len(header)]
    for r in sorted(results, key=lambda x: (x.days_left is not None, x.days_left or 0)):
        expires = (r.not_after or "-")[:19].replace("T", " ")
        days = "-" if r.days_left is None else str(r.days_left)
        details = r.error or f"CN={r.subject} issuer={r.issuer}"
        rows.append(f"{r.status:<9} {Target(r.host, r.port)!s:<40} {days:>5}  {expires:<20} {details}")
    return "\n".join(rows)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    maybe_print_banner_for_info(argv)
    args = build_parser().parse_args(argv)
    if args.format != "json":  # never mix the banner with machine-readable output
        maybe_print_banner(args.no_banner)
    if args.crit > args.warn:
        print("error: --crit must not be greater than --warn", file=sys.stderr)
        return 3
    try:
        targets = load_targets(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    if not targets:
        print("error: no targets given", file=sys.stderr)
        return 3

    results = check_all(targets, args.warn, args.crit, timeout=args.timeout, workers=args.workers)
    status = overall_status(results)
    if args.format == "json":
        print(json.dumps({"status": status, "results": [r.to_dict() for r in results]}, indent=2))
    else:
        print(render_table(results))

    if args.notify and (status != "OK" or args.notify_always):
        url = webhook_url_from_env()
        if not url:
            print(f"warning: --notify given but {WEBHOOK_ENV} is not set", file=sys.stderr)
        else:
            try:
                send(url, build_payload(results), timeout=args.timeout)
            except WebhookError as exc:
                print(f"warning: {exc}", file=sys.stderr)
    return EXIT_CODES[status]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
