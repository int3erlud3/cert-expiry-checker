"""MOTD-style startup banner (Bastion Ops Toolkit).

The banner is purely cosmetic: it is written to STDERR and only when STDERR is an
interactive terminal, so pipes, cron jobs and machine-readable output are never
affected. Disable it with ``--no-banner`` or ``NO_BANNER=1``.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from typing import TextIO

from . import __version__

SUITE = "Bastion Ops Toolkit"
AUTHOR = "int3erlud3"
TITLE = "CERT EXPIRY CHECKER  ::  TLS Certificate Expiry Monitor"
TAGLINE = "Catch expiring certificates before your users do"
WIDTH = 70
INFO_FLAGS = frozenset({"-h", "--help", "-V", "--version"})

WORDMARK = r"""
              _                    _
   __ ___ _ _| |_ ___ _____ ___ __(_)_ _ _  _
  / _/ -_) '_|  _|___/ -_) \ / '_ \ | '_| || |
  \__\___|_|  \__|   \___/_\_\ .__/_|_|  \_, |
                             |_|         |__/
      _           _
   __| |_  ___ __| |_____ _ _
  / _| ' \/ -_) _| / / -_) '_|
  \__|_||_\___\__|_\_\___|_|
"""


def render(version: str = __version__) -> str:
    """Return the full banner (wordmark + framed info block)."""
    inner = WIDTH - 6
    thick = "+" + "=" * (WIDTH - 2) + "+"
    thin = "+" + "-" * (WIDTH - 2) + "+"

    def row(text: str) -> str:
        return f"|  {text[:inner]:<{inner}}  |"

    lines = [
        *WORDMARK.strip("\n").splitlines(),
        "",
        thick,
        row(TITLE),
        thin,
        row(TAGLINE),
        row(f"v{version}  -  {SUITE}  -  by {AUTHOR}"),
        thick,
    ]
    return "\n".join(lines) + "\n"


def banner_enabled(no_banner: bool = False, stream: TextIO | None = None) -> bool:
    """True only if not disabled and the target stream is an interactive terminal."""
    if no_banner or os.environ.get("NO_BANNER", "") not in ("", "0"):
        return False
    target = sys.stderr if stream is None else stream
    try:
        return bool(target.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def maybe_print_banner(no_banner: bool = False, stream: TextIO | None = None) -> bool:
    """Print the banner to ``stream`` (default: stderr) if enabled. Returns True if printed."""
    target = sys.stderr if stream is None else stream
    if not banner_enabled(no_banner, target):
        return False
    try:
        target.write(render() + "\n")
        target.flush()
    except (OSError, ValueError):
        return False
    return True


def maybe_print_banner_for_info(argv: Sequence[str], stream: TextIO | None = None) -> bool:
    """Show the banner above ``--help``/``--version`` output (same stderr/TTY rules)."""
    if not INFO_FLAGS.intersection(argv):
        return False
    return maybe_print_banner("--no-banner" in argv, stream)
