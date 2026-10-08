"""TLS certificate retrieval and expiry evaluation."""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
SEVERITY = {"OK": 0, "WARNING": 1, "UNKNOWN": 2, "CRITICAL": 3}
EXIT_CODES = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 443

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Result:
    host: str
    port: int
    status: str
    days_left: int | None = None
    not_after: str | None = None
    subject: str | None = None
    issuer: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def parse_target(value: str) -> Target:
    """Parse ``host`` or ``host:port``; raise ValueError on invalid input."""
    value = value.strip().lower().rstrip(".")
    host, sep, port_s = value.rpartition(":") if ":" in value else (value, "", "")
    if sep and not port_s.isdigit():
        raise ValueError(f"invalid port in {value!r}")
    port = int(port_s) if sep else 443
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range in {value!r}")
    if not HOST_RE.fullmatch(host):
        raise ValueError(f"invalid hostname {host!r}")
    return Target(host, port)


def _name(rdns: tuple[tuple[tuple[str, str], ...], ...] | None, key: str) -> str | None:
    for rdn in rdns or ():
        for k, v in rdn:
            if k == key:
                return v
    return None


def fetch_cert(target: Target, timeout: float) -> dict:
    """Connect with full certificate and hostname verification and return the peer cert."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with (
        socket.create_connection((target.host, target.port), timeout=timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=target.host) as tls,
    ):
        return tls.getpeercert()


def evaluate(target: Target, cert: dict, warn_days: int, crit_days: int, now: datetime) -> Result:
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    days_left = int((not_after - now).total_seconds() // 86400)
    status = "CRITICAL" if days_left < crit_days else "WARNING" if days_left < warn_days else "OK"
    return Result(
        host=target.host,
        port=target.port,
        status=status,
        days_left=days_left,
        not_after=not_after.isoformat(),
        subject=_name(cert.get("subject"), "commonName"),
        issuer=_name(cert.get("issuer"), "organizationName") or _name(cert.get("issuer"), "commonName"),
    )


def check(target: Target, warn_days: int, crit_days: int, timeout: float = 10.0) -> Result:
    now = datetime.now(timezone.utc)
    try:
        cert = fetch_cert(target, timeout)
    except ssl.SSLCertVerificationError as exc:
        # Expired, self-signed or wrong-host certificates are a problem, not a reason to skip checks.
        return Result(
            target.host, target.port, "CRITICAL", error=f"verification failed: {exc.verify_message}"
        )
    except (OSError, ssl.SSLError) as exc:
        return Result(target.host, target.port, "UNKNOWN", error=f"{type(exc).__name__}: {exc}")
    return evaluate(target, cert, warn_days, crit_days, now)


def check_all(
    targets: list[Target], warn_days: int, crit_days: int, timeout: float = 10.0, workers: int = 8
) -> list[Result]:
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        return list(pool.map(lambda t: check(t, warn_days, crit_days, timeout), targets))


def overall_status(results: list[Result]) -> str:
    return max((r.status for r in results), key=SEVERITY.__getitem__, default="OK")
