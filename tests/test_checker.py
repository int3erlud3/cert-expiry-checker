import ssl
from datetime import datetime, timezone

import pytest

from cert_expiry_checker import checker
from cert_expiry_checker.checker import Target, evaluate, overall_status, parse_target

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)


def make_cert(not_after: str) -> dict:
    return {
        "notAfter": not_after,
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example R1"),)),
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", Target("example.com", 443)),
        ("Example.COM.", Target("example.com", 443)),
        ("mail.example.org:465", Target("mail.example.org", 465)),
        ("localhost:8443", Target("localhost", 8443)),
    ],
)
def test_parse_target_valid(raw, expected):
    assert parse_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "exa mple.com",
        "-bad.com",
        "example.com:0",
        "example.com:70000",
        "example.com:abc",
        "https://example.com",
        "a" * 64 + ".com",
        "host;rm -rf /",
        "$(id).com",
    ],
)
def test_parse_target_invalid(raw):
    with pytest.raises(ValueError):
        parse_target(raw)


@pytest.mark.parametrize(
    ("not_after", "status", "days"),
    [
        ("Jan  6 12:00:00 2027 GMT", "OK", 90),
        ("Oct 28 12:00:00 2026 GMT", "WARNING", 20),
        ("Oct 15 12:00:00 2026 GMT", "CRITICAL", 7),
    ],
)
def test_evaluate_thresholds(not_after, status, days):
    r = evaluate(Target("example.com"), make_cert(not_after), warn_days=30, crit_days=14, now=NOW)
    assert (r.status, r.days_left) == (status, days)
    assert r.subject == "example.com"
    assert r.issuer == "Example CA"


def test_check_verification_failure_is_critical(monkeypatch):
    err = ssl.SSLCertVerificationError("cert verify failed")
    err.verify_message = "certificate has expired"

    def boom(*_a, **_k):
        raise err

    monkeypatch.setattr(checker, "fetch_cert", boom)
    r = checker.check(Target("expired.example"), 30, 14)
    assert r.status == "CRITICAL"
    assert "certificate has expired" in r.error


def test_check_connection_error_is_unknown(monkeypatch):
    def boom(*_a, **_k):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(checker, "fetch_cert", boom)
    r = checker.check(Target("down.example"), 30, 14)
    assert r.status == "UNKNOWN"
    assert "ConnectionRefusedError" in r.error


def test_fetch_cert_uses_verifying_context(monkeypatch):
    seen = {}

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeCtx:
        minimum_version = None

        def wrap_socket(self, sock, server_hostname):
            seen["sni"] = server_hostname
            tls = FakeSock()
            tls.getpeercert = lambda: {"notAfter": "x"}
            return tls

    real_ctx = ssl.create_default_context()
    assert real_ctx.verify_mode == ssl.CERT_REQUIRED
    assert real_ctx.check_hostname is True
    monkeypatch.setattr(checker.ssl, "create_default_context", FakeCtx)
    monkeypatch.setattr(checker.socket, "create_connection", lambda addr, timeout: FakeSock())
    assert checker.fetch_cert(Target("example.com"), 5) == {"notAfter": "x"}
    assert seen["sni"] == "example.com"


def test_overall_status_ordering():
    mk = lambda s: checker.Result("h", 443, s)  # noqa: E731
    assert overall_status([]) == "OK"
    assert overall_status([mk("OK"), mk("WARNING")]) == "WARNING"
    assert overall_status([mk("UNKNOWN"), mk("WARNING")]) == "UNKNOWN"
    assert overall_status([mk("UNKNOWN"), mk("CRITICAL"), mk("OK")]) == "CRITICAL"
