"""Optional webhook notification (Slack/Mattermost/Teams-compatible ``text`` payload)."""

from __future__ import annotations

import json
import os
import urllib.request
from urllib.parse import urlsplit

from .checker import Result

WEBHOOK_ENV = "CERT_EXPIRY_WEBHOOK_URL"


class WebhookError(RuntimeError):
    """Raised when a notification cannot be delivered. Never contains the URL."""


def webhook_url_from_env() -> str | None:
    return os.environ.get(WEBHOOK_ENV) or None


def validate_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise WebhookError(f"{WEBHOOK_ENV} must be an https:// URL")
    return url


def build_payload(results: list[Result]) -> dict[str, object]:
    problems = [r for r in results if r.status != "OK"]
    lines = [
        f"{r.status}: {r.host}:{r.port} "
        + (f"expires in {r.days_left} days ({r.not_after})" if r.days_left is not None else str(r.error))
        for r in problems
    ]
    text = "TLS certificate check: " + (
        f"{len(problems)} problem(s)\n" + "\n".join(lines) if problems else "all OK"
    )
    return {"text": text, "results": [r.to_dict() for r in results]}


def send(url: str, payload: dict[str, object], timeout: float = 10.0) -> int:
    """POST the JSON payload. The URL is treated as a secret and never logged."""
    request = urllib.request.Request(  # noqa: S310 - scheme restricted to https by validate_url()
        validate_url(url),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "cert-expiry-checker"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            return resp.status
    except OSError as exc:
        reason = str(getattr(exc, "reason", None) or getattr(exc, "code", None) or type(exc).__name__)
        # Webhook URLs usually embed a secret token: make sure it never reaches logs.
        raise WebhookError(f"webhook delivery failed: {reason.replace(url, '<redacted>')}") from None
