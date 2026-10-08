import json
import urllib.error

import pytest

from cert_expiry_checker import checker, cli, notify
from cert_expiry_checker.checker import Result

WEBHOOK_URL = "https://hooks.example.invalid/services/T000/B000/XXXXTOKEN"


@pytest.fixture
def fake_results(monkeypatch):
    """Replace network checks with canned results keyed by host."""
    canned = {
        "ok.example": Result("ok.example", 443, "OK", 90, "2027-01-06T12:00:00+00:00", "ok.example", "CA"),
        "soon.example": Result("soon.example", 443, "WARNING", 20, "2026-10-28T12:00:00+00:00", "s", "CA"),
        "bad.example": Result("bad.example", 443, "CRITICAL", error="verification failed: expired"),
    }
    monkeypatch.setattr(cli, "check_all", lambda targets, *a, **k: [canned[t.host] for t in targets])
    return canned


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "send", lambda url, payload, timeout: calls.append((url, payload)) or 200)
    return calls


def test_json_output_and_exit_code(fake_results, capsys):
    rc = cli.main(["-f", "json", "ok.example", "soon.example"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["status"] == "WARNING"
    assert [r["host"] for r in out["results"]] == ["ok.example", "soon.example"]


def test_table_output_sorted_by_urgency(fake_results, capsys):
    assert cli.main(["ok.example", "bad.example", "soon.example"]) == 2
    lines = capsys.readouterr().out.splitlines()
    assert lines[2].startswith("CRITICAL")
    assert lines[3].startswith("WARNING")


def test_input_file_with_comments_and_duplicates(fake_results, tmp_path, capsys):
    f = tmp_path / "hosts.txt"
    f.write_text("# list\nok.example\nok.example:443  # dup\n\n")
    assert cli.main(["-f", "json", "-i", str(f)]) == 0
    assert len(json.loads(capsys.readouterr().out)["results"]) == 1


@pytest.mark.parametrize("timeout", ["0", "-1", "abc", "1000"])
def test_invalid_timeout_rejected(timeout):
    with pytest.raises(SystemExit) as exc:
        cli.main(["-t", timeout, "ok.example"])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    "argv", [[], ["bad host"], ["-w", "10", "-c", "20", "ok.example"], ["-i", "/nonexistent/file"]]
)
def test_usage_errors_exit_3(fake_results, argv, capsys):
    assert cli.main(argv) == 3


def test_notify_only_on_problems(fake_results, sent, monkeypatch):
    monkeypatch.setenv(notify.WEBHOOK_ENV, WEBHOOK_URL)
    cli.main(["--notify", "ok.example"])
    assert sent == []
    cli.main(["--notify", "soon.example"])
    assert len(sent) == 1
    assert "WARNING: soon.example:443 expires in 20 days" in sent[0][1]["text"]
    cli.main(["--notify", "--notify-always", "ok.example"])
    assert len(sent) == 2


def test_notify_without_env_warns(fake_results, sent, monkeypatch, capsys):
    monkeypatch.delenv(notify.WEBHOOK_ENV, raising=False)
    cli.main(["--notify", "bad.example"])
    assert sent == []
    assert "is not set" in capsys.readouterr().err


@pytest.mark.parametrize("url", ["http://hooks.example/x", "file:///etc/passwd", "ftp://x/y", "https://"])
def test_webhook_requires_https(url):
    with pytest.raises(notify.WebhookError, match="https"):
        notify.send(url, {"text": "x"})


def test_webhook_posts_json(monkeypatch):
    captured = {}

    class Resp:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        captured.update(url=req.full_url, method=req.get_method(), body=json.loads(req.data), timeout=timeout)
        return Resp()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    assert notify.send(WEBHOOK_URL, {"text": "hi"}, timeout=3) == 204
    assert captured == {"url": WEBHOOK_URL, "method": "POST", "body": {"text": "hi"}, "timeout": 3}


def test_webhook_error_does_not_leak_url(fake_results, monkeypatch, capsys):
    def fail(req, timeout):
        raise urllib.error.URLError(f"cannot reach {req.full_url}")

    monkeypatch.setattr(notify.urllib.request, "urlopen", fail)
    with pytest.raises(notify.WebhookError) as exc:
        notify.send(WEBHOOK_URL, {"text": "x"})
    assert "XXXXTOKEN" not in str(exc.value)
    assert "<redacted>" in str(exc.value)

    def fail_http(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr(notify.urllib.request, "urlopen", fail_http)
    monkeypatch.setenv(notify.WEBHOOK_ENV, WEBHOOK_URL)
    cli.main(["--notify", "bad.example"])
    err = capsys.readouterr().err
    assert "webhook delivery failed: Forbidden" in err
    assert "XXXXTOKEN" not in err


def test_payload_summary():
    payload = notify.build_payload([Result("a.example", 443, "OK", 100)])
    assert payload["text"] == "TLS certificate check: all OK"
    assert checker.SEVERITY["CRITICAL"] > checker.SEVERITY["UNKNOWN"]
