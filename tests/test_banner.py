"""Banner behaviour: cosmetic, stderr-only, TTY-only, never in machine output."""

import io
import json
from pathlib import Path

import pytest

from cert_expiry_checker import __version__, banner, cli
from cert_expiry_checker.checker import Result


@pytest.fixture
def fake_check(monkeypatch):
    ok = Result("ok.example", 443, "OK", 90, "2027-01-06T12:00:00+00:00", "ok.example", "CA")
    monkeypatch.setattr(cli, "check_all", lambda targets, *a, **k: [ok for _ in targets])


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture(autouse=True)
def _no_env_override(monkeypatch):
    monkeypatch.delenv("NO_BANNER", raising=False)


@pytest.fixture
def tty_stderr(monkeypatch):
    """A fake interactive stderr. Call ``.install()`` inside the test body: pytest's
    capture re-installs its own sys.stderr after fixture setup."""
    fake = FakeTTY()
    fake.install = lambda: monkeypatch.setattr("sys.stderr", fake)
    return fake


def test_render_fits_terminal_and_identifies_suite():
    text = banner.render()
    lines = text.splitlines()
    assert max(len(line) for line in lines) <= 70
    assert text.isascii()
    assert banner.SUITE in text
    assert f"v{__version__}" in text
    assert "by int3erlud3" in text


def test_readme_shows_current_banner():
    readme = Path(__file__).resolve().parents[1] / "README.md"
    assert banner.render() in readme.read_text(encoding="utf-8")


def test_printed_on_tty_only():
    tty, pipe = FakeTTY(), io.StringIO()
    assert banner.maybe_print_banner(stream=tty)
    assert banner.render() in tty.getvalue()
    assert not banner.maybe_print_banner(stream=pipe)
    assert pipe.getvalue() == ""


@pytest.mark.parametrize("value", ["1", "yes", "true"])
def test_no_banner_env_disables(monkeypatch, value):
    monkeypatch.setenv("NO_BANNER", value)
    tty = FakeTTY()
    assert not banner.maybe_print_banner(stream=tty)
    assert tty.getvalue() == ""


def test_no_banner_env_zero_keeps_banner(monkeypatch):
    monkeypatch.setenv("NO_BANNER", "0")
    assert banner.maybe_print_banner(stream=FakeTTY())


def test_closed_stream_is_ignored():
    stream = FakeTTY()
    stream.close()
    assert not banner.maybe_print_banner(stream=stream)


def test_cli_prints_banner_to_stderr_on_tty(fake_check, tty_stderr, capsys):
    tty_stderr.install()
    cli.main(["ok.example"])
    assert banner.render() in tty_stderr.getvalue()
    assert banner.SUITE not in capsys.readouterr().out


def test_cli_no_banner_flag(fake_check, tty_stderr, capsys):
    tty_stderr.install()
    cli.main(["--no-banner", "ok.example"])
    assert banner.SUITE not in tty_stderr.getvalue()


def test_cli_no_banner_env(fake_check, tty_stderr, monkeypatch, capsys):
    tty_stderr.install()
    monkeypatch.setenv("NO_BANNER", "1")
    cli.main(["ok.example"])
    assert banner.SUITE not in tty_stderr.getvalue()


def test_cli_without_tty_has_no_banner(fake_check, capsys):
    cli.main(["ok.example"])
    captured = capsys.readouterr()
    assert banner.SUITE not in captured.err
    assert banner.SUITE not in captured.out


def test_json_output_never_has_banner(fake_check, tty_stderr, capsys):
    tty_stderr.install()
    cli.main(["--format", "json", "ok.example"])
    assert banner.SUITE not in tty_stderr.getvalue()
    json.loads(capsys.readouterr().out)  # stdout is pure JSON


@pytest.mark.parametrize("flag", ["--version", "--help"])
def test_info_flags_show_banner_on_tty(tty_stderr, capsys, flag):
    tty_stderr.install()
    with pytest.raises(SystemExit) as exc:
        cli.main([flag])
    assert exc.value.code == 0
    assert banner.SUITE in tty_stderr.getvalue()
    out = capsys.readouterr().out
    assert banner.SUITE not in out
    if flag == "--version":
        assert __version__ in out


def test_info_flags_respect_no_banner(tty_stderr):
    tty_stderr.install()
    with pytest.raises(SystemExit):
        cli.main(["--version", "--no-banner"])
    assert tty_stderr.getvalue() == ""
