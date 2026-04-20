"""Tests for flux.server."""
from __future__ import annotations

import pytest

from flux import server as tbenv


def test_default_webshell_paths_include_azure_wp_checker_anchor():
    """The Azure WP Webshell Checker anchor (hellopress/wp_filemanager.php)
    plus all observed short-named PHPs from the April 2026 burst must match."""
    must_match = [
        "/wp-content/plugins/hellopress/wp_filemanager.php",
        "/hellopress/wp_filemanager.php",
        "/doc.php",
        "/ws80.php",
        "/bthil.php",
        "/xminie.php",
        "/inputs.php",
        "/ioxi-o.php",
        "/8.php",
        "/an.php",
        "/kma.php",
        "/ssh3ll.php",
        "/new4.php",
        "/sf.php",
    ]
    for path in must_match:
        assert tbenv.is_webshell_path(path), f"expected webshell match: {path}"


def test_webshell_path_is_case_insensitive():
    assert tbenv.is_webshell_path("/WP-Content/Plugins/HelloPress/WP_FILEMANAGER.PHP")


def test_non_webshell_path_does_not_match():
    for path in ["/", "/.env", "/index.html", "/wp-login.php"]:
        assert not tbenv.is_webshell_path(path)


def test_parse_cookies_basic():
    result = tbenv.parse_cookies("sid=abc; cmd=id; _hp_tid=xyz")
    assert result == {"sid": "abc", "cmd": "id", "_hp_tid": "xyz"}


def test_parse_cookies_empty():
    assert tbenv.parse_cookies("") == {}


def test_parse_form_body_urlencoded():
    body = b"cmd=id&x=y&empty="
    result = tbenv.parse_form_body(body, "application/x-www-form-urlencoded")
    assert result == {"cmd": ["id"], "x": ["y"], "empty": [""]}


def test_parse_form_body_ignores_non_form_content_type():
    """JSON body shouldn't be parsed as form data; we want to see it in bodyPreview instead."""
    assert tbenv.parse_form_body(b'{"cmd":"id"}', "application/json") == {}


def test_parse_form_body_treats_missing_content_type_as_form():
    """Many shell clients omit Content-Type entirely."""
    assert tbenv.parse_form_body(b"cmd=id", "") == {"cmd": ["id"]}


class _FakeHeaders(dict):
    def get(self, key, default=""):  # case-insensitive like HTTPMessage
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


def test_extract_webshell_command_from_query():
    source, key, cmd = tbenv.extract_webshell_command(
        {"cmd": ["id"]}, {}, {}, _FakeHeaders(),
    )
    assert (source, key, cmd) == ("query", "cmd", "id")


def test_extract_webshell_command_from_form():
    source, key, cmd = tbenv.extract_webshell_command(
        {}, {"command": ["whoami"]}, {}, _FakeHeaders(),
    )
    assert (source, key, cmd) == ("form", "command", "whoami")


def test_extract_webshell_command_prefers_query_over_form():
    """Scanners sometimes set both; query-string is the more common observed channel."""
    source, key, cmd = tbenv.extract_webshell_command(
        {"c": ["from_query"]}, {"c": ["from_form"]}, {}, _FakeHeaders(),
    )
    assert source == "query"
    assert cmd == "from_query"


def test_extract_webshell_command_from_cookie():
    source, key, cmd = tbenv.extract_webshell_command(
        {}, {}, {"cmd": "uname -a"}, _FakeHeaders(),
    )
    assert (source, key, cmd) == ("cookie", "cmd", "uname -a")


def test_extract_webshell_command_from_header():
    headers = _FakeHeaders({"X-Cmd": "id"})
    source, key, cmd = tbenv.extract_webshell_command({}, {}, {}, headers)
    assert source == "header"
    assert cmd == "id"


def test_extract_webshell_command_none():
    source, key, cmd = tbenv.extract_webshell_command({}, {}, {}, _FakeHeaders())
    assert (source, key, cmd) == ("", "", "")


def test_extract_webshell_command_case_variant_param_name():
    """Some shells use uppercase CMD."""
    source, key, cmd = tbenv.extract_webshell_command(
        {"CMD": ["id"]}, {}, {}, _FakeHeaders(),
    )
    assert source == "query"
    assert cmd == "id"


def test_simulate_command_output_id():
    assert "uid=33(www-data)" in tbenv.simulate_command_output("id")


def test_simulate_command_output_whoami():
    assert tbenv.simulate_command_output("whoami").strip() == "www-data"


def test_simulate_command_output_uname():
    out = tbenv.simulate_command_output("uname -a")
    assert "Linux" in out and "GNU/Linux" in out


def test_simulate_command_output_cat_etc_passwd():
    out = tbenv.simulate_command_output("cat /etc/passwd")
    assert "root:x:0:0" in out
    assert "www-data" in out


def test_simulate_command_output_unknown_empty():
    """Unknown commands return empty output rather than an error banner,
    so the response looks like a silently-run command."""
    assert tbenv.simulate_command_output("some_fake_bin --flag") == ""


def test_simulate_command_output_empty_input():
    assert tbenv.simulate_command_output("") == ""


def test_render_webshell_page_includes_form_and_command():
    html = tbenv.render_webshell_page(command="id", output="uid=33")
    assert b"<form" in html
    assert b"name='cmd'" in html
    assert b"id" in html
    assert b"uid=33" in html


def test_render_webshell_page_escapes_html():
    html = tbenv.render_webshell_page(command="<script>alert(1)</script>", output="")
    assert b"<script>" not in html
    assert b"&lt;script&gt;" in html


def test_render_webshell_page_empty_is_still_valid():
    html = tbenv.render_webshell_page()
    assert html.startswith(b"<!doctype html>")
    assert b"File Manager" in html


def test_webshell_disabled_returns_false_even_for_anchor_path(monkeypatch):
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", False)
    assert not tbenv.is_webshell_path(
        "/wp-content/plugins/hellopress/wp_filemanager.php",
    )


# --- End-to-end dispatch tests (gate behavior) ---
#
# Context: April 2026 observed a scanner (Azure WP Webshell Checker variant)
# sending ~100 probes to our env-trap host with Host=staging.<victim>.<tld>
# — a fully spoofed Host. The original host_allowed gate (inherited from
# /.env canary handling) 404'd every probe because the spoofed Host didn't
# match ALLOWED_HOSTS. The dispatch now gates webshell routing on "is this a
# trap sensor at all" (ALLOWED_HOSTS non-empty), not "does this specific
# request's Host match".


def _fake_handler(tbenv_mod, allowed_hosts: set[str]):
    """Build a minimal EnvHandler stand-in + exercise _handle."""
    import io

    class StubHeaders:
        def __init__(self, data: dict[str, str]) -> None:
            self._data = data

        def get(self, key: str, default: str = "") -> str:
            for k, v in self._data.items():
                if k.lower() == key.lower():
                    return v
            return default

        def __iter__(self):
            return iter(self._data)

        def items(self):
            return self._data.items()

    class RecordingHandler(tbenv_mod.EnvHandler):
        def __init__(self, headers: dict[str, str], path: str) -> None:
            # Skip super().__init__ — it expects a real socket.
            self.headers = StubHeaders(headers)
            self.path = path
            self.command = "GET"
            self.response_code = None
            self.response_body = b""
            self.sent_headers: list[tuple[str, str]] = []
            self.rfile = io.BytesIO(b"")
            self.wfile = io.BytesIO()
            self.client_address = ("127.0.0.1", 0)

        def send_response(self, code, message=None):
            self.response_code = code

        def send_header(self, key, val):
            self.sent_headers.append((key, val))

        def end_headers(self):
            pass

    return RecordingHandler, StubHeaders


def test_dispatch_serves_webshell_when_host_is_spoofed(monkeypatch, tmp_path):
    """Scanner with a spoofed Host header should still get the webshell
    response on a trap sensor (ALLOWED_HOSTS non-empty)."""
    monkeypatch.setattr(tbenv, "ALLOWED_HOSTS", {"trap.example.com"})
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")

    RecordingHandler, _ = _fake_handler(tbenv, tbenv.ALLOWED_HOSTS)
    h = RecordingHandler(
        headers={
            "Host": "staging.victim.example",  # spoofed
            "X-Forwarded-Host": "staging.victim.example",
            "X-Forwarded-For": "203.0.113.7",
            "X-Forwarded-Proto": "https",
        },
        path="/wp-content/plugins/hellopress/wp_filemanager.php",
    )
    h._handle(send_body=True)

    assert h.response_code == 200
    assert b"File Manager" in h.wfile.getvalue()

    log_lines = (tmp_path / "env-canary.jsonl").read_text().splitlines()
    assert len(log_lines) == 1
    import json
    entry = json.loads(log_lines[0])
    assert entry["result"] == "webshell-probe"
    assert entry["clientIp"] == "203.0.113.7"


def test_dispatch_control_sensor_with_empty_allowed_hosts_still_404s_webshell(
    monkeypatch, tmp_path,
):
    """Control sensor (no TRACEBIT_ENV_HOSTS_CSV → empty ALLOWED_HOSTS) must
    still return 404 for webshell paths even with a matching path."""
    monkeypatch.setattr(tbenv, "ALLOWED_HOSTS", set())
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")

    RecordingHandler, _ = _fake_handler(tbenv, set())
    h = RecordingHandler(
        headers={
            "Host": "example.com",
            "X-Forwarded-Host": "example.com",
            "X-Forwarded-For": "203.0.113.7",
            "X-Forwarded-Proto": "https",
        },
        path="/wp-content/plugins/hellopress/wp_filemanager.php",
    )
    h._handle(send_body=True)

    assert h.response_code == 404

    log_lines = (tmp_path / "env-canary.jsonl").read_text().splitlines()
    assert len(log_lines) == 1
    import json
    entry = json.loads(log_lines[0])
    assert entry["result"] == "not-handled"


def test_dispatch_without_tracebit_api_key_404s_env_and_git(monkeypatch, tmp_path):
    """Without a Tracebit API key, /.env and /.git/* both 404 — the handler
    must not try to issue a canary against an empty key."""
    monkeypatch.setattr(tbenv, "ALLOWED_HOSTS", {"trap.example.com"})
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")

    RecordingHandler, _ = _fake_handler(tbenv, tbenv.ALLOWED_HOSTS)
    for path in ["/.env", "/.git/HEAD", "/.git/config"]:
        h = RecordingHandler(
            headers={
                "Host": "trap.example.com",
                "X-Forwarded-Host": "trap.example.com",
                "X-Forwarded-For": "203.0.113.8",
                "X-Forwarded-Proto": "https",
            },
            path=path,
        )
        h._handle(send_body=True)
        assert h.response_code == 404, f"expected 404 for {path} without API key, got {h.response_code}"
