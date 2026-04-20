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
# No Host-based gating — flux is a honeypot, it responds on every Host.
# The only sensor-level gate is TRACEBIT_API_KEY, which only controls the
# Tracebit-backed traps (/.env, /.git/*, canary file traps). Webshell and
# tarpit do not need a key.


def _fake_handler(tbenv_mod):
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
    """Scanner with a spoofed Host header still gets the webshell response —
    flux serves traps regardless of Host."""
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")

    RecordingHandler, _ = _fake_handler(tbenv)
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


def test_dispatch_webshell_disabled_returns_404(monkeypatch, tmp_path):
    """With WEBSHELL_ENABLED=False, webshell paths 404 instead of serving."""
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", False)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")

    RecordingHandler, _ = _fake_handler(tbenv)
    h = RecordingHandler(
        headers={
            "Host": "example.com",
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
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")

    RecordingHandler, _ = _fake_handler(tbenv)
    for path in ["/.env", "/.git/HEAD", "/.git/config"]:
        h = RecordingHandler(
            headers={
                "Host": "trap.example.com",
                "X-Forwarded-For": "203.0.113.8",
                "X-Forwarded-Proto": "https",
            },
            path=path,
        )
        h._handle(send_body=True)
        assert h.response_code == 404, f"expected 404 for {path} without API key, got {h.response_code}"


# --- Fingerprint paths ---


def test_is_fingerprint_path_defaults_match_generic_paths():
    """Fingerprinting is on by default for the built-in generic paths."""
    assert tbenv.FINGERPRINT_PATHS_ENABLED, (
        "FINGERPRINT_PATHS_ENABLED should default to True — flux is a honeypot"
    )
    for path in ["/", "/index.html", "/index.php", "/robots.txt", "/sitemap.xml", "/favicon.ico"]:
        assert tbenv.is_fingerprint_path(path), f"expected match: {path}"


def test_is_fingerprint_path_respects_explicit_disable(monkeypatch):
    monkeypatch.setattr(tbenv, "FINGERPRINT_PATHS_ENABLED", False)
    assert not tbenv.is_fingerprint_path("/")
    assert not tbenv.is_fingerprint_path("/index.html")


def test_tarpit_modules_default_on():
    """All fingerprint modules default to on. A user who explicitly disables
    one via env var still wins; the defaults just mean a fresh sensor
    already fingerprints without any extra env tuning."""
    assert tbenv.MOD_COOKIE_ENABLED
    assert tbenv.MOD_ETAG_PROBE_ENABLED
    assert tbenv.MOD_REDIRECT_CHAIN_ENABLED
    assert tbenv.MOD_VARIABLE_DRIP_ENABLED
    assert tbenv.MOD_CONTENT_LENGTH_MISMATCH_ENABLED
    # DNS callback is default-on but is a no-op unless the domain is set.
    assert tbenv.MOD_DNS_CALLBACK_ENABLED


def test_tarpit_enabled_by_default():
    assert tbenv.TARPIT_ENABLED


# --- Canary-backed file traps ---

FAKE_TRACEBIT = {
    "aws": {
        "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
        "awsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "awsSessionToken": "FwoGZXIvYXdzEXAMPLEFAKE=",
        "awsExpiration": "2030-01-01T00:00:00Z",
        "awsConfirmationId": "conf-aws-1",
    },
    "ssh": {
        "sshIp": "203.0.113.99",
        "sshPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEY\n-----END OPENSSH PRIVATE KEY-----",
        "sshPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE canary@flux",
        "sshExpiration": "2030-01-01T00:00:00Z",
        "sshConfirmationId": "conf-ssh-1",
    },
    "http": {
        "gitlab-username-password": {
            "credentials": {"username": "deploybot42", "password": "p@ssCanaryValue"},
            "hostNames": ["gitlab.canary.example"],
            "expiresAt": "2030-01-01T00:00:00Z",
            "browserDeploymentId": "bd-gup-1",
            "confirmationId": "conf-gup-1",
        },
        "gitlab-cookie": {
            "credentials": {"name": "_gitlab_session", "value": "cookieCanaryValue"},
            "hostNames": ["gitlab.canary.example"],
            "expiresAt": "2030-01-01T00:00:00Z",
            "browserDeploymentId": "bd-gc-1",
            "confirmationId": "conf-gc-1",
        },
    },
}


@pytest.mark.parametrize("path,needle", [
    ("/.aws/credentials", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/backup.sql", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/config.json", b'"access_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/firebase.json", b'"private_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/.docker/config.json", b'"auths"'),
    ("/docker-compose.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/application.properties", b"aws.access.key.id=AKIAFAKEEXAMPLE01"),
    ("/application.yml", b"access-key-id: AKIAFAKEEXAMPLE01"),
    ("/.env.production", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/phpinfo.php", b"AKIAFAKEEXAMPLE01"),
    ("/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/authorized_keys", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
    ("/.netrc", b"login deploybot42"),
    ("/.npmrc", b"p@ssCanaryValue"),
    ("/.pypirc", b"username = deploybot42"),
    ("/api/v4/user", b'"username": "deploybot42"'),
    ("/users/sign_in", b"<title>Sign in"),
])
def test_canary_trap_renderers_embed_canary(path, needle):
    trap = tbenv._TRAP_BY_PATH[path]
    body = trap.render(FAKE_TRACEBIT)
    assert needle in body, f"expected {needle!r} in rendered {path}; got {body[:200]!r}"


def test_find_canary_trap_returns_none_when_disabled(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    assert tbenv.find_canary_trap("/.aws/credentials") is None


def test_find_canary_trap_matches_case_insensitively(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    assert tbenv.find_canary_trap("/WP-Config.PHP") is not None
    assert tbenv.find_canary_trap("/.AWS/Credentials") is not None


def test_find_canary_trap_misses_non_trap_paths(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    for p in ["/", "/index.html", "/api/v4/projects", "/.env"]:
        assert tbenv.find_canary_trap(p) is None, f"unexpected match for {p}"


def test_every_trap_has_distinct_paths():
    """Catch accidental duplicates across traps (which one wins would be undefined)."""
    seen: dict[str, str] = {}
    for trap in tbenv.CANARY_TRAPS:
        for p in trap.paths:
            lp = p.lower()
            assert lp not in seen, f"{lp} claimed by both {seen[lp]} and {trap.name}"
            seen[lp] = trap.name


def test_gitlab_cookie_emits_set_cookie_header():
    """The gitlab-sign-in trap returns the gitlab-cookie canary as Set-Cookie,
    not in the body. That's how the scanner picks it up."""
    trap = tbenv._TRAP_BY_PATH["/users/sign_in"]
    headers = trap.extra_headers(FAKE_TRACEBIT)
    assert headers, "expected at least one extra header"
    names = {h[0] for h in headers}
    assert "Set-Cookie" in names
    cookie_value = next(v for k, v in headers if k == "Set-Cookie")
    assert "cookieCanaryValue" in cookie_value


def test_dispatch_routes_aws_credentials_file_to_trap(monkeypatch, tmp_path):
    """Full dispatch path — hit /.aws/credentials, see the canary in the body,
    see one JSON log line with result=aws-credentials-file."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", lambda *a, **kw: FAKE_TRACEBIT)

    RecordingHandler, _ = _fake_handler(tbenv)
    h = RecordingHandler(
        headers={
            "Host": "trap.example.com",
            "X-Forwarded-For": "203.0.113.10",
            "X-Forwarded-Proto": "https",
        },
        path="/.aws/credentials",
    )
    h._handle(send_body=True)

    assert h.response_code == 200
    assert b"AKIAFAKEEXAMPLE01" in h.wfile.getvalue()
    import json
    entry = json.loads((tmp_path / "env-canary.jsonl").read_text().splitlines()[-1])
    assert entry["result"] == "aws-credentials-file"


def test_dispatch_trap_404s_without_api_key(monkeypatch, tmp_path):
    """Every canary trap requires API_KEY — no key → 404."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")

    RecordingHandler, _ = _fake_handler(tbenv)
    for path in ["/.aws/credentials", "/wp-config.php", "/id_rsa", "/api/v4/user"]:
        h = RecordingHandler(
            headers={
                "Host": "trap.example.com",
                "X-Forwarded-For": "203.0.113.11",
                "X-Forwarded-Proto": "https",
            },
            path=path,
        )
        h._handle(send_body=True)
        assert h.response_code == 404, f"expected 404 for {path} sans API_KEY"


def test_dispatch_trap_serves_on_any_host(monkeypatch, tmp_path):
    """No Host-based gating — traps respond whatever the Host header says."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", lambda *a, **kw: FAKE_TRACEBIT)

    RecordingHandler, _ = _fake_handler(tbenv)
    for host in ["staging.victim.example", "example.com", "", "123.45.67.8"]:
        h = RecordingHandler(
            headers={
                "Host": host,
                "X-Forwarded-For": "203.0.113.13",
                "X-Forwarded-Proto": "https",
            },
            path="/wp-config.php",
        )
        h._handle(send_body=True)
        assert h.response_code == 200, f"trap should fire for Host={host!r}"
        assert b"AWS_ACCESS_KEY_ID" in h.wfile.getvalue()


def test_dispatch_gitlab_sign_in_emits_set_cookie(monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", lambda *a, **kw: FAKE_TRACEBIT)

    RecordingHandler, _ = _fake_handler(tbenv)
    h = RecordingHandler(
        headers={
            "Host": "trap.example.com",
            "X-Forwarded-For": "203.0.113.14",
            "X-Forwarded-Proto": "https",
        },
        path="/users/sign_in",
    )
    h._handle(send_body=True)
    assert h.response_code == 200
    set_cookies = [v for k, v in h.sent_headers if k == "Set-Cookie"]
    assert any("cookieCanaryValue" in v for v in set_cookies), set_cookies


def test_is_fingerprint_path_case_insensitive(monkeypatch):
    monkeypatch.setattr(tbenv, "FINGERPRINT_PATHS_ENABLED", True)
    assert tbenv.is_fingerprint_path("/Index.HTML")


def test_is_fingerprint_path_non_match(monkeypatch):
    monkeypatch.setattr(tbenv, "FINGERPRINT_PATHS_ENABLED", True)
    for path in ["/wp-login.php", "/api/v1/users", "/readme", "/.env"]:
        assert not tbenv.is_fingerprint_path(path)
