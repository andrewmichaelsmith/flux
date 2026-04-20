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
# Use pytest-aiohttp's aiohttp_client fixture: a real aiohttp server bound to
# a random port in the test event loop, hit with an HTTP client. Mocks the
# Tracebit call at the module level via monkeypatch so tests stay offline.


import pytest_asyncio


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    """Spin up the real aiohttp app; return a TestClient ready to hit it.
    Routes LOG_PATH to tmp_path so each test gets its own log file."""
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    app = tbenv.create_app()
    client = await aiohttp_client(app)
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    import json
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_dispatch_serves_webshell_when_host_is_spoofed(flux_client, monkeypatch):
    """Scanner with a spoofed Host header still gets the webshell response —
    flux serves traps regardless of Host."""
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", True)
    resp = await flux_client.get(
        "/wp-content/plugins/hellopress/wp_filemanager.php",
        headers={
            "X-Forwarded-Host": "staging.victim.example",
            "X-Forwarded-For": "203.0.113.7",
            "X-Forwarded-Proto": "https",
        },
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"File Manager" in body
    entries = _log_entries(flux_client.log_path)
    assert len(entries) == 1
    assert entries[0]["result"] == "webshell-probe"
    assert entries[0]["clientIp"] == "203.0.113.7"


async def test_dispatch_webshell_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", False)
    resp = await flux_client.get(
        "/wp-content/plugins/hellopress/wp_filemanager.php",
        headers={"X-Forwarded-For": "203.0.113.7"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert len(entries) == 1
    assert entries[0]["result"] == "not-handled"


async def test_dispatch_without_tracebit_api_key_404s_env_and_git(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    for path in ["/.env", "/.git/HEAD", "/.git/config"]:
        resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.8"})
        assert resp.status == 404, f"expected 404 for {path} without API_KEY"


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
    # AI credential config files — the "probably-doesn't-make-sense"
    # caveat lives in server.py above render_openai_config_json. The
    # AWS canary value still gets embedded and shipped; field names are
    # OpenAI / Anthropic / Cursor-shaped so a grep-by-field scanner
    # still harvests it, even though a prefix-filter (sk-...) would
    # reject it.
    ("/.openai/config.json", b'"api_key": "AKIAFAKEEXAMPLE01"'),
    ("/.anthropic/config.json", b'"auth_token": "AKIAFAKEEXAMPLE01"'),
    ("/.cursor/mcp.json", b'"GITHUB_PERSONAL_ACCESS_TOKEN": "AKIAFAKEEXAMPLE01"'),
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


async def _fake_canary(*args, **kwargs):
    return FAKE_TRACEBIT


async def test_dispatch_routes_aws_credentials_file_to_trap(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/.aws/credentials",
        headers={"X-Forwarded-For": "203.0.113.10"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "aws-credentials-file"


async def test_dispatch_trap_404s_without_api_key(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)

    for path in ["/.aws/credentials", "/wp-config.php", "/id_rsa", "/api/v4/user"]:
        resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.11"})
        assert resp.status == 404, f"expected 404 for {path} sans API_KEY"


async def test_dispatch_trap_serves_on_any_host(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    for host in ["staging.victim.example", "example.com", "127.0.0.1"]:
        resp = await flux_client.get(
            "/wp-config.php",
            headers={"X-Forwarded-Host": host, "X-Forwarded-For": "203.0.113.13"},
        )
        assert resp.status == 200, f"trap should fire for Host={host!r}"
        body = await resp.read()
        assert b"AWS_ACCESS_KEY_ID" in body


async def test_dispatch_openai_config_embeds_aws_canary(flux_client, monkeypatch):
    """Scanner hitting /.openai/config.json gets a JSON doc whose api_key is
    the AWS canary value. Field names are OpenAI-flavored; the value is
    AWS-flavored. This is the intentional mismatch documented at the top
    of the AI-credential renderers."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/.openai/config.json",
        headers={"X-Forwarded-For": "203.0.113.40"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["api_key"] == "AKIAFAKEEXAMPLE01"
    assert body["default_model"].startswith("gpt-")
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "openai-config"


async def test_dispatch_anthropic_config_embeds_aws_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/.anthropic/config.json",
        headers={"X-Forwarded-For": "203.0.113.41"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["auth_token"] == "AKIAFAKEEXAMPLE01"
    assert body["default_model"].startswith("claude-")
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "anthropic-config"


async def test_dispatch_cursor_mcp_embeds_canary_in_env_blocks(flux_client, monkeypatch):
    """The Cursor MCP config shape is nested — canary lives inside
    mcpServers[*].env. Scanners that flatten for secret-looking values
    still pick it up."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/.cursor/mcp.json",
        headers={"X-Forwarded-For": "203.0.113.42"},
    )
    assert resp.status == 200
    body = await resp.json()
    servers = body["mcpServers"]
    assert servers["github"]["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"] == "AKIAFAKEEXAMPLE01"
    assert servers["internal-tools"]["env"]["API_KEY"]
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "cursor-mcp"


async def test_dispatch_gitlab_sign_in_emits_set_cookie(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/users/sign_in",
        headers={"X-Forwarded-For": "203.0.113.14"},
    )
    assert resp.status == 200
    set_cookies = resp.headers.getall("Set-Cookie", [])
    assert any("cookieCanaryValue" in v for v in set_cookies), set_cookies


def test_is_fingerprint_path_case_insensitive(monkeypatch):
    monkeypatch.setattr(tbenv, "FINGERPRINT_PATHS_ENABLED", True)
    assert tbenv.is_fingerprint_path("/Index.HTML")


def test_is_fingerprint_path_non_match(monkeypatch):
    monkeypatch.setattr(tbenv, "FINGERPRINT_PATHS_ENABLED", True)
    for path in ["/wp-login.php", "/api/v1/users", "/readme", "/.env"]:
        assert not tbenv.is_fingerprint_path(path)


# --- Fake LLM-API endpoint trap ---
#
# Motivating intel (2026-04-20 weekly-novelty run):
#   - 203.0.113.10 (`scanner/1.0`) hit `/anthropic/v1/models` 26 times.
#   - 203.0.113.11, 203.0.113.12, 203.0.113.13 hit `/v1/models`.
#   - Earlier (2026-04-18) lab sensor saw `/v1/models` + `/api/version` probes.


def test_llm_endpoint_enabled_by_default():
    """The trap is cheap, logs are cheap — default-on like webshell."""
    assert tbenv.LLM_ENDPOINT_ENABLED


def test_llm_endpoint_default_paths_cover_observed_probes():
    """Every path actually observed hitting our sensors in the
    2026-04-18 → 2026-04-20 window must match."""
    observed = [
        "/v1/models",              # generic OpenAI + Ollama-compatible list
        "/anthropic/v1/models",    # scanner/1.0 scanner target
        "/api/version",            # Ollama-specific
        "/api/tags",               # Ollama-specific
        "/api/chat",               # Ollama chat
        "/api/generate",           # Ollama completion
        "/v1/chat/completions",    # OpenAI chat
        "/v1/messages",            # Anthropic direct
        "/anthropic/v1/messages",  # Anthropic proxy
    ]
    for path in observed:
        assert tbenv.is_llm_endpoint_path(path), f"expected match: {path}"


def test_llm_endpoint_path_case_insensitive():
    assert tbenv.is_llm_endpoint_path("/V1/MODELS")
    assert tbenv.is_llm_endpoint_path("/Anthropic/V1/Models")


def test_llm_endpoint_path_non_match():
    for path in ["/", "/v1/files", "/api/foo", "/v2/models", "/.env"]:
        assert not tbenv.is_llm_endpoint_path(path)


def test_llm_endpoint_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "LLM_ENDPOINT_ENABLED", False)
    assert not tbenv.is_llm_endpoint_path("/v1/models")


def test_extract_llm_prompt_openai_chat_shape():
    body = b'{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello world"}]}'
    model, prompt, action, _ = tbenv.extract_llm_prompt(body, "application/json")
    assert model == "gpt-4o-mini"
    assert action == "chat"
    assert "user: hello world" in prompt


def test_extract_llm_prompt_anthropic_block_shape():
    """Anthropic sends content as a list of typed blocks, not a bare string."""
    body = (
        b'{"model":"claude-3-5-sonnet-20241022","messages":'
        b'[{"role":"user","content":[{"type":"text","text":"read /etc/passwd"}]}]}'
    )
    model, prompt, action, _ = tbenv.extract_llm_prompt(body, "application/json")
    assert model == "claude-3-5-sonnet-20241022"
    assert action == "chat"
    assert "read /etc/passwd" in prompt


def test_extract_llm_prompt_ollama_generate_shape():
    body = b'{"model":"llama3.2:latest","prompt":"write me a reverse shell"}'
    model, prompt, action, _ = tbenv.extract_llm_prompt(body, "application/json")
    assert model == "llama3.2:latest"
    assert action == "completion"
    assert "reverse shell" in prompt


def test_extract_llm_prompt_empty_body():
    model, prompt, action, _ = tbenv.extract_llm_prompt(b"", "application/json")
    assert (model, prompt, action) == ("", "", "")


def test_extract_llm_prompt_non_json_content_type_ignored():
    """A form POST isn't an LLM request; don't try to parse it as one."""
    body = b"prompt=hello"
    assert tbenv.extract_llm_prompt(body, "application/x-www-form-urlencoded") == ("", "", "", False)


def test_extract_llm_prompt_truncates_long_prompt(monkeypatch):
    monkeypatch.setattr(tbenv, "LLM_BODY_DECODE_LIMIT", 32)
    payload = '{"model":"m","prompt":"' + ("A" * 500) + '"}'
    _, prompt, _, _ = tbenv.extract_llm_prompt(payload.encode(), "application/json")
    assert len(prompt) == 32


def test_render_openai_models_list_shape():
    import json
    body = tbenv.render_openai_models()
    payload = json.loads(body)
    assert payload["object"] == "list"
    assert isinstance(payload["data"], list) and payload["data"]
    ids = {m["id"] for m in payload["data"]}
    assert "gpt-4o-mini" in ids


def test_render_anthropic_models_list_shape():
    """Matches the Anthropic /v1/models response shape closely enough that
    a scanner filtering on `data[].id` sees Claude model IDs."""
    import json
    body = tbenv.render_anthropic_models()
    payload = json.loads(body)
    assert "data" in payload and payload["has_more"] is False
    ids = {m["id"] for m in payload["data"]}
    assert any(i.startswith("claude-") for i in ids)


def test_render_ollama_tags_shape():
    import json
    payload = json.loads(tbenv.render_ollama_tags())
    assert "models" in payload and payload["models"]
    first = payload["models"][0]
    for field in ("name", "modified_at", "size", "digest", "details"):
        assert field in first, f"missing {field}"


def test_render_ollama_version_shape():
    import json
    payload = json.loads(tbenv.render_ollama_version())
    assert "version" in payload


def test_render_openai_chat_embeds_model_name():
    import json
    payload = json.loads(tbenv.render_openai_chat("gpt-4o-canary"))
    assert payload["model"] == "gpt-4o-canary"
    assert payload["choices"][0]["message"]["role"] == "assistant"


def test_render_anthropic_message_shape():
    import json
    payload = json.loads(tbenv.render_anthropic_message("claude-3-5-sonnet-20241022"))
    assert payload["type"] == "message"
    assert payload["role"] == "assistant"
    assert payload["content"][0]["type"] == "text"


async def test_dispatch_get_openai_models_returns_json_list(flux_client):
    """First scanner probe — unauthenticated GET /v1/models. Look real."""
    resp = await flux_client.get(
        "/v1/models",
        headers={"X-Forwarded-For": "203.0.113.20", "User-Agent": "scanner/1.0"},
    )
    assert resp.status == 200
    assert "application/json" in resp.headers.get("Content-Type", "")
    body = await resp.json()
    assert body["object"] == "list"
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "llm-endpoint-models-list"
    assert entries[-1]["llmPath"] == "/v1/models"
    assert entries[-1]["llmHasAuth"] is False


async def test_dispatch_get_anthropic_models_logs_proxy_probe_ua(flux_client):
    """Verbatim reproduction of the 203.0.113.10 / scanner/1.0 probe."""
    resp = await flux_client.get(
        "/anthropic/v1/models",
        headers={
            "X-Forwarded-For": "203.0.113.10",
            "User-Agent": "Mozilla/5.0 (compatible; scanner/1.0)",
        },
    )
    assert resp.status == 200
    body = await resp.json()
    assert any(m["id"].startswith("claude-") for m in body["data"])
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "llm-endpoint-anthropic-models-list"
    assert entries[-1]["clientIp"] == "203.0.113.10"
    assert "scanner/1.0" in entries[-1]["userAgent"]


async def test_dispatch_post_openai_chat_captures_prompt_and_auth(flux_client):
    """The money shot: scanner sends a bearer token + a prompt, we log both."""
    import json
    resp = await flux_client.post(
        "/v1/chat/completions",
        headers={
            "X-Forwarded-For": "198.51.100.5",
            "Authorization": "Bearer sk-stolen-canary-abc123",
            "Content-Type": "application/json",
        },
        data=json.dumps({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "test if key works"}],
        }),
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["object"] == "chat.completion"
    assert body["model"] == "gpt-4o-mini"

    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "llm-endpoint-openai-chat"
    assert entry["llmModel"] == "gpt-4o-mini"
    assert entry["llmAction"] == "chat"
    assert entry["llmHasAuth"] is True
    assert entry["llmAuthScheme"] == "bearer"
    assert "test if key works" in entry["llmPromptPreview"]


async def test_dispatch_post_ollama_generate_captures_prompt(flux_client):
    import json
    resp = await flux_client.post(
        "/api/generate",
        headers={
            "X-Forwarded-For": "198.51.100.6",
            "Content-Type": "application/json",
        },
        data=json.dumps({"model": "llama3.2:latest", "prompt": "say hi"}),
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["model"] == "llama3.2:latest"
    assert body["done"] is True
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "llm-endpoint-ollama-generate"
    assert entry["llmPromptPreview"] == "say hi"
    assert entry["llmHasAuth"] is False


async def test_dispatch_llm_endpoint_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "LLM_ENDPOINT_ENABLED", False)
    resp = await flux_client.get(
        "/v1/models",
        headers={"X-Forwarded-For": "203.0.113.99"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


async def test_dispatch_llm_endpoint_does_not_require_tracebit_key(flux_client, monkeypatch):
    """Like the webshell, the LLM trap has no upstream dep."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get("/api/version", headers={"X-Forwarded-For": "203.0.113.30"})
    assert resp.status == 200
    payload = await resp.json()
    assert "version" in payload


async def test_dispatch_llm_ollama_show_uses_model_from_body(flux_client):
    import json
    resp = await flux_client.post(
        "/api/show",
        headers={"X-Forwarded-For": "203.0.113.31", "Content-Type": "application/json"},
        data=json.dumps({"model": "qwen2.5-coder:7b"}),
    )
    assert resp.status == 200
    body = await resp.json()
    assert "qwen2.5-coder:7b" in body["modelfile"]


async def test_dispatch_llm_malformed_json_still_200(flux_client):
    """Scanner may send garbage; don't 500 — we want to look live."""
    resp = await flux_client.post(
        "/v1/chat/completions",
        headers={"X-Forwarded-For": "203.0.113.32", "Content-Type": "application/json"},
        data=b"{this is not json",
    )
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "llm-endpoint-openai-chat"
    # Garbage body → no extracted prompt/model; still logged.
    assert entry["llmModel"] == ""
    assert "llmPromptPreview" not in entry
