"""Tests for flux.server."""
from __future__ import annotations

import base64
import json

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


def test_webshell_path_regexes_match_well_known_php_shells():
    """The /.well-known/<name>.php pattern is used as a shell-drop directory
    (writable by the certbot user on many LAMP boxes). Scanners probe a rotating
    set of filenames there."""
    for path in [
        "/.well-known/rk2.php",
        "/.well-known/gecko-litespeed.php",
        "/.well-known/admin.php",
        "/.well-known/error.php",
        "/.well-known/index.php",
        "/.WELL-KNOWN/RK2.PHP",
    ]:
        assert tbenv.is_webshell_path(path), f"expected match: {path}"


def test_webshell_regex_excludes_well_known_acme_challenge():
    """nginx routes /.well-known/acme-challenge/ to the LE webroot, not flux,
    but even if it did hit flux we shouldn't trap on it — legit cert renewals
    would fire the shell dispatch path. The regex only matches <name>.php, not
    subdirectory tokens."""
    assert not tbenv.is_webshell_path("/.well-known/acme-challenge/")
    assert not tbenv.is_webshell_path("/.well-known/acme-challenge/abc123")


def test_webshell_regex_matches_numbered_trash_directories():
    """Numbered /.trash<N>/ and /.tmb/ staging paths are a specific malware
    family's shell-drop convention."""
    for path in [
        "/.trash7206/index.php",
        "/.trash7309/f/",
        "/.trash99/",
        "/.tmb/shell.php",
        "/.tresh/index.php",
        "/.dj/index.php",
        "/.alf/index.php",
        "/.mopj.php",
        "/.info.php",
    ]:
        assert tbenv.is_webshell_path(path), f"expected match: {path}"


def test_webshell_regex_rejects_benign_hidden_dirs():
    """Dot-directories we do NOT want to snag (other canary traps own some of
    these, and legitimate framework paths use others)."""
    for path in [
        "/.env",
        "/.git/HEAD",
        "/.ssh/authorized_keys",
        "/.aws/credentials",
        "/.well-known/openid-configuration",   # standards-defined non-.php
        "/.trash",                              # bare name, no numbered dir
    ]:
        assert not tbenv.is_webshell_path(path), f"unexpected match: {path}"


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


def test_all_trap_families_default_on():
    """Every trap master-switch defaults to on — flux is a honeypot, the
    whole point is to run every trap that's cheap to run. Deployments that
    lack TRACEBIT_API_KEY still 404 the canary-backed traps (/.env,
    /.git/*, canary file table) at dispatch time."""
    assert tbenv.TARPIT_ENABLED
    assert tbenv.FINGERPRINT_PATHS_ENABLED
    assert tbenv.CANARY_TRAPS_ENABLED
    assert tbenv.FAKE_GIT_ENABLED, (
        "FAKE_GIT_ENABLED should default to True — the per-IP cache bounds "
        "quota burn and the dispatch still requires TRACEBIT_API_KEY."
    )
    assert tbenv.WEBSHELL_ENABLED
    assert tbenv.LLM_ENDPOINT_ENABLED
    assert tbenv.SONICWALL_ENABLED
    assert tbenv.CISCO_WEBVPN_ENABLED
    assert tbenv.GEOSERVER_ENABLED


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
    ("/.aws/config", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/.pgpass", b":deploybot42:p@ssCanaryValue"),
    ("/.claude/.credentials.json", b'"accessToken": "AKIAFAKEEXAMPLE01"'),
    ("/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/backup.sql", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/config.json", b'"access_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/firebase.json", b'"private_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/.docker/config.json", b'"auths"'),
    ("/docker-compose.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.prod.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.production.yaml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.staging.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.override.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/actuator/env", b'"AWS_ACCESS_KEY_ID"'),
    ("/actuator/env", b'"value": "AKIAFAKEEXAMPLE01"'),
    ("/env", b'"activeProfiles"'),
    ("/manage/env", b'"activeProfiles"'),
    ("/management/env", b"applicationConfig"),
    ("/api/actuator/env", b"applicationConfig"),
    ("/application.properties", b"aws.access.key.id=AKIAFAKEEXAMPLE01"),
    ("/application.yml", b"access-key-id: AKIAFAKEEXAMPLE01"),
    ("/.env.production", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/phpinfo.php", b"AKIAFAKEEXAMPLE01"),
    ("/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_ed25519", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_dsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/root/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/home/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/authorized_keys", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
    ("/.ssh/authorized_keys2", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
    ("/static/.ssh/authorized_keys", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
    # The config + known_hosts traps are the other half of the IP↔key
    # pairing — without them, a harvested /id_rsa has no target to
    # replay against, so the canary can't fire.
    ("/.ssh/config", b"HostName 203.0.113.99"),
    ("/.ssh/config", b"IdentityFile ~/.ssh/id_rsa"),
    ("/.ssh/known_hosts", b"203.0.113.99 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
    ("/known_hosts", b"203.0.113.99 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
    ("/.netrc", b"login deploybot42"),
    ("/.git-credentials", b"https://deploybot42:"),
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


@pytest.mark.parametrize("path", [
    "/wp-config.php",
    "/application.properties",
    "/application.yml",
    "/.env.production",
    "/phpinfo.php",
])
def test_canary_trap_renderers_do_not_embed_fixed_password_literal(path):
    # Regression: the ``h6T!9pq2Wz@LmRnV`` / ``prod_rw`` DB-password literal
    # that used to be baked into these renderers acted as a cross-sensor
    # fingerprint — a scanner pulling /wp-config.php and /application.yml from
    # different hosts could confirm they were the same honeypot operator by
    # matching on the shared literal. DB-cred canaries aren't a thing in
    # Tracebit Community today (gitlab-username-password only fires against the
    # specific hosted gitlab URL, not arbitrary MySQL/Postgres endpoints), so
    # we substitute a per-hit random value instead. Assert the old literal is
    # gone AND that two renders produce different passwords.
    trap = tbenv._TRAP_BY_PATH[path]
    body_1 = trap.render(FAKE_TRACEBIT)
    body_2 = trap.render(FAKE_TRACEBIT)
    for fingerprint in (b"h6T!9pq2Wz@LmRnV", b"h6T!9pq2Wz"):
        assert fingerprint not in body_1, f"{path!r} still embeds fixed DB password literal"
    # Passwords generated from secrets.token_urlsafe(16) are ~22 chars — the
    # rendered bodies should differ somewhere. (Same AWS canary mock is used
    # for both, so anything that varies is necessarily the DB password.)
    assert body_1 != body_2, f"{path!r} renders identically across calls — password not randomized"


def test_ssh_config_and_known_hosts_return_empty_when_ssh_missing():
    # If Tracebit didn't return an ssh block (e.g. the handler was asked
    # for aws-only by mistake), the config/known_hosts traps must render
    # an empty body rather than spraying a truncated IdentityFile stub or
    # a bare ``ssh-ed25519 AAAA`` line with no host.
    for r in ({"aws": {}}, {}, {"ssh": None}, {"ssh": {}}):
        assert tbenv.render_ssh_config(r) == b""
        assert tbenv.render_known_hosts(r) == b""


def test_ssh_renderers_base64_decode_tracebit_values():
    # Tracebit Community returns sshPrivateKey / sshPublicKey as base64
    # over the on-wire JSON. If flux serves the base64 verbatim on /id_rsa
    # an attacker running `ssh -i stolen_id_rsa` gets "invalid format" and
    # the canary never fires — which matches the dashboard reality of ~5
    # SSH canaries ever issued despite ~700 SSH-path hits/30d. Lock in the
    # decode so a future edit can't silently regress it.
    real_priv = "-----BEGIN OPENSSH PRIVATE KEY-----\nABC123\n-----END OPENSSH PRIVATE KEY-----\n"
    real_pub = "ssh-ed25519 AAAAC3Nza... canary@flux\n"
    response = {
        "ssh": {
            "sshPrivateKey": base64.b64encode(real_priv.encode()).decode(),
            "sshPublicKey": base64.b64encode(real_pub.encode()).decode(),
        },
    }
    assert tbenv.render_ssh_private_key(response).startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    assert tbenv.render_ssh_public_key(response).startswith(b"ssh-ed25519 ")
    assert b"ssh-ed25519 " in tbenv.render_authorized_keys(response)
    # ``format_env_payload`` deliberately names its env var ``_B64`` and
    # ships the raw base64 — scanners that exfil the line can decode it
    # themselves, and we don't want to double-decode.
    env_body = tbenv.format_env_payload(response)
    assert f"SSH_PRIVATE_KEY_B64={response['ssh']['sshPrivateKey']}" in env_body


def test_ssh_renderers_fallback_when_value_is_raw_pem():
    # Defensive: if the upstream format ever flips back to raw PEM
    # (or the fixture in tests passes PEM, as some older tests do), a
    # PEM string isn't valid base64 — the decoder falls through to the
    # raw value rather than exploding.
    response = {
        "ssh": {
            "sshPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEY\n-----END OPENSSH PRIVATE KEY-----",
            "sshPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE canary@flux",
        },
    }
    assert b"BEGIN OPENSSH PRIVATE KEY" in tbenv.render_ssh_private_key(response)
    assert b"ssh-ed25519 AAAA" in tbenv.render_ssh_public_key(response)
    assert b"ssh-ed25519 AAAA" in tbenv.render_authorized_keys(response)


def test_render_env_production_database_url_is_parseable():
    # The DB password is random per hit and gets inlined into a postgres://
    # userinfo component. It must stay parseable so the rendered .env is
    # credible — secrets.token_urlsafe uses only [A-Za-z0-9_-], none of
    # which need percent-encoding inside URL userinfo.
    from urllib.parse import urlsplit
    body = tbenv.render_env_production(FAKE_TRACEBIT).decode("utf-8")
    db_line = next(line for line in body.splitlines() if line.startswith("DATABASE_URL="))
    parsed = urlsplit(db_line.split("=", 1)[1])
    assert parsed.scheme == "postgresql"
    assert parsed.username == "prod_rw"
    assert parsed.password  # non-empty
    assert parsed.hostname == "db.internal"


def test_render_actuator_env_json_is_valid_and_per_hit_unique():
    # The actuator /env response MUST parse as JSON (scanners filter on shape)
    # and MUST embed a per-hit DB password — a fixed literal would fingerprint
    # every sensor identically (see the README "per-hit and Tracebit-backed"
    # design principle).
    body1 = tbenv.render_actuator_env_json(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body1)
    assert payload["activeProfiles"] == ["production"]
    sources = {s["name"]: s for s in payload["propertySources"]}
    assert "systemEnvironment" in sources
    assert sources["systemEnvironment"]["properties"]["AWS_ACCESS_KEY_ID"]["value"] \
        == "AKIAFAKEEXAMPLE01"
    app_source = next(s for name, s in sources.items() if name.startswith("applicationConfig"))
    pw1 = app_source["properties"]["spring.datasource.password"]["value"]
    assert pw1, "password must not be empty"
    # Second call mints a new synthetic password — never reused.
    body2 = tbenv.render_actuator_env_json(FAKE_TRACEBIT).decode("utf-8")
    pw2 = json.loads(body2)["propertySources"][2]["properties"]["spring.datasource.password"]["value"]
    assert pw1 != pw2


def test_default_canary_types_includes_gitlab_username_password():
    # /.env bare handler uses CANARY_TYPES when the caller doesn't pass an
    # explicit list. Default should request both aws (fires globally via
    # STS) and gitlab-username-password (fires against the Tracebit-hosted
    # gitlab URL, which format_env_payload emits alongside the creds).
    # Previously default was just ["aws"], which is why the canary dashboard
    # showed ~99% AWS even though the other types cost nothing extra to request.
    import importlib
    module = importlib.reload(tbenv)
    try:
        assert "aws" in module.CANARY_TYPES
        assert "gitlab-username-password" in module.CANARY_TYPES
    finally:
        importlib.reload(tbenv)


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
# Covers the path set scanner fleets were observed probing in April 2026
# across Ollama-native, OpenAI-compatible, and corporate AI-proxy shapes.


def test_llm_endpoint_enabled_by_default():
    """The trap is cheap, logs are cheap — default-on like webshell."""
    assert tbenv.LLM_ENDPOINT_ENABLED


def test_llm_endpoint_default_paths_cover_observed_probes():
    """Every path observed hitting our sensors in the April 2026
    AI-endpoint-probe window must match."""
    observed = [
        "/v1/models",              # generic OpenAI + Ollama-compatible list
        "/anthropic/v1/models",    # corporate AI-proxy target
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


async def test_dispatch_get_anthropic_models_logs_proxy_probe(flux_client):
    """GET /anthropic/v1/models from a scanner UA — the corporate AI-proxy
    probe shape. Logs the client IP and UA so follow-up probes can be linked."""
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


# --- Fake SonicWall SSL VPN trap ---
#
# Two overlapping behaviour patterns observed in mid-April 2026:
#   - A dedicated SonicWall-precondition fleet hitting only
#     `/api/sonicos/is-sslvpn-enabled`.
#   - A broader enterprise-appliance probe running the full chain
#     `is-sslvpn-enabled` → `auth` → `tfa` on every target.


def test_sonicwall_enabled_by_default():
    assert tbenv.SONICWALL_ENABLED
    assert tbenv.CISCO_WEBVPN_ENABLED


def test_sonicwall_default_paths_cover_cve_2024_53704_chain():
    """Every path in the observed CVE-2024-53704 bait sequence must match."""
    for path in (
        "/api/sonicos/is-sslvpn-enabled",
        "/api/sonicos/auth",
        "/api/sonicos/tfa",
    ):
        assert tbenv.is_sonicwall_path(path), f"expected match: {path}"


def test_sonicwall_path_is_case_insensitive():
    assert tbenv.is_sonicwall_path("/API/SonicOS/Auth")


def test_sonicwall_path_non_match():
    for path in ["/", "/api/sonicos", "/api/sonicos/other", "/.env", "/sonicos/auth"]:
        assert not tbenv.is_sonicwall_path(path)


def test_sonicwall_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "SONICWALL_ENABLED", False)
    assert not tbenv.is_sonicwall_path("/api/sonicos/is-sslvpn-enabled")


def test_extract_sonicwall_username_json():
    body = b'{"user":"admin","password":"guess"}'
    assert tbenv.extract_sonicwall_username(body, "application/json") == "admin"


def test_extract_sonicwall_username_form():
    body = b"user=root&password=guess"
    assert tbenv.extract_sonicwall_username(body, "application/x-www-form-urlencoded") == "root"


def test_extract_sonicwall_username_alternate_keys():
    assert tbenv.extract_sonicwall_username(b'{"username":"u1"}', "application/json") == "u1"
    assert tbenv.extract_sonicwall_username(b'{"login":"u2"}', "application/json") == "u2"


def test_extract_sonicwall_username_empty_body():
    assert tbenv.extract_sonicwall_username(b"", "application/json") == ""


def test_extract_sonicwall_username_malformed_json():
    assert tbenv.extract_sonicwall_username(b"{not json", "application/json") == ""


def test_render_sonicwall_is_sslvpn_enabled_shape():
    import json
    payload = json.loads(tbenv.render_sonicwall_is_sslvpn_enabled())
    assert payload["is_ssl_vpn_enabled"] is True
    assert payload["status"]["success"] is True


def test_render_sonicwall_auth_success_embeds_session_id():
    import json
    payload = json.loads(tbenv.render_sonicwall_auth_success("sess-abc"))
    assert payload["auth"]["session_id"] == "sess-abc"
    assert payload["auth"]["tfa_required"] is True
    assert payload["status"]["success"] is True


def test_render_sonicwall_tfa_success_clears_tfa_required():
    import json
    payload = json.loads(tbenv.render_sonicwall_tfa_success("sess-xyz"))
    assert payload["auth"]["session_id"] == "sess-xyz"
    assert payload["auth"]["tfa_required"] is False


async def test_dispatch_sonicwall_is_sslvpn_enabled_returns_true(flux_client):
    """CVE-2024-53704 step 1: the precondition check. Scanner wants a 200 +
    boolean true to proceed to the auth POST."""
    resp = await flux_client.get(
        "/api/sonicos/is-sslvpn-enabled",
        headers={"X-Forwarded-For": "203.0.113.20", "User-Agent": "scanner/1.0"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["is_ssl_vpn_enabled"] is True

    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "sonicwall-is-sslvpn-enabled"
    assert entry["sonicwallPath"] == "/api/sonicos/is-sslvpn-enabled"
    assert entry["sonicwallMethod"] == "GET"
    assert entry["clientIp"] == "203.0.113.20"


async def test_dispatch_sonicwall_auth_post_captures_username_and_body(flux_client):
    """The money shot: scanner POSTs credentials, we log the username and
    the full body hash for post-hoc replay analysis."""
    import json
    resp = await flux_client.post(
        "/api/sonicos/auth",
        headers={
            "X-Forwarded-For": "203.0.113.21",
            "Content-Type": "application/json",
        },
        data=json.dumps({"user": "admin", "password": "admin"}),
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["status"]["success"] is True
    assert body["auth"]["tfa_required"] is True
    assert body["auth"]["session_id"]

    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "sonicwall-auth"
    assert entry["sonicwallUsername"] == "admin"
    assert entry["sonicwallMethod"] == "POST"
    assert entry["bodySha256"]
    assert "admin" in entry["bodyPreview"]
    assert "password" in entry["bodyPreview"]


async def test_dispatch_sonicwall_tfa_post_captures_payload(flux_client):
    """Step 3 of the chain: TFA bypass. Log whatever the scanner sends."""
    import json
    resp = await flux_client.post(
        "/api/sonicos/tfa",
        headers={
            "X-Forwarded-For": "203.0.113.21",
            "Content-Type": "application/json",
        },
        data=json.dumps({"code": "000000", "session_id": "replayed"}),
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["auth"]["tfa_required"] is False

    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "sonicwall-tfa"
    assert "000000" in entry["bodyPreview"]


async def test_dispatch_sonicwall_form_body_username(flux_client):
    """Some SonicOS clients send x-www-form-urlencoded instead of JSON."""
    resp = await flux_client.post(
        "/api/sonicos/auth",
        headers={
            "X-Forwarded-For": "203.0.113.40",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data="user=root&password=abc",
    )
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["sonicwallUsername"] == "root"


async def test_dispatch_sonicwall_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "SONICWALL_ENABLED", False)
    resp = await flux_client.get(
        "/api/sonicos/is-sslvpn-enabled",
        headers={"X-Forwarded-For": "203.0.113.41"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


async def test_dispatch_sonicwall_does_not_require_tracebit_key(flux_client, monkeypatch):
    """Like webshell/LLM, no upstream dep — the intel is the probe itself."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/api/sonicos/is-sslvpn-enabled",
        headers={"X-Forwarded-For": "203.0.113.42"},
    )
    assert resp.status == 200


async def test_dispatch_sonicwall_detects_session_cookie(flux_client):
    """If a scanner replays a harvested SonicOS session cookie, flag it —
    that's a stronger compromise signal than a cold probe."""
    resp = await flux_client.get(
        "/api/sonicos/is-sslvpn-enabled",
        headers={
            "X-Forwarded-For": "203.0.113.43",
            "Cookie": "swap_session=stolen-abc; other=x",
        },
    )
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["sonicwallHasAuth"] is True


async def test_dispatch_sonicwall_malformed_json_still_200(flux_client):
    """Scanner may send garbage; don't 500."""
    resp = await flux_client.post(
        "/api/sonicos/auth",
        headers={"X-Forwarded-For": "203.0.113.44", "Content-Type": "application/json"},
        data=b"{broken",
    )
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "sonicwall-auth"
    assert entry["sonicwallUsername"] == ""


# --- Fake Cisco WebVPN trap ---


def test_cisco_webvpn_enabled_by_default():
    assert tbenv.CISCO_WEBVPN_ENABLED


def test_cisco_webvpn_default_paths_match_observed_sequence():
    for path in (
        "/+CSCOE+/logon.html",
        "/+CSCOE+/logon_forms.js",
        "/+CSCOL+/Java.jar",
        "/+CSCOL+/a1.jar",
    ):
        assert tbenv.is_cisco_webvpn_path(path), f"expected match: {path}"


def test_cisco_webvpn_path_non_match():
    for path in ["/", "/+CSCOE+/", "/+CSCOE+/logon.php", "/+CSCOL+/", "/.env"]:
        assert not tbenv.is_cisco_webvpn_path(path)


def test_cisco_webvpn_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "CISCO_WEBVPN_ENABLED", False)
    assert not tbenv.is_cisco_webvpn_path("/+CSCOE+/logon.html")


def test_render_cisco_webvpn_logon_forms_js_shape():
    body = tbenv.render_cisco_webvpn_logon_forms_js().decode("utf-8")
    assert "window.webvpn" in body


async def test_dispatch_cisco_webvpn_logon_html(flux_client):
    resp = await flux_client.get(
        "/+CSCOE+/logon.html",
        headers={"X-Forwarded-For": "203.0.113.51", "Host": "vpn.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Secure Access SSL VPN" in text
    assert "/+CSCOE+/logon_forms.js" in text

    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "cisco-webvpn-logon"
    assert entry["ciscoWebvpnPath"] == "/+CSCOE+/logon.html"


async def test_dispatch_cisco_webvpn_jar(flux_client):
    resp = await flux_client.get("/+CSCOL+/Java.jar", headers={"X-Forwarded-For": "203.0.113.52"})
    assert resp.status == 200
    body = await resp.read()
    assert body.startswith(b"PK")

    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "cisco-webvpn-java-jar"


async def test_dispatch_cisco_webvpn_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CISCO_WEBVPN_ENABLED", False)
    resp = await flux_client.get("/+CSCOE+/logon.html", headers={"X-Forwarded-For": "203.0.113.53"})
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- GeoServer trap (CVE-2024-36401 bait) ---


def test_geoserver_enabled_by_default():
    assert tbenv.GEOSERVER_ENABLED


def test_is_geoserver_path_match():
    for path in (
        "/geoserver",
        "/geoserver/",
        "/geoserver/web/",
        "/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage",
        "/geoserver/index.html",
        "/geoserver/ows",
        "/geoserver/wfs",
        "/geoserver/rest/workspaces",
        "/GeoServer/Web/",  # case-insensitive
    ):
        assert tbenv.is_geoserver_path(path), f"expected match: {path}"


def test_is_geoserver_path_non_match():
    for path in [
        "/",
        "/.env",
        "/admin/",
        "/geo",
        "/geoserveradmin",  # no trailing slash, not /geoserver itself
        "/wp-admin/",
    ]:
        assert not tbenv.is_geoserver_path(path), f"unexpected match: {path}"


def test_is_geoserver_path_disabled(monkeypatch):
    monkeypatch.setattr(tbenv, "GEOSERVER_ENABLED", False)
    assert not tbenv.is_geoserver_path("/geoserver/web/")


def test_geoserver_has_ognl_detects_runtime():
    assert tbenv._geoserver_has_ognl(
        "service=wfs&exec(Runtime.getRuntime", ""
    )
    assert tbenv._geoserver_has_ognl(
        "", '<wfs:Query><Filter><PropertyName>exec(Runtime.getRuntime().exec("id"))</PropertyName></Filter></wfs:Query>'
    )
    assert tbenv._geoserver_has_ognl(
        "evaluateProperty=foo", ""
    )


def test_geoserver_has_ognl_clean_returns_false():
    assert not tbenv._geoserver_has_ognl("service=wfs&request=GetCapabilities", "")
    assert not tbenv._geoserver_has_ognl("", "<Query>boring</Query>")


def test_render_geoserver_landing_includes_login_and_version():
    body = tbenv.render_geoserver_landing("victim.example", "2.25.1").decode("utf-8")
    assert "GeoServer" in body
    assert "2.25.1" in body
    assert "/geoserver/j_spring_security_check" in body
    assert "AboutGeoServerPage" in body


def test_render_geoserver_about_includes_version():
    body = tbenv.render_geoserver_about("h", "2.25.1").decode("utf-8")
    assert "About GeoServer" in body
    assert "2.25.1" in body


def test_render_geoserver_capabilities_xml_root_matches_service():
    body = tbenv.render_geoserver_capabilities("wms", "2.25.1").decode("utf-8")
    assert "<WMS_Capabilities" in body
    assert "</WMS_Capabilities>" in body


async def test_dispatch_geoserver_root_redirects(flux_client):
    resp = await flux_client.get(
        "/geoserver/",
        headers={"X-Forwarded-For": "203.0.113.61", "Host": "victim.example"},
        allow_redirects=False,
    )
    assert resp.status == 302
    assert resp.headers["Location"] == "/geoserver/web/"
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "geoserver-redirect-root"
    assert entry["geoserverPath"] == "/geoserver/"


async def test_dispatch_geoserver_web_landing(flux_client):
    resp = await flux_client.get(
        "/geoserver/web/",
        headers={"X-Forwarded-For": "203.0.113.62", "Host": "victim.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "GeoServer" in text
    assert "Login" in text
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "geoserver-web-landing"
    assert entry["geoserverHasOgnl"] is False


async def test_dispatch_geoserver_about_page_logs_ognl_payload(flux_client):
    # AboutGeoServerPage is the CVE-2024-36401 trigger surface; an OGNL-bearing
    # query must flip geoserverHasOgnl and capture the payload preview.
    resp = await flux_client.get(
        "/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage"
        "?evaluateProperty=exec(Runtime.getRuntime().exec(%22id%22))",
        headers={"X-Forwarded-For": "203.0.113.63"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "About GeoServer" in text
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "geoserver-about-page"
    assert entry["geoserverHasOgnl"] is True
    assert "geoserverPayloadPreview" in entry


async def test_dispatch_geoserver_ows_capabilities(flux_client):
    resp = await flux_client.get(
        "/geoserver/ows?service=wfs&version=2.0.0&request=GetCapabilities",
        headers={"X-Forwarded-For": "203.0.113.64"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<WFS_Capabilities" in text
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "geoserver-ogc-wfs"


async def test_dispatch_geoserver_rest_returns_401(flux_client):
    resp = await flux_client.get(
        "/geoserver/rest/workspaces",
        headers={"X-Forwarded-For": "203.0.113.65"},
    )
    assert resp.status == 401
    assert resp.headers.get("WWW-Authenticate", "").startswith("Basic ")
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "geoserver-rest-401"


async def test_dispatch_geoserver_post_body_logs_ognl(flux_client):
    body = (
        b'<wfs:GetPropertyValue xmlns:wfs="http://www.opengis.net/wfs/2.0">'
        b'<valueReference>exec(Runtime.getRuntime().exec(\'id\'))</valueReference>'
        b'</wfs:GetPropertyValue>'
    )
    resp = await flux_client.post(
        "/geoserver/wfs",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.66",
            "Content-Type": "application/xml",
        },
    )
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "geoserver-ogc-wfs"
    assert entry["geoserverHasOgnl"] is True


async def test_dispatch_geoserver_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "GEOSERVER_ENABLED", False)
    resp = await flux_client.get(
        "/geoserver/web/", headers={"X-Forwarded-For": "203.0.113.67"}
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"



# --- _env_bool: explicit env var parsing ---


def test_env_bool_reads_truthy_string(monkeypatch):
    """Explicit env values are honored; defaults are overridden."""
    monkeypatch.setenv("FLUX_TEST_BOOL", "YES")
    assert tbenv._env_bool("FLUX_TEST_BOOL", default=False) is True
    monkeypatch.setenv("FLUX_TEST_BOOL", "nope")
    assert tbenv._env_bool("FLUX_TEST_BOOL", default=True) is False
    monkeypatch.delenv("FLUX_TEST_BOOL", raising=False)
    assert tbenv._env_bool("FLUX_TEST_BOOL", default=True) is True


# --- Pure LLM renderers ---


def test_render_ollama_chat_shape():
    import json
    payload = json.loads(tbenv.render_ollama_chat("llama3.1:8b"))
    assert payload["model"] == "llama3.1:8b"
    assert payload["done"] is True
    assert payload["message"]["role"] == "assistant"
    assert payload["message"]["content"]


def test_render_ollama_chat_defaults_model():
    import json
    payload = json.loads(tbenv.render_ollama_chat(""))
    assert payload["model"]  # non-empty default


def test_render_ollama_generate_shape():
    import json
    payload = json.loads(tbenv.render_ollama_generate("mistral:7b"))
    assert payload["model"] == "mistral:7b"
    assert payload["done"] is True
    assert payload["response"]


def test_render_openai_completion_shape():
    import json
    payload = json.loads(tbenv.render_openai_completion("gpt-4o"))
    assert payload["object"] == "text_completion"
    assert payload["model"] == "gpt-4o"
    assert payload["choices"][0]["text"]
    assert payload["choices"][0]["finish_reason"] == "stop"


def test_render_openai_embedding_shape():
    import json
    payload = json.loads(tbenv.render_openai_embedding(""))
    assert payload["object"] == "list"
    assert payload["model"]  # default populated
    assert isinstance(payload["data"][0]["embedding"], list)
    assert all(isinstance(v, (int, float)) for v in payload["data"][0]["embedding"])


def test_render_ollama_ps_shape():
    import json
    payload = json.loads(tbenv.render_ollama_ps())
    assert payload == {"models": []}


# --- extract_llm_prompt: edge shapes ---


def test_extract_llm_prompt_embedding_list_input():
    model, prompt, action, has_auth = tbenv.extract_llm_prompt(
        b'{"model":"text-embedding-3-small","input":["hello","world"]}',
        "application/json",
    )
    assert model == "text-embedding-3-small"
    assert action == "embedding"
    assert "hello" in prompt and "world" in prompt
    assert has_auth is False


def test_extract_llm_prompt_embedding_scalar_input():
    _, prompt, action, _ = tbenv.extract_llm_prompt(
        b'{"model":"text-embedding-3-small","input":42}',
        "application/json",
    )
    assert action == "embedding"
    assert prompt == "42"


def test_extract_llm_prompt_messages_skips_non_dict_entries():
    _, prompt, action, _ = tbenv.extract_llm_prompt(
        b'{"model":"gpt-4o","messages":[null,{"role":"user","content":"hi"}]}',
        "application/json",
    )
    assert action == "chat"
    assert "hi" in prompt


def test_extract_llm_prompt_messages_coerces_non_string_content():
    _, prompt, action, _ = tbenv.extract_llm_prompt(
        b'{"model":"gpt-4o","messages":[{"role":"user","content":7}]}',
        "application/json",
    )
    assert action == "chat"
    assert "7" in prompt


# --- simulate_command_output: remaining branches ---


def test_simulate_command_output_hostname():
    assert tbenv.simulate_command_output("hostname") == "web-01\n"


def test_simulate_command_output_pwd():
    assert tbenv.simulate_command_output("pwd").startswith("/var/www/html")


def test_simulate_command_output_ls():
    assert "wp_filemanager.php" in tbenv.simulate_command_output("ls")


def test_simulate_command_output_w_who():
    assert tbenv.simulate_command_output("who") == "\n"


# --- parse_cookies: malformed parts ---


def test_parse_cookies_skips_malformed_parts():
    result = tbenv.parse_cookies("; good=1; bad; another=2")
    assert result == {"good": "1", "another": "2"}


# --- _parse_chain_params ---


def test_parse_chain_params_extracts_both():
    assert tbenv._parse_chain_params("_hp_chain=abc&_hp_hop=3") == ("abc", 3)


def test_parse_chain_params_empty():
    assert tbenv._parse_chain_params("") == ("", 0)


def test_parse_chain_params_non_integer_hop_silently_zero():
    # Malformed hop must not raise — scanners send junk.
    assert tbenv._parse_chain_params("_hp_chain=abc&_hp_hop=xyz") == ("abc", 0)


def test_parse_chain_params_ignores_unrelated_and_keyless_parts():
    assert tbenv._parse_chain_params("foo=bar&keyless&_hp_chain=cid") == ("cid", 0)


# --- Tarpit modules (pure classes) ---


class _Ctx:
    """Minimal stand-in for a tarpit ctx dict in augment-only tests."""


def _log_ctx():
    return {"clientIp": "203.0.113.5", "path": "/", "host": "", "query": ""}


def test_cookie_tracking_augment_sets_cookie_and_records_returned_tid():
    mod = tbenv.CookieTrackingModule()

    class FakeReq:
        headers = {"Cookie": "_hp_tid=prev-id; foo=bar"}

    headers, meta = mod.augment(FakeReq(), {"log_context": _log_ctx(), "path": "/"})
    assert "_hp_tid=" in headers["Set-Cookie"]
    assert "HttpOnly" in headers["Set-Cookie"]
    assert meta["cookieReturned"] == "prev-id"
    assert meta["cookieId"]  # fresh per-request id


def test_cookie_tracking_augment_first_visit_has_no_returned_tid():
    mod = tbenv.CookieTrackingModule()

    class FakeReq:
        headers = {"Cookie": ""}

    _, meta = mod.augment(FakeReq(), {})
    assert "cookieReturned" not in meta
    assert meta["cookieId"]


def test_etag_probe_augment_no_conditional_headers():
    mod = tbenv.ETagProbeModule()

    class FakeReq:
        headers = {}

    headers, meta = mod.augment(FakeReq(), {"request_id": "req-abc"})
    assert headers["ETag"] == '"req-abc"'
    assert headers["Last-Modified"]
    assert meta["etag"] == '"req-abc"'
    assert "conditionalRequest" not in meta


def test_etag_probe_augment_records_if_none_match_and_if_modified_since():
    mod = tbenv.ETagProbeModule()

    class FakeReq:
        headers = {
            "If-None-Match": '"prev"',
            "If-Modified-Since": "Mon, 01 Jan 2024 00:00:00 GMT",
        }

    _, meta = mod.augment(FakeReq(), {"request_id": "x"})
    assert meta["conditionalRequest"] is True
    assert meta["ifNoneMatch"] == '"prev"'
    assert meta["ifModifiedSince"].startswith("Mon,")


def test_content_length_mismatch_augment_returns_claimed_bytes(monkeypatch):
    monkeypatch.setattr(tbenv, "MOD_CONTENT_LENGTH_CLAIMED_BYTES", 1_000_000_000)
    mod = tbenv.ContentLengthMismatchModule()
    headers, meta = mod.augment(None, {})
    assert headers["Content-Length"] == "1000000000"
    assert meta["claimedBytes"] == 1_000_000_000


def test_redirect_chain_should_run_false_when_chain_already_set(monkeypatch):
    monkeypatch.setattr(tbenv, "MOD_REDIRECT_CHAIN_ENABLED", True)
    mod = tbenv.RedirectChainModule()
    assert not mod.should_run({"query": "_hp_chain=existing"})
    # And true for the initial request (no chain param yet).
    assert mod.should_run({"query": "other=1"})
    assert mod.should_run({"query": ""})


def test_dns_callback_should_run_requires_domain(monkeypatch):
    monkeypatch.setattr(tbenv, "MOD_DNS_CALLBACK_ENABLED", True)
    monkeypatch.setattr(tbenv, "MOD_DNS_CALLBACK_DOMAIN", "")
    assert not tbenv.DNSCallbackModule().should_run({})
    monkeypatch.setattr(tbenv, "MOD_DNS_CALLBACK_DOMAIN", "track.example")
    assert tbenv.DNSCallbackModule().should_run({})


def test_tarpit_module_base_defaults():
    """Base class is a no-op. Subclasses opt in by overriding."""
    base = tbenv.TarpitModule()
    assert base.should_run({}) is False
    headers, meta = base.augment(None, {})
    assert headers == {} and meta == {}


# --- build_tarpit_chunk ---


def test_build_tarpit_chunk_pads_to_chunk_bytes_plus_newline(monkeypatch):
    monkeypatch.setattr(tbenv, "TARPIT_CHUNK_BYTES", 64)
    chunk = tbenv.build_tarpit_chunk("abcdef1234567890-req", "/short", 1)
    assert len(chunk) == 65  # TARPIT_CHUNK_BYTES + trailing newline
    assert chunk.endswith(b"\n")
    assert b"TRACEBIT_TARPIT_" in chunk
    assert b"/short" in chunk


def test_build_tarpit_chunk_truncates_long_payload(monkeypatch):
    monkeypatch.setattr(tbenv, "TARPIT_CHUNK_BYTES", 8)
    long_path = "/" + ("verylongpath" * 20)
    chunk = tbenv.build_tarpit_chunk("req", long_path, 7)
    assert len(chunk) == 9  # 8 + newline
    assert chunk.endswith(b"\n")


# --- format_env_payload ---


def test_format_env_payload_includes_aws_ssh_and_http_blocks():
    response = {
        "aws": {
            "awsAccessKeyId": "AKIAEXAMPLE",
            "awsSecretAccessKey": "supersecret",
            "awsSessionToken": "token123",
            "awsExpiration": "2030-01-01T00:00:00Z",
        },
        "ssh": {
            "sshIp": "198.51.100.5",
            "sshPrivateKey": "PRIV",
            "sshPublicKey": "PUB",
            "sshExpiration": "2030-01-01T00:00:00Z",
        },
        "http": {
            "gitlab-cookie": {
                "credentials": {"name": "_gitlab_session", "value": "v"},
                "hostNames": ["gitlab.example"],
                "expiresAt": "2030-01-01T00:00:00Z",
            },
        },
    }
    payload = tbenv.format_env_payload(response)
    assert "AWS_ACCESS_KEY_ID=AKIAEXAMPLE" in payload
    assert "SSH_HOST=198.51.100.5" in payload
    assert "SSH_PRIVATE_KEY_B64=PRIV" in payload
    # http blocks upper-case + underscore the canary type
    assert "GITLAB_COOKIE_HOSTNAMES=gitlab.example" in payload
    assert "GITLAB_COOKIE_EXPIRATION=2030-01-01T00:00:00Z" in payload
    # credentials are JSON-encoded inline
    assert '"_gitlab_session"' in payload


def test_format_env_payload_empty_response_returns_empty_body():
    # An upstream that returns nothing usable must render as an empty body,
    # not a self-labelling error sentinel. An empty .env is unremarkable;
    # "TRACEBIT_CANARY_ERROR=..." would burn the trap.
    assert tbenv.format_env_payload({}) == ""


def test_format_env_payload_ignores_non_dict_entries():
    # Defensive: upstream must not crash flux. Also must not leak a tell.
    payload = tbenv.format_env_payload({"aws": "not a dict", "http": "also not", "ssh": None})
    assert payload == ""


def test_format_env_payload_no_honeypot_tell_in_output():
    # The rendered payload is served to the attacker on /.env; any literal
    # mention of "honeypot", "autogenerated", "canary", "tracebit", or
    # "issued_at" anywhere in the body burns the trap. Covers every populated
    # branch so credential-key names are guarded alongside headers.
    response = {
        "aws": {
            "awsAccessKeyId": "AKIAEXAMPLE",
            "awsSecretAccessKey": "supersecret",
            "awsSessionToken": "token123",
            "awsExpiration": "2030-01-01T00:00:00Z",
        },
        "ssh": {
            "sshIp": "198.51.100.5",
            "sshPrivateKey": "PRIV",
            "sshPublicKey": "PUB",
            "sshExpiration": "2030-01-01T00:00:00Z",
        },
        "http": {
            "gitlab-cookie": {
                "credentials": {"name": "_gitlab_session", "value": "v"},
                "hostNames": ["gitlab.example"],
                "expiresAt": "2030-01-01T00:00:00Z",
            },
        },
    }
    payload = tbenv.format_env_payload(response).lower()
    for tell in ("honeypot", "autogenerated", "canary", "tracebit", "issued_at"):
        assert tell not in payload, f"payload leaks '{tell}'"
    # Empty response must also not leak.
    assert tbenv.format_env_payload({}) == ""


# --- Fake git primitives ---


def test_git_loose_object_is_valid_for_blob():
    import zlib
    content = b"hello, git\n"
    sha, blob_bytes = tbenv._git_loose_object(b"blob", content)
    raw = zlib.decompress(blob_bytes)
    # Git loose-object header: "blob <len>\x00" + content
    header, _, body = raw.partition(b"\x00")
    assert header == b"blob 11"
    assert body == content
    # Canonical git sha = sha1(header\x00 + content)
    import hashlib
    assert sha == hashlib.sha1(raw).hexdigest()


def test_git_tree_entry_packs_mode_name_and_binary_sha():
    entry = tbenv._git_tree_entry("100644", "README.md", "1" * 40)
    assert entry.startswith(b"100644 README.md\x00")
    assert entry[-20:] == bytes.fromhex("1" * 40)


def test_format_secrets_yaml_embeds_aws_canary():
    body = tbenv._format_secrets_yaml({"aws": {
        "awsAccessKeyId": "AKIAFAKEYAML01",
        "awsSecretAccessKey": "yamlSecret",
        "awsSessionToken": "yamlTok",
        "awsExpiration": "2030-01-01T00:00:00Z",
    }})
    assert "access_key_id: AKIAFAKEYAML01" in body
    assert "session_token: yamlTok" in body
    assert body.startswith("# config/secrets.yml")


def test_format_secrets_yaml_tolerates_missing_aws():
    # Not expected in practice, but the function must not crash.
    body = tbenv._format_secrets_yaml({})
    assert "access_key_id:" in body  # placeholder line still present


def test_build_fake_repo_produces_expected_layout_and_sha_linkage():
    import zlib
    secrets_body = tbenv._format_secrets_yaml({"aws": {
        "awsAccessKeyId": "AKIATESTREPO",
        "awsSecretAccessKey": "x", "awsSessionToken": "y", "awsExpiration": "z",
    }})
    files, meta = tbenv._build_fake_repo(secrets_body)

    # The minimum surface a git-dumper walks. Keys are lowercased so
    # lookups via extract_git_path() (which returns a lowercase key) match
    # regardless of the case a scanner uses on the wire.
    for required in ("/.git/head", "/.git/config", "/.git/refs/heads/main",
                     "/.git/packed-refs", "/.git/info/refs", "/.git/logs/head"):
        assert required in files, required

    # refs/heads/main + packed-refs both reference the commit SHA.
    assert meta["commitSha"] in files["/.git/refs/heads/main"].decode()
    assert meta["commitSha"] in files["/.git/packed-refs"].decode()

    # The secrets blob object exists at its hashed path and decompresses
    # to a body that still carries the canary.
    secrets_path = f"/.git/objects/{meta['secretsBlobSha'][:2]}/{meta['secretsBlobSha'][2:]}"
    assert secrets_path in files
    raw = zlib.decompress(files[secrets_path])
    assert raw.startswith(b"blob ")
    assert b"AKIATESTREPO" in raw

    # Commit object references the root tree sha.
    commit_path = f"/.git/objects/{meta['commitSha'][:2]}/{meta['commitSha'][2:]}"
    commit_raw = zlib.decompress(files[commit_path])
    assert commit_raw.startswith(b"commit ")
    assert f"tree {meta['rootTreeSha']}".encode() in commit_raw


# --- /.git/config URL embeds Tracebit canary (git-config-canary) ---


def test_fake_git_config_url_embeds_canary_credential(monkeypatch):
    # With no operator override, the URL userinfo is the Tracebit AWS key
    # pair — so a scraper that only reads /.git/config still walks away
    # with a live canary.
    monkeypatch.setattr(tbenv, "FAKE_GIT_REMOTE_URL", "")
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, _meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    config = files["/.git/config"].decode()
    assert "url = https://AKIAFAKEEXAMPLE01:" in config
    # '/' '+' '=' in the secret are percent-encoded so downstream URL
    # parsers don't choke.
    assert "wJalrXUtnFEMI%2FK7MDENG%2FbPxRfiCYEXAMPLEKEY" in config
    assert "@github.com/internal/tools.git" in config


def test_fake_git_config_url_respects_operator_override(monkeypatch):
    # If the operator pins FAKE_GIT_REMOTE_URL, it's used verbatim.
    monkeypatch.setattr(tbenv, "FAKE_GIT_REMOTE_URL", "git@corp.example:myrepo.git")
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, _meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    config = files["/.git/config"].decode()
    assert "url = git@corp.example:myrepo.git" in config
    # No canary leaked in the URL when an override is set.
    assert "AKIAFAKEEXAMPLE01" not in config


def test_fake_git_config_url_falls_back_when_canary_missing(monkeypatch):
    # If Tracebit returns a response without AWS creds, we must not emit
    # a malformed URL — fall back to a static SSH URL.
    monkeypatch.setattr(tbenv, "FAKE_GIT_REMOTE_URL", "")
    secrets_body = tbenv._format_secrets_yaml({})
    files, _meta = tbenv._build_fake_repo(secrets_body, {})
    config = files["/.git/config"].decode()
    assert "url = git@github.com:internal/tools.git" in config


# --- extract_git_path: prefix + case-insensitive coverage ---


@pytest.mark.parametrize("path,expected", [
    # Direct /.git/ access
    ("/.git/config", "/.git/config"),
    ("/.git/HEAD", "/.git/head"),
    ("/.git/refs/heads/main", "/.git/refs/heads/main"),
    # Root pointers
    ("/.git", "/.git/"),
    ("/.git/", "/.git/"),
    # Case variants
    ("/.GIT/CONFIG", "/.git/config"),
    ("/.Git/Config", "/.git/config"),
    ("/.gIt/cOnFiG", "/.git/config"),
    # Prefixed-app variants (app deployed at subpath)
    ("/login/.git/config", "/.git/config"),
    ("/project/.git/HEAD", "/.git/head"),
    ("/api/.git/index", "/.git/index"),
    ("/backend/.git/refs/heads/main", "/.git/refs/heads/main"),
    # Nested prefix
    ("/a/b/c/.git/config", "/.git/config"),
    # Case-variant inside a prefix
    ("/Login/.GiT/CoNfIg", "/.git/config"),
])
def test_extract_git_path_recognises_git_requests(path, expected):
    assert tbenv.extract_git_path(path) == expected


@pytest.mark.parametrize("path", [
    "/",
    "/.env",
    "/.gitignore",
    "/.gitconfig",
    "/.git-credentials",
    "/gitconfig",
    "/foo/bar",
    "",
    # `.git` as part of a filename segment, not a directory
    "/.gitlab-ci.yml",
    # Decoy — must require actual `/.git/` substring
    "/gitrepo/config",
])
def test_extract_git_path_ignores_non_git_requests(path):
    assert tbenv.extract_git_path(path) is None


# --- /.git/index placeholder ---


def test_fake_git_index_is_valid_dirc_header():
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, _meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    index = files["/.git/index"]
    # Signature + version 2 + entry count 0 + 20 zero bytes (trailer slot).
    assert index.startswith(b"DIRC")
    assert index[4:8] == b"\x00\x00\x00\x02"
    assert index[8:12] == b"\x00\x00\x00\x00"
    assert len(index) == 32


# --- _close_http_session lifecycle ---


async def test_close_http_session_closes_lazy_session():
    # Prime a session, then verify cleanup hook closes it and clears the global.
    session = await tbenv._get_http_session()
    assert not session.closed
    await tbenv._close_http_session(None)
    assert session.closed
    assert tbenv._http_session is None


async def test_close_http_session_is_safe_when_nothing_opened():
    # Reset, then call cleanup with no prior session — must not raise.
    tbenv._http_session = None
    await tbenv._close_http_session(None)
    assert tbenv._http_session is None


# --- Method handling ---


async def test_dispatch_rejects_unsupported_methods(flux_client):
    """PUT / DELETE / etc. short-circuit to 405. Prevents confused logging
    downstream and stops tarpit/canary logic from running on odd verbs."""
    resp = await flux_client.put("/anything", data=b"x")
    assert resp.status == 405
