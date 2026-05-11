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


async def test_integration_env_502s_when_tracebit_raises(live_server, monkeypatch):
    """Upstream Tracebit failures must return 502 + logged error, not 500."""
    async def boom(*_a, **_kw):
        raise aiohttp.ClientConnectionError("connection refused")

    monkeypatch.setattr(tbenv, "issue_credentials", boom)
    base, log_path = live_server
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/.env", headers={"X-Forwarded-For": "203.0.113.31"},
        ) as resp:
            assert resp.status == 502

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert any(e["result"] == "tracebit-error" for e in entries)


async def test_integration_env_502s_on_tracebit_http_error(live_server, monkeypatch):
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
            assert resp.status == 502

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


async def test_integration_fake_git_502s_when_tracebit_fails(live_server, monkeypatch):
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
            assert resp.status == 502

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
        async with session.get(f"{base}/.env.bak") as resp:
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
