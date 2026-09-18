"""Tests for the WordPress plugin upload-vector matrix.

A recurring campaign shape POSTs to several WordPress plugin upload
endpoints in one burst, then GETs one token-named `.php` file back from
each endpoint's landing directory. The token is constant across the
burst, so the round is an A/B test over upload vectors and the answer the
operator reads is which landing path returns their file.

The trap accepts exactly one vector per source. These tests pin the two
properties that makes it worth anything: the answer is *coherent* — the
landing path of the refused vector stays 404 even though the sweep gate
would answer its shape — and it is *singular*, because a host claiming
every plugin vulnerability is live at once is not a host anyone believes.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


@pytest.fixture(autouse=True)
def clear_claims():
    """The claim registry is module-level; keep tests independent."""
    tbenv._WP_PLUGIN_UPLOAD_CLAIMS.clear()
    tbenv._WEBSHELL_SWEEP_SEEN.clear()
    yield
    tbenv._WP_PLUGIN_UPLOAD_CLAIMS.clear()
    tbenv._WEBSHELL_SWEEP_SEEN.clear()


def log_lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# nginx puts the real source here; flux reads the chain, never the peer.
SRC = "203.0.113.42"
XFF = {"X-Forwarded-For": SRC}


def multipart(filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----fluxtest0123"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="upload[]"; filename="{filename}"\r\n'
        f"Content-Type: application/x-php\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


# --------------------------------------------------------------------------
# Vector matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,query,vector_id", [
    ("/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "", "wp-file-manager"),
    ("/wp-content/plugins/wp-file-manager/lib/php/connector.php", "", "wp-file-manager"),
    ("/wp-content/plugins/contact-form-7-db/img/upload.php", "", "contact-form-7-db"),
    ("/wp-content/plugins/backup-backup/includes/backup-heart.php", "", "backup-backup"),
    ("/wp-admin/admin-ajax.php", "action=uploadFontIcon", "kaswara"),
    ("/wp-admin/admin-ajax.php", "action=wpr_addons_upload_file", "wpr-addons"),
    ("/wp-admin/admin-ajax.php", "action=ecsload", "ecsload"),
    # Case and trailing slash are the scanner's, not ours.
    ("/WP-CONTENT/plugins/contact-form-7-db/img/UPLOAD.PHP", "", "contact-form-7-db"),
    ("/wp-admin/admin-ajax.php", "action=UPLOADFONTICON", "kaswara"),
])
def test_observed_upload_vectors_match(path, query, vector_id):
    vector = tbenv.wp_plugin_upload_vector(path, query)
    assert vector is not None, f"unexpected miss: {path}?{query}"
    assert vector["id"] == vector_id


@pytest.mark.parametrize("path,query", [
    # `admin-ajax.php` is overwhelmingly used for things that are not
    # uploads; claiming it on address alone would take the whole endpoint
    # away from the trap that owns it.
    ("/wp-admin/admin-ajax.php", ""),
    ("/wp-admin/admin-ajax.php", "action=heartbeat"),
    ("/wp-admin/admin-ajax.php", "action=wp_ajax_query_attachments"),
    ("/wp-content/plugins/wp-file-manager/readme.txt", ""),
    ("/wp-content/uploads/probe_token_aabbcc.php", ""),
    ("/wp-content/plugins/contact-form-7-db/img/", ""),
    ("/", ""),
])
def test_non_upload_addresses_are_not_claimed(path, query):
    assert tbenv.wp_plugin_upload_vector(path, query) is None


def test_vector_matching_disabled_when_env_off(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_PLUGIN_UPLOAD_ENABLED", False)
    assert tbenv.wp_plugin_upload_vector(
        "/wp-content/plugins/contact-form-7-db/img/upload.php", "",
    ) is None


def test_wp_plugin_upload_default_on():
    """Flux is a honeypot; a fresh sensor runs every trap without tuning."""
    assert tbenv.WP_PLUGIN_UPLOAD_ENABLED


# --------------------------------------------------------------------------
# Exactly one vector per source
# --------------------------------------------------------------------------

def test_accepted_vector_is_stable_for_a_source():
    """A matrix probe that got two different answers for the same vector
    would be more suspicious than any single answer."""
    first = tbenv.wp_plugin_upload_accepted_vector("203.0.113.9")
    for _ in range(20):
        assert tbenv.wp_plugin_upload_accepted_vector("203.0.113.9") == first


def test_accepted_vector_is_a_real_vector_and_varies_across_sources():
    ids = {v["id"] for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS}
    seen = set()
    for octet in range(120):
        chosen = tbenv.wp_plugin_upload_accepted_vector(f"198.51.100.{octet}")
        assert chosen in ids
        seen.add(chosen)
    # Not a constant — otherwise every host in a fleet answers identically.
    assert len(seen) > 1


# --------------------------------------------------------------------------
# The burst, end to end
# --------------------------------------------------------------------------

async def _post_vector(client, vector, body, content_type):
    path = vector["path"]
    url = f"{path}?action={vector['action']}" if vector["action"] else path
    return await client.post(
        url, data=body, headers={"Content-Type": content_type, **XFF},
    )


@pytest.mark.asyncio
async def test_matrix_burst_yields_exactly_one_writable_landing_path(flux_client):
    """The whole point: POST every vector, GET every landing path, and
    exactly one of them returns the operator's file."""
    token = "probe_token_cfd75b"
    body, content_type = multipart(f"{token}.php", f"<?php echo '{token}'; ?>".encode())

    for vector in tbenv._WP_PLUGIN_UPLOAD_VECTORS:
        resp = await _post_vector(flux_client, vector, body, content_type)
        assert resp.status == 200

    # Two vectors can share a landing directory, and a GET cannot tell
    # which of them wrote the file — so the invariant is one writable
    # *address*, not one writable vector.
    statuses = {}
    for vector in tbenv._WP_PLUGIN_UPLOAD_VECTORS:
        landing = f"{vector['landing']}/{token}.php"
        resp = await flux_client.get(landing, headers=XFF)
        statuses[landing] = resp.status
        if resp.status == 200:
            assert token in await resp.text()

    ok = [path for path, status in statuses.items() if status == 200]
    assert len(ok) == 1, f"expected exactly one writable landing path, got {ok}"
    accepted = tbenv.wp_plugin_upload_accepted_vector(SRC)
    landing = next(
        v["landing"] for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] == accepted
    )
    assert ok[0] == f"{landing}/{token}.php"


@pytest.mark.asyncio
async def test_accepted_vector_answers_in_its_plugin_idiom(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "wpr-addons")
    body, content_type = multipart("shell.php", b"<?php echo 'x'; ?>")
    vector = next(v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] == "wpr-addons")
    resp = await _post_vector(flux_client, vector, body, content_type)
    payload = await resp.json()
    assert payload["success"] is True
    assert payload["data"]["url"] == "/wp-content/uploads/wpr-addons/templates/shell.php"


@pytest.mark.asyncio
async def test_refused_vector_answers_in_its_plugin_idiom(flux_client, monkeypatch):
    """A refusal has to look like the plugin's refusal — a 404 everywhere
    is as much of a tell as a 200 everywhere."""
    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "wpr-addons")
    body, content_type = multipart("shell.php", b"<?php echo 'x'; ?>")
    vector = next(v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] == "kaswara")
    resp = await _post_vector(flux_client, vector, body, content_type)
    assert resp.status == 200
    payload = await resp.json()
    assert payload["success"] is False
    assert "not permitted" in payload["data"]["message"]


@pytest.mark.asyncio
async def test_elfinder_vector_uses_elfinder_envelopes(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "wp-file-manager")
    body, content_type = multipart("s.php", b"<?php echo 'x'; ?>")
    vector = next(v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] == "wp-file-manager")
    accepted = await (await _post_vector(flux_client, vector, body, content_type)).json()
    assert accepted["added"][0]["name"] == "s.php"

    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "ecsload")
    tbenv._WP_PLUGIN_UPLOAD_CLAIMS.clear()
    refused = await (await _post_vector(flux_client, vector, body, content_type)).json()
    assert refused["error"][0] == "errUploadFile"


# --------------------------------------------------------------------------
# Coherence — the refusal has to hold against the sweep gate
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_refused_landing_path_stays_404_against_the_sweep_gate(flux_client, monkeypatch):
    """`/wp-content/...` `.php` names are exactly the shape the shell-jacking
    sweep gate answers once a source has walked a few of them. A landing
    path whose vector was refused has to keep its 404 anyway, or the host
    contradicts itself inside one burst."""
    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "wp-file-manager")
    token = "probe_token_ffee11"
    body, content_type = multipart(f"{token}.php", f"<?php echo '{token}'; ?>".encode())
    for vector in tbenv._WP_PLUGIN_UPLOAD_VECTORS:
        await _post_vector(flux_client, vector, body, content_type)

    refused = [v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] != "wp-file-manager"]
    for vector in refused:
        resp = await flux_client.get(f"{vector['landing']}/{token}.php", headers=XFF)
        assert resp.status == 404, f"{vector['id']} landing path should stay 404"

    results = {line.get("result") for line in log_lines(flux_client.log_path)}
    assert "wp-plugin-upload-refuted" in results
    assert "webshell-probe" not in results


@pytest.mark.asyncio
async def test_landing_path_is_scoped_to_the_source_that_uploaded(flux_client, monkeypatch):
    """A claim is one source's. Another source asking the same address
    gets whatever it would have got anyway, never the first one's file."""
    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "ecsload")
    body, content_type = multipart("only_mine.php", b"<?php echo 'mine'; ?>")
    vector = next(v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] == "ecsload")
    await _post_vector(flux_client, vector, body, content_type)
    assert tbenv.wp_plugin_upload_lookup(SRC, "/wp-content/uploads/only_mine.php")
    assert tbenv.wp_plugin_upload_lookup("203.0.113.7", "/wp-content/uploads/only_mine.php") is None


@pytest.mark.asyncio
async def test_verification_get_serves_the_operators_own_file(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "ecsload")
    token = "probe_token_123abc"
    body, content_type = multipart(f"{token}.php", f"<?php echo '{token}'; ?>".encode())
    vector = next(v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] == "ecsload")
    await _post_vector(flux_client, vector, body, content_type)

    resp = await flux_client.get(f"/wp-content/uploads/{token}.php", headers=XFF)
    assert resp.status == 200
    assert (await resp.text()) == token

    entries = [
        line for line in log_lines(flux_client.log_path)
        if line.get("result") == "wp-plugin-upload-verified"
    ]
    assert entries and entries[-1]["wpPluginUploadVector"] == "ecsload"


@pytest.mark.asyncio
async def test_unparsed_filename_still_answers_from_the_directory_claim(
    flux_client, monkeypatch,
):
    """The landing directory is claimed too, so a verification GET for a
    name that could not be parsed out of the multipart body is still
    answered consistently with what the source was told."""
    monkeypatch.setattr(tbenv, "wp_plugin_upload_accepted_vector", lambda ip: "kaswara")
    vector = next(v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS if v["id"] == "kaswara")
    await _post_vector(flux_client, vector, b"not-multipart-at-all", "application/octet-stream")
    resp = await flux_client.get(
        "/wp-content/uploads/kaswara/fonts/whatever_9f.php", headers=XFF,
    )
    assert resp.status == 200


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

@pytest.mark.parametrize("uploaded,expected", [
    (b"<?php echo 'tok123'; ?>", b"tok123"),
    (b'<?php echo "tok123"; ?>', b"tok123"),
    (b"<?php print('tok123'); ?>", b"tok123"),
    (b"<?= 'tok123' ?>", b"<?= 'tok123' ?>"),
    (b"<?php echo 'tok123';", b"tok123"),
    (b"  <?php   ECHO   'tok123'  ;  ?>  ", b"tok123"),
])
def test_single_echo_stub_is_rendered_as_the_host_would_run_it(uploaded, expected):
    assert tbenv._wp_plugin_upload_rendered(uploaded) == expected


@pytest.mark.parametrize("uploaded", [
    b"<?php system($_GET['c']); ?>",
    b"<?php eval($_POST['x']); echo 'a'; ?>",
    b"\x89PNG\r\n\x1a\n\x00binary",
])
def test_anything_beyond_a_single_echo_is_served_as_it_arrived(uploaded):
    """Nothing here interprets an upload. What is not the one emulated
    shape is returned verbatim, which is what a host that stored the file
    without executing it returns."""
    assert tbenv._wp_plugin_upload_rendered(uploaded) == uploaded


def test_empty_upload_renders_empty():
    assert tbenv._wp_plugin_upload_rendered(b"") == b""


# --------------------------------------------------------------------------
# Registry bounds and expiry
# --------------------------------------------------------------------------

def test_claims_expire():
    vector = tbenv._WP_PLUGIN_UPLOAD_VECTORS[0]
    tbenv.wp_plugin_upload_register("192.0.2.5", vector, True, ["a.php"], b"x", now=1000.0)
    assert tbenv.wp_plugin_upload_lookup(
        "192.0.2.5", f"{vector['landing']}/a.php", now=1000.0,
    )
    later = 1000.0 + tbenv.WP_PLUGIN_UPLOAD_TTL_SECONDS + 1
    assert tbenv.wp_plugin_upload_lookup(
        "192.0.2.5", f"{vector['landing']}/a.php", now=later,
    ) is None


def test_source_table_is_bounded():
    vector = tbenv._WP_PLUGIN_UPLOAD_VECTORS[0]
    for i in range(tbenv.WP_PLUGIN_UPLOAD_MAX_SOURCES + 60):
        tbenv.wp_plugin_upload_register(
            f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}",
            vector, True, ["a.php"], b"x", now=2000.0 + i,
        )
    assert len(tbenv._WP_PLUGIN_UPLOAD_CLAIMS) <= tbenv.WP_PLUGIN_UPLOAD_MAX_SOURCES


def test_claims_per_source_are_bounded():
    vector = tbenv._WP_PLUGIN_UPLOAD_VECTORS[0]
    names = [f"n{i}.php" for i in range(tbenv.WP_PLUGIN_UPLOAD_MAX_CLAIMS_PER_SOURCE + 40)]
    for name in names:
        tbenv.wp_plugin_upload_register("192.0.2.9", vector, True, [name], b"x", now=3000.0)
    claims = tbenv._WP_PLUGIN_UPLOAD_CLAIMS["192.0.2.9"][1]
    assert len(claims) <= tbenv.WP_PLUGIN_UPLOAD_MAX_CLAIMS_PER_SOURCE


def test_retained_body_is_bounded():
    vector = tbenv._WP_PLUGIN_UPLOAD_VECTORS[0]
    oversized = b"A" * (tbenv.WP_PLUGIN_UPLOAD_BODY_LIMIT * 4)
    tbenv.wp_plugin_upload_register("192.0.2.11", vector, True, ["a.php"], oversized, now=4000.0)
    claim = tbenv.wp_plugin_upload_lookup("192.0.2.11", f"{vector['landing']}/a.php", now=4000.0)
    assert len(claim["content"]) == tbenv.WP_PLUGIN_UPLOAD_BODY_LIMIT


def test_refused_claim_retains_no_body():
    """Nothing is kept for a vector whose landing path will never serve."""
    vector = tbenv._WP_PLUGIN_UPLOAD_VECTORS[0]
    tbenv.wp_plugin_upload_register("192.0.2.12", vector, False, ["a.php"], b"payload", now=5000.0)
    claim = tbenv.wp_plugin_upload_lookup("192.0.2.12", f"{vector['landing']}/a.php", now=5000.0)
    assert claim["accepted"] is False
    assert claim["content"] == b""


def test_non_php_landing_lookup_is_ignored():
    vector = tbenv._WP_PLUGIN_UPLOAD_VECTORS[0]
    tbenv.wp_plugin_upload_register("192.0.2.13", vector, True, ["a.php"], b"x", now=6000.0)
    assert tbenv.wp_plugin_upload_lookup(
        "192.0.2.13", f"{vector['landing']}/logo.png", now=6000.0,
    ) is None


# --------------------------------------------------------------------------
# No regression on the endpoint this trap now shares
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_ajax_without_an_upload_action_is_untouched(flux_client):
    resp = await flux_client.get(
        "/wp-admin/admin-ajax.php", allow_redirects=False, headers=XFF,
    )
    results = [line.get("result") for line in log_lines(flux_client.log_path)]
    assert "wp-plugin-upload-attempt" not in results
    assert resp.status != 500


@pytest.mark.parametrize("order", [
    ("backup-backup", "ecsload"),
    ("ecsload", "backup-backup"),
])
def test_a_refusal_never_takes_back_a_shared_directory(order):
    """`backup-backup` and `ecsload` write into the same directory. When
    one is accepted and the other refused, the address stays writable
    regardless of which POST lands first — the file really is there, and
    withdrawing it mid-burst is the contradiction this registry prevents."""
    by_id = {v["id"]: v for v in tbenv._WP_PLUGIN_UPLOAD_VECTORS}
    assert by_id["backup-backup"]["landing"] == by_id["ecsload"]["landing"]
    accepted_id, refused_id = "ecsload", "backup-backup"
    for first in order:
        tbenv.wp_plugin_upload_register(
            "192.0.2.77", by_id[first], first == accepted_id, ["p.php"], b"payload",
            now=7000.0,
        )
    claim = tbenv.wp_plugin_upload_lookup(
        "192.0.2.77", f"{by_id[accepted_id]['landing']}/p.php", now=7000.0,
    )
    assert claim is not None and claim["accepted"] is True
    assert claim["content"] == b"payload"
