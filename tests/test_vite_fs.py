"""Tests for the Vite `/@fs/<absolute path>` arbitrary-file-read trap.

The trap's job is to resolve an absolute filesystem path the scanner
invented onto whichever existing renderer serves that file, so the
coverage question is "does the suffix walk find the right trap", not
"is this literal path in a list".
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- Path parsing / resolution (pure, no server needed) ----------------


def test_non_fs_paths_are_not_claimed():
    """Anything outside the `/@fs/` prefix must return None so dispatch
    falls through to the traps that own those paths."""
    for path in ("/.env", "/@vite/env", "/fs/root/.env", "/@fsx/.env", "/"):
        assert tbenv.resolve_vite_fs(path) is None


def test_prefix_match_is_case_insensitive():
    assert tbenv.resolve_vite_fs("/@FS/.env") is not None


@pytest.mark.parametrize("path,expected", [
    ("/@fs/.env", "/.env"),
    ("/@fs/root/.aws/credentials", "/root/.aws/credentials"),
    ("/@fs/usr/src/app/.env", "/usr/src/app/.env"),
    ("/@fs/proc/self/environ", "/proc/self/environ"),
])
def test_requested_path_is_the_absolute_path_asked_for(path, expected):
    """The logged `viteFsRequestedPath` is the intel — it must be the
    filesystem path, not the URL it arrived as."""
    resolution = tbenv.resolve_vite_fs(path)
    assert resolution.requested_path == expected


@pytest.mark.parametrize("path,expected", [
    # `..` climbing past root clamps at `/`, same as real resolution.
    ("/@fs/../../../../../proc/self/environ", "/proc/self/environ"),
    ("/@fs/app/../.env", "/.env"),
    ("/@fs/./app/./.env", "/app/.env"),
    ("/@fs/app//.env", "/app/.env"),
])
def test_traversal_and_empty_segments_collapse(path, expected):
    assert tbenv.resolve_vite_fs(path).requested_path == expected


def test_bare_prefix_resolves_to_root_and_misses():
    resolution = tbenv.resolve_vite_fs("/@fs/")
    assert resolution.requested_path == "/"
    assert resolution.trap is None


def test_self_cancelling_traversal_resolves_to_root():
    resolution = tbenv.resolve_vite_fs("/@fs/app/..")
    assert resolution.requested_path == "/"
    assert resolution.trap is None


# --- Suffix walk: the point of the whole design ------------------------


def test_exact_absolute_path_matches_at_depth_zero():
    resolution = tbenv.resolve_vite_fs("/@fs/proc/self/environ")
    assert resolution.trap is not None
    assert resolution.trap.name == "proc-environ"
    assert resolution.match_depth == 0


def test_unknown_prefix_still_finds_the_file_via_suffix_walk():
    """`/usr/src/app/.env` is not a path anyone enumerated; the walk has
    to drop leading directories until `/.env` matches. This is what makes
    the trap cover prefixes we have never seen."""
    resolution = tbenv.resolve_vite_fs("/@fs/usr/src/app/.env")
    assert resolution.trap is not None
    assert resolution.match_depth > 0
    # Dropping three leading segments off `/usr/src/app/.env` lands on
    # `/.env`; anything shallower would have to be a real trap entry.
    assert resolution.match_depth <= 3


@pytest.mark.parametrize("path", [
    "/@fs/root/.aws/credentials",
    "/@fs/home/node/.aws/credentials",
    "/@fs/home/ubuntu/.aws/credentials",
    "/@fs/var/www/.env",
    "/@fs/var/www/html/.env",
    "/@fs/data/.env",
    "/@fs/workspace/.env",
    "/@fs/app/.env.production",
    "/@fs/.env.local",
    "/@fs/.env.development",
    "/@fs/root/.bash_history",
])
def test_observed_probe_shapes_all_resolve(path):
    """Every one of these arrived on the wire and 404'd or tarpitted
    before this trap existed."""
    resolution = tbenv.resolve_vite_fs(path)
    assert resolution.resolved, f"{path} did not resolve"


def test_suffix_walk_is_bounded(monkeypatch):
    """A deeply nested path must not turn into an unbounded dict walk."""
    monkeypatch.setattr(tbenv, "VITE_FS_MAX_SUFFIX_WALK", 2)
    deep = "/@fs/" + "/".join(f"d{i}" for i in range(20)) + "/.env"
    assert tbenv.resolve_vite_fs(deep).trap is None


def test_unknown_file_misses_rather_than_inventing_a_body():
    """A real dev server 404s a file that isn't there. Answering 200 for
    anything at all would be an obvious tell."""
    resolution = tbenv.resolve_vite_fs("/@fs/etc/shadow")
    assert resolution.trap is None
    assert resolution.requested_path == "/etc/shadow"


def test_resolution_still_reports_the_path_on_a_miss():
    """The dictionary is worth recording whether or not we answer it."""
    resolution = tbenv.resolve_vite_fs("/@fs/opt/secret/thing.key")
    assert resolution.trap is None
    assert resolution.requested_path == "/opt/secret/thing.key"


def test_canary_traps_disabled_means_no_resolution():
    """With the trap table off there is nothing to resolve onto, but the
    path is still parsed so the request stays loggable."""
    original = tbenv.CANARY_TRAPS_ENABLED
    try:
        tbenv.CANARY_TRAPS_ENABLED = False
        resolution = tbenv.resolve_vite_fs("/@fs/proc/self/environ")
        assert resolution.trap is None
        assert resolution.requested_path == "/proc/self/environ"
    finally:
        tbenv.CANARY_TRAPS_ENABLED = original


# --- End-to-end dispatch ----------------------------------------------


async def _fake_canary(*_args, **_kwargs):
    return {
        "aws": {
            "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
            "awsSecretAccessKey": "fakeSecretExample01",
            "awsSessionToken": "fakeSessionExample01",
        },
    }


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "VITE_FS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_dispatch_serves_the_canary_for_a_resolved_read(flux_client):
    resp = await flux_client.get(
        "/@fs/root/.aws/credentials",
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"].startswith("vite-fs-")
    assert entry["viteFsRequestedPath"] == "/root/.aws/credentials"


async def test_dispatch_logs_the_requested_path_on_a_miss(flux_client):
    resp = await flux_client.get(
        "/@fs/etc/shadow",
        headers={"X-Forwarded-For": "203.0.113.10"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "vite-fs-miss"
    assert entry["viteFsRequestedPath"] == "/etc/shadow"
    assert entry["viteFsRawSuffix"] == "etc/shadow"


async def test_env_variant_takes_the_canary_not_the_tarpit(flux_client):
    """`/@fs/app/.env.local` matches `is_tarpit_path`, so dispatch order
    decides whether this hit yields a replay-detectable credential or a
    slow drip with no canary at all. It must be the credential."""
    assert tbenv.is_tarpit_path("/@fs/app/.env.local") is True
    resp = await flux_client.get(
        "/@fs/app/.env.local",
        headers={"X-Forwarded-For": "203.0.113.11"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"].startswith("vite-fs-")


async def test_traversal_below_the_prefix_reaches_the_same_trap(flux_client):
    """Traversal that stays under `/@fs/` is collapsed by the resolver and
    still tagged as a filesystem-walk read."""
    resp = await flux_client.get(
        "/@fs/app/config/../../proc/self/environ",
        headers={"X-Forwarded-For": "203.0.113.12"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "vite-fs-proc-environ"
    assert entry["viteFsRequestedPath"] == "/proc/self/environ"


async def test_traversal_above_the_prefix_becomes_a_plain_probe(flux_client):
    """Encoded traversal that climbs past `/@fs/` itself is collapsed by
    `normalize_path` before dispatch, so the `/@fs/` prefix is gone by the
    time this trap would see it and the request lands on the plain path.

    Pinned because the tagging difference is real and easy to misread as
    a coverage gap: same body, same canary, but it is genuinely no longer
    an `/@fs/` read once the prefix has been normalised away."""
    resp = await flux_client.get(
        "/@fs/..%2f..%2f..%2fproc/self/environ",
        headers={"X-Forwarded-For": "203.0.113.16"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "proc-environ"
    assert "viteFsRequestedPath" not in entry


async def test_disabled_falls_through_to_previous_behaviour(flux_client, monkeypatch):
    """With the trap off, an `/@fs/` path must not 404 differently than it
    did before — it goes back to whichever handler used to claim it."""
    monkeypatch.setattr(tbenv, "VITE_FS_ENABLED", False)
    resp = await flux_client.get(
        "/@fs/root/.bash_history",
        headers={"X-Forwarded-For": "203.0.113.13"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "bash-history"


async def test_no_api_key_does_not_serve_the_trap(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/@fs/root/.aws/credentials",
        headers={"X-Forwarded-For": "203.0.113.14"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] != "vite-fs-miss"


async def test_bare_webroot_probe_keeps_its_own_result_tag(flux_client):
    """Regression: the `/@fs/` prefix must not capture the plain path."""
    resp = await flux_client.get(
        "/proc/self/environ",
        headers={"X-Forwarded-For": "203.0.113.15"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "proc-environ"


# --- World-readable system files ---------------------------------------


@pytest.mark.parametrize("path,expected", [
    ("/@fs/etc/passwd", "/etc/passwd"),
    ("/@fs/etc/nginx/nginx.conf", "/etc/nginx/nginx.conf"),
])
def test_system_files_resolve(path, expected):
    """The credential walk never matches an absolute system path, so
    these used to fall out as misses."""
    resolution = tbenv.resolve_vite_fs(path)
    assert resolution.system_file == expected
    assert resolution.resolved
    assert resolution.trap is None


def test_system_file_match_is_exact_not_walked():
    """A system file only means something where it really lives. The
    suffix walk must not turn an arbitrary prefix into a passwd hit."""
    for path in (
        "/@fs/var/www/etc/passwd",
        "/@fs/passwd",
        "/@fs/etc/passwd.bak",
        "/@fs/etc/shadow",
        "/@fs/etc/nginx/sites-enabled/default",
    ):
        assert tbenv.resolve_vite_fs(path).system_file == ""


def test_system_files_do_not_shadow_a_credential_trap():
    """Ordering guard: the trap table is consulted first, so adding
    system files can never steal a read that used to issue a canary."""
    resolution = tbenv.resolve_vite_fs("/@fs/root/.aws/credentials")
    assert resolution.trap is not None
    assert resolution.system_file == ""


def test_system_files_respect_their_switch(monkeypatch):
    monkeypatch.setattr(tbenv, "VITE_FS_SYSTEM_FILES_ENABLED", False)
    resolution = tbenv.resolve_vite_fs("/@fs/etc/passwd")
    assert resolution.system_file == ""
    assert not resolution.resolved


def test_aws_credentials_backup_suffix_resolves():
    """`.bak` and `.old` were covered; the dictionary also walks the
    spelled-out `.backup`, which was the one suffix left 404ing."""
    resolution = tbenv.resolve_vite_fs("/@fs/root/.aws/credentials.backup")
    assert resolution.trap is not None
    assert resolution.trap.name == "aws-credentials-file"


async def test_passwd_read_is_served_and_tagged(flux_client):
    """The oracle a scanner uses to confirm the read primitive works
    must answer, and must stay separable in the log."""
    resp = await flux_client.get(
        "/@fs/etc/passwd",
        headers={"X-Forwarded-For": "203.0.113.30"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert body.startswith("root:x:0:0:")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "vite-fs-etc-passwd"
    assert entry["viteFsRequestedPath"] == "/etc/passwd"


async def test_nginx_conf_read_is_served_and_tagged(flux_client):
    resp = await flux_client.get(
        "/@fs/etc/nginx/nginx.conf",
        headers={"X-Forwarded-For": "203.0.113.31"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert "worker_connections" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "vite-fs-etc-nginx-conf"


async def test_system_file_body_carries_no_credential(flux_client):
    """These bodies are static and shared across the fleet, so nothing
    secret-shaped may appear in them."""
    resp = await flux_client.get(
        "/@fs/etc/nginx/nginx.conf",
        headers={"X-Forwarded-For": "203.0.113.32"},
    )
    body = await resp.text()
    for marker in ("AKIA", "password", "secret", "BEGIN "):
        assert marker.lower() not in body.lower()


async def test_unlisted_system_path_still_misses(flux_client):
    """Scope guard: this is a fixed list, not an answer-everything
    switch. An unlisted system file must still 404 and log the miss."""
    resp = await flux_client.get(
        "/@fs/etc/shadow",
        headers={"X-Forwarded-For": "203.0.113.33"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "vite-fs-miss"
    assert entry["viteFsRequestedPath"] == "/etc/shadow"
