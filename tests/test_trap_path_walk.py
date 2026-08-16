"""Tests for app-layout trap resolution and the deploy-credential trap.

Two related additions:

* `resolve_canary_trap` lets an exact-path trap answer the same file when
  it arrives nested under a recognised deployment directory, because
  secret-dredging dictionaries walk `<layout dir>/<secret file>` rather
  than a flat filename list.
* `deploy-sync-config` serves editor-plugin deploy configs whose
  credential is an SSH one, minted per hit and reproducible from the
  trap log line.
"""
from __future__ import annotations

import hashlib
import json
import re

import pytest
import pytest_asyncio

from flux import server as tbenv


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    """Real aiohttp app with LOG_PATH routed into tmp_path."""
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


# --------------------------------------------------------------------------
# resolve_canary_trap
# --------------------------------------------------------------------------

def test_exact_path_resolves_at_depth_zero():
    trap, depth = tbenv.resolve_canary_trap("/aws.json")
    assert trap is not None
    assert trap.name == "aws-credentials-json"
    assert depth == 0


@pytest.mark.parametrize(
    "path,expected_depth",
    [
        ("/admin/aws.json", 1),
        ("/api/aws.json", 1),
        ("/storage/aws.json", 1),
        ("/admin/config/aws.json", 2),
        ("/backup/config/aws.json", 2),
    ],
)
def test_layout_nested_paths_resolve_to_the_same_trap(path, expected_depth):
    """The leaf keeps its own renderer; only the depth changes."""
    trap, depth = tbenv.resolve_canary_trap(path)
    assert trap is not None, path
    assert trap.name == "aws-credentials-json"
    assert depth == expected_depth


def test_walk_reaches_the_phpinfo_family_under_a_layout_dir():
    trap, depth = tbenv.resolve_canary_trap("/admin/phpinfo.php")
    assert trap is not None
    assert trap.name == "phpinfo"
    assert depth == 1


def test_unknown_leading_segment_does_not_resolve():
    """The vocabulary gate is the camouflage. Answering an arbitrary
    parent directory would advertise a host that says yes to anything."""
    for path in ("/9f2a1c/aws.json", "/zzqx/aws.json", "/admin2x/aws.json"):
        assert tbenv.resolve_canary_trap(path) == (None, 0), path


def test_walk_stops_at_the_depth_cap():
    """Three layout dirs deep is past what real dictionaries walk."""
    assert tbenv.resolve_canary_trap("/admin/config/backup/aws.json") == (None, 0)


def test_walk_stops_at_the_first_unrecognised_segment():
    """`/admin/<junk>/aws.json` must not resolve just because `admin`
    passed — every segment dropped has to be a layout name."""
    assert tbenv.resolve_canary_trap("/admin/9f2a1c/aws.json") == (None, 0)


def test_walk_can_be_disabled_without_disabling_traps(monkeypatch):
    monkeypatch.setattr(tbenv, "TRAP_PATH_WALK_ENABLED", False)
    assert tbenv.resolve_canary_trap("/admin/aws.json") == (None, 0)
    # The exact path still answers.
    trap, depth = tbenv.resolve_canary_trap("/aws.json")
    assert trap is not None and depth == 0


def test_walk_is_off_when_canary_traps_are_off(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    assert tbenv.resolve_canary_trap("/admin/aws.json") == (None, 0)
    assert tbenv.resolve_canary_trap("/aws.json") == (None, 0)


def test_walk_prefix_vocabulary_covers_the_env_family_prefixes():
    """The `.env` trap already curates a layout vocabulary; the walk
    reuses it rather than maintaining a second divergent list."""
    for prefix in tbenv._ENV_WEBROOT_PREFIXES:
        assert prefix.lower() in tbenv._TRAP_WALK_PREFIXES, prefix
    for prefix in tbenv._APP_LAYOUT_CRED_PREFIXES:
        assert prefix.lower() in tbenv._TRAP_WALK_PREFIXES, prefix


def test_walk_never_shadows_an_exact_entry():
    """Any path with its own table entry must resolve at depth 0, even
    when its leading segment happens to be a layout word."""
    for path in tbenv._TRAP_BY_PATH:
        trap, depth = tbenv.resolve_canary_trap(path)
        assert depth == 0, path
        assert trap is tbenv._TRAP_BY_PATH[path]


# --------------------------------------------------------------------------
# dispatch + logging
# --------------------------------------------------------------------------

def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_nested_path_is_served_and_logs_walk_depth(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")

    async def _fake_issue(types, *args, **kwargs):
        return {"aws": {"awsAccessKeyId": "AKIAEXAMPLE", "awsSecretAccessKey": "s3cret"}}

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_issue)

    resp = await flux_client.get(
        "/admin/aws.json", headers={"X-Forwarded-For": "203.0.113.11"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[0]
    assert entry["result"] == "aws-credentials-json"
    assert entry["trapWalkDepth"] == 1


async def test_unnested_path_logs_no_walk_depth(flux_client, monkeypatch):
    """Absence of the field is the signal for 'arrived at its real
    location', so it must not be stamped as 0 on the common case."""
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")

    async def _fake_issue(types, *args, **kwargs):
        return {"aws": {"awsAccessKeyId": "AKIAEXAMPLE", "awsSecretAccessKey": "s3cret"}}

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_issue)

    resp = await flux_client.get(
        "/aws.json", headers={"X-Forwarded-For": "203.0.113.12"},
    )
    assert resp.status == 200
    assert "trapWalkDepth" not in _log_entries(flux_client.log_path)[0]


async def test_unrecognised_parent_still_404s(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")
    resp = await flux_client.get(
        "/9f2a1c/aws.json", headers={"X-Forwarded-For": "203.0.113.13"},
    )
    assert resp.status == 404
    assert _log_entries(flux_client.log_path)[0]["result"] == "not-handled"


# --------------------------------------------------------------------------
# deploy-sync-config
# --------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^deploy_[0-9a-f]{8}$")


@pytest.mark.parametrize(
    "path",
    [
        "/remote-sync.json",
        "/ftp-sync.json",
        "/deployment-config.json",
        "/ftpsync.settings",
        "/.vscode/remote-sync.json",
        "/deploy.json",
        # via the layout walk
        "/admin/remote-sync.json",
        "/config/deploy.json",
    ],
)
def test_deploy_sync_paths_resolve(path):
    trap, _ = tbenv.resolve_canary_trap(path)
    assert trap is not None, path
    assert trap.name == "deploy-sync-config"


def test_deploy_sync_trap_needs_no_tracebit_canary():
    """It mints its own credential, so it must not declare canary types —
    that is what keeps it serving when the upstream API is unavailable."""
    trap, _ = tbenv.resolve_canary_trap("/remote-sync.json")
    assert trap.canary_types == ()


def test_deploy_sync_renders_the_requested_host_on_port_22():
    body = json.loads(tbenv.render_deploy_sync_json({
        "_requestHost": "shop.example.com", "_requestId": "abc",
    }))
    assert body["host"] == "shop.example.com"
    assert body["port"] == 22
    assert body["protocol"] == "sftp"


def test_deploy_sync_username_is_derived_from_the_request_id():
    """Reproducible from the log line alone — the log already carries
    requestId, so a replay is attributable without recording anything
    extra at issue time."""
    request_id = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
    body = json.loads(tbenv.render_deploy_sync_json({
        "_requestHost": "h.example", "_requestId": request_id,
    }))
    expected = "deploy_" + hashlib.sha256(request_id.encode()).hexdigest()[:8]
    assert body["username"] == expected
    assert _USERNAME_RE.match(body["username"])


def test_deploy_sync_credentials_are_unique_per_hit():
    """Nothing credential-shaped may be a fixed literal: two hits must
    share neither the username nor the password."""
    a = json.loads(tbenv.render_deploy_sync_json({"_requestHost": "h", "_requestId": "req-a"}))
    b = json.loads(tbenv.render_deploy_sync_json({"_requestHost": "h", "_requestId": "req-b"}))
    assert a["username"] != b["username"]
    assert a["password"] != b["password"]
    assert a["password"] and b["password"]


def test_deploy_sync_falls_back_when_host_is_missing_or_junk():
    for bad in ({}, {"_requestHost": ""}, {"_requestHost": "a b"}, {"_requestHost": "a/b"}):
        body = json.loads(tbenv.render_deploy_sync_json({**bad, "_requestId": "x"}))
        assert body["host"] == "deploy.internal"


async def test_deploy_sync_served_without_an_upstream_call(flux_client, monkeypatch):
    """No canary types means no Tracebit request — an upstream blip must
    not 404 a trap that has no upstream dependency."""
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")

    async def _boom(*args, **kwargs):
        raise AssertionError("must not issue a canary for this trap")

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _boom)

    resp = await flux_client.get(
        "/remote-sync.json",
        headers={"X-Forwarded-For": "203.0.113.21", "X-Forwarded-Host": "shop.example.com"},
    )
    assert resp.status == 200
    body = json.loads(await resp.read())
    assert body["host"] == "shop.example.com"
    assert _USERNAME_RE.match(body["username"])

    entry = _log_entries(flux_client.log_path)[0]
    assert entry["result"] == "deploy-sync-config"
    # The served username must be recomputable from the logged request id.
    expected = "deploy_" + hashlib.sha256(entry["requestId"].encode()).hexdigest()[:8]
    assert body["username"] == expected


# --------------------------------------------------------------------------
# sftp-config host upgrade
# --------------------------------------------------------------------------

def test_sftp_config_names_the_requested_host():
    body = json.loads(tbenv.render_sftp_config_json({
        "_requestHost": "shop.example.com",
        "http": {"gitlab-username-password": {
            "credentials": {"username": "u", "password": "p"},
        }},
    }))
    assert body["host"] == "shop.example.com"
    # The gitlab canary still supplies the credential — unchanged.
    assert body["username"] == "u"
    assert body["password"] == "p"


def test_sftp_config_keeps_its_placeholder_without_a_host():
    body = json.loads(tbenv.render_sftp_config_json({
        "http": {"gitlab-username-password": {
            "credentials": {"username": "u", "password": "p"},
        }},
    }))
    assert body["host"] == "deploy.internal"


# --------------------------------------------------------------------------
# host plausibility
# --------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "127.0.0.1", "0.0.0.0", "10.0.0.5", "192.168.1.1", "::1", "[::1]",
    "localhost", "localhost.localdomain", "box.local", "upstream", "",
    "a b", "a/b",
])
def test_implausible_deploy_hosts_fall_back(host):
    """A reverse proxy that rewrites Host to its upstream address makes
    every sensor emit the same loopback literal — a fleet-wide constant
    in a file that is otherwise unique per hit, and not a target anyone
    could act on. Anything that is not a real external name falls back."""
    assert tbenv._plausible_deploy_host({"_requestHost": host}) == "deploy.internal"


def test_missing_host_key_falls_back():
    assert tbenv._plausible_deploy_host({}) == "deploy.internal"


@pytest.mark.parametrize("host", [
    "shop.example.com", "example.com", "a.b.c.example.org", "xn--80ak6aa92e.com",
])
def test_plausible_deploy_hosts_are_used(host):
    assert tbenv._plausible_deploy_host({"_requestHost": host}) == host


def test_host_is_normalised_to_lowercase():
    assert tbenv._plausible_deploy_host({"_requestHost": "Shop.Example.COM "}) == "shop.example.com"


def test_both_deploy_renderers_reject_a_loopback_host():
    """Regression: the first deployment served `127.0.0.1` because nginx
    rewrites Host to the proxy_pass target."""
    body = json.loads(tbenv.render_deploy_sync_json({
        "_requestHost": "127.0.0.1", "_requestId": "x",
    }))
    assert body["host"] == "deploy.internal"

    sftp = json.loads(tbenv.render_sftp_config_json({
        "_requestHost": "127.0.0.1",
        "http": {"gitlab-username-password": {
            "credentials": {"username": "u", "password": "p"},
        }},
    }))
    assert sftp["host"] == "deploy.internal"
