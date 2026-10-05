"""Tests for the Vite RSC source-map lookup as a file-read surface.

The endpoint takes a `file://` URL in a query parameter. It is the same
arbitrary-read question `/@fs/` asks, in a different spelling, so the
coverage question is "does a filename resolve and answer identically on
both surfaces", not "is this literal path listed".
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


ENDPOINT = "/__vite_rsc_findSourceMapURL"

# The four targets observed on this endpoint in the wild. Each is a file
# the `/@fs/` surface already answers, which is the whole argument for
# wiring this one up.
OBSERVED = [
    ("file:///app/.env", "/app/.env"),
    ("file:///root/.aws/credentials", "/root/.aws/credentials"),
    ("file:///proc/self/environ", "/proc/self/environ"),
    ("file:///root/.ssh/id_rsa", "/root/.ssh/id_rsa"),
]


# --- Resolution (pure) -------------------------------------------------


def test_other_paths_are_not_claimed():
    """Dispatch must fall through for anything but this one endpoint."""
    for path in ("/@fs/.env", "/__vite_rsc", "/.env", "/", "/__vite_rsc_findSourceMapURL/x"):
        assert tbenv.resolve_vite_rsc_sourcemap(path, {"filename": "file:///app/.env"}) is None


def test_endpoint_match_is_case_insensitive():
    assert tbenv.resolve_vite_rsc_sourcemap(
        "/__VITE_RSC_FINDSOURCEMAPURL", {"filename": "file:///app/.env"}
    ) is not None


@pytest.mark.parametrize("value,expected", OBSERVED)
def test_observed_targets_resolve_to_the_absolute_path(value, expected):
    target = tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {"filename": value})
    assert target.requested_path == expected


@pytest.mark.parametrize("value,expected", OBSERVED)
def test_observed_targets_all_resolve_to_a_trap(value, expected):
    """A 404 here while `/@fs/<same file>` pays is the drift this trap
    exists to remove."""
    target = tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {"filename": value})
    assert target.resolved, f"{value} must resolve"


@pytest.mark.parametrize("value,expected", OBSERVED)
def test_both_spellings_resolve_to_the_same_answer(value, expected):
    """The point of routing through the shared walk: one filename, one
    resolution, whichever surface asked for it."""
    via_rsc = tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {"filename": value})
    via_fs = tbenv.resolve_vite_fs("/@fs" + expected)
    assert via_rsc.requested_path == via_fs.requested_path
    assert via_rsc.resolved == via_fs.resolved
    assert via_rsc.system_file == via_fs.system_file
    assert via_rsc.bare_env == via_fs.bare_env
    assert getattr(via_rsc.trap, "name", None) == getattr(via_fs.trap, "name", None)


def test_bare_absolute_path_is_accepted():
    """A hand-rolled probe that omits the scheme asked the same thing."""
    target = tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {"filename": "/app/.env"})
    assert target is not None and target.requested_path == "/app/.env"


@pytest.mark.parametrize("param", ["file", "url", "source"])
def test_alternate_parameter_names_are_read(param):
    target = tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {param: "file:///app/.env"})
    assert target is not None and target.requested_path == "/app/.env"


def test_percent_encoded_filename_is_decoded():
    target = tbenv.resolve_vite_rsc_sourcemap(
        ENDPOINT, {"filename": "file%3A%2F%2F%2Froot%2F.aws%2Fcredentials"}
    )
    assert target is not None
    assert target.requested_path == "/root/.aws/credentials"


def test_traversal_in_the_filename_is_collapsed():
    target = tbenv.resolve_vite_rsc_sourcemap(
        ENDPOINT, {"filename": "file:///app/sub/../.env"}
    )
    assert target.requested_path == "/app/.env"


@pytest.mark.parametrize("value", [
    "http://169.254.169.254/latest/meta-data/",
    "https://example.test/x",
    "data:text/plain,hello",
])
def test_remote_schemes_are_refused(value):
    """A client asking this endpoint to fetch a URL is probing for request
    forgery. It must not be answered off the filesystem table as though it
    had named a local file."""
    assert tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {"filename": value}) is None


def test_no_filename_falls_through():
    """A bare hit is a reachability check, not a read."""
    assert tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {}) is None
    assert tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {"filename": "  "}) is None
    assert tbenv.resolve_vite_rsc_sourcemap(ENDPOINT, {"environmentName": "rsc"}) is None


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
    monkeypatch.setattr(tbenv, "VITE_RSC_SOURCEMAP_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_dispatch_serves_the_canary_for_a_resolved_read(flux_client):
    resp = await flux_client.get(
        ENDPOINT, params={"filename": "file:///root/.aws/credentials",
                          "environmentName": "rsc"},
        headers={"X-Forwarded-For": "203.0.113.21"},
    )
    assert resp.status == 200
    assert b"AKIAFAKEEXAMPLE01" in await resp.read()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "vite-rsc-sourcemap-aws-credentials-file"
    assert entry["viteRscSourcemapRequestedPath"] == "/root/.aws/credentials"


async def test_result_tag_keeps_this_surface_separable(flux_client):
    """Same file, two surfaces, two tags — that separation is what tells
    us whether a source knows only the older prefix or both."""
    await flux_client.get(ENDPOINT, params={"filename": "file:///app/.env"},
                          headers={"X-Forwarded-For": "203.0.113.22"})
    rsc = _log_entries(flux_client.log_path)[-1]["result"]
    await flux_client.get("/@fs/app/.env",
                          headers={"X-Forwarded-For": "203.0.113.22"})
    fs = _log_entries(flux_client.log_path)[-1]["result"]
    assert rsc.startswith("vite-rsc-sourcemap-")
    assert fs.startswith("vite-fs-")
    assert rsc != fs
    # Same underlying trap, different prefix.
    assert rsc[len("vite-rsc-sourcemap-"):] == fs[len("vite-fs-"):]


async def test_body_is_byte_identical_to_the_fs_spelling(flux_client):
    """The shared read path's contract: one filename, one body, whichever
    surface asked.

    Checked on a system file, because that is the only part of the read
    surface where byte-identity is the right assertion — every
    credential-bearing renderer is per-hit unique by design, so two reads
    of `/app/.env` differ from each other on one surface too. Those are
    covered by the resolution tests above, which assert both spellings
    reach the same renderer.
    """
    r1 = await flux_client.get(ENDPOINT, params={"filename": "file:///etc/passwd"},
                               headers={"X-Forwarded-For": "203.0.113.23"})
    r2 = await flux_client.get("/@fs/etc/passwd",
                               headers={"X-Forwarded-For": "203.0.113.23"})
    assert r1.status == r2.status == 200
    assert await r1.read() == await r2.read()
    assert r1.headers["Content-Type"] == r2.headers["Content-Type"]


async def test_system_file_read_is_served_and_tagged(flux_client):
    """The read oracle a scanner confirms the primitive with, before it
    walks to the credential files."""
    resp = await flux_client.get(ENDPOINT, params={"filename": "file:///etc/passwd"},
                                 headers={"X-Forwarded-For": "203.0.113.28"})
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"].startswith("vite-rsc-sourcemap-")
    assert entry["result"] != "vite-rsc-sourcemap-miss"
    assert entry["viteRscSourcemapRequestedPath"] == "/etc/passwd"


async def test_miss_is_a_404_and_still_logs_the_path(flux_client):
    resp = await flux_client.get(ENDPOINT, params={"filename": "file:///etc/hosts"},
                                 headers={"X-Forwarded-For": "203.0.113.24"})
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "vite-rsc-sourcemap-miss"
    assert entry["viteRscSourcemapRequestedPath"] == "/etc/hosts"


async def test_ssrf_shaped_request_is_not_answered_as_a_file(flux_client):
    resp = await flux_client.get(
        ENDPOINT, params={"filename": "http://169.254.169.254/latest/meta-data/"},
        headers={"X-Forwarded-For": "203.0.113.25"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert not entry["result"].startswith("vite-rsc-sourcemap-")


async def test_disabled_falls_through(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "VITE_RSC_SOURCEMAP_ENABLED", False)
    resp = await flux_client.get(ENDPOINT, params={"filename": "file:///app/.env"},
                                 headers={"X-Forwarded-For": "203.0.113.26"})
    entry = _log_entries(flux_client.log_path)[-1]
    assert not entry["result"].startswith("vite-rsc-sourcemap-")
    assert resp.status != 200 or b"AKIAFAKEEXAMPLE01" not in await resp.read()


async def test_no_api_key_does_not_serve_the_trap(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(ENDPOINT, params={"filename": "file:///app/.env"},
                                 headers={"X-Forwarded-For": "203.0.113.27"})
    entry = _log_entries(flux_client.log_path)[-1]
    assert not entry["result"].startswith("vite-rsc-sourcemap-")
    assert resp.status != 200 or b"AKIAFAKEEXAMPLE01" not in await resp.read()
