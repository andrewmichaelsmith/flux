"""Soft-404 calibration probes.

A scanner that intends to act on a 200 has to know what a miss looks
like first — a host that answers everything makes every hit worthless.
So it asks for a name nothing could be serving and keeps the answer as
its baseline. That request is a 404 among 404s and invisible to any log
keyed on status, while being the one request that says the sender's
later 200s mean something to it.

These tests pin the shapes, the exclusions that keep an ordinary route
name out, and the two properties that make the observer safe: it reads
only the path, and it changes no response byte.
"""
import pytest

import flux.server as tbenv


# Shapes taken from probe traffic, one per observed family.
@pytest.mark.parametrize("path,shape", [
    # Fixed alphabetic tag + per-probe hex. Two tags from this family
    # arrive interleaved from the same addresses.
    ("/kmonbaseqtb28219f5", "tagged-hex"),
    ("/kmonbasezd22773351", "tagged-hex"),
    ("/cmsd-4f1a9c7e22b1-404.html", "tagged-hex"),
    # Tag + counter or millisecond clock instead of hex.
    ("/odinhttpcall1791241960", "tagged-counter"),
    # Wrapped token — the wrapper is itself the tell.
    ("/__ss_probe_c93bfb6126b36888b64c4def78fdf901__", "wrapped-token"),
    # No tag at all.
    ("/7f13c0a9d8644f3ca0a563b6b56e49d7", "bare-hex"),
    ("/e7iyk7mdsz5t8d80e465", "bare-alnum"),
    ("/f90a912c-0993-4b72-8edc-ad6ecb700b97", "bare-uuid"),
])
def test_token_shapes_are_recognised(path, shape):
    out = tbenv.soft404_control_probe_scan(path)
    assert out, path
    assert shape in out["soft404ProbeShapes"], out
    assert out["soft404ProbeTokenKind"] == shape
    assert out["soft404ProbeToken"]


@pytest.mark.parametrize("path,marker", [
    ("/pscan-bf821f4b-nonexistent.txt", "nonexistent"),
    ("/nonexistent-330443700.php", "nonexistent"),
    ("/zz-nonexistent-test-8492.html", "nonexistent"),
    ("/api/nonexistent-xyz-probe", "nonexistent"),
    ("/netbot-catchall-baseline-9f3a2c7d.nonexistent", "nonexistent"),
    ("/thisfiledoesnotexist", "thisfiledoesnotexist"),
    ("/some/deep/path/doesnotexist.html", "doesnotexist"),
])
def test_declared_absence_is_recognised_at_any_depth(path, marker):
    """A word that says the sender does not expect the file is a control
    whatever else is in the path, and whatever depth it is asked at —
    nobody deploys a file called `doesnotexist`."""
    out = tbenv.soft404_control_probe_scan(path)
    assert out, path
    assert "declared-absent" in out["soft404ProbeShapes"]
    assert out["soft404ProbeMarker"] == marker


def test_a_weak_marker_beside_a_token_is_reported_as_hinted():
    out = tbenv.soft404_control_probe_scan("/scnr-probe-404-b7e21c9a4f")
    assert out
    assert "hinted" in out["soft404ProbeShapes"]


@pytest.mark.parametrize("path", [
    # Ordinary route names. A weak marker alone never promotes.
    "/probe",
    "/baseline",
    "/healthcheck",
    "/404.html",
    "/404",
    "/test",
    "/status",
    "/api/v1/health",
    # Dictionary entries flux answers. These are filenames, not tokens.
    "/.env",
    "/wp-login.php",
    "/config.php.bak",
    "/.aws/credentials",
    "/appsettings.production.json",
    "/web.config",
    # Short alphanumerics a dictionary walks. Too short to be a token,
    # and promoting them would flag half a sweep.
    "/aaa9",
    "/aab9",
    "/v1",
    "/sdk",
    "/admin",
    # Content-hashed build artefacts — the one filename that is
    # legitimately high-entropy.
    "/main.9f2a1b3c4d5e6f70.js",
    "/a7f3c9d2e1b40582.css",
    "/4f1a9c7e22b1aa03.woff2",
    "/d41d8cd98f00b204e9800998ecf8427e.png",
    # Deep high-entropy names: an object key or a content-addressed blob,
    # which is where these legitimately live.
    "/objects/7f13c0a9d8644f3ca0a563b6b56e49d7",
    "/.git/objects/4f/1a9c7e22b1aa0355d2e9f8b7c6a4e3d2c1b0a9f8",
])
def test_ordinary_names_are_not_flagged(path):
    assert tbenv.soft404_control_probe_scan(path) == {}, path


def test_a_hashed_asset_still_counts_when_absence_is_declared():
    """The asset-extension exclusion is about entropy being explainable,
    not about the extension granting immunity. A name that says it is
    absent is still a control however it ends."""
    out = tbenv.soft404_control_probe_scan("/nonexistent-4f1a9c7e22b1.js")
    assert out
    assert "declared-absent" in out["soft404ProbeShapes"]


def test_the_token_is_reported_so_a_reused_one_is_countable():
    """A per-run random token groups by nothing. A token hardcoded in a
    tool groups every address running it, which is the more useful of the
    two outcomes and the reason the value is logged rather than a flag."""
    a = tbenv.soft404_control_probe_scan("/7f13c0a9d8644f3ca0a563b6b56e49d7")
    b = tbenv.soft404_control_probe_scan("/7f13c0a9d8644f3ca0a563b6b56e49d7")
    assert a["soft404ProbeToken"] == b["soft404ProbeToken"]
    c = tbenv.soft404_control_probe_scan("/7f13c0a9d8644f3ca0a563b6b56e49d8")
    assert c["soft404ProbeToken"] != a["soft404ProbeToken"]


def test_the_token_is_bounded():
    out = tbenv.soft404_control_probe_scan("/tag" + "a" * 4000 + "1")
    # Either it does not match at all or the reported token is capped;
    # what must not happen is an unbounded field reaching the log.
    if out:
        assert len(out["soft404ProbeToken"]) <= tbenv.SOFT404_PROBE_TOKEN_LIMIT


def test_disabled_by_env(monkeypatch):
    monkeypatch.setattr(tbenv, "SOFT404_PROBE_ENABLED", False)
    assert tbenv.soft404_control_probe_scan("/7f13c0a9d8644f3ca0a563b6b56e49d7") == {}


def test_scan_reads_only_the_path():
    """No body, no headers, no response. The signature is the contract:
    an observer that needed the body would cost a read on every request
    for a signal the name already carries."""
    import inspect
    sig = inspect.signature(tbenv.soft404_control_probe_scan)
    assert list(sig.parameters) == ["path"]


# --- End to end: the field is stamped, the response is untouched ---------

import json

import pytest_asyncio


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "SOFT404_PROBE_ENABLED", True)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _last(log_path):
    return json.loads(log_path.read_text().splitlines()[-1])


async def test_the_field_reaches_the_log_line(flux_client):
    resp = await flux_client.get("/__ss_probe_c93bfb6126b36888b64c4def78fdf901__")
    await resp.read()
    entry = _last(flux_client.log_path)
    assert "wrapped-token" in entry["soft404ProbeShapes"]
    assert entry["soft404ProbeToken"] == "c93bfb6126b36888b64c4def78fdf901"


async def test_the_response_is_byte_identical_to_an_unrecognised_miss(flux_client):
    """The load-bearing property. A probe answered even slightly
    differently from an ordinary miss would let any sender separate this
    host from a real one by sending a token and diffing the answer."""
    probe = await flux_client.get("/7f13c0a9d8644f3ca0a563b6b56e49d7")
    probe_body = await probe.read()
    # Same length, same shape, but not a recognised token — a plain name.
    plain = await flux_client.get("/zzzzzzzz-not-a-token-at-all-here")
    plain_body = await plain.read()

    assert probe.status == plain.status
    assert probe_body == plain_body
    assert probe.headers.get("Content-Type") == plain.headers.get("Content-Type")
    # And the log lines prove the two were classified differently, so the
    # identical response is not simply the observer failing to fire.
    entries = [json.loads(l) for l in flux_client.log_path.read_text().splitlines()]
    assert "soft404ProbeShapes" in entries[-2]
    assert "soft404ProbeShapes" not in entries[-1]


async def test_a_probe_against_a_path_a_trap_owns_still_gets_the_trap(flux_client):
    """The observer annotates; it never intercepts. A sweep that sprays a
    token into a path we answer must still get the answer."""
    resp = await flux_client.get("/nonexistent/../wp-login.php")
    await resp.read()
    assert resp.status == 200
