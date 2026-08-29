"""Tests for the shell-jacking sweep gate.

The literal `WEBSHELL_PATHS` list cannot track the dictionary a shell-jacking
scanner walks — each cohort brings its own root-level `*.php` names. The sweep
gate matches the shape instead and opens only after a source has asked for
several distinct unclaimed names, so a one-off prober still sees the router's
ordinary 404 and cannot use a random filename to prove the host fabricates
responses.
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
def clear_sweep_state():
    """The gate table is module-level; keep tests independent."""
    tbenv._WEBSHELL_SWEEP_SEEN.clear()
    yield
    tbenv._WEBSHELL_SWEEP_SEEN.clear()


def log_lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --------------------------------------------------------------------------
# Candidate matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/tires.php", "/debug.php", "/database.php", "/like.php", "/test1.php",
    "/samll.php", "/aaf.php", "/2P.php", "/p.php", "/ppp.php", "/wp-info.php",
    "/25d653587fdfd1.php", "/wpconf.php", "/xenon1337.php", "/koala.php",
    "/lock360.php", "/alfa.php", "/a7.php", "/fone1.php",
])
def test_observed_sweep_names_are_candidates(path):
    assert tbenv.is_webshell_sweep_candidate(path)


@pytest.mark.parametrize("path", [
    "/index.php",            # ordinary front controller — stays 404 always
    "/home.php",
    "/main.php",
    "/wp-content/plugins/hellopress/wp_filemanager.php",  # nested: literal list
    "/admin/adminer.php",    # nested, another trap's business
    "/shell.php",            # already in the literal list
    "/x.php",                # already in the literal list
    "/notaphp.txt",
    "/",
    "",
    "/.env",
    "/dir.php/extra",        # not a single root segment
])
def test_non_candidates_are_rejected(path):
    assert not tbenv.is_webshell_sweep_candidate(path)


def test_absurdly_long_name_is_not_a_candidate():
    assert not tbenv.is_webshell_sweep_candidate("/" + "a" * 200 + ".php")


# --------------------------------------------------------------------------
# Observation bookkeeping
# --------------------------------------------------------------------------

def test_distinct_count_rises_and_repeats_do_not_inflate():
    assert tbenv.webshell_sweep_observe("198.51.100.7", "/aaf.php", now=1000.0) == 1
    assert tbenv.webshell_sweep_observe("198.51.100.7", "/koala.php", now=1000.0) == 2
    # Same path again — still 2 distinct.
    assert tbenv.webshell_sweep_observe("198.51.100.7", "/koala.php", now=1000.0) == 2
    assert tbenv.webshell_sweep_observe("198.51.100.7", "/tires.php", now=1000.0) == 3


def test_case_folding_does_not_inflate_the_count():
    tbenv.webshell_sweep_observe("198.51.100.8", "/AAF.php", now=1000.0)
    assert tbenv.webshell_sweep_observe("198.51.100.8", "/aaf.PHP", now=1000.0) == 1


def test_sources_are_tracked_independently():
    tbenv.webshell_sweep_observe("198.51.100.9", "/a.php", now=1000.0)
    tbenv.webshell_sweep_observe("198.51.100.9", "/b.php", now=1000.0)
    assert tbenv.webshell_sweep_observe("203.0.113.9", "/c.php", now=1000.0) == 1


def test_window_expiry_resets_the_count():
    tbenv.webshell_sweep_observe("198.51.100.10", "/a.php", now=1000.0)
    tbenv.webshell_sweep_observe("198.51.100.10", "/b.php", now=1000.0)
    later = 1000.0 + tbenv.WEBSHELL_SWEEP_TTL_SECONDS + 1
    # A slow prober never accumulates through the gate.
    assert tbenv.webshell_sweep_observe("198.51.100.10", "/c.php", now=later) == 1


def test_empty_source_ip_is_not_tracked():
    assert tbenv.webshell_sweep_observe("", "/a.php", now=1000.0) == 0
    assert not tbenv._WEBSHELL_SWEEP_SEEN


def test_source_table_is_bounded():
    limit = tbenv.WEBSHELL_SWEEP_MAX_SOURCES
    for i in range(limit + 50):
        tbenv.webshell_sweep_observe(f"10.0.{i // 256}.{i % 256}", "/a.php", now=1000.0)
    assert len(tbenv._WEBSHELL_SWEEP_SEEN) <= limit


def test_paths_per_source_are_bounded():
    cap = tbenv.WEBSHELL_SWEEP_MAX_PATHS_PER_SOURCE
    for i in range(cap + 25):
        count = tbenv.webshell_sweep_observe("198.51.100.11", f"/n{i}.php", now=1000.0)
    assert count <= cap


# --------------------------------------------------------------------------
# End-to-end dispatch behaviour
# --------------------------------------------------------------------------

async def test_probe_below_threshold_is_indistinguishable_from_not_handled(flux_client):
    """The whole point of the gate: a one-off prober cannot tell it exists."""
    unclaimed = await flux_client.get(
        "/zzunlikelyname.php", headers={"X-Forwarded-For": "203.0.113.20"})
    assert unclaimed.status == 404
    assert await unclaimed.read() == b"not found\n"

    control = await flux_client.get(
        "/definitely-not-a-trap.txt", headers={"X-Forwarded-For": "203.0.113.20"})
    assert control.status == 404
    assert await control.read() == b"not found\n"

    lines = log_lines(flux_client.log_path)
    tags = {line["result"] for line in lines}
    assert "webshell-sweep-observed" in tags
    assert "not-handled" in tags


async def test_gate_opens_after_threshold_and_serves_the_shell(flux_client):
    ip = "203.0.113.21"
    names = ["/aaf.php", "/koala.php", "/tires.php", "/lock360.php"]
    responses = []
    for name in names:
        responses.append(await flux_client.get(name, headers={"X-Forwarded-For": ip}))

    # First (MIN_DISTINCT - 1) stay 404; the rest are served.
    threshold = tbenv.WEBSHELL_SWEEP_MIN_DISTINCT
    for resp in responses[: threshold - 1]:
        assert resp.status == 404
    for resp in responses[threshold - 1:]:
        assert resp.status == 200

    lines = log_lines(flux_client.log_path)
    served = [line for line in lines if line["result"] == "webshell-probe"]
    assert served, "expected the gate to hand off to the webshell handler"
    assert served[0]["webshellSweepDistinct"] >= threshold


async def test_gate_opened_hit_captures_a_follow_up_command(flux_client):
    """The reason the gate is worth having: the `?cmd=` step is the intel."""
    ip = "203.0.113.22"
    for name in ["/aaf.php", "/koala.php", "/tires.php"]:
        await flux_client.get(name, headers={"X-Forwarded-For": ip})

    resp = await flux_client.get(
        "/tires.php?cmd=id;uname+-a", headers={"X-Forwarded-For": ip})
    assert resp.status == 200

    lines = log_lines(flux_client.log_path)
    commands = [line for line in lines if line["result"] == "webshell-command"]
    assert commands
    assert commands[-1]["command"] == "id;uname -a"
    assert commands[-1]["commandKey"] == "cmd"


async def test_never_list_stays_404_regardless_of_sweeping(flux_client):
    """`/home.php` and `/main.php` reach the gate and must still be refused.

    (`/index.php` is on the never-list too, but an earlier trap claims it, so
    it never gets this far — the never-list entry is defence in depth.)
    """
    ip = "203.0.113.23"
    for name in ["/aaf.php", "/koala.php", "/tires.php", "/lock360.php"]:
        await flux_client.get(name, headers={"X-Forwarded-For": ip})

    for name in ["/home.php", "/main.php"]:
        resp = await flux_client.get(name, headers={"X-Forwarded-For": ip})
        assert resp.status == 404, name
        assert await resp.read() == b"not found\n"


async def test_one_source_sweeping_does_not_open_the_gate_for_another(flux_client):
    sweeper = "203.0.113.24"
    for name in ["/aaf.php", "/koala.php", "/tires.php", "/lock360.php"]:
        await flux_client.get(name, headers={"X-Forwarded-For": sweeper})

    resp = await flux_client.get(
        "/tires.php", headers={"X-Forwarded-For": "203.0.113.25"})
    assert resp.status == 404


async def test_disabled_switch_falls_through_to_not_handled(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WEBSHELL_SWEEP_ENABLED", False)
    ip = "203.0.113.26"
    for name in ["/aaf.php", "/koala.php", "/tires.php", "/lock360.php"]:
        resp = await flux_client.get(name, headers={"X-Forwarded-For": ip})
        assert resp.status == 404

    lines = log_lines(flux_client.log_path)
    assert {line["result"] for line in lines} == {"not-handled"}


async def test_literal_list_still_answers_without_any_sweep(flux_client):
    """Regression: the gate must not have displaced the curated list."""
    resp = await flux_client.get("/shell.php", headers={"X-Forwarded-For": "203.0.113.27"})
    assert resp.status == 200
    lines = log_lines(flux_client.log_path)
    assert lines[-1]["result"] == "webshell-probe"
    assert "webshellSweepDistinct" not in lines[-1]


# --------------------------------------------------------------------------
# Nested WordPress asset directories
#
# A large share of observed shell-hunting never touches webroot: it walks
# `.php` names inside WordPress's asset directories. WordPress ships a blank
# `index.php` in each of those ("silence is golden"), so a `.php` there that
# does something is somebody's planted shell and a source walking the names
# is hunting for one. Before the nested shape was recognised this whole
# family sat on the 404 path no matter how wide a dictionary was walked.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/wp-content/uploads/index.php",
    "/wp-admin/js/index.php",
    "/wp-content/plugins/admin.php",
    "/wp-includes/ID3/about.php",
    "/wp-admin/css/colors/blue/index.php",
    "/wp-content/themes/admin.php",
    "/wp-admin/maint/index.php",
    "/wp-includes/assets/index.php",
    "/wp-content/about.php",
])
def test_nested_wordpress_names_are_candidates(path):
    assert tbenv.is_webshell_sweep_candidate(path)


@pytest.mark.parametrize("path", [
    "/wp-content/uploads/logo.png",          # not a .php leaf
    "/wp-content/plugins/hellopress/wp_filemanager.php",  # literal list's
    "/assets/js/index.php",                  # outside the fixed vocabulary
    "/vendor/wp-content/index.php",          # vocabulary must anchor at root
    "/wp-content/index.php/extra",           # .php must be the leaf
    "/wp-contentXX/uploads/index.php",       # no partial-segment matching
])
def test_nested_non_candidates_are_rejected(path):
    assert not tbenv.is_webshell_sweep_candidate(path)


def test_nested_depth_is_bounded():
    """Bounded so the widened shape cannot be walked into arbitrary nesting."""
    deep = "/wp-content" + "/a" * 8 + "/shell.php"
    assert not tbenv.is_webshell_sweep_candidate(deep)


async def test_nested_sweep_is_gated_exactly_like_the_root_sweep(flux_client):
    """The widened shape must not weaken the behavioural gate: a source
    still sees the ordinary 404 until it has walked MIN_DISTINCT names."""
    ip = "203.0.113.31"
    names = [
        "/wp-content/uploads/index.php",
        "/wp-admin/js/index.php",
        "/wp-content/plugins/admin.php",
        "/wp-includes/ID3/about.php",
    ]
    responses = [
        await flux_client.get(n, headers={"X-Forwarded-For": ip}) for n in names
    ]
    threshold = tbenv.WEBSHELL_SWEEP_MIN_DISTINCT
    for resp in responses[: threshold - 1]:
        assert resp.status == 404
    for resp in responses[threshold - 1:]:
        assert resp.status == 200

    served = [
        line for line in log_lines(flux_client.log_path)
        if line["result"] == "webshell-probe"
    ]
    assert served
    assert served[0]["webshellSweepDistinct"] >= threshold


async def test_single_nested_probe_still_looks_like_an_ordinary_404(flux_client):
    """One probe must stay indistinguishable from a host with nothing there,
    or the widened shape becomes a fingerprint."""
    resp = await flux_client.get(
        "/wp-content/uploads/index.php", headers={"X-Forwarded-For": "203.0.113.32"})
    assert resp.status == 404
    assert (await resp.read()) == b"not found\n"


async def test_nested_gate_captures_the_follow_up_command(flux_client):
    """Same payoff as the root-level gate: the `?cmd=` step is the intel."""
    ip = "203.0.113.33"
    for n in ["/wp-content/uploads/index.php", "/wp-admin/js/index.php",
              "/wp-content/plugins/admin.php"]:
        await flux_client.get(n, headers={"X-Forwarded-For": ip})

    resp = await flux_client.get(
        "/wp-content/plugins/admin.php?cmd=whoami", headers={"X-Forwarded-For": ip})
    assert resp.status == 200

    commands = [
        line for line in log_lines(flux_client.log_path)
        if line["result"] == "webshell-command"
    ]
    assert commands
    assert commands[-1]["command"] == "whoami"
