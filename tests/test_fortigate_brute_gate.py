"""Tests for the FortiOS SSL VPN credential-sink conversion gate.

`/remote/logincheck` is the busiest credential POST surface this honeypot
exposes, and it used to reject every guess identically. That recorded the
dictionary and nothing about what an operator does with a credential that
works, because none ever did.

The gate lets a source find exactly one credential after it has burned a
per-source number of attempts, then serves the post-authentication portal
that a real successful login lands on. These tests pin the three
properties that make the surface believable: the first guess never works,
only one pair ever works, and a rejection carries no session.
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
def _clear_brute_state():
    """Per-source state is module-level; keep tests independent."""
    tbenv._FORTIGATE_BRUTE_STATE.clear()
    yield
    tbenv._FORTIGATE_BRUTE_STATE.clear()


def _log_entries(log_path):
    if not log_path.exists():
        return []
    return [
        json.loads(line)
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]


async def _post_cred(client, ip, username, password):
    return await client.post(
        "/remote/logincheck",
        data=f"username={username}&credential={password}",
        headers={
            "X-Forwarded-For": ip,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )


async def _threshold_for(client, ip):
    """The gate keys on (source, host); the test client's host is only
    knowable from a served request, so ask the log what it was."""
    await _post_cred(client, ip, "probe", "probe")
    host = _log_entries(client.log_path)[-1].get("host", "")
    tbenv._FORTIGATE_BRUTE_STATE.clear()
    return tbenv._fortigate_accept_threshold(ip, host)


# --------------------------------------------------------------------------
# threshold derivation
# --------------------------------------------------------------------------

def test_threshold_sits_inside_the_configured_band():
    for i in range(64):
        threshold = tbenv._fortigate_accept_threshold(f"198.51.100.{i}")
        assert tbenv.FORTIGATE_VPN_ACCEPT_MIN_ATTEMPTS <= threshold
        assert threshold <= tbenv.FORTIGATE_VPN_ACCEPT_MAX_ATTEMPTS


def test_threshold_is_stable_per_source():
    assert (
        tbenv._fortigate_accept_threshold("198.51.100.7")
        == tbenv._fortigate_accept_threshold("198.51.100.7")
    )


def test_threshold_varies_across_sources():
    """A fleet-wide constant would fingerprint the trap itself."""
    seen = {tbenv._fortigate_accept_threshold(f"198.51.100.{i}") for i in range(64)}
    assert len(seen) > 1


def test_threshold_varies_across_hosts_for_one_source():
    """Otherwise one operator sees the same threshold on every host they
    hit, which is the same constant measured a different way."""
    ip = "198.51.100.20"
    seen = {tbenv._fortigate_accept_threshold(ip, f"vpn{i}.example.com") for i in range(64)}
    assert len(seen) > 1


def test_state_is_scoped_per_host():
    ip = "198.51.100.21"
    tbenv.fortigate_evaluate_credential(ip, "admin", "pw", "a.example.com")
    _, _, attempts = tbenv.fortigate_evaluate_credential(ip, "admin", "pw", "b.example.com")
    assert attempts == 1, "a second host should start its own count"


# --------------------------------------------------------------------------
# credential identity
# --------------------------------------------------------------------------

def test_credential_id_is_stable_and_pair_specific():
    a = tbenv.fortigate_credential_id("admin", "hunter2")
    assert a == tbenv.fortigate_credential_id("admin", "hunter2")
    assert a != tbenv.fortigate_credential_id("admin", "hunter3")
    assert a != tbenv.fortigate_credential_id("root", "hunter2")


def test_credential_id_does_not_leak_the_secret():
    assert "hunter2" not in tbenv.fortigate_credential_id("admin", "hunter2")


def test_credential_id_separates_pairs_that_concatenate_alike():
    """`ab` + `c` and `a` + `bc` must not collide."""
    assert (
        tbenv.fortigate_credential_id("ab", "c")
        != tbenv.fortigate_credential_id("a", "bc")
    )


# --------------------------------------------------------------------------
# gate behaviour
# --------------------------------------------------------------------------

def test_first_guess_is_always_rejected():
    accepted, _, attempts = tbenv.fortigate_evaluate_credential(
        "198.51.100.10", "admin", "admin",
    )
    assert accepted is False
    assert attempts == 1


def test_source_converts_once_past_its_threshold():
    ip = "198.51.100.11"
    threshold = tbenv._fortigate_accept_threshold(ip)
    accepts = [
        tbenv.fortigate_evaluate_credential(ip, "admin", f"pw{i}")[0]
        for i in range(threshold)
    ]
    assert accepts.count(True) == 1
    assert accepts[-1] is True, "acceptance should land on the threshold attempt"


def test_only_the_found_credential_keeps_working():
    ip = "198.51.100.12"
    threshold = tbenv._fortigate_accept_threshold(ip)
    for i in range(threshold - 1):
        tbenv.fortigate_evaluate_credential(ip, "admin", f"pw{i}")
    accepted, newly, _ = tbenv.fortigate_evaluate_credential(ip, "admin", "winner")
    assert (accepted, newly) == (True, True)

    # The pair that worked keeps working...
    assert tbenv.fortigate_evaluate_credential(ip, "admin", "winner")[0] is True
    # ...and nothing else starts working.
    assert tbenv.fortigate_evaluate_credential(ip, "admin", "other")[0] is False
    assert tbenv.fortigate_evaluate_credential(ip, "root", "winner")[0] is False


def test_first_accept_is_reported_once():
    ip = "198.51.100.13"
    threshold = tbenv._fortigate_accept_threshold(ip)
    firsts = [
        tbenv.fortigate_evaluate_credential(ip, "admin", "winner")[1]
        for _ in range(threshold + 3)
    ]
    assert firsts.count(True) == 1


def test_sources_convert_independently():
    a, b = "198.51.100.14", "198.51.100.15"
    for i in range(tbenv._fortigate_accept_threshold(a)):
        tbenv.fortigate_evaluate_credential(a, "admin", f"pw{i}")
    # `a` has converted; `b` has never been seen and must not inherit it.
    assert tbenv.fortigate_evaluate_credential(b, "admin", "pw0")[0] is False


def test_incomplete_pairs_never_convert():
    """A session the operator cannot reproduce is worse than no session."""
    ip = "198.51.100.16"
    threshold = tbenv._fortigate_accept_threshold(ip)
    for _ in range(threshold + 5):
        accepted, _, _ = tbenv.fortigate_evaluate_credential(ip, "admin", "")
        assert accepted is False
    for _ in range(5):
        accepted, _, _ = tbenv.fortigate_evaluate_credential(ip, "", "pw")
        assert accepted is False


def test_brute_state_is_bounded(monkeypatch):
    monkeypatch.setattr(tbenv, "FORTIGATE_VPN_BRUTE_STATE_MAX_ENTRIES", 32)
    for i in range(400):
        tbenv.fortigate_evaluate_credential(f"203.0.113.{i // 4}.{i % 4}", "u", "p")
    assert len(tbenv._FORTIGATE_BRUTE_STATE) <= 32


def test_expired_state_is_dropped():
    ip = "198.51.100.17"
    tbenv.fortigate_evaluate_credential(ip, "admin", "pw")
    key = next(iter(tbenv._FORTIGATE_BRUTE_STATE))
    assert key.startswith(ip)
    tbenv._FORTIGATE_BRUTE_STATE[key]["expiry"] = 0.0
    tbenv.fortigate_evaluate_credential("198.51.100.18", "admin", "pw")
    assert key not in tbenv._FORTIGATE_BRUTE_STATE


# --------------------------------------------------------------------------
# response shapes
# --------------------------------------------------------------------------

def test_success_and_failure_bodies_are_distinguishable():
    ok = tbenv.render_fortigate_logincheck_success().decode()
    bad = tbenv.render_fortigate_logincheck().decode()
    assert ok != bad
    assert "error=1" in bad
    assert "error=1" not in ok
    assert "/remote/portal" in ok


def test_portal_names_only_urls_it_serves():
    html = tbenv.render_fortigate_portal_html("vpn.example.com", "7.4.4").decode()
    assert "/remote/portal.css" in html
    assert "/remote/network" in html
    for slug, _label in tbenv._FORTIGATE_PORTAL_BOOKMARKS:
        assert f"bookmark={slug}" in html


def test_portal_carries_no_credential_shaped_material():
    html = tbenv.render_fortigate_portal_html("vpn.example.com", "7.4.4").decode().lower()
    for marker in ("password", "passwd", "secret", "api_key", "token", "credential"):
        assert marker not in html


def test_portal_escapes_the_host():
    html = tbenv.render_fortigate_portal_html('"><script>x</script>', "7.4.4").decode()
    assert "<script>" not in html


# --------------------------------------------------------------------------
# end-to-end through the handler
# --------------------------------------------------------------------------

async def test_rejected_login_sets_no_session_cookie(flux_client):
    resp = await _post_cred(flux_client, "198.51.100.30", "admin", "admin")
    assert resp.status == 200
    assert "SVPNCOOKIE=" not in resp.headers.get("Set-Cookie", "")
    assert "error=1" in await resp.text()


async def test_accepted_login_sets_session_and_redirects_to_portal(flux_client):
    ip = "198.51.100.31"
    threshold = await _threshold_for(flux_client, ip)
    for i in range(threshold - 1):
        await _post_cred(flux_client, ip, "admin", f"pw{i}")
    resp = await _post_cred(flux_client, ip, "admin", "winner")

    assert resp.status == 200
    text = await resp.text()
    assert "/remote/portal" in text
    assert "error=1" not in text
    assert "SVPNCOOKIE=" in resp.headers.get("Set-Cookie", "")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fortigate-logincheck-accepted"
    assert entry["fortigateAccepted"] is True
    assert entry["fortigateFirstAccept"] is True
    assert entry["fortigateAttempt"] == threshold
    # The join key is present, and it is a hash rather than the pair it
    # was derived from. (The raw POST body still reaches `bodyPreview`,
    # which is the deliberate payload-capture field every trap shares —
    # the gate's own fields add no new exposure.)
    assert entry["fortigateCredentialId"] == tbenv.fortigate_credential_id("admin", "winner")
    assert "winner" not in entry["fortigateCredentialId"]
    assert "credential" not in entry


async def test_session_cookie_is_unique_per_acceptance(flux_client):
    cookies = []
    for ip in ("198.51.100.32", "198.51.100.33"):
        threshold = await _threshold_for(flux_client, ip)
        for i in range(threshold - 1):
            await _post_cred(flux_client, ip, "admin", f"pw{i}")
        resp = await _post_cred(flux_client, ip, "admin", "winner")
        cookies.append(resp.headers.get("Set-Cookie", ""))
    assert all("SVPNCOOKIE=" in c for c in cookies)
    assert cookies[0] != cookies[1]


async def test_credential_id_logged_on_rejected_attempts_too(flux_client):
    """Replay analysis needs the join key on every attempt, not just hits."""
    await _post_cred(flux_client, "198.51.100.34", "admin", "admin")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["fortigateCredentialId"] == tbenv.fortigate_credential_id("admin", "admin")
    assert entry["fortigateAccepted"] is False


async def test_portal_serves_and_records_session_presence(flux_client):
    resp = await flux_client.get(
        "/remote/portal", headers={"X-Forwarded-For": "198.51.100.35"},
    )
    assert resp.status == 200
    assert "Bookmarks" in await resp.text()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fortigate-portal"
    assert entry["fortigatePortalHasSession"] is False

    resp = await flux_client.get(
        "/remote/portal",
        headers={"X-Forwarded-For": "198.51.100.35", "Cookie": "SVPNCOOKIE=deadbeef"},
    )
    assert resp.status == 200
    assert _log_entries(flux_client.log_path)[-1]["fortigatePortalHasSession"] is True


async def test_portal_records_which_bookmark_was_taken(flux_client):
    resp = await flux_client.get(
        "/remote/portal?bookmark=ssh-build01",
        headers={"X-Forwarded-For": "198.51.100.36"},
    )
    assert resp.status == 200
    assert _log_entries(flux_client.log_path)[-1]["fortigateBookmark"] == "ssh-build01"


async def test_portal_alias_and_assets_answer(flux_client):
    for path, marker in (
        ("/sslvpn/portal.html", "Bookmarks"),
        ("/remote/network", "tunnel"),
        ("/remote/portal.css", "sslvpn"),
    ):
        resp = await flux_client.get(path, headers={"X-Forwarded-For": "198.51.100.37"})
        assert resp.status == 200, path
        assert marker in (await resp.text()).lower() or marker in await resp.text()


async def test_logout_clears_the_session(flux_client):
    resp = await flux_client.get(
        "/remote/logout", headers={"X-Forwarded-For": "198.51.100.38"},
    )
    assert resp.status == 200
    assert "Max-Age=0" in resp.headers.get("Set-Cookie", "")


async def test_gate_off_never_accepts_through_the_handler(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "FORTIGATE_VPN_ACCEPT_ENABLED", False)
    ip = "198.51.100.39"
    threshold = tbenv._fortigate_accept_threshold(ip)
    for i in range(threshold + 5):
        resp = await _post_cred(flux_client, ip, "admin", f"pw{i}")
        assert "SVPNCOOKIE=" not in resp.headers.get("Set-Cookie", "")
    assert _log_entries(flux_client.log_path)[-1]["result"] == "fortigate-logincheck"
