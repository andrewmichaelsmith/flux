"""Tests for the RD Web Access credential-sink conversion gate.

The remote-desktop login POST is the busiest credential surface this
honeypot exposes, and it used to answer *every* guess with the post-auth
resource list. That is the mirror image of the failure the FortiOS gate
was built for: a sink that accepts everything records the dictionary and
nothing about what an operator does with a credential that works, spends
an upstream canary on every guess, and tells any client that submits two
passwords for one account that it is not talking to a real deployment.

The gate lets a source find exactly one credential after it has burned a
per-source number of attempts, then serves the resource list a real
successful logon lands on. These tests pin the properties that make the
surface believable: the first guess never works, only one pair ever
works, a rejection carries no session and no canary, and the threshold is
not a constant across the fleet.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio

from flux import server as tbenv

FAKE_TRACEBIT = {
    "aws": {
        "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
        "awsSecretAccessKey": "wJalrXUtnFEMIfakeexamplekey",
        "awsSessionToken": "FAKESESSIONTOKEN",
    },
}


async def _fake_canary(*args, **kwargs):
    return FAKE_TRACEBIT


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


@pytest.fixture(autouse=True)
def _clear_brute_state():
    """Per-source state is module-level; keep tests independent."""
    tbenv._RDWEB_BRUTE_STATE.clear()
    yield
    tbenv._RDWEB_BRUTE_STATE.clear()


def _log_entries(log_path):
    if not log_path.exists():
        return []
    return [
        json.loads(line)
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]


async def _post_cred(client, ip, username, password, path="/RDWeb/Pages/en-US/login.aspx"):
    return await client.post(
        path,
        data=f"DomainUserName={username}&UserPass={password}&MachineType=private",
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
    tbenv._RDWEB_BRUTE_STATE.clear()
    return tbenv._rdweb_accept_threshold(ip, host)


# --------------------------------------------------------------------------
# threshold derivation
# --------------------------------------------------------------------------

def test_threshold_sits_inside_the_configured_band():
    for i in range(64):
        threshold = tbenv._rdweb_accept_threshold(f"198.51.100.{i}")
        assert tbenv.RDWEB_ACCEPT_MIN_ATTEMPTS <= threshold
        assert threshold <= tbenv.RDWEB_ACCEPT_MAX_ATTEMPTS


def test_threshold_is_stable_per_source():
    assert (
        tbenv._rdweb_accept_threshold("198.51.100.7")
        == tbenv._rdweb_accept_threshold("198.51.100.7")
    )


def test_threshold_varies_across_sources():
    """A fleet-wide constant would fingerprint the trap itself."""
    seen = {tbenv._rdweb_accept_threshold(f"198.51.100.{i}") for i in range(64)}
    assert len(seen) > 1


def test_threshold_varies_across_hosts_for_one_source():
    ip = "198.51.100.20"
    seen = {tbenv._rdweb_accept_threshold(ip, f"rdweb{i}.example.com") for i in range(64)}
    assert len(seen) > 1


def test_threshold_differs_from_the_vpn_sink_for_one_source_and_host():
    """A source working both credential sinks on one host must not find
    them give way on the same attempt number."""
    differ = 0
    for i in range(64):
        ip = f"198.51.100.{i}"
        a = tbenv._brute_accept_threshold("rdweb", ip, "h.example", 1, 4096)
        b = tbenv._brute_accept_threshold("fortigate-sslvpn", ip, "h.example", 1, 4096)
        differ += int(a != b)
    assert differ == 64


def test_state_is_scoped_per_host():
    ip = "198.51.100.21"
    tbenv.rdweb_evaluate_credential(ip, "admin", "pw", "a.example.com")
    _, _, attempts = tbenv.rdweb_evaluate_credential(ip, "admin", "pw", "b.example.com")
    assert attempts == 1, "a second host should start its own count"


def test_state_is_separate_from_the_vpn_sink():
    """Guesses spent on one surface must not advance the other's count."""
    ip = "198.51.100.22"
    tbenv._FORTIGATE_BRUTE_STATE.clear()
    try:
        for i in range(5):
            tbenv.fortigate_evaluate_credential(ip, "admin", f"pw{i}", "h.example")
        _, _, attempts = tbenv.rdweb_evaluate_credential(ip, "admin", "pw", "h.example")
        assert attempts == 1
    finally:
        tbenv._FORTIGATE_BRUTE_STATE.clear()


# --------------------------------------------------------------------------
# credential identity
# --------------------------------------------------------------------------

def test_credential_id_is_stable_and_pair_specific():
    a = tbenv.rdweb_credential_id("admin", "hunter2")
    assert a == tbenv.rdweb_credential_id("admin", "hunter2")
    assert a != tbenv.rdweb_credential_id("admin", "hunter3")
    assert a != tbenv.rdweb_credential_id("root", "hunter2")


def test_credential_id_does_not_leak_the_secret():
    assert "hunter2" not in tbenv.rdweb_credential_id("admin", "hunter2")


def test_credential_id_separates_pairs_that_concatenate_alike():
    assert tbenv.rdweb_credential_id("ab", "c") != tbenv.rdweb_credential_id("a", "bc")


def test_credential_id_is_the_shared_join_key():
    """The same pair submitted to either sink produces the same id; that
    is what makes "one dictionary, several surfaces" measurable."""
    assert (
        tbenv.rdweb_credential_id("admin", "hunter2")
        == tbenv.fortigate_credential_id("admin", "hunter2")
    )


# --------------------------------------------------------------------------
# gate behaviour
# --------------------------------------------------------------------------

def test_first_guess_is_always_rejected():
    accepted, _, attempts = tbenv.rdweb_evaluate_credential(
        "198.51.100.10", "admin", "admin",
    )
    assert accepted is False
    assert attempts == 1


def test_source_converts_once_past_its_threshold():
    ip = "198.51.100.11"
    threshold = tbenv._rdweb_accept_threshold(ip)
    accepts = [
        tbenv.rdweb_evaluate_credential(ip, "admin", f"pw{i}")[0]
        for i in range(threshold)
    ]
    assert accepts.count(True) == 1
    assert accepts[-1] is True, "acceptance should land on the threshold attempt"


def test_only_the_found_credential_keeps_working():
    ip = "198.51.100.12"
    threshold = tbenv._rdweb_accept_threshold(ip)
    for i in range(threshold - 1):
        tbenv.rdweb_evaluate_credential(ip, "admin", f"pw{i}")
    accepted, newly, _ = tbenv.rdweb_evaluate_credential(ip, "admin", "winner")
    assert (accepted, newly) == (True, True)
    assert tbenv.rdweb_evaluate_credential(ip, "admin", "winner")[0] is True
    assert tbenv.rdweb_evaluate_credential(ip, "admin", "other")[0] is False
    assert tbenv.rdweb_evaluate_credential(ip, "someone", "winner")[0] is False


def test_first_accept_is_reported_once():
    ip = "198.51.100.13"
    threshold = tbenv._rdweb_accept_threshold(ip)
    firsts = [
        tbenv.rdweb_evaluate_credential(ip, "admin", "winner")[1]
        for _ in range(threshold + 3)
    ]
    assert firsts.count(True) == 1


def test_sources_convert_independently():
    a, b = "198.51.100.14", "198.51.100.15"
    threshold_a = tbenv._rdweb_accept_threshold(a)
    for i in range(threshold_a):
        tbenv.rdweb_evaluate_credential(a, "admin", f"pw{i}")
    assert tbenv.rdweb_evaluate_credential(b, "admin", "pw0")[0] is False


def test_incomplete_pairs_never_convert():
    """A pair we cannot identify would hand over a session the operator
    could not reproduce."""
    ip = "198.51.100.16"
    threshold = tbenv._rdweb_accept_threshold(ip)
    for _ in range(threshold + 5):
        accepted, _, _ = tbenv.rdweb_evaluate_credential(ip, "admin", "")
        assert accepted is False
    for _ in range(threshold + 5):
        accepted, _, _ = tbenv.rdweb_evaluate_credential(ip, "", "pw")
        assert accepted is False


def test_brute_state_is_bounded(monkeypatch):
    monkeypatch.setattr(tbenv, "RDWEB_BRUTE_STATE_MAX_ENTRIES", 8)
    for i in range(64):
        tbenv.rdweb_evaluate_credential(f"203.0.113.{i}", "admin", "pw")
    assert len(tbenv._RDWEB_BRUTE_STATE) <= 8


def test_expired_state_is_dropped(monkeypatch):
    monkeypatch.setattr(tbenv, "RDWEB_BRUTE_STATE_TTL_SECONDS", 60)
    tbenv.rdweb_evaluate_credential("198.51.100.17", "admin", "pw")
    assert tbenv._RDWEB_BRUTE_STATE
    tbenv._rdweb_prune_brute_state(__import__("time").time() + 3600)
    assert not tbenv._RDWEB_BRUTE_STATE


# --------------------------------------------------------------------------
# served responses
# --------------------------------------------------------------------------

async def test_rejected_post_returns_the_logon_page_with_an_error_and_no_session(
    flux_client,
):
    resp = await _post_cred(flux_client, "198.51.100.30", "admin", "hunter2")
    assert resp.status == 200
    text = await resp.text()
    assert "The user name or password is incorrect" in text
    assert "UserPass" in text, "the form itself is still there to post again"
    assert "RemoteApp and Desktop Connections" not in text
    assert "TSWAAuthHttpOnlyCookie" not in resp.headers.get("Set-Cookie", "")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-login-post"
    assert entry["rdwebAccepted"] is False
    assert entry["rdwebAttempt"] == 1
    assert entry["rdwebUsername"] == "admin"
    assert entry["rdwebHasPassword"] is True
    assert entry["rdwebCredentialId"] == tbenv.rdweb_credential_id("admin", "hunter2")
    assert "canaryTypes" not in entry
    assert "hunter2" not in json.dumps(
        {k: v for k, v in entry.items() if k != "bodyPreview"},
    )


async def test_rejected_post_mints_no_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    calls = []

    async def _counting_canary(*args, **kwargs):
        calls.append(args)
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _counting_canary)
    resp = await _post_cred(flux_client, "198.51.100.31", "admin", "hunter2")
    text = await resp.text()
    assert "AKIAFAKEEXAMPLE01" not in text
    assert calls == [], "a guess that failed is not worth an upstream issuance"


async def test_converted_source_gets_the_resource_list_a_session_and_the_canary(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    ip = "198.51.100.32"
    threshold = await _threshold_for(flux_client, ip)
    for i in range(threshold - 1):
        resp = await _post_cred(flux_client, ip, "admin", f"pw{i}")
        assert "TSWAAuthHttpOnlyCookie" not in resp.headers.get("Set-Cookie", "")
    resp = await _post_cred(flux_client, ip, "admin", "winner")
    assert resp.status == 200
    text = await resp.text()
    assert "RemoteApp and Desktop Connections" in text
    assert "AKIAFAKEEXAMPLE01" in text
    assert "TSWAAuthHttpOnlyCookie=" in resp.headers.get("Set-Cookie", "")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-login-post-accepted"
    assert entry["rdwebAccepted"] is True
    assert entry["rdwebFirstAccept"] is True
    assert entry["rdwebAttempt"] == threshold
    assert "aws" in entry["canaryTypes"]


async def test_session_cookie_is_per_request_unique_on_the_accepted_pair(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    ip = "198.51.100.33"
    threshold = await _threshold_for(flux_client, ip)
    for i in range(threshold - 1):
        await _post_cred(flux_client, ip, "admin", f"pw{i}")
    cookies = []
    for _ in range(2):
        resp = await _post_cred(flux_client, ip, "admin", "winner")
        cookies.append(resp.headers.get("Set-Cookie", ""))
    assert all("TSWAAuthHttpOnlyCookie=" in c for c in cookies)
    assert cookies[0] != cookies[1]


async def test_success_and_failure_bodies_are_distinguishable(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    ip = "198.51.100.34"
    threshold = await _threshold_for(flux_client, ip)
    failure = await (await _post_cred(flux_client, ip, "admin", "pw0")).text()
    for i in range(threshold - 2):
        await _post_cred(flux_client, ip, "admin", f"pwx{i}")
    success = await (await _post_cred(flux_client, ip, "admin", "winner")).text()
    assert failure != success


async def test_short_landing_paths_share_one_source_count(flux_client):
    """The same operator POSTing to `/RDWeb` and to the full handler URL
    is one brute, not two."""
    ip = "198.51.100.35"
    await _post_cred(flux_client, ip, "admin", "pw0", path="/RDWeb")
    await _post_cred(flux_client, ip, "admin", "pw1", path="/RDWeb/Pages")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["rdwebAttempt"] == 2


async def test_gate_off_never_accepts_through_the_handler(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "RDWEB_ACCEPT_ENABLED", False)
    ip = "198.51.100.39"
    threshold = tbenv._rdweb_accept_threshold(ip)
    for i in range(threshold + 5):
        resp = await _post_cred(flux_client, ip, "admin", f"pw{i}")
        assert "TSWAAuthHttpOnlyCookie" not in resp.headers.get("Set-Cookie", "")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "rdweb-login-post"
    assert "rdwebAttempt" not in entry
