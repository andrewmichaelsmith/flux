"""Tests for the Check Point Mobile Access / Gaia trap and its
CVE-2024-24919 read primitive.

Three things are worth asserting here and they are quite different from
each other:

1. **Surface classification.** The portal, the management UI and the read
   endpoint are three different answers, and the trap is only worth
   having if a log reader can tell which one a source asked for.
2. **Body parsing.** The traversal rides in the request body, so unlike
   every path-matched trap the signature is not in anything dispatch has
   already normalised. The parser is the trap.
3. **Credential hygiene.** Nothing secret-shaped in these responses may
   be a fixed literal, because the same code runs on every deployment.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- Surface classification (pure) --------------------------------------


@pytest.mark.parametrize("path,expected", [
    ("/sslvpn/Login/Login", "portal"),
    ("/sslvpn/login/login", "portal"),
    ("/SSLVPN/LOGIN/LOGIN", "portal"),
    ("/Login/Login", "portal"),
    ("/sslvpn/", "portal"),
    ("/sslvpn", "portal"),
    ("/sslvpn/Portal/Main", "portal"),
    ("/sslvpn/Login/Login?RelayState=abc", "portal"),
    ("/cgi-bin/home.tcl", "gaia"),
    ("/clients/MyCRL", "read"),
    ("/clients/mycrl", "read"),
    ("/clients/MyCRL?", "read"),
])
def test_surfaces_are_classified(path, expected):
    assert tbenv.checkpoint_surface(path) == expected


@pytest.mark.parametrize("path", [
    "/",
    "/login",                    # the generic web-app form owns this
    "/login/login.html",         # a different vendor's spelling
    "/login/login.cgi",
    "/sslvpn/portal.html",       # owned by the FortiOS portal
    "/sslvpnclient",             # owned by the F5 trap
    "/clients/.env",             # a credential dredge, not the CRL client
    "/clients/",
    "/cgi-bin/home.cgi",
])
def test_neighbouring_paths_are_not_claimed(path):
    """Every one of these is a path some other trap owns or that means
    something else entirely. Claiming them would move an existing route,
    which is a regression this trap must not cause."""
    assert tbenv.checkpoint_surface(path) == ""


def test_switch_disables_every_surface(monkeypatch):
    monkeypatch.setattr(tbenv, "CHECKPOINT_ENABLED", False)
    for path in ("/sslvpn/Login/Login", "/cgi-bin/home.tcl", "/clients/MyCRL"):
        assert tbenv.checkpoint_surface(path) == ""
        assert tbenv.is_checkpoint_path(path) is False


# --- Read-primitive body parsing (pure) ---------------------------------


@pytest.mark.parametrize("body,expected", [
    # The published proof-of-concept shape.
    (b"aCSHELL/../../../../../../../etc/shadow", "/etc/shadow"),
    # Fewer / more traversal segments, both seen in the wild.
    (b"aCSHELL/../../../etc/passwd", "/etc/passwd"),
    (b"aCSHELL/../../../../../../../../../../home/admin/.ssh/id_rsa",
     "/home/admin/.ssh/id_rsa"),
    # URL-encoded traversal.
    (b"aCSHELL/%2e%2e/%2e%2e/%2e%2e/etc/shadow", "/etc/shadow"),
    # Backslash separators.
    (b"aCSHELL\\..\\..\\..\\etc\\shadow", "/etc/shadow"),
    # Carried as a form value rather than the whole body.
    (b"file=aCSHELL/../../../../etc/shadow&submit=1", "/etc/shadow"),
])
def test_traversal_targets_are_extracted(body, expected):
    assert tbenv.extract_checkpoint_read_target(body) == expected


@pytest.mark.parametrize("body", [
    b"",
    b"aCSHELL/",                       # the endpoint's ordinary use
    b"sslvpn",
    b"file=index.html",
    b"/etc/shadow",                    # absolute, but no traversal: not the CVE
])
def test_bodies_without_a_traversal_yield_nothing(body):
    """A body with no traversal is not an exploitation attempt, and must
    not be treated as one — otherwise the log cannot separate the
    scanners checking that the endpoint exists from the ones using it."""
    assert tbenv.extract_checkpoint_read_target(body) == ""


def test_parser_does_not_depend_on_us_having_a_trap_for_the_file():
    """Parsing and resolution are separate on purpose: the requested path
    is intel even when nothing answers it."""
    assert tbenv.extract_checkpoint_read_target(
        b"aCSHELL/../../../../var/opt/some/file/we/never/heard/of"
    ) == "/var/opt/some/file/we/never/heard/of"


def test_read_resolution_shares_the_dev_server_table():
    """One filename means one document, whichever surface asked for it.
    If these two ever diverge, a source probing both learns the host is
    two different hosts."""
    requested = tbenv.extract_checkpoint_read_target(
        b"aCSHELL/../../../../root/.aws/credentials"
    )
    body_side = tbenv.resolve_fs_read(requested)
    url_side = tbenv.resolve_vite_fs("/@fs/root/.aws/credentials")
    assert body_side.trap is not None
    assert body_side.trap is url_side.trap
    assert body_side.requested_path == url_side.requested_path


# --- Credential hygiene (pure) ------------------------------------------


def test_shadow_hashes_are_minted_per_hit():
    """A fixed hash here would ship one crackable string from every host
    running this software."""
    first = tbenv.render_fake_shadow()
    second = tbenv.render_fake_shadow()
    assert first != second
    assert b"$6$" in first


def test_shadow_account_list_matches_the_passwd_body():
    """A source that reads both files must see one consistent host."""
    passwd_users = {
        line.split(b":", 1)[0]
        for line in tbenv.render_fake_passwd().splitlines() if line
    }
    shadow_users = {
        line.split(b":", 1)[0]
        for line in tbenv.render_fake_shadow().splitlines() if line
    }
    assert passwd_users <= shadow_users


def test_portal_page_carries_no_credential_material():
    body = tbenv.render_checkpoint_portal_html("vpn.example.com").lower()
    for marker in (b"akia", b"password=", b"secret", b"begin "):
        assert marker not in body


# --- End-to-end dispatch -------------------------------------------------


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
    monkeypatch.setattr(tbenv, "CHECKPOINT_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_portal_get_serves_the_login_page(flux_client):
    resp = await flux_client.get(
        "/sslvpn/Login/Login", headers={"X-Forwarded-For": "203.0.113.40"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert "Mobile Access Portal" in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "checkpoint-portal"
    assert entry["checkpointSurface"] == "portal"


async def test_gaia_and_portal_are_separable_in_the_log(flux_client):
    """The whole reason both are served: which one a source asked for
    says whether it came for the users or for the appliance."""
    await flux_client.get(
        "/cgi-bin/home.tcl", headers={"X-Forwarded-For": "203.0.113.41"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "checkpoint-gaia-portal"
    assert entry["checkpointSurface"] == "gaia"


async def test_session_cookie_is_unique_per_request(flux_client):
    first = await flux_client.get(
        "/sslvpn/Login/Login", headers={"X-Forwarded-For": "203.0.113.42"},
    )
    second = await flux_client.get(
        "/sslvpn/Login/Login", headers={"X-Forwarded-For": "203.0.113.42"},
    )
    assert first.headers["Set-Cookie"] != second.headers["Set-Cookie"]


async def test_login_post_captures_the_credential(flux_client):
    resp = await flux_client.post(
        "/sslvpn/Login/Login",
        data="userName=admin&password=Winter2026%21&selectedRealm=ldap",
        headers={
            "X-Forwarded-For": "203.0.113.43",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "checkpoint-portal-login-post"
    assert entry["checkpointUsername"] == "admin"
    assert entry["checkpointHasPassword"] is True
    assert entry["checkpointRealm"] == "ldap"


async def test_login_form_target_is_a_path_this_server_answers(flux_client):
    """A login page whose form posts into a 404 drops the credential it
    exists to collect."""
    page = await (await flux_client.get(
        "/sslvpn/Login/Login", headers={"X-Forwarded-For": "203.0.113.44"},
    )).text()
    assert 'action="/sslvpn/Login/Login"' in page
    posted = await flux_client.post(
        "/sslvpn/Login/Login", data="userName=x&password=y",
        headers={"X-Forwarded-For": "203.0.113.44"},
    )
    assert posted.status == 200


async def test_crl_probe_without_a_traversal_answers_empty(flux_client):
    """The existence check gets the endpoint's ordinary answer, not a
    404 — a 404 tells the scanner the gateway is not there at all."""
    resp = await flux_client.post(
        "/clients/MyCRL", data="aCSHELL/",
        headers={"X-Forwarded-For": "203.0.113.45"},
    )
    assert resp.status == 200
    assert await resp.read() == b""
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "checkpoint-crl-probe"


async def test_read_primitive_serves_the_canary_and_logs_the_file(flux_client):
    resp = await flux_client.post(
        "/clients/MyCRL",
        data="aCSHELL/../../../../../../../root/.aws/credentials",
        headers={"X-Forwarded-For": "203.0.113.46"},
    )
    assert resp.status == 200
    assert b"AKIAFAKEEXAMPLE01" in await resp.read()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"].startswith("checkpoint-read-")
    assert entry["checkpointReadPath"] == "/root/.aws/credentials"


async def test_read_primitive_serves_shadow_with_fresh_hashes(flux_client):
    bodies = []
    for _ in range(2):
        resp = await flux_client.post(
            "/clients/MyCRL",
            data="aCSHELL/../../../../../../../etc/shadow",
            headers={"X-Forwarded-For": "203.0.113.47"},
        )
        assert resp.status == 200
        bodies.append(await resp.read())
    assert b"root:$6$" in bodies[0]
    assert bodies[0] != bodies[1]
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "checkpoint-read-etc-shadow"


async def test_read_miss_answers_empty_200_and_still_logs_the_path(flux_client):
    """An appliance whose read found nothing still answered the request.
    404ing here would end the exchange at the first miss, and the missed
    filenames are the half of the dictionary we have chosen not to
    furnish — worth recording."""
    resp = await flux_client.post(
        "/clients/MyCRL",
        data="aCSHELL/../../../../var/opt/nothing/we/serve",
        headers={"X-Forwarded-For": "203.0.113.48"},
    )
    assert resp.status == 200
    assert await resp.read() == b""
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "checkpoint-read-miss"
    assert entry["checkpointReadPath"] == "/var/opt/nothing/we/serve"


async def test_disabled_trap_falls_through(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CHECKPOINT_ENABLED", False)
    resp = await flux_client.get(
        "/sslvpn/Login/Login", headers={"X-Forwarded-For": "203.0.113.49"},
    )
    assert resp.status == 404
