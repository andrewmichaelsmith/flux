"""Tests for the self-hosted AI / MLOps control-plane credential sinks.

Three control planes — a GitOps delivery controller and two self-hosted
RAG/LLM platforms — share one route table, one conversion gate and one
set of log fields. These tests pin the properties that make the surface
worth having: every route answers, each product answers in its own
envelope, the first guess never works, exactly one pair ever works, and
the authenticated surfaces stay shut to a caller holding somebody else's
token.
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
    tbenv._AIPLATFORM_BRUTE_STATE.clear()
    yield
    tbenv._AIPLATFORM_BRUTE_STATE.clear()


def _log_entries(log_path):
    if not log_path.exists():
        return []
    return [
        json.loads(line) for line in log_path.read_text().splitlines() if line.strip()
    ]


LOGIN_PATHS = {
    "argocd": "/api/v1/session",
    "ragflow": "/v1/user/login",
    "maxkb": "/api/user/login",
}


async def _login(client, ip, path, payload):
    return await client.post(
        path, data=json.dumps(payload),
        headers={"X-Forwarded-For": ip, "Content-Type": "application/json"},
    )


async def _host_for(client, ip):
    await _login(client, ip, "/api/v1/session", {"username": "p", "password": "p"})
    host = _log_entries(client.log_path)[-1].get("host", "")
    tbenv._AIPLATFORM_BRUTE_STATE.clear()
    return host


# --------------------------------------------------------------------------
# routing
# --------------------------------------------------------------------------

def test_every_route_resolves_to_a_product_and_surface():
    for path, (product, surface) in tbenv._AIPLATFORM_LOGIN_ROUTES.items():
        assert tbenv.is_aiplatform_login_path(path) == (product, surface)
        assert product in {"argocd", "ragflow", "maxkb"}
        assert surface in {"login", "userinfo", "inventory", "repositories"}


def test_routes_match_case_insensitively_and_ignore_query():
    assert tbenv.is_aiplatform_login_path("/API/V1/Session") == ("argocd", "login")
    assert tbenv.is_aiplatform_login_path("/v1/user/login?x=1") == ("ragflow", "login")


@pytest.mark.parametrize("path", [
    "/api/session",             # the analytics surface — a different trap
    "/api/version",             # the model-runner surface — a different trap
    "/api/v1/sessions",
    "/api/v1/session/extra",
    "/user/login",
    "/v1/user/logout",
    "/",
])
def test_unrelated_paths_are_not_claimed(path):
    assert tbenv.is_aiplatform_login_path(path) is None


async def test_analytics_surface_still_owned_by_its_own_trap(flux_client):
    """`/api/session` predates this table; claiming it here would have
    silently replaced a working chain."""
    await flux_client.post(
        "/api/session", data=json.dumps({"username": "a", "password": "b"}),
        headers={"Content-Type": "application/json"},
    )
    assert _log_entries(flux_client.log_path)[-1]["result"] == "metabase-session-login"


# --------------------------------------------------------------------------
# the conversion gate
# --------------------------------------------------------------------------

def test_threshold_sits_inside_the_configured_band():
    for i in range(64):
        threshold = tbenv._brute_accept_threshold(
            "aiplatform-login", f"198.51.100.{i}", "",
            tbenv.AIPLATFORM_LOGIN_ACCEPT_MIN_ATTEMPTS,
            tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS,
        )
        assert tbenv.AIPLATFORM_LOGIN_ACCEPT_MIN_ATTEMPTS <= threshold
        assert threshold <= tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS


def test_band_is_lower_than_the_vpn_sinks():
    """A control-plane pass tries a handful of product defaults; the VPN
    floor would mean this surface never converts for its own traffic."""
    assert (
        tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS
        < tbenv.FORTIGATE_VPN_ACCEPT_MIN_ATTEMPTS
    )


def test_first_guess_is_never_accepted():
    for i in range(64):
        accepted, _, _ = tbenv.aiplatform_evaluate_credential(
            f"203.0.113.{i}", "admin", "admin", "h.example.com",
        )
        assert accepted is False


def test_exactly_one_pair_converts_and_keeps_working():
    ip, host = "203.0.113.9", "h.example.com"
    found = None
    for i in range(tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS + 2):
        accepted, newly, _ = tbenv.aiplatform_evaluate_credential(
            ip, "admin", f"pw{i}", host,
        )
        if newly:
            found = f"pw{i}"
            break
    assert found is not None
    # Only that pair keeps working.
    assert tbenv.aiplatform_evaluate_credential(ip, "admin", found, host)[0] is True
    assert tbenv.aiplatform_evaluate_credential(ip, "admin", "other", host)[0] is False


def test_products_share_one_budget():
    """A pass walking three control planes on one host is one operator;
    making them share means the surface converts on the pass."""
    ip, host = "203.0.113.11", "h.example.com"
    for i in range(5):
        tbenv.aiplatform_evaluate_credential(ip, "argocd", f"a{i}", host)
    _, _, attempts = tbenv.aiplatform_evaluate_credential(ip, "ragflow", "r", host)
    assert attempts == 6


def test_blank_credential_cannot_be_the_found_pair():
    ip, host = "203.0.113.12", "h.example.com"
    for _ in range(tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS + 4):
        accepted, _, _ = tbenv.aiplatform_evaluate_credential(ip, "admin", "", host)
        assert accepted is False


# --------------------------------------------------------------------------
# response envelopes
# --------------------------------------------------------------------------

@pytest.mark.parametrize("product,path", sorted(LOGIN_PATHS.items()))
async def test_failed_login_uses_the_products_own_failure_shape(
    flux_client, product, path,
):
    response = await _login(
        flux_client, "203.0.113.20", path, {"username": "admin", "password": "admin"},
    )
    payload = await response.json()
    if product == "argocd":
        assert response.status == 401
        assert payload["code"] == 16
    else:
        # Both of these report failure in a 200 body, not an HTTP error.
        assert response.status == 200
        assert payload["code"] != 0 if product == "ragflow" else payload["code"] == 400
    assert "token" not in payload


@pytest.mark.parametrize("product,path", sorted(LOGIN_PATHS.items()))
async def test_failed_login_is_logged_without_the_password(
    flux_client, product, path,
):
    await _login(
        flux_client, "203.0.113.21", path,
        {"username": "someone", "password": "hunter2", "email": "someone"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "aiplatform-login"
    assert entry["aiplatformProduct"] == product
    assert entry["aiplatformHasPassword"] is True
    assert entry["aiplatformPasswordLen"] == len("hunter2")
    assert entry["aiplatformCredentialId"]
    assert "hunter2" not in json.dumps(entry)


async def test_credential_id_joins_across_products_and_surfaces(flux_client):
    """One dictionary reaching several surfaces has to be a measurable
    claim, which is what the shared pair hash is for."""
    await _login(
        flux_client, "203.0.113.22", "/api/v1/session",
        {"username": "root", "password": "toor"},
    )
    await _login(
        flux_client, "203.0.113.23", "/api/user/login",
        {"username": "root", "password": "toor"},
    )
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["aiplatformCredentialId"] == entries[-2]["aiplatformCredentialId"]
    assert entries[-1]["aiplatformCredentialId"] == tbenv.credential_pair_id("root", "toor")


async def test_form_encoded_body_is_still_read(flux_client):
    """Tooling that posts a form to a JSON endpoint is replaying a recipe
    written for a different product — worth reading, not discarding."""
    await flux_client.post(
        "/api/v1/session", data="username=admin&password=secret",
        headers={
            "X-Forwarded-For": "203.0.113.24",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["aiplatformBodyParsedJson"] is False
    assert entry["aiplatformUsername"] == "admin"
    assert entry["aiplatformPasswordLen"] == len("secret")


async def test_get_on_a_login_endpoint_does_not_spend_an_attempt(flux_client):
    response = await flux_client.get(
        "/api/v1/session", headers={"X-Forwarded-For": "203.0.113.25"},
    )
    assert response.status == 405
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "aiplatform-login-method-not-allowed"
    assert not tbenv._AIPLATFORM_BRUTE_STATE


# --------------------------------------------------------------------------
# conversion, end to end
# --------------------------------------------------------------------------

async def _convert(client, ip, path):
    """Drive one source past its threshold; return the accepted body."""
    for i in range(tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS + 4):
        response = await _login(client, ip, path, {
            "username": "admin", "email": "admin", "password": f"pw{i}",
        })
        payload = await response.json()
        if _log_entries(client.log_path)[-1]["result"] == "aiplatform-login-accepted":
            return payload
    raise AssertionError("source never converted")


async def test_argocd_conversion_returns_a_parseable_jwt(flux_client):
    payload = await _convert(flux_client, "203.0.113.30", "/api/v1/session")
    token = payload["token"]
    assert token.count(".") == 2
    import base64 as _b64
    body = token.split(".")[1]
    claims = json.loads(_b64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert claims["iss"] == "argocd"
    assert claims["exp"] > claims["iat"]


async def test_ragflow_conversion_returns_token_in_body_and_header(flux_client):
    for i in range(tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS + 4):
        response = await _login(flux_client, "203.0.113.31", "/v1/user/login", {
            "email": "admin@example.com", "password": f"pw{i}",
        })
        if _log_entries(flux_client.log_path)[-1]["result"] == "aiplatform-login-accepted":
            payload = await response.json()
            assert payload["code"] == 0
            assert payload["data"]["access_token"]
            assert response.headers["Authorization"] == payload["data"]["access_token"]
            return
    raise AssertionError("source never converted")


async def test_maxkb_conversion_returns_its_own_envelope(flux_client):
    payload = await _convert(flux_client, "203.0.113.32", "/api/user/login")
    assert payload["code"] == 200
    assert isinstance(payload["data"], str) and payload["data"]


async def test_replay_of_the_found_pair_is_tagged_as_a_replay(flux_client):
    ip = "203.0.113.33"
    found = None
    for i in range(tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS + 4):
        await _login(flux_client, ip, "/api/v1/session", {
            "username": "admin", "password": f"pw{i}",
        })
        if _log_entries(flux_client.log_path)[-1]["result"] == "aiplatform-login-accepted":
            found = f"pw{i}"
            break
    assert found is not None
    await _login(flux_client, ip, "/api/v1/session", {
        "username": "admin", "password": found,
    })
    assert _log_entries(flux_client.log_path)[-1]["result"] == "aiplatform-login-replay"


# --------------------------------------------------------------------------
# authenticated surfaces
# --------------------------------------------------------------------------

async def test_inventory_is_shut_without_a_session(flux_client):
    response = await flux_client.get(
        "/api/v1/applications", headers={"X-Forwarded-For": "203.0.113.40"},
    )
    assert response.status == 401
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "aiplatform-inventory-unauthenticated"
    assert entry["aiplatformTokenPresented"] is False
    assert entry["aiplatformTokenValid"] is False


async def test_foreign_token_does_not_open_the_inventory(flux_client):
    response = await flux_client.get("/api/v1/applications", headers={
        "X-Forwarded-For": "203.0.113.41",
        "Authorization": "Bearer not-a-session-this-server-issued",
    })
    assert response.status == 401
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["aiplatformTokenPresented"] is True
    assert entry["aiplatformTokenValid"] is False


async def test_argocd_userinfo_answers_anonymously(flux_client):
    """The controller answers this one without a session — a 401 here
    would be the inconsistency, not the open door."""
    response = await flux_client.get(
        "/api/v1/session/userinfo", headers={"X-Forwarded-For": "203.0.113.42"},
    )
    assert response.status == 200
    assert (await response.json()) == {"loggedIn": False}
    assert _log_entries(flux_client.log_path)[-1]["result"] == "aiplatform-userinfo-anonymous"


async def test_issued_session_opens_the_inventory(flux_client):
    ip = "203.0.113.43"
    payload = await _convert(flux_client, ip, "/api/v1/session")
    response = await flux_client.get("/api/v1/applications", headers={
        "X-Forwarded-For": ip, "Authorization": "Bearer " + payload["token"],
    })
    assert response.status == 200
    doc = await response.json()
    assert doc["items"] and doc["items"][0]["spec"]["source"]["repoURL"]
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "aiplatform-inventory"
    assert entry["aiplatformTokenValid"] is True


async def test_session_cookie_is_accepted_as_well_as_the_header(flux_client):
    ip = "203.0.113.44"
    payload = await _convert(flux_client, ip, "/api/v1/session")
    response = await flux_client.get("/api/v1/applications", headers={
        "X-Forwarded-For": ip, "Cookie": "argocd.token=" + payload["token"],
    })
    assert response.status == 200


async def test_ragflow_tenant_document_carries_a_provider_key(flux_client):
    ip = "203.0.113.45"
    for i in range(tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS + 4):
        response = await _login(flux_client, ip, "/v1/user/login", {
            "email": "admin@example.com", "password": f"pw{i}",
        })
        if _log_entries(flux_client.log_path)[-1]["result"] == "aiplatform-login-accepted":
            token = (await response.json())["data"]["access_token"]
            break
    else:
        raise AssertionError("source never converted")
    response = await flux_client.get("/v1/user/tenant_info", headers={
        "X-Forwarded-For": ip, "Authorization": token,
    })
    assert response.status == 200
    doc = await response.json()
    assert doc["data"]["api_key"].startswith("sk-")


# --------------------------------------------------------------------------
# nothing fixed
# --------------------------------------------------------------------------

def test_provider_key_is_per_hit_unique():
    """A fixed literal here would be the same string on every host
    running this, which is a fleet-wide fingerprint and gives a replay
    nothing to detect."""
    keys = {tbenv._aiplatform_provider_key() for _ in range(32)}
    assert len(keys) == 32


def test_session_token_differs_across_sources_and_hosts():
    base = tbenv._aiplatform_session_token("argocd", "203.0.113.50", "a.example.com")
    assert base != tbenv._aiplatform_session_token("argocd", "203.0.113.51", "a.example.com")
    assert base != tbenv._aiplatform_session_token("argocd", "203.0.113.50", "b.example.com")
    assert base != tbenv._aiplatform_session_token("ragflow", "203.0.113.50", "a.example.com")


def test_session_token_is_stable_for_one_source():
    """A session that stops working on the next request is not a
    session."""
    assert (
        tbenv._aiplatform_session_token("argocd", "203.0.113.52", "a.example.com")
        == tbenv._aiplatform_session_token("argocd", "203.0.113.52", "a.example.com")
    )


def test_rendered_surfaces_carry_no_fixed_credential_literal():
    apps = tbenv.render_argocd_applications("example.com").decode()
    repos = tbenv.render_argocd_repositories("example.com").decode()
    for blob in (apps, repos):
        assert "password" not in blob.lower()
        assert "api_key" not in blob.lower()
    first = json.loads(tbenv.render_ragflow_tenant_info())["data"]
    second = json.loads(tbenv.render_ragflow_tenant_info())["data"]
    assert first["api_key"] != second["api_key"]
    assert first["tenant_id"] != second["tenant_id"]


# --------------------------------------------------------------------------
# master switch
# --------------------------------------------------------------------------

async def test_disabled_switch_404s_every_route(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "AIPLATFORM_LOGIN_ENABLED", False)
    client = await aiohttp_client(tbenv.create_app())
    for path in tbenv._AIPLATFORM_LOGIN_ROUTES:
        response = await client.get(path)
        assert response.status == 404, path


@pytest.mark.parametrize("product,login_path,surface_path", [
    ("argocd", "/api/v1/session", "/api/v1/applications"),
    ("ragflow", "/v1/user/login", "/v1/user/info"),
    ("maxkb", "/api/user/login", "/api/user/profile"),
])
async def test_issued_session_is_accepted_by_its_own_product(
    flux_client, product, login_path, surface_path,
):
    """Regression: two products hand back a truncated token while the
    validator checked the full digest, so a client spending the session
    it had just been given was refused and no post-authentication
    surface was ever reachable."""
    ip = "203.0.113.60"
    issued = None
    for i in range(tbenv.AIPLATFORM_LOGIN_ACCEPT_MAX_ATTEMPTS + 4):
        response = await _login(flux_client, ip, login_path, {
            "username": "admin", "email": "admin@example.com", "password": f"pw{i}",
        })
        if _log_entries(flux_client.log_path)[-1]["result"] == "aiplatform-login-accepted":
            payload = await response.json()
            issued = (
                payload["token"] if product == "argocd"
                else payload["data"]["access_token"] if product == "ragflow"
                else payload["data"]
            )
            break
    assert issued, "source never converted"
    response = await flux_client.get(surface_path, headers={
        "X-Forwarded-For": ip, "Authorization": "Bearer " + issued,
    })
    assert response.status == 200
    assert _log_entries(flux_client.log_path)[-1]["aiplatformTokenValid"] is True
