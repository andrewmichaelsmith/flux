"""Tests for the fake Tomcat Manager.

The trap's whole value rests on one difference: an unauthenticated
request gets `401` with a Basic challenge rather than `404`. A 404 tells
a scanner there is nothing here and the exchange ends at the cheapest
possible moment; a 401 tells it there is something here worth a
password, and the passwords it then tries are the measurement.

Four properties are worth defending:

1. **Unauthenticated means challenged, never 404.** This is the change.
2. **Any credential is accepted.** A sink that can never succeed records
   the dictionary and nothing about what a client does once it is in —
   and what it does once it is in is the part worth capturing.
3. **The uploaded application is kept.** Every Tomcat Manager brute
   exists to deploy a WAR; capturing it is the point of accepting the
   login.
4. **One consistent server.** A client that reads `serverinfo` and then
   the HTML must not see two different Tomcats, and the surfaces must
   not split into some-401/some-404 under a keyless deployment.
"""

import base64
import hashlib
import json

import pytest
import pytest_asyncio

from flux import server as tbenv


FAKE_CANARY = {
    "aws": {
        "awsAccessKeyId": "ASIAFAKETOMCAT000001",
        "awsSecretAccessKey": "s" * 40,
    }
}


def auth(user="tomcat", password="s3cret"):
    raw = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setattr(tbenv, "TOMCAT_MANAGER_ENABLED", True)


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "TOMCAT_MANAGER_ENABLED", True)

    async def _fake_canary(*_a, **_kw):
        return FAKE_CANARY

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _last(log_path):
    return [json.loads(l) for l in log_path.read_text().splitlines()][-1]


# --- Matching -------------------------------------------------------------


@pytest.mark.parametrize("path,kind", [
    ("/manager/html", "ui"),
    ("/manager/html/", "ui"),
    ("/MANAGER/HTML", "ui"),
    ("/manager/status", "ui"),
    ("/manager/status/all", "ui"),
    ("/host-manager/html", "ui"),
    ("/manager/jmxproxy", "ui"),
    ("/manager/text/list", "text"),
    ("/manager/text/serverinfo", "text"),
    ("/manager/text/deploy", "deploy"),
    ("/manager/html/upload", "deploy"),
    ("/jmx-console", "console"),
    ("/web-console/", "console"),
    ("/admin-console", "console"),
    ("/invoker/JMXInvokerServlet", "console"),
])
def test_matched_surfaces(path, kind):
    assert tbenv.tomcat_manager_kind(path) == kind


@pytest.mark.parametrize("path", [
    "/", "/manager.html", "/managers/html", "/wp-login.php",
    # Generic addresses this trap deliberately does not claim, because
    # better-targeted surfaces already live under them.
    "/status", "/debug", "/server-status", "/manager/html/../../etc/passwd",
])
def test_unmatched_paths(path):
    assert tbenv.tomcat_manager_kind(path) == ""


def test_disabled_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "TOMCAT_MANAGER_ENABLED", False)
    assert tbenv.tomcat_manager_kind("/manager/html") == ""


# --- Basic auth parsing ---------------------------------------------------


def test_basic_auth_round_trip():
    assert tbenv.parse_basic_auth("Basic " + base64.b64encode(b"u:p").decode()) == ("u", "p")


def test_basic_auth_keeps_colons_in_the_password():
    raw = base64.b64encode(b"admin:pa:ss:word").decode()
    assert tbenv.parse_basic_auth(f"Basic {raw}") == ("admin", "pa:ss:word")


@pytest.mark.parametrize("header", [
    "", "Bearer abc", "Basic", "Basic !!!not-base64!!!",
    "Basic " + base64.b64encode(b"nocolon").decode(),
])
def test_basic_auth_rejects_junk(header):
    """Everything here is "no credential was presented", and a real server
    answers all of them with the same challenge."""
    assert tbenv.parse_basic_auth(header) is None


# --- The challenge, which is the whole point ------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/manager/html", "/manager/status", "/manager/text/list",
    "/jmx-console", "/host-manager/html", "/manager/text/deploy",
])
async def test_unauthenticated_is_challenged_not_404(flux_client, path):
    """Property 1. A 404 ends the exchange; a 401 starts a brute."""
    resp = await flux_client.get(path)
    assert resp.status == 401
    assert resp.headers["WWW-Authenticate"].startswith('Basic realm="')
    body = await resp.text()
    assert "401" in body and "Tomcat" in body


@pytest.mark.asyncio
async def test_challenge_is_logged_with_its_surface(flux_client):
    await flux_client.get("/manager/html")
    entry = _last(flux_client.log_path)
    assert entry["result"] == "tomcat-manager-ui-challenge"
    assert entry["status"] == 401
    assert entry["tomcatSurface"] == "ui"


# --- The credential is the intel -----------------------------------------


@pytest.mark.asyncio
async def test_any_credential_is_accepted(flux_client):
    """Property 2."""
    resp = await flux_client.get("/manager/html", headers=auth("admin", "admin"))
    assert resp.status == 200
    assert "Tomcat Web Application Manager" in await resp.text()


@pytest.mark.asyncio
async def test_credential_is_recorded_without_storing_the_password(flux_client):
    await flux_client.get("/manager/html", headers=auth("tomcat", "hunter2"))
    entry = _last(flux_client.log_path)
    assert entry["tomcatUsername"] == "tomcat"
    assert entry["tomcatPasswordLen"] == len("hunter2")
    assert entry["tomcatPasswordSha256"] == hashlib.sha256(b"hunter2").hexdigest()
    # The value itself must not appear anywhere on the line.
    assert "hunter2" not in json.dumps(entry)


@pytest.mark.asyncio
async def test_same_guess_hashes_alike_across_sources(flux_client):
    """The hash is what groups one dictionary entry across many senders."""
    await flux_client.get("/manager/html", headers={
        **auth("a", "p@ss"), "X-Forwarded-For": "198.51.100.1"})
    one = _last(flux_client.log_path)["tomcatPasswordSha256"]
    await flux_client.get("/manager/html", headers={
        **auth("b", "p@ss"), "X-Forwarded-For": "198.51.100.2"})
    two = _last(flux_client.log_path)["tomcatPasswordSha256"]
    assert one == two


# --- The deploy step is what the brute was for ---------------------------


@pytest.mark.asyncio
async def test_uploaded_application_is_captured(flux_client):
    """Property 3. `PK` is a real zip header — a WAR actually arrived."""
    war = b"PK\x03\x04" + b"\x00" * 200
    resp = await flux_client.post(
        "/manager/html/upload?path=/evil", data=war, headers=auth(),
    )
    assert resp.status == 200
    assert "OK - Deployed application at context path [/evil]" in await resp.text()
    entry = _last(flux_client.log_path)
    assert entry["result"] == "tomcat-manager-deploy"
    assert entry["tomcatDeployBytes"] == len(war)
    assert entry["tomcatDeploySha256"] == hashlib.sha256(war).hexdigest()
    assert entry["tomcatDeployIsArchive"] is True
    assert entry["tomcatDeployPath"] == "/evil"


@pytest.mark.asyncio
async def test_empty_deploy_probe_is_not_an_archive(flux_client):
    """A client touching the deploy address without a body is probing, not
    deploying, and the two should not read alike."""
    resp = await flux_client.post("/manager/html/upload", data=b"", headers=auth())
    assert resp.status == 200
    entry = _last(flux_client.log_path)
    assert entry["tomcatDeployBytes"] == 0
    assert entry["tomcatDeployIsArchive"] is False


@pytest.mark.asyncio
async def test_deploy_requires_a_credential_too(flux_client):
    resp = await flux_client.post("/manager/html/upload", data=b"PK\x03\x04")
    assert resp.status == 401


@pytest.mark.asyncio
async def test_html_form_names_the_upload_address(flux_client):
    """The page has to give a client that parses it a concrete next
    request, or the deploy step is only reachable by prior knowledge."""
    body = await (await flux_client.get("/manager/html", headers=auth())).text()
    assert "/manager/html/upload" in body
    assert "multipart/form-data" in body


# --- The text API tooling actually drives --------------------------------


@pytest.mark.asyncio
async def test_text_list_is_parseable(flux_client):
    body = await (await flux_client.get("/manager/text/list", headers=auth())).text()
    assert body.startswith("OK - Listed applications for virtual host")
    assert "/manager:running:" in body


@pytest.mark.asyncio
async def test_serverinfo_and_html_agree_on_the_version(flux_client):
    """Property 4: one server, not two."""
    info = await (await flux_client.get("/manager/text/serverinfo", headers=auth())).text()
    html = await (await flux_client.get("/manager/html", headers=auth())).text()
    assert tbenv.TOMCAT_MANAGER_VERSION in info
    assert tbenv.TOMCAT_MANAGER_VERSION in html


# --- The one surface that carries a credential ---------------------------


@pytest.mark.asyncio
async def test_jmxproxy_serves_a_canary_in_the_environment(flux_client):
    """The JVM environment is where a deployment's cloud keys live, which
    is why a client asks the proxy for the Runtime bean at all."""
    body = await (await flux_client.get("/manager/jmxproxy", headers=auth())).text()
    assert "AWS_ACCESS_KEY_ID = ASIAFAKETOMCAT000001" in body
    entry = _last(flux_client.log_path)
    assert entry["result"] == "tomcat-manager-jmxproxy"


@pytest.mark.asyncio
async def test_no_fixed_credential_literal_in_any_surface(flux_client, monkeypatch):
    """Two different canaries must produce two different bodies — a value
    that survived unchanged would be a fleet-wide fingerprint and would
    give zero detection on replay."""
    other = {"aws": {"awsAccessKeyId": "ASIAFAKETOMCAT000002",
                     "awsSecretAccessKey": "z" * 40}}
    first = await (await flux_client.get("/manager/jmxproxy", headers=auth())).text()

    async def _other(*_a, **_kw):
        return other

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _other)
    second = await (await flux_client.get("/manager/jmxproxy", headers=auth())).text()
    assert first != second
    assert "ASIAFAKETOMCAT000002" in second


@pytest.mark.asyncio
async def test_issuance_failure_is_indistinguishable_from_an_unserved_path(
    flux_client, monkeypatch,
):
    async def _fail(*_a, **_kw):
        return None

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fail)
    resp = await flux_client.get("/manager/jmxproxy", headers=auth())
    assert resp.status == tbenv.CREDENTIAL_FAILURE_STATUS
    assert _last(flux_client.log_path)["result"] == "tomcat-manager-jmxproxy-tracebit-error"


@pytest.mark.asyncio
async def test_keyless_deployment_serves_no_surface(aiohttp_client, monkeypatch, tmp_path):
    """Property 4, other half. Answering four of five surfaces and 404ing
    the one that needs a key would be a louder tell than answering none."""
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "TOMCAT_MANAGER_ENABLED", True)
    client = await aiohttp_client(tbenv.create_app())
    for path in ("/manager/html", "/manager/text/list", "/manager/jmxproxy"):
        assert (await client.get(path)).status == 404


@pytest.mark.asyncio
async def test_bodyless_post_to_the_ui_is_not_a_deploy(flux_client):
    """A POST with nothing in it is not an upload, and labelling it one
    would put empty rows in the set of captured applications."""
    resp = await flux_client.post("/manager/html", data=b"", headers=auth())
    assert resp.status == 200
    entry = _last(flux_client.log_path)
    assert entry["result"] == "tomcat-manager-ui"
    assert "tomcatDeploySha256" not in entry


@pytest.mark.asyncio
async def test_post_with_a_body_to_the_ui_is_still_captured(flux_client):
    """But a POST that carries something must not be discarded — the
    surface it arrived on is recorded separately in `tomcatSurface`."""
    resp = await flux_client.post("/manager/html", data=b"PK\x03\x04junk", headers=auth())
    assert resp.status == 200
    entry = _last(flux_client.log_path)
    assert entry["result"] == "tomcat-manager-deploy"
    assert entry["tomcatSurface"] == "ui"
    assert entry["tomcatDeployIsArchive"] is True
