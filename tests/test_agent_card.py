"""`/.well-known/` agent + MCP discovery cards.

The population these answer never reads a file and never guesses an
endpoint — it asks the discovery namespace what a host publishes and
stops. Every assertion here is about the chain that makes that walk
measurable: the card resolves, it names a surface this server actually
answers, and the name it publishes agrees with what the endpoint says
about itself when the client gets there.
"""
import json
import re

import pytest

import flux.server as tbenv


A2A_PATHS = [
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
    "/.well-known/agents.json",
]
MCP_CARD_PATHS = [
    "/.well-known/mcp",
    "/.well-known/mcp.json",
    "/.well-known/mcp/server-card",
    "/.well-known/mcp/server-card.json",
    "/.well-known/webmcp",
    "/.well-known/webmcp.json",
]
PLUGIN_PATHS = ["/.well-known/ai-plugin.json"]


@pytest.mark.parametrize("path", A2A_PATHS)
def test_a2a_paths_match(path):
    assert tbenv.agent_card_kind(path) == "a2a-agent-card"


@pytest.mark.parametrize("path", MCP_CARD_PATHS)
def test_mcp_card_paths_match(path):
    assert tbenv.agent_card_kind(path) == "mcp-server-card"


@pytest.mark.parametrize("path", PLUGIN_PATHS)
def test_plugin_paths_match(path):
    assert tbenv.agent_card_kind(path) == "ai-plugin-manifest"


@pytest.mark.parametrize("path", [
    "/.WELL-KNOWN/Agent-Card.JSON",
    "/.well-known/mcp/",
    "/.well-known/mcp.json?probe=1",
    "/.well-known/webmcp?",
])
def test_case_slash_and_query_normalisation(path):
    assert tbenv.agent_card_kind(path) != ""


@pytest.mark.parametrize("path", [
    # The namespace root is not a card.
    "/.well-known/",
    "/.well-known",
    # Documents in the same namespace owned by other traps. Claiming
    # these here would take the OIDC discovery doc and the AWS
    # credentials envelope away from the handlers that render them.
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/credentials.json",
    # ACME lives on the webroot in front of this server; answering it
    # would break certificate issuance.
    "/.well-known/acme-challenge/token",
    # Near-misses.
    "/.well-known/agent-card.yaml",
    "/.well-known/agent-cards.json",
    "/well-known/mcp",
    "/.well-known/mcp/server-card.txt",
    "/mcp.json",
    "/agent.json",
])
def test_non_card_paths_do_not_match(path):
    assert tbenv.agent_card_kind(path) == ""


def test_other_well_known_owners_keep_their_paths():
    """The two `/.well-known/` documents other traps already render must
    still route to those traps, not to a card."""
    assert tbenv.is_oidc_discovery_path("/.well-known/openid-configuration")
    trap = tbenv._TRAP_BY_PATH.get("/.well-known/credentials.json")
    assert trap is not None and trap.name == "aws-credentials-json"


def test_disabled_switch_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "AGENT_CARD_ENABLED", False)
    for path in A2A_PATHS + MCP_CARD_PATHS + PLUGIN_PATHS:
        assert tbenv.agent_card_kind(path) == ""
        assert not tbenv.is_agent_card_path(path)


# --- Card bodies -------------------------------------------------------

HOST = "sensor.example.com"


def test_agent_card_advertises_the_served_jsonrpc_endpoint():
    card = json.loads(tbenv.render_a2a_agent_card(HOST))
    assert card["url"] == f"https://{HOST}{tbenv.MCP_SELF_ENDPOINT_PATH}"
    assert tbenv.is_mcp_server_endpoint_path(tbenv.MCP_SELF_ENDPOINT_PATH)
    assert card["preferredTransport"] == "JSONRPC"


def test_mcp_card_advertises_both_served_transports():
    card = json.loads(tbenv.render_mcp_server_card(HOST))
    urls = [t["url"] for t in card["transports"]]
    assert f"https://{HOST}{tbenv.MCP_SELF_ENDPOINT_PATH}" in urls
    assert f"https://{HOST}/sse" in urls
    # Both advertised paths must be ones the endpoint trap answers,
    # otherwise the card sends a parsing client to a 404.
    for url in urls:
        path = url[len(f"https://{HOST}"):]
        assert tbenv.is_mcp_server_endpoint_path(path), path


def test_plugin_manifest_advertises_a_served_openapi_document():
    manifest = json.loads(tbenv.render_ai_plugin_manifest(HOST))
    url = manifest["api"]["url"]
    assert url.startswith(f"https://{HOST}")
    assert tbenv.is_openapi_swagger_path(url[len(f"https://{HOST}"):])


def test_card_tool_names_match_the_endpoint_catalog():
    """The card and `tools/list` describe one server. A name in the card
    that the endpoint does not list is the cheapest tell available to a
    client that fetches both."""
    catalog = {tool["name"] for tool in tbenv._mcp_tool_catalog()}
    mcp_card = json.loads(tbenv.render_mcp_server_card(HOST))
    assert {tool["name"] for tool in mcp_card["tools"]} == catalog
    agent_card = json.loads(tbenv.render_a2a_agent_card(HOST))
    assert {skill["id"] for skill in agent_card["skills"]} == catalog


def test_card_resource_uris_match_the_endpoint_catalog():
    catalog = {res["uri"] for res in tbenv._mcp_resource_catalog()}
    card = json.loads(tbenv.render_mcp_server_card(HOST))
    assert {res["uri"] for res in card["resources"]} == catalog


def _string_values(node):
    """Every string *value* in a decoded card, keys excluded. A resource
    named `env://AWS_SECRET_ACCESS_KEY` is a URI the endpoint already
    lists and is the whole point of publishing the catalog; what must
    never appear is a credential *value*."""
    if isinstance(node, dict):
        for value in node.values():
            yield from _string_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from _string_values(value)
    elif isinstance(node, str):
        yield node


_CREDENTIAL_VALUE_SHAPES = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}"),          # AWS key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),    # PEM
    re.compile(r"\b(?:Bearer|Basic)\s+\S{8,}"),           # inline auth header
    re.compile(r"://[^/\s:]+:[^/\s@]+@"),                 # URL userinfo
    re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$"),            # bare base64 blob
)


@pytest.mark.parametrize("renderer", [
    tbenv.render_a2a_agent_card,
    tbenv.render_mcp_server_card,
    tbenv.render_ai_plugin_manifest,
])
def test_cards_carry_no_credential_shaped_value(renderer):
    """A public discovery document that ships a secret is implausible on
    its face, and a *fixed* secret would be identical on every host this
    runs on. The credential slot in this chain is one hop further on, at
    the tool call the card is trying to provoke."""
    card = json.loads(renderer(HOST))
    for value in _string_values(card):
        for shape in _CREDENTIAL_VALUE_SHAPES:
            assert not shape.search(value), (shape.pattern, value)


@pytest.mark.parametrize("renderer", [
    tbenv.render_a2a_agent_card,
    tbenv.render_mcp_server_card,
    tbenv.render_ai_plugin_manifest,
])
def test_loopback_host_falls_back_rather_than_advertising_it(renderer):
    """Behind a proxy that rewrites Host, the requested host arrives as a
    loopback literal. Publishing it would point the reader at its own
    machine and, being identical everywhere, fingerprint the fleet."""
    body = renderer("127.0.0.1").decode()
    assert "127.0.0.1" not in body
    assert "localhost" not in body


@pytest.mark.parametrize("renderer", [
    tbenv.render_a2a_agent_card,
    tbenv.render_mcp_server_card,
    tbenv.render_ai_plugin_manifest,
])
def test_cards_are_valid_json_objects(renderer):
    assert isinstance(json.loads(renderer(HOST)), dict)


# --- Dispatch ----------------------------------------------------------

from tests.test_server import flux_client, _log_entries  # noqa: F401,E402


@pytest.mark.parametrize("path", A2A_PATHS + MCP_CARD_PATHS + PLUGIN_PATHS)
async def test_dispatch_serves_card(flux_client, path):  # noqa: F811
    resp = await flux_client.get(path)
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    assert isinstance(json.loads(await resp.text()), dict)


async def test_dispatch_logs_kind_and_advertised_endpoint(flux_client):  # noqa: F811
    resp = await flux_client.get("/.well-known/mcp/server-card.json")
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "agent-card-mcp-server-card"
    assert entry["agentCardKind"] == "mcp-server-card"
    assert entry["agentCardPath"] == "/.well-known/mcp/server-card.json"
    assert entry["agentCardMethod"] == "GET"
    # The field the chain is measured on — a later mcp-server-* line from
    # the same source against this endpoint is a client that read a
    # discovery document and acted on it.
    assert entry["agentCardEndpoint"].endswith(tbenv.MCP_SELF_ENDPOINT_PATH)


async def test_post_gets_the_405_a_static_document_returns(flux_client):  # noqa: F811
    resp = await flux_client.post("/.well-known/agent-card.json", data=b"{}")
    assert resp.status == 405
    assert resp.headers["Allow"] == "GET, HEAD"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "agent-card-a2a-agent-card-method-not-allowed"
    assert entry["agentCardMethod"] == "POST"


async def test_head_returns_headers_without_a_body(flux_client):  # noqa: F811
    resp = await flux_client.head("/.well-known/mcp")
    assert resp.status == 200
    assert await resp.read() == b""
    assert int(resp.headers["Content-Length"]) > 0


async def test_acme_challenge_is_not_claimed(flux_client):  # noqa: F811
    """The ACME webroot is served in front of this process. If this trap
    ever answered the challenge path, certificate renewal would fail."""
    resp = await flux_client.get("/.well-known/acme-challenge/sometoken")
    assert resp.status != 200 or "agentCard" not in await resp.text()


# --- Endpoint spellings the cards' readers fall back to ----------------

@pytest.mark.parametrize("path", ["/api/mcp/v1", "/api/v1/mcp", "/api/mcp/mcp"])
def test_gateway_mount_spellings_reach_the_endpoint(path):
    assert tbenv.is_mcp_server_endpoint_path(path)


@pytest.mark.parametrize("path", ["/api/mcp/v2", "/api/v1/mcp/tools", "/mcp/v1"])
def test_near_miss_gateway_spellings_do_not(path):
    assert not tbenv.is_mcp_server_endpoint_path(path)


@pytest.mark.parametrize("path", A2A_PATHS + MCP_CARD_PATHS + PLUGIN_PATHS)
async def test_no_earlier_trap_shadows_a_card_path(flux_client, path):  # noqa: F811
    """Pins dispatch precedence. `/.well-known/mcp.json` is one prefix
    walk away from the `/mcp.json` config file the canary table serves,
    and a card path answered by the file trap would hand back a config
    instead of the descriptor the client asked for — a 200 either way,
    so nothing but the result tag would show it had happened."""
    resp = await flux_client.get(path)
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert str(entry["result"]).startswith("agent-card-"), entry["result"]


# --- Percent-encoded dot-segment dodge ---------------------------------

@pytest.mark.parametrize("path,kind", [
    ("/%2ewell-known/ai-plugin.json", "ai-plugin-manifest"),
    ("/%2Ewell-known/agent.json", "a2a-agent-card"),
    ("/%2ewell-known/mcp.json", "mcp-server-card"),
])
def test_percent_encoded_dot_still_resolves(path, kind):
    """Clients reach these through the encoded spelling to get past
    filters matching the literal dot-segment. The request that arrives
    after the dodge is the same request."""
    assert tbenv.agent_card_kind(path) == kind


@pytest.mark.parametrize("path", [
    "/.well-known/mcp/server.json",
    "/.well-known/openai-plugin.json",
])
def test_registry_and_vendor_spellings_match(path):
    assert tbenv.agent_card_kind(path) != ""


def test_well_known_graphql_reaches_the_graphql_trap():
    """The GraphQL trap was answering eleven spellings and 404ing the
    discovery-namespace twelfth. It must not be claimed as a card."""
    assert tbenv.is_graphql_path("/.well-known/graphql")
    assert tbenv.agent_card_kind("/.well-known/graphql") == ""
