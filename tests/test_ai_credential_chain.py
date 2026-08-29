"""AI-developer credential paths, and the config→endpoint chain.

Three things are covered here:

1. The three paths in the AI-tooling credential dictionary that this
   server used to miss — `/claude_desktop_config.json` (not dot-prefixed,
   so a dotfile-shaped matcher skipped it) and the provider-scoped
   `/.env.anthropic` / `/.env.openai` fragments.
2. The tarpit interaction, which is the subtle half: `is_tarpit_path`
   claims every `.env`-prefixed leaf except bare `/.env`, exempting only
   paths that carry a CanaryTrap entry. A regression that drops those
   entries does not fail with a 404 — it silently returns a redirect
   chain, and the canary that gives replay-side telemetry is never
   issued. So the assertion is on the trap response, not merely on
   "not 404".
3. The served MCP config advertising an HTTP-transport server pointing
   at this host's own JSON-RPC endpoint, so that reading the config has
   a followable next step.
"""
import json

import pytest

from flux import server as tbenv
from .test_server import FAKE_TRACEBIT, _fake_canary, flux_client  # noqa: F401

MCP_CONFIG_PATHS = [
    "/.mcp.json",
    "/.cursor/mcp.json",
    "/mcp.json",
    "/claude_desktop_config.json",
]


@pytest.fixture
def canary(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)


# --- 1. the previously-missing paths ------------------------------------

@pytest.mark.parametrize("path", MCP_CONFIG_PATHS)
async def test_mcp_config_paths_serve_the_config(flux_client, canary, path):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.10"})
    assert resp.status == 200
    body = json.loads(await resp.read())
    assert "mcpServers" in body


def test_claude_desktop_config_is_registered():
    """The only name in the family without a leading dot. It is asserted
    on the registry rather than only over HTTP so the failure names the
    cause — a missing path entry — instead of a bare 404."""
    assert "/claude_desktop_config.json" in tbenv._TRAP_BY_PATH


@pytest.mark.parametrize(
    "path,key_slot,url_slot",
    [
        ("/.env.anthropic", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
        ("/.env.openai", "OPENAI_API_KEY", "OPENAI_BASE_URL"),
    ],
)
async def test_provider_dotenv_serves_a_canary(
    flux_client, canary, path, key_slot, url_slot
):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.11"})
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "text/plain; charset=utf-8"
    body = (await resp.read()).decode("utf-8")
    aws = FAKE_TRACEBIT["aws"]
    canary_values = {
        aws["awsAccessKeyId"], aws["awsSecretAccessKey"], aws["awsSessionToken"],
    }
    slots = dict(
        line.split("=", 1) for line in body.splitlines() if "=" in line
    )
    assert slots[key_slot] in canary_values
    # Non-secret shape has to be there too: a file holding one key and
    # nothing else reads as bait.
    assert slots[url_slot].startswith("https://")


# --- 2. the tarpit interaction ------------------------------------------

@pytest.mark.parametrize("path", ["/.env.anthropic", "/.env.openai"])
def test_provider_dotenv_is_exempt_from_the_tarpit(path):
    """`is_tarpit_path` exempts paths carrying a trap entry. If these
    lose their entry they get a redirect chain instead of a canary —
    a silent downgrade with no 404 to notice."""
    assert tbenv.is_tarpit_path(path) is False


def test_bare_env_variants_without_a_trap_still_tarpit():
    """The exemption must stay keyed on the registry, not widened into
    "anything `.env`-prefixed", or the generic tarpit stops working."""
    assert tbenv.is_tarpit_path("/.env.somethingnobodytrapped") is True


# --- 3. the config -> endpoint chain ------------------------------------

@pytest.mark.parametrize("path", MCP_CONFIG_PATHS)
async def test_config_advertises_a_followable_http_server(flux_client, canary, path):
    resp = await flux_client.get(
        path,
        headers={"Host": "sensor.example.net", "X-Forwarded-For": "203.0.113.12"},
    )
    gw = json.loads(await resp.read())["mcpServers"]["internal-gateway"]
    assert gw["type"] == "http"
    assert gw["url"] == "https://sensor.example.net/mcp"


def test_advertised_endpoint_is_one_this_server_answers():
    """The invariant that stops the advertised URL rotting into a 404 if
    the endpoint set is ever renamed via the paths CSV."""
    assert tbenv.MCP_SELF_ENDPOINT_PATH in tbenv.MCP_SERVER_PATHS


def test_advertised_endpoint_follows_a_renamed_path_set(monkeypatch):
    """`MCP_SELF_ENDPOINT_PATH` is derived from the live set rather than
    written out a second time, so an operator renaming the endpoint does
    not leave the config pointing at the old one."""
    import importlib

    monkeypatch.setenv("HONEYPOT_MCP_SERVER_PATHS_CSV", "/rpc,/sse")
    reloaded = importlib.reload(tbenv)
    try:
        assert reloaded.MCP_SELF_ENDPOINT_PATH == "/rpc"
        assert reloaded.MCP_SELF_ENDPOINT_PATH in reloaded.MCP_SERVER_PATHS
    finally:
        monkeypatch.delenv("HONEYPOT_MCP_SERVER_PATHS_CSV", raising=False)
        importlib.reload(tbenv)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "10.0.0.5", ""])
def test_advertised_url_never_publishes_a_loopback_or_literal(host):
    """Behind a proxy that rewrites `Host`, the requested host arrives as
    an address literal. Publishing it would advertise the reader's own
    machine and would be the same string from every host running this,
    which is a fleet fingerprint rather than a cosmetic slip."""
    url = tbenv._mcp_self_endpoint({"_requestHost": host})
    assert "127.0.0.1" not in url
    assert "localhost" not in url
    assert url.startswith("https://")


def test_gateway_bearer_is_the_per_hit_canary_not_a_literal():
    """The bearer is what joins a follow-up connection back to the config
    read that issued it, so it has to come from the canary — a fixed
    literal would both break that join and ship one string fleet-wide."""
    body = tbenv.render_cursor_mcp_json(FAKE_TRACEBIT).decode("utf-8")
    gw = json.loads(body)["mcpServers"]["internal-gateway"]
    token = gw["headers"]["Authorization"].split(" ", 1)[1]
    aws = FAKE_TRACEBIT["aws"]
    assert token in {
        aws["awsAccessKeyId"], aws["awsSecretAccessKey"], aws["awsSessionToken"],
    }


def test_no_secret_slot_holds_a_non_canary_value():
    """Every secret-shaped slot in the rendered config must trace to the
    canary; nothing fixed."""
    body = tbenv.render_cursor_mcp_json(FAKE_TRACEBIT).decode("utf-8")
    cfg = json.loads(body)["mcpServers"]
    aws = FAKE_TRACEBIT["aws"]
    canary_values = {
        aws["awsAccessKeyId"], aws["awsSecretAccessKey"], aws["awsSessionToken"],
    }
    secretish = ("TOKEN", "KEY", "SECRET", "PASSWORD")
    for server in cfg.values():
        for name, value in (server.get("env") or {}).items():
            if any(marker in name.upper() for marker in secretish):
                assert value in canary_values, (
                    f"env slot {name!r} holds a value the canary did not "
                    f"supply — a fixed literal here ships the same string "
                    f"from every host"
                )


async def test_harvested_bearer_reaches_the_json_rpc_endpoint(flux_client, canary):
    """The chain end to end: read the config, follow the URL it
    advertises, present the bearer it carried, and get the JSON-RPC
    dispatch rather than a 404 or a 405."""
    resp = await flux_client.get(
        "/.mcp.json",
        headers={"Host": "sensor.example.net", "X-Forwarded-For": "203.0.113.13"},
    )
    gw = json.loads(await resp.read())["mcpServers"]["internal-gateway"]
    endpoint = gw["url"].split("sensor.example.net", 1)[1]

    followed = await flux_client.post(
        endpoint,
        headers={
            "Host": "sensor.example.net",
            "Authorization": gw["headers"]["Authorization"],
            "X-Forwarded-For": "203.0.113.13",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert followed.status == 200
    payload = json.loads(await followed.read())
    assert payload["jsonrpc"] == "2.0"
    assert "tools" in payload["result"]
