"""Gateway mount prefixes and un-versioned spellings on the LLM-API trap.

The inference trap already captured the thing worth having — the model
requested, the prompt body, and the bearer token a client presents. What it
could not do was get reached. Probe traffic walks the model-listing route
under a mount prefix (`/api/v1/models`, `/openai/v1/models`) and without the
version segment at all, and the trap matched an exact path list, so the most
commonly probed spelling in the family 404'd while the bare one answered.

Listing is the entry point of the chain: a client that gets a 404 there never
sends the completion POST, which is where the prompt and the token are. So
these tests pin the route canonicalisation rather than the response text:

1. A mount prefix resolves to the same route as the bare spelling, for every
   route in the dictionary — not just for the listing.
2. An exact dictionary member is matched before any stripping, so a vendor
   spelling that needs its own response shape keeps it.
3. The shape follows the route, so a client probing for one vendor's API is
   not handed another vendor's envelope.
"""

import json

import pytest

import flux.server as tbenv

from .test_server import _log_entries, flux_client  # noqa: F401


# --- Route canonicalisation (pure) -------------------------------------

@pytest.mark.parametrize("path,expected", [
    # The spelling that carried the most distinct probe sources in this
    # family and had no handler before this change.
    ("/api/v1/models", "/v1/models"),
    ("/openai/v1/models", "/v1/models"),
    ("/azure/v1/models", "/v1/models"),
    ("/openrouter/v1/models", "/v1/models"),
    ("/zen/v1/models", "/v1/models"),
    # Mount stripping is a property of the mount, not of the listing route.
    ("/api/v1/chat/completions", "/v1/chat/completions"),
    ("/openai/v1/chat/completions", "/v1/chat/completions"),
    ("/api/v1/embeddings", "/v1/embeddings"),
    ("/api/v1/messages", "/v1/messages"),
    # Un-versioned gateway spellings, bare and mounted.
    ("/models", "/models"),
    ("/api/models", "/models"),
    ("/openai/models", "/models"),
    ("/chat/completions", "/chat/completions"),
    ("/completions", "/completions"),
    ("/embeddings", "/embeddings"),
    # Google's listing route carries its own version segment.
    ("/v1beta/models", "/v1beta/models"),
    ("/api/v1beta/models", "/v1beta/models"),
    # Unchanged: already-answered spellings keep resolving to themselves.
    ("/v1/models", "/v1/models"),
    ("/api/tags", "/api/tags"),
    ("/api/generate", "/api/generate"),
])
def test_mounted_and_bare_spellings_resolve_to_a_route(path, expected):
    assert tbenv.llm_endpoint_route(path) == expected
    assert tbenv.is_llm_endpoint_path(path)


def test_exact_member_wins_before_stripping():
    """`/anthropic/v1/models` needs the Anthropic envelope, so it has to stay
    its own route even though `anthropic` looks like a mount segment."""
    assert tbenv.llm_endpoint_route("/anthropic/v1/models") == "/anthropic/v1/models"
    assert tbenv.llm_endpoint_route("/anthropic/v1/messages") == "/anthropic/v1/messages"


@pytest.mark.parametrize("path", sorted(tbenv.LLM_ENDPOINT_PATHS))
def test_every_configured_route_matches_with_case_slash_and_query(path):
    assert tbenv.is_llm_endpoint_path(path)
    assert tbenv.is_llm_endpoint_path(path.upper())
    assert tbenv.is_llm_endpoint_path(path + "?limit=1")
    if path != "/":
        assert tbenv.is_llm_endpoint_path(path + "/")


@pytest.mark.parametrize("path", [
    "/",
    "/api",
    "/api/v1",
    "/v1",
    "/modelsx",
    "/models/foo",
    "/embeddings/foo",
    "/api/v1/session",     # a different trap's control-plane route
    "/api/fs/read",        # a different trap's file-read route
    "/wp-login.php",
    "/unknownvendor/v1/models",   # only known mounts are stripped
])
def test_non_llm_paths_do_not_match(path):
    assert tbenv.llm_endpoint_route(path) is None
    assert not tbenv.is_llm_endpoint_path(path)


def test_only_one_mount_segment_is_stripped():
    """Two stacked prefixes are not a shape we have seen, and allowing them
    would let the rule claim arbitrarily deep application paths."""
    assert tbenv.llm_endpoint_route("/api/openai/v1/models") is None


def test_disabled_switch_disables_every_spelling(monkeypatch):
    monkeypatch.setattr(tbenv, "LLM_ENDPOINT_ENABLED", False)
    for path in ("/v1/models", "/api/v1/models", "/models", "/v1beta/models"):
        assert not tbenv.is_llm_endpoint_path(path)


# --- Served responses --------------------------------------------------

async def test_mounted_listing_serves_the_same_shape_as_the_bare_route(flux_client):
    mounted = await flux_client.get("/api/v1/models")
    assert mounted.status == 200
    bare = await flux_client.get("/v1/models")
    assert bare.status == 200
    assert json.loads(await mounted.read()) == json.loads(await bare.read())

    entry = _log_entries(flux_client.log_path)[-2]
    assert entry["result"] == "llm-endpoint-models-list"


async def test_gemini_listing_gets_the_google_envelope(flux_client):
    """The Google listing is structurally unlike the OpenAI one, so handing
    back the OpenAI envelope here would tell the client it is not Gemini."""
    resp = await flux_client.get("/v1beta/models")
    assert resp.status == 200
    doc = json.loads(await resp.read())
    assert "models" in doc and "data" not in doc
    first = doc["models"][0]
    assert first["name"].startswith("models/")
    assert "generateContent" in first["supportedGenerationMethods"]

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "llm-endpoint-gemini-models-list"


async def test_anthropic_listing_keeps_its_own_envelope(flux_client):
    resp = await flux_client.get("/anthropic/v1/models")
    assert resp.status == 200
    doc = json.loads(await resp.read())
    assert doc["data"][0]["type"] == "model"
    assert doc["has_more"] is False
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "llm-endpoint-anthropic-models-list"


async def test_mounted_completion_post_still_captures_prompt_and_token(flux_client):
    """The reason the listing gap mattered: this is the request the chain
    leads to, and it has to work on the mounted spelling too."""
    resp = await flux_client.post(
        "/api/v1/chat/completions",
        headers={"Authorization": "Bearer sk-probe-token"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello there"}]},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "llm-endpoint-openai-chat"
    assert entry["llmModel"] == "gpt-4o"
    assert "hello there" in entry["llmPromptPreview"]
    assert entry["llmAuthTokenSha256"]
    # The log keeps the spelling the client actually sent, not the canonical
    # route, so which mounts are being probed stays measurable.
    assert entry["llmPath"] == "/api/v1/chat/completions"


async def test_unversioned_completion_post_is_answered(flux_client):
    resp = await flux_client.post(
        "/chat/completions",
        json={"model": "llama3.1:8b", "messages": [{"role": "user", "content": "ping"}]},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "llm-endpoint-openai-chat"


async def test_no_served_route_falls_to_the_defensive_404(flux_client):
    """Every dictionary route must have a renderer, or the handler's own
    bottom branch would serve a 404 from inside a matched trap."""
    for path in sorted(tbenv.LLM_ENDPOINT_PATHS):
        resp = await flux_client.get(path)
        assert resp.status != 404, path
        entry = _log_entries(flux_client.log_path)[-1]
        assert entry["result"] != "llm-endpoint-miss", path
