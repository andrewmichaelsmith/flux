"""AI-gateway proxy admin API (control plane).

The inference trap answers `/v1/chat/completions` and friends — someone
looking for free tokens. This one answers the routes that manage the
gateway itself: the model registry, key minting, and spend reporting.
A client walking those is not after inference, it is after a proxy it
can mint its own keys on.

Two behaviours carry the whole trap and are pinned hardest here:

1. Any presented token is accepted and its hash + prefix preview logged.
   The guessed master keys are the intel; a 404 would have recorded none
   of them. A request with no token at all gets the proxy's own 401,
   because that is the answer that says "real route, guess again".
2. The model registry carries a live canary in the upstream provider
   credential slot — the operator's cloud credential, not the proxy's —
   and every other credential-shaped field in the family is per-hit
   random. Nothing fixed, anywhere.
"""

import json

import pytest
import pytest_asyncio

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


AUTH = {"Authorization": "Bearer sk-1234"}


# --- Path matching (pure) ----------------------------------------------

@pytest.mark.parametrize("path", sorted(tbenv.LITELLM_ADMIN_PATHS))
def test_every_configured_path_matches(path):
    assert tbenv.is_litellm_admin_path(path)
    assert tbenv.is_litellm_admin_path(path + "/")
    assert tbenv.is_litellm_admin_path(path.upper())
    assert tbenv.is_litellm_admin_path(path + "?page=1")


@pytest.mark.parametrize("path", [
    "/model/info,/v1/model/info,/key/info",  # the CSV, not a path
    "/key",
    "/model",
    "/key/generate/extra",
    "/global/spend",
    "/global/spend/logs/detail",
    "/api/key/generate",
    "/v2/model/info",
    "/models",
    "/health",
    "/v1/models",          # the inference trap owns this one
    "/v1/chat/completions",
    "/",
])
def test_does_not_match(path):
    assert not tbenv.is_litellm_admin_path(path)


def test_observed_spellings_match_by_literal():
    """Pinned by literal rather than by iterating the set, so trimming
    the set fails visibly instead of silently shrinking coverage to
    whatever the set happens to contain."""
    for path in ("/model/info", "/v1/model/info", "/key/info",
                 "/key/generate", "/global/spend/logs"):
        assert tbenv.is_litellm_admin_path(path), path


def test_disabled_switch_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "LITELLM_ADMIN_ENABLED", False)
    assert not tbenv.is_litellm_admin_path("/model/info")


def test_default_on():
    assert tbenv.LITELLM_ADMIN_ENABLED is True


# --- Renderers (pure) ---------------------------------------------------

def test_model_registry_carries_the_canary_in_the_provider_slot():
    doc = json.loads(tbenv.render_litellm_model_info(FAKE_TRACEBIT))
    bedrock = [
        e for e in doc["data"]
        if e["litellm_params"]["model"].startswith("bedrock/")
    ]
    assert len(bedrock) == 1
    params = bedrock[0]["litellm_params"]
    assert params["aws_access_key_id"] == FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
    assert params["aws_secret_access_key"] == FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]
    assert params["aws_session_token"] == FAKE_TRACEBIT["aws"]["awsSessionToken"]


def test_every_non_canary_secret_slot_is_per_hit_random():
    """The design principle, enforced: two renders must not share any
    credential-shaped value except the canary itself."""
    a = json.loads(tbenv.render_litellm_model_info(FAKE_TRACEBIT))
    b = json.loads(tbenv.render_litellm_model_info(FAKE_TRACEBIT))
    for ea, eb in zip(a["data"], b["data"]):
        for key in ("api_key",):
            if key in ea["litellm_params"]:
                assert ea["litellm_params"][key] != eb["litellm_params"][key], key
        assert ea["model_info"]["id"] != eb["model_info"]["id"]

    assert tbenv._litellm_virtual_key() != tbenv._litellm_virtual_key()
    assert tbenv._litellm_token_hash() != tbenv._litellm_token_hash()

    ka = json.loads(tbenv.render_litellm_key_info())
    kb = json.loads(tbenv.render_litellm_key_info())
    assert ka["key"] != kb["key"]
    assert ka["info"]["token"] != kb["info"]["token"]

    sa = json.loads(tbenv.render_litellm_spend_logs())
    sb = json.loads(tbenv.render_litellm_spend_logs())
    assert [r["api_key"] for r in sa] != [r["api_key"] for r in sb]


def test_minted_key_has_the_proxy_key_shape():
    key = json.loads(tbenv.render_litellm_key_generate([]))["key"]
    assert key.startswith("sk-")
    assert len(key) > 20


def test_key_info_returns_a_hash_not_key_material():
    doc = json.loads(tbenv.render_litellm_key_info())
    assert not doc["key"].startswith("sk-")
    assert len(doc["key"]) == 64


def test_key_generate_echoes_the_requested_models():
    doc = json.loads(tbenv.render_litellm_key_generate(["gpt-4o", "claude-3-5-sonnet"]))
    assert doc["models"] == ["gpt-4o", "claude-3-5-sonnet"]


# --- Request-field extraction (pure) ------------------------------------

def test_key_request_fields_capture_intent():
    fields = tbenv._litellm_key_request_fields(json.dumps({
        "models": ["gpt-4o", "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0"],
        "max_budget": 500,
        "duration": "30d",
        "key_alias": "ops",
    }).encode())
    assert fields["models"][0] == "gpt-4o"
    assert fields["budget"] == "500"
    assert fields["duration"] == "30d"
    assert fields["alias"] == "ops"


@pytest.mark.parametrize("body", [b"", b"not json", b"[1,2,3]", b"null", b'{"models": 3}'])
def test_key_request_fields_survive_junk(body):
    assert isinstance(tbenv._litellm_key_request_fields(body), dict)


# --- Dispatch -----------------------------------------------------------

@pytest_asyncio.fixture
def _canary(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "LITELLM_ADMIN_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)


async def test_no_token_gets_the_proxy_401_not_a_404(flux_client, _canary):
    """A 404 would tell the sweep nothing and end the walk; the 401
    envelope says the route is real, which is what makes the next
    request a key guess we can record."""
    resp = await flux_client.get("/model/info")
    assert resp.status == 401
    doc = json.loads(await resp.read())
    assert doc["error"]["type"] == "auth_error"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "litellm-admin-unauthenticated"
    assert entry["litellmHasAuth"] is False
    assert "litellmAuthTokenSha256" not in entry


async def test_guessed_master_key_is_accepted_and_recorded(flux_client, _canary):
    resp = await flux_client.get("/model/info", headers=AUTH)
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "litellm-model-info"
    assert entry["litellmHasAuth"] is True
    assert entry["litellmAuthScheme"] == "bearer"
    assert len(entry["litellmAuthTokenSha256"]) == 64
    # The preview keeps the prefix, which is what groups a key across IPs.
    assert entry["litellmAuthTokenPreview"].startswith("sk-1")


async def test_the_same_guessed_key_hashes_identically(flux_client, _canary):
    """Grouping the same stolen or guessed key across source IPs is the
    reason the hash is logged at all."""
    await flux_client.get("/key/info", headers=AUTH)
    await flux_client.get("/v1/key/info", headers={"x-api-key": "sk-1234"})
    a, b = _log_entries(flux_client.log_path)[-2:]
    assert a["litellmAuthTokenSha256"] == b["litellmAuthTokenSha256"]


async def test_model_registry_serves_a_live_canary_over_dispatch(flux_client, _canary):
    resp = await flux_client.get("/v1/model/info", headers=AUTH)
    body = await resp.read()
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"].encode() in body
    assert FAKE_TRACEBIT["aws"]["awsSecretAccessKey"].encode() in body


async def test_key_generate_post_mints_and_logs_the_request(flux_client, _canary):
    resp = await flux_client.post(
        "/key/generate", headers=AUTH,
        data=json.dumps({"models": ["gpt-4o"], "max_budget": 100,
                         "duration": "7d"}).encode(),
    )
    assert resp.status == 200
    assert json.loads(await resp.read())["key"].startswith("sk-")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "litellm-key-generate"
    assert entry["litellmRequestedModels"] == ["gpt-4o"]
    assert entry["litellmRequestedBudget"] == "100"
    assert entry["litellmRequestedDuration"] == "7d"


async def test_key_generate_get_is_a_405_that_still_confirms_the_route(
        flux_client, _canary):
    """The route is POST-only upstream, and the observed sweeps GET it
    anyway. 405 is both the honest answer and a confirmation."""
    resp = await flux_client.get("/key/generate", headers=AUTH)
    assert resp.status == 405
    assert json.loads(await resp.read())["detail"] == "Method Not Allowed"
    assert _log_entries(flux_client.log_path)[-1]["result"] == "litellm-key-generate-probe"


async def test_spend_logs_dispatch(flux_client, _canary):
    resp = await flux_client.get("/global/spend/logs", headers=AUTH)
    assert resp.status == 200
    rows = json.loads(await resp.read())
    assert rows and all(not r["api_key"].startswith("sk-") for r in rows)
    assert _log_entries(flux_client.log_path)[-1]["result"] == "litellm-spend-logs"


async def test_every_route_returns_parseable_json_and_a_distinct_tag(
        flux_client, _canary):
    seen = set()
    for path in sorted(tbenv.LITELLM_ADMIN_PATHS):
        resp = await flux_client.get(path, headers=AUTH)
        json.loads(await resp.read())
        entry = _log_entries(flux_client.log_path)[-1]
        assert entry["result"].startswith("litellm-"), path
        seen.add(entry["result"])
    # Distinct shapes must not collapse into one tag, or the log cannot
    # separate a registry read from a key mint.
    assert {"litellm-model-info", "litellm-key-info", "litellm-spend-logs",
            "litellm-key-generate-probe"} <= seen


async def test_keyless_deployment_404s_the_family(flux_client, monkeypatch):
    """Canary-backed family: without an issuing key the registry would
    have empty credential slots, so the whole surface stays 404."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    for path in ("/model/info", "/key/info", "/global/spend/logs"):
        resp = await flux_client.get(path, headers=AUTH)
        assert resp.status == 404, path


async def test_issuance_failure_does_not_serve_empty_credential_slots(
        flux_client, monkeypatch):
    async def _no_canary(*args, **kwargs):
        return None

    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _no_canary)
    resp = await flux_client.get("/model/info", headers=AUTH)
    body = await resp.read()
    assert b"aws_access_key_id" not in body
    assert _log_entries(flux_client.log_path)[-1]["result"] == (
        "litellm-model-info-tracebit-error")


async def test_inference_trap_still_owns_its_paths(flux_client, _canary):
    """Regression: the control-plane matcher sits beside a trap whose
    paths share the `/v1/` prefix."""
    resp = await flux_client.get("/v1/models")
    assert resp.status == 200
    assert _log_entries(flux_client.log_path)[-1]["result"] == (
        "llm-endpoint-models-list")


async def test_head_sends_headers_without_a_body(flux_client, _canary):
    resp = await flux_client.head("/key/info", headers=AUTH)
    assert resp.status == 200
    assert await resp.read() == b""
