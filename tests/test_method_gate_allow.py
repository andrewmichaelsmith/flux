"""The global method gate: OPTIONS is answered, and a 405 carries `Allow`.

The gate in front of every trap used to refuse everything outside
GET/HEAD/POST with a bare 405. Two things were wrong with that shape and
neither is about which methods reach a handler:

  * RFC 9110 §15.5.6 requires an origin server to generate `Allow` on a
    405 response. This one did not, which is a narrower population than
    servers in general.
  * OPTIONS is the method a client sends to ask what the server accepts.
    Refusing it is self-refuting, and the gate's own log rows say OPTIONS
    is the most-asked method outside the big three by a wide margin.

These tests pin the new shape and, just as importantly, pin that the gate
still refuses the methods it refused before — the fix is to the rejection,
not to what gets through.
"""
import pytest

from flux import server as tbenv

from .test_server import _log_entries, flux_client  # noqa: F401


REFUSED = ["PUT", "DELETE", "PATCH", "PROPFIND", "TRACE"]


# ------------------------------------------------------------------ OPTIONS

@pytest.mark.asyncio
async def test_options_is_answered_not_refused(flux_client):  # noqa: F811
    resp = await flux_client.options("/")
    assert resp.status == 204
    body = await resp.read()
    assert body == b""


@pytest.mark.asyncio
async def test_options_carries_allow_and_cors(flux_client):  # noqa: F811
    resp = await flux_client.options("/api/anything")
    assert resp.headers["Allow"] == "GET, HEAD, POST, OPTIONS"
    assert resp.headers["Access-Control-Allow-Origin"] == "*"
    assert resp.headers["Access-Control-Allow-Methods"] == "GET, HEAD, POST, OPTIONS"
    assert "Content-Type" in resp.headers["Access-Control-Allow-Headers"]
    assert resp.headers["Access-Control-Max-Age"] == "86400"


@pytest.mark.asyncio
async def test_options_logs_its_own_tag(flux_client):  # noqa: F811
    await flux_client.options("/.env")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "options-preflight"
    assert entry["status"] == 204
    # The row must still identify the request, or answering OPTIONS would
    # cost the measurement the 405 row used to provide.
    assert entry["path"] == "/.env"
    assert entry["method"] == "OPTIONS"


@pytest.mark.asyncio
async def test_options_separates_browser_preflight_from_bare_probe(flux_client):  # noqa: F811
    await flux_client.options("/", headers={
        "Origin": "https://example.invalid",
        "Access-Control-Request-Method": "POST",
    })
    preflight = _log_entries(flux_client.log_path)[-1]
    assert preflight["optionsIsPreflight"] is True
    assert preflight["optionsRequestMethod"] == "POST"

    await flux_client.options("/")
    bare = _log_entries(flux_client.log_path)[-1]
    assert bare["optionsIsPreflight"] is False
    assert bare["optionsRequestMethod"] == ""


@pytest.mark.asyncio
async def test_options_does_not_reach_a_trap(flux_client):  # noqa: F811
    """OPTIONS on a canary path must not spend a canary. The gate answers
    before dispatch, so the trap is never consulted."""
    resp = await flux_client.options("/.aws/credentials")
    assert resp.status == 204
    assert _log_entries(flux_client.log_path)[-1]["result"] == "options-preflight"


# ---------------------------------------------------------------------- 405

@pytest.mark.asyncio
@pytest.mark.parametrize("method", REFUSED)
async def test_refused_methods_still_refused(flux_client, method):  # noqa: F811
    resp = await flux_client.request(method, "/")
    assert resp.status == 405


@pytest.mark.asyncio
@pytest.mark.parametrize("method", REFUSED)
async def test_405_carries_allow_header(flux_client, method):  # noqa: F811
    """RFC 9110 §15.5.6: the origin server MUST generate Allow on a 405."""
    resp = await flux_client.request(method, "/")
    assert resp.headers.get("Allow") == "GET, HEAD, POST, OPTIONS"


@pytest.mark.asyncio
async def test_405_still_logs_its_row(flux_client):  # noqa: F811
    await flux_client.request("PROPFIND", "/webdav")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "method-not-allowed"
    assert entry["status"] == 405
    assert entry["method"] == "PROPFIND"
    assert entry["path"] == "/webdav"


@pytest.mark.asyncio
async def test_405_body_unchanged(flux_client):  # noqa: F811
    resp = await flux_client.request("DELETE", "/inngest")
    assert await resp.read() == b"method not allowed\n"


@pytest.mark.asyncio
async def test_allow_header_set_is_shared_by_both_answers(flux_client):  # noqa: F811
    """One source for both, so the 405 and the 204 cannot drift apart and
    advertise different method sets for the same server."""
    refusal = await flux_client.request("PUT", "/")
    answer = await flux_client.options("/")
    assert refusal.headers["Allow"] == answer.headers["Allow"]


def test_allow_header_advertises_exactly_what_the_gate_passes():
    """The advertised set must equal the set the gate actually lets
    through, plus OPTIONS — an `Allow` that lies is worse than none."""
    advertised = {
        m.strip() for m in tbenv._ALLOW_HEADERS["Allow"].split(",")
    }
    assert advertised == {"GET", "HEAD", "POST", "OPTIONS"}
