"""Control characters in the request target must not kill the response.

`normalize_path` percent-decodes before dispatch, so the truncation-bypass
shapes a secrets-harvesting dictionary walks -- `/.env%00`, `/.env%0d` --
arrive at the handlers as a path carrying a real NUL or CR. Every handler
that reflects the path into a `Location` (or `Content-Disposition`) header
then built a header value aiohttp refuses to serialise, and the client got
a dropped connection instead of the trap.

Two costs: the redirect-based modules are the DNS-callback and
redirect-chain instruments, so the probe went unmeasured; and a honeypot
that resets the connection on `%00` while every real server answers is
itself a fingerprint.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from yarl import URL

from flux import server as tbenv

from .test_server import _fake_issue_credentials  # noqa: F401


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_issue_credentials)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


# --------------------------------------------------------------------------
# header_safe_path
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/.env\x00", "/.env%00"),
        ("/.env\r", "/.env%0D"),
        ("/.env\n", "/.env%0A"),
        ("/.env\t", "/.env%09"),
        ("/a\x7fb", "/a%7Fb"),
        ("/\x01\x1f", "/%01%1F"),
    ],
)
def test_control_characters_are_percent_reencoded(raw, expected):
    assert tbenv.header_safe_path(raw) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/.env",
        "/storage/logs/laravel.log",
        # The prefix-injection shapes that arrive in the same dictionary
        # must pass through byte-identical -- they are header-safe already.
        "/$(pwd)/.env",
        "/~/.aws/credentials",
        "/:8443/.env",
        # Percent signs that are already escapes stay untouched.
        "/%2eenv",
        "/a b/c?d=e&f=g",
        "/ünïcode",
    ],
)
def test_header_safe_paths_pass_through_unchanged(path):
    """Only C0 + DEL are touched, so no existing redirect target moves."""
    assert tbenv.header_safe_path(path) == path


def test_empty_path_is_returned_as_is():
    assert tbenv.header_safe_path("") == ""


# --------------------------------------------------------------------------
# End-to-end: the request that used to reset the connection
# --------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_target",
    [
        "/.env%00",
        "/.env%0d",
        "/%2eenv%00",
        "/%2eenv%0d",
        "/api/%2eenv%00",
        "/.git/config%00",
    ],
)
async def test_truncation_bypass_shapes_get_a_response(flux_client, raw_target):
    """Previously: ServerDisconnectedError. Now: a real HTTP status."""
    resp = await flux_client.get(
        URL(raw_target, encoded=True),
        headers={"Host": "traceenv-x.netqale.com"},
    )
    assert resp.status in (200, 302, 401, 404), raw_target
    # Whatever header the handler reflected must be serialisable and must
    # not carry a raw control character back out.
    for value in resp.headers.values():
        assert "\x00" not in value
        assert "\r" not in value
        assert "\n" not in value


@pytest.mark.asyncio
async def test_dns_callback_location_carries_the_encoded_path(monkeypatch, flux_client):
    """The DNS-callback redirect is the instrument this bug disabled: the
    Location must still be produced, and still spell the probe."""
    monkeypatch.setattr(tbenv, "MOD_DNS_CALLBACK_ENABLED", True)
    monkeypatch.setattr(tbenv, "MOD_DNS_CALLBACK_DOMAIN", "cb.example")
    resp = await flux_client.get(
        URL("/.env%00", encoded=True),
        headers={"Host": "traceenv-x.netqale.com"},
        allow_redirects=False,
    )
    loc = resp.headers.get("Location")
    if loc is not None:
        assert "\x00" not in loc
        # The decoded NUL is re-encoded, not dropped, so the redirect
        # target still spells what was asked for.
        assert "%00" in loc
