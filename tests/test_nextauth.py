"""Auth.js / NextAuth credential-provider surface.

The behaviour under test is not "does the path return 200" — it is whether
the log can tell a client that completed the two-step CSRF exchange from
one that replayed a path, and whether an attacker-supplied `callbackUrl`
is captured as its own field.
"""
import json

import pytest

from flux import server as tbenv


@pytest.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


def _last(log_path):
    return _entries(log_path)[-1]


# --- routing --------------------------------------------------------------


@pytest.mark.parametrize("path,op,provider", [
    ("/api/auth/providers", "providers", ""),
    ("/api/auth/csrf", "csrf", ""),
    ("/api/auth/session", "session", ""),
    ("/api/auth/signin", "signin", ""),
    ("/api/auth/signin/", "signin", ""),
    ("/api/auth/signin/credentials", "signin", "credentials"),
    ("/api/auth/callback/credentials", "callback", "credentials"),
    ("/api/auth/callback/google", "callback", "google"),
    ("/api/auth/signout", "signout", ""),
    ("/api/auth/error", "error", ""),
    # The basePath override, and the bare provider-less callback probe.
    ("/auth/signin", "signin", ""),
    ("/auth/callback", "callback", ""),
    ("/auth/csrf", "csrf", ""),
    # Case-insensitive, as the framework's own router is.
    ("/API/Auth/CSRF", "csrf", ""),
])
def test_nextauth_route_resolves(path, op, provider):
    assert tbenv.nextauth_route(path) == (op, provider)


@pytest.mark.parametrize("path", [
    "/api/auth",
    "/api/auth/",
    "/api/authenticate",
    "/api/auth/unknown",
    # `providers` takes no provider segment, so this is not a real route.
    "/api/auth/providers/google",
    # One segment deeper than the framework serves.
    "/api/auth/callback/google/extra",
    "/authentication/signin",
    "/wp-login.php",
    "/login",
    "/",
])
def test_nextauth_route_rejects_non_routes(path):
    assert tbenv.nextauth_route(path) is None


async def test_nextauth_disabled_404s(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "NEXTAUTH_ENABLED", False)
    resp = await flux_client.get("/api/auth/csrf")
    assert resp.status == 404


# --- the leaf routes ------------------------------------------------------


async def test_providers_lists_a_credentials_provider(flux_client):
    resp = await flux_client.get(
        "/api/auth/providers", headers={"X-Forwarded-For": "203.0.113.20"})
    assert resp.status == 200
    body = json.loads(await resp.text())
    assert body["credentials"]["type"] == "credentials"
    # The URLs must point back at the mount point the client used, or the
    # next step of the flow leaves the path family it arrived on.
    assert body["credentials"]["callbackUrl"] == "/api/auth/callback/credentials"
    assert _last(flux_client.log_path)["result"] == "nextauth-providers"


async def test_providers_answers_under_the_basepath_override(flux_client):
    resp = await flux_client.get("/auth/providers")
    body = json.loads(await resp.text())
    assert body["credentials"]["signinUrl"] == "/auth/signin/credentials"


async def test_session_is_an_empty_object_not_a_401(flux_client):
    """Auth.js answers an unauthenticated session with 200 `{}`. A 401
    here would be the tell."""
    resp = await flux_client.get("/api/auth/session")
    assert resp.status == 200
    assert json.loads(await resp.text()) == {}
    assert _last(flux_client.log_path)["result"] == "nextauth-session"


async def test_error_page_reflects_the_named_error(flux_client):
    resp = await flux_client.get("/api/auth/error?error=CredentialsSignin")
    assert resp.status == 200
    assert b"CredentialsSignin" in await resp.read()
    assert _last(flux_client.log_path)["result"] == "nextauth-error"


async def test_error_page_escapes_a_reflected_value(flux_client):
    resp = await flux_client.get("/api/auth/error?error=%3Cscript%3Ex%3C/script%3E")
    body = await resp.read()
    assert b"<script>" not in body
    assert b"&lt;script&gt;" in body


# --- the CSRF exchange, which is the point --------------------------------


async def test_csrf_issues_a_token_and_sets_the_cookie(flux_client):
    resp = await flux_client.get(
        "/api/auth/csrf", headers={"X-Forwarded-For": "203.0.113.21"})
    assert resp.status == 200
    token = json.loads(await resp.text())["csrfToken"]
    assert len(token) == 64
    assert "next-auth.csrf-token=" in resp.headers["Set-Cookie"]
    assert _last(flux_client.log_path)["result"] == "nextauth-csrf"


async def test_csrf_token_is_per_request_not_fixed(flux_client):
    """A fixed token would ship the same string from every host and give
    zero discrimination on replay."""
    seen = set()
    for _ in range(4):
        resp = await flux_client.get("/api/auth/csrf")
        seen.add(json.loads(await resp.text())["csrfToken"])
    assert len(seen) == 4


async def test_signin_page_embeds_a_token_that_scores_as_known(flux_client):
    """A client that reads the token out of the HTML rather than the JSON
    endpoint did more work, not less, and must not be scored as a
    replayer."""
    ip = "203.0.113.22"
    resp = await flux_client.get(
        "/api/auth/signin", headers={"X-Forwarded-For": ip})
    html = await resp.text()
    token = html.split('name="csrfToken" value="', 1)[1].split('"', 1)[0]

    resp = await flux_client.post(
        "/api/auth/callback/credentials",
        data={"username": "admin", "password": "hunter2", "csrfToken": token},
        headers={"X-Forwarded-For": ip}, allow_redirects=False)
    assert resp.status == 302
    entry = _last(flux_client.log_path)
    assert entry["result"] == "nextauth-credentials"
    assert entry["nextauthCsrfKnown"] is True


async def test_completed_exchange_scores_known(flux_client):
    ip = "203.0.113.23"
    resp = await flux_client.get(
        "/api/auth/csrf", headers={"X-Forwarded-For": ip})
    token = json.loads(await resp.text())["csrfToken"]

    resp = await flux_client.post(
        "/api/auth/callback/credentials",
        data={"username": "root", "password": "toor", "csrfToken": token},
        headers={"X-Forwarded-For": ip}, allow_redirects=False)
    entry = _last(flux_client.log_path)
    assert entry["nextauthCsrfKnown"] is True
    assert entry["nextauthUsername"] == "root"
    assert entry["nextauthHasPwd"] is True


async def test_blind_post_scores_unknown(flux_client):
    """The replay case: credentials with no prior GET and an invented
    token. This is the majority population and must be separable."""
    resp = await flux_client.post(
        "/api/auth/signin",
        data={"username": "admin", "password": "admin", "csrfToken": "deadbeef"},
        headers={"X-Forwarded-For": "203.0.113.24"}, allow_redirects=False)
    assert resp.status == 302
    entry = _last(flux_client.log_path)
    assert entry["nextauthCsrfKnown"] is False
    assert entry["nextauthCsrfSubmitted"] == "deadbeef"


async def test_a_token_issued_to_one_source_is_not_known_for_another(flux_client):
    """Tokens are scoped per source, so one actor cannot make another
    look protocol-aware by sharing a harvested value."""
    resp = await flux_client.get(
        "/api/auth/csrf", headers={"X-Forwarded-For": "203.0.113.25"})
    token = json.loads(await resp.text())["csrfToken"]

    await flux_client.post(
        "/api/auth/callback/credentials",
        data={"username": "a", "password": "b", "csrfToken": token},
        headers={"X-Forwarded-For": "203.0.113.26"}, allow_redirects=False)
    assert _last(flux_client.log_path)["nextauthCsrfKnown"] is False


# --- capture --------------------------------------------------------------


async def test_json_body_credentials_are_captured(flux_client):
    """Hand-written clients post JSON; a form-only reader would drop
    these captures silently."""
    resp = await flux_client.post(
        "/api/auth/callback/credentials",
        data=json.dumps({"email": "ops@example.com", "password": "s3cret"}),
        headers={"Content-Type": "application/json",
                 "X-Forwarded-For": "203.0.113.27"},
        allow_redirects=False)
    entry = _last(flux_client.log_path)
    assert entry["nextauthUsername"] == "ops@example.com"
    assert entry["nextauthUsernameKey"] == "email"
    assert entry["nextauthHasPwd"] is True


async def test_the_password_value_is_never_logged_as_its_own_field(flux_client):
    await flux_client.post(
        "/api/auth/callback/credentials",
        data={"username": "u", "password": "TopSecret123"},
        headers={"X-Forwarded-For": "203.0.113.28"}, allow_redirects=False)
    entry = _last(flux_client.log_path)
    assert "nextauthPassword" not in entry
    assert entry["nextauthHasPwd"] is True


async def test_attacker_supplied_callback_url_is_captured(flux_client):
    """`callbackUrl` is an open-redirect target, so an off-host value is a
    piece of the attacker's own infrastructure rather than a guess about
    ours — it gets its own field."""
    await flux_client.post(
        "/api/auth/signin",
        data={"username": "u", "password": "p",
              "callbackUrl": "https://evil.example.net/collect"},
        headers={"X-Forwarded-For": "203.0.113.29"}, allow_redirects=False)
    entry = _last(flux_client.log_path)
    assert entry["nextauthCallbackUrl"] == "https://evil.example.net/collect"


async def test_callback_url_from_the_query_string_is_captured(flux_client):
    await flux_client.post(
        "/api/auth/signin?callbackUrl=https://evil.example.net/q",
        data={"username": "u", "password": "p"},
        headers={"X-Forwarded-For": "203.0.113.30"}, allow_redirects=False)
    assert _last(flux_client.log_path)["nextauthCallbackUrl"] == (
        "https://evil.example.net/q")


async def test_credentials_post_is_always_rejected(flux_client):
    """Every guess fails, which is what an app with working credentials
    does and what keeps this trap from inventing a session token."""
    for password in ("admin", "password", "123456"):
        resp = await flux_client.post(
            "/api/auth/callback/credentials",
            data={"username": "admin", "password": password},
            headers={"X-Forwarded-For": "203.0.113.31"},
            allow_redirects=False)
        assert resp.status == 302
        assert "error=CredentialsSignin" in resp.headers["Location"]


async def test_no_set_cookie_session_is_ever_granted(flux_client):
    resp = await flux_client.post(
        "/api/auth/callback/credentials",
        data={"username": "admin", "password": "admin"},
        headers={"X-Forwarded-For": "203.0.113.32"}, allow_redirects=False)
    assert "Set-Cookie" not in resp.headers


async def test_rejection_redirect_stays_on_the_clients_mount_point(flux_client):
    resp = await flux_client.post(
        "/auth/callback/credentials",
        data={"username": "u", "password": "p"},
        headers={"X-Forwarded-For": "203.0.113.33"}, allow_redirects=False)
    assert resp.headers["Location"] == "/auth/error?error=CredentialsSignin"


async def test_bare_callback_probe_is_tagged_separately(flux_client):
    """`/auth/callback` with no submission is a different behaviour from a
    sign-in page fetch and should not share its bucket."""
    resp = await flux_client.get(
        "/auth/callback", headers={"X-Forwarded-For": "203.0.113.34"})
    assert resp.status == 200
    assert _last(flux_client.log_path)["result"] == "nextauth-callback-probe"


async def test_head_returns_headers_without_a_body(flux_client):
    resp = await flux_client.head("/api/auth/providers")
    assert resp.status == 200
    assert await resp.read() == b""


# --- cache bounds ---------------------------------------------------------


def test_csrf_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(tbenv, "NEXTAUTH_CSRF_CACHE_MAX", 8)
    tbenv._NEXTAUTH_CSRF_CACHE.clear()
    for i in range(200):
        tbenv._nextauth_csrf_store(f"198.51.100.{i % 250}", f"token{i}")
    assert len(tbenv._NEXTAUTH_CSRF_CACHE) <= 9


def test_csrf_tokens_per_source_are_bounded(monkeypatch):
    tbenv._NEXTAUTH_CSRF_CACHE.clear()
    for i in range(500):
        tbenv._nextauth_csrf_store("198.51.100.7", f"token{i}")
    assert len(tbenv._NEXTAUTH_CSRF_CACHE["198.51.100.7"][1]) <= 33


def test_expired_tokens_stop_scoring_as_known(monkeypatch):
    monkeypatch.setattr(tbenv, "NEXTAUTH_CSRF_CACHE_TTL", 60)
    tbenv._NEXTAUTH_CSRF_CACHE.clear()
    tbenv._nextauth_csrf_store("198.51.100.9", "tok")
    assert tbenv._nextauth_csrf_known("198.51.100.9", "tok")

    expiry, tokens = tbenv._NEXTAUTH_CSRF_CACHE["198.51.100.9"]
    tbenv._NEXTAUTH_CSRF_CACHE["198.51.100.9"] = (expiry - 10_000, tokens)
    assert not tbenv._nextauth_csrf_known("198.51.100.9", "tok")


def test_nextauth_defaults_on():
    assert tbenv.NEXTAUTH_ENABLED, (
        "HONEYPOT_NEXTAUTH_ENABLED should default to True — no branch on "
        "this surface issues a canary, so it costs nothing upstream."
    )
