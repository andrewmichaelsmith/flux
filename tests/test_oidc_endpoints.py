"""The endpoints the OIDC discovery document advertises.

The document was already served; every address it published 404'd. These
tests pin the two properties that fixes that and keeps it fixed:

  1. Every URL in the published document resolves to a trap (the guard
     test walks the document and follows each one), and a route added to
     the advertised table without a handler makes that guard fail.
  2. Nothing the surface emits is a fixed literal, and nothing it emits
     is a working open redirect.
"""
import json

import pytest

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


HEADERS = {
    "X-Forwarded-Host": "idp.example.com",
    "X-Forwarded-For": "203.0.113.7",
    "X-Forwarded-Proto": "https",
}


@pytest.fixture
def oidc_on(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "OIDC_DISCOVERY_ENABLED", True)
    monkeypatch.setattr(tbenv, "OIDC_ENDPOINTS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)


# --- matching -----------------------------------------------------------

@pytest.mark.parametrize("path,kind,realm", [
    ("/oauth/certs", "certs", ""),
    ("/oauth/auth", "auth", ""),
    ("/oauth/token", "token", ""),
    ("/oauth/token/introspect", "token/introspect", ""),
    ("/oauth/revoke", "revoke", ""),
    ("/oauth/userinfo", "userinfo", ""),
    ("/oauth/logout", "logout", ""),
    ("/oauth/clients-registrations/openid-connect",
     "clients-registrations/openid-connect", ""),
    ("/oauth2/token", "token", ""),
    ("/idp/certs", "certs", ""),
    # Keycloak realm layouts, modern and legacy-`/auth`-prefixed.
    ("/realms/master/protocol/openid-connect/certs", "certs", "master"),
    ("/realms/acme/protocol/openid-connect/token", "token", "acme"),
    ("/auth/realms/acme/protocol/openid-connect/userinfo", "userinfo", "acme"),
    # The login form's own submit target sits beside `protocol/`.
    ("/realms/acme/login-actions/authenticate",
     "login-actions/authenticate", "acme"),
    # Standalone JWKS spellings a client guesses without reading the doc.
    ("/.well-known/jwks.json", "certs", ""),
    ("/jwks.json", "certs", ""),
    ("/oauth2/certs", "certs", ""),
    # Trailing slash and query string are tolerated.
    ("/oauth/certs/", "certs", ""),
    ("/oauth/token?x=1", "token", ""),
    # The discovery normaliser's encoded-slash handling applies here too.
    ("/%2Foauth/certs", "certs", ""),
])
def test_endpoint_paths_match(path, kind, realm, monkeypatch):
    monkeypatch.setattr(tbenv, "OIDC_ENDPOINTS_ENABLED", True)
    match = tbenv.is_oidc_endpoint_path(path)
    assert match is not None, f"{path} did not match"
    assert match.kind == kind
    assert match.realm == realm


@pytest.mark.parametrize("path", [
    # Bare `/certs` is too generic to claim — it collides with ordinary
    # static-asset layouts and buys no signal the advertised address
    # does not already give us.
    "/certs",
    "/token",
    "/userinfo",
    "/oauth",
    "/oauth/",
    "/oauth/nope",
    "/oauth/tokenx",
    "/realms/master/protocol/openid-connect/nope",
    "/realms/master/protocol/saml/certs",
    "/realms/master/certs",
    "/realms/certs",
    "/wp-json/wp/v2/users",
    "/.env",
])
def test_non_endpoint_paths_do_not_match(path, monkeypatch):
    monkeypatch.setattr(tbenv, "OIDC_ENDPOINTS_ENABLED", True)
    assert tbenv.is_oidc_endpoint_path(path) is None


def test_disabled_switch_stops_matching(monkeypatch):
    monkeypatch.setattr(tbenv, "OIDC_ENDPOINTS_ENABLED", False)
    assert tbenv.is_oidc_endpoint_path("/oauth/certs") is None


# --- the guard: advertised == served ------------------------------------

async def test_following_every_advertised_endpoint_reaches_a_trap(
    flux_client, oidc_on,
):
    """Fetch the discovery document and follow every URL it publishes.

    This is the property the trap exists to establish. It asserts *a
    trap answered* rather than a particular status, because the correct
    answer differs per endpoint — a JWKS is 200, an unauthenticated
    token endpoint is 405 on GET, userinfo is 401 — and all three prove
    the route is registered where a 404 would prove the opposite.
    """
    resp = await flux_client.get(
        "/.well-known/openid-configuration", headers=HEADERS,
    )
    assert resp.status == 200
    doc = json.loads(await resp.text())

    advertised = [
        (key, value) for key, value in doc.items()
        if key.endswith(("_endpoint", "_uri")) and isinstance(value, str)
    ]
    # The document must actually publish the endpoints, or this test
    # passes vacuously.
    assert len(advertised) >= 8, sorted(k for k, _ in advertised)

    for key, url in advertised:
        assert url.startswith("https://idp.example.com/"), (key, url)
        path = url[len("https://idp.example.com"):]
        followed = await flux_client.get(path, headers=HEADERS)
        assert followed.status != 404, f"{key} -> {path} is advertised but 404s"

    entries = _log_entries(flux_client.log_path)
    tags = {e["result"] for e in entries}
    assert "not-handled" not in tags, [
        e["path"] for e in entries if e["result"] == "not-handled"
    ]


async def test_a_new_table_entry_is_advertised_and_served_together(
    flux_client, oidc_on, monkeypatch,
):
    """Mutation check: the table is genuinely the single source.

    Adding an entry must move *both* sides at once — the document starts
    advertising the address and the matcher starts accepting it. That is
    the property that makes an advertised-but-404ing endpoint
    unrepresentable, which is the defect this trap was built to remove.

    If a future refactor gave the renderer and the matcher separate
    lists, this test would fail: the document would advertise the new
    address and following it would 404.
    """
    monkeypatch.setitem(
        tbenv._OIDC_ENDPOINT_KINDS, "never-listed-elsewhere", ("bogus_endpoint", False),
    )
    resp = await flux_client.get(
        "/.well-known/openid-configuration", headers=HEADERS,
    )
    doc = json.loads(await resp.text())
    assert "bogus_endpoint" in doc, "renderer does not read the table"

    path = doc["bogus_endpoint"][len("https://idp.example.com"):]
    assert tbenv.is_oidc_endpoint_path(path) is not None, (
        "matcher does not read the table — the two sides have drifted apart"
    )
    followed = await flux_client.get(path, headers=HEADERS)
    assert followed.status != 404, "advertised address 404s"


# --- the host the document publishes -----------------------------------

@pytest.mark.parametrize("proxy_host", [
    "127.0.0.1", "localhost", "::1", "[::1]", "10.0.0.5", "192.168.1.1",
    "127.0.0.1:18081", "",
])
def test_a_proxy_rewritten_host_never_reaches_the_published_urls(proxy_host):
    """Reproduces the deployment condition, which is what the other
    tests could not see.

    A reverse proxy in front of this server rewrites `Host` (and
    `X-Forwarded-Host` with it) to its upstream address. Every test that
    passes a hostname straight into the renderer is blind to that, and
    the document shipped `issuer: https://127.0.0.1` with all nine of its
    endpoints under it because of exactly that blind spot. Found by
    probing a deployment, not by reading the code.
    """
    doc = json.loads(
        tbenv.render_oidc_discovery_json(
            FAKE_TRACEBIT, proxy_host, "", False, "24.0.5",
        )
    )
    published = [
        v for k, v in doc.items()
        if (k == "issuer" or k.endswith(("_endpoint", "_uri"))) and isinstance(v, str)
    ]
    assert len(published) >= 9
    for url in published:
        assert "127.0.0.1" not in url, url
        assert "localhost" not in url, url
        assert "::1" not in url, url
        assert "10.0.0.5" not in url and "192.168.1.1" not in url, url
        assert url.startswith("https://"), url
        # And it must still be a followable name, not an empty authority.
        authority = url[len("https://"):].split("/", 1)[0]
        assert tbenv._host_is_externally_plausible(authority), url


def test_the_login_form_action_is_not_loopback_either():
    """The action is an absolute URL the browser posts to. A loopback
    one posts the credentials to the client's own machine."""
    body = tbenv.render_oidc_login_page("127.0.0.1", "master", "account", "24.0.5").decode()
    action = body.split('action="', 1)[1].split('"', 1)[0]
    assert "127.0.0.1" not in action
    assert action.startswith("https://")


async def test_over_the_wire_a_rewritten_host_still_publishes_followable_urls(
    flux_client, oidc_on, monkeypatch,
):
    """End to end through the real dispatch, with the header a proxy
    actually sends."""
    resp = await flux_client.get(
        "/.well-known/openid-configuration",
        headers={
            "X-Forwarded-Host": "127.0.0.1",
            "X-Forwarded-For": "203.0.113.7",
            "X-Forwarded-Proto": "https",
        },
    )
    doc = json.loads(await resp.text())
    assert "127.0.0.1" not in json.dumps(doc)

    # Every advertised path still resolves when followed relative to the
    # server, which is what makes the fix a fix rather than a mask.
    for key, url in doc.items():
        if not (key.endswith(("_endpoint", "_uri")) and isinstance(url, str)):
            continue
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        followed = await flux_client.get(path, headers=HEADERS)
        assert followed.status != 404, f"{key} -> {path}"


def test_oauth_sibling_document_omits_the_oidc_only_endpoints():
    oauth = json.loads(
        tbenv.render_oidc_discovery_json(FAKE_TRACEBIT, "idp.example.com", "", True, "24.0.5")
    )
    oidc = json.loads(
        tbenv.render_oidc_discovery_json(FAKE_TRACEBIT, "idp.example.com", "", False, "24.0.5")
    )
    assert "userinfo_endpoint" not in oauth
    assert "end_session_endpoint" not in oauth
    assert oidc["userinfo_endpoint"].endswith("/oauth/userinfo")
    assert oidc["end_session_endpoint"].endswith("/oauth/logout")
    # The shared endpoints are identical between the two documents.
    assert oauth["token_endpoint"] == oidc["token_endpoint"]
    assert oauth["jwks_uri"] == oidc["jwks_uri"]


def test_realm_placement_advertises_realm_scoped_endpoints():
    doc = json.loads(
        tbenv.render_oidc_discovery_json(
            FAKE_TRACEBIT, "idp.example.com", "acme", False, "24.0.5",
        )
    )
    assert doc["issuer"] == "https://idp.example.com/realms/acme"
    assert doc["jwks_uri"] == (
        "https://idp.example.com/realms/acme/protocol/openid-connect/certs"
    )
    # And that advertised address is one the matcher accepts.
    match = tbenv.is_oidc_endpoint_path(
        doc["jwks_uri"][len("https://idp.example.com"):]
    )
    assert match is not None and match.kind == "certs" and match.realm == "acme"


# --- responses ----------------------------------------------------------

async def test_jwks_is_well_formed_and_never_fixed(flux_client, oidc_on):
    bodies = []
    for _ in range(2):
        resp = await flux_client.get("/oauth/certs", headers=HEADERS)
        assert resp.status == 200
        assert resp.headers["Content-Type"].startswith("application/json")
        bodies.append(json.loads(await resp.text()))

    first, second = bodies
    keys = first["keys"]
    assert len(keys) == 3
    by_kty = {k["kty"] for k in keys}
    assert by_kty == {"RSA", "EC"}
    for key in keys:
        assert key["kid"]
        if key["kty"] == "RSA":
            assert key["e"] == "AQAB"
            # 2048-bit modulus: 256 bytes -> 342 unpadded base64url chars.
            assert len(key["n"]) == 342
        else:
            assert key["crv"] == "P-256" and key["x"] and key["y"]

    # A fixed key would be a fleet-wide fingerprint in a document
    # scanners archive, which is why this is a hard assertion and not a
    # style preference.
    for a, b in zip(first["keys"], second["keys"]):
        assert a["kid"] != b["kid"]
        assert a.get("n", a.get("x")) != b.get("n", b.get("x"))


async def test_token_endpoint_captures_the_client_credential(flux_client, oidc_on):
    resp = await flux_client.post(
        "/realms/acme/protocol/openid-connect/token",
        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        data=(
            "grant_type=client_credentials&client_id=admin-cli"
            "&client_secret=sup3r-s3cret-value&scope=openid"
        ),
    )
    assert resp.status == 401
    payload = json.loads(await resp.text())
    assert payload["error"] == "invalid_client"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "oidc-token"
    assert entry["oidcEndpointRealm"] == "acme"
    assert entry["oidcEndpointFields"]["client_id"] == "admin-cli"
    assert entry["oidcEndpointFields"]["grant_type"] == "client_credentials"

    secret = entry["oidcEndpointSecrets"]["client_secret"]
    # Hash + preview, never the value in clear — grouping the same guess
    # across sources only needs the hash.
    assert secret["length"] == len("sup3r-s3cret-value")
    assert "sup3r-s3cret-value" not in json.dumps(entry)
    assert secret["sha256"] == (
        __import__("hashlib").sha256(b"sup3r-s3cret-value").hexdigest()
    )


async def test_token_endpoint_rejects_a_get_the_way_the_product_does(
    flux_client, oidc_on,
):
    resp = await flux_client.get("/oauth/token", headers=HEADERS)
    # 405 confirms the route is registered; a 404 would say it is not.
    assert resp.status == 405
    assert json.loads(await resp.text())["error"] == "invalid_request"


async def test_userinfo_captures_a_replayed_bearer_token(flux_client, oidc_on):
    resp = await flux_client.get(
        "/oauth/userinfo",
        headers={**HEADERS, "Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.stolen"},
    )
    assert resp.status == 401
    assert "invalid_token" in resp.headers["WWW-Authenticate"]

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "oidc-userinfo"
    assert entry["oidcEndpointBearer"]["length"] == len(
        "eyJhbGciOiJSUzI1NiJ9.stolen"
    )
    assert "eyJhbGciOiJSUzI1NiJ9.stolen" not in json.dumps(entry)


async def test_registration_captures_the_callers_own_callback(flux_client, oidc_on):
    """Dynamic client registration names the address the caller wants
    tokens delivered to — their infrastructure, which survives source-IP
    rotation the way an out-of-band exploit callback does."""
    resp = await flux_client.post(
        "/oauth/clients-registrations/openid-connect",
        headers={**HEADERS, "Content-Type": "application/json"},
        data=json.dumps({
            "client_name": "totally-legit",
            "redirect_uris": ["https://attacker.example.net/cb", "http://127.0.0.1:9/x"],
        }),
    )
    assert resp.status == 401

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["oidcEndpointFields"]["client_name"] == "totally-legit"
    assert entry["oidcEndpointFields"]["redirect_uris"] == [
        "https://attacker.example.net/cb", "http://127.0.0.1:9/x",
    ]


async def test_authorization_endpoint_splits_on_client_id(flux_client, oidc_on):
    """A caller naming a client Keycloak actually ships gets the login
    form; one fuzzing client ids gets the product's own error page.
    Real Keycloak makes exactly this split."""
    known = await flux_client.get(
        "/realms/acme/protocol/openid-connect/auth"
        "?client_id=admin-cli&redirect_uri=https://attacker.example.net/cb"
        "&response_type=code&state=abc",
        headers=HEADERS,
    )
    assert known.status == 200
    form = await known.text()
    assert 'name="username"' in form and 'name="password"' in form

    unknown = await flux_client.get(
        "/realms/acme/protocol/openid-connect/auth?client_id=zzz-not-real",
        headers=HEADERS,
    )
    assert unknown.status == 400
    assert "Invalid parameter: client_id" in await unknown.text()

    entries = _log_entries(flux_client.log_path)
    assert entries[0]["result"] == "oidc-auth-login-form"
    assert entries[1]["result"] == "oidc-auth-unknown-client"
    # The caller's own callback address is captured off the query string.
    assert entries[0]["oidcEndpointFields"]["redirect_uri"] == (
        "https://attacker.example.net/cb"
    )


async def test_login_form_action_is_served_and_captures_credentials(
    flux_client, oidc_on,
):
    """The form's submit target must answer. A login page whose action
    404s records nothing from anyone who fills it in."""
    page = await flux_client.get(
        "/realms/acme/protocol/openid-connect/auth?client_id=account",
        headers=HEADERS,
    )
    body = await page.text()
    action = body.split('action="', 1)[1].split('"', 1)[0]
    assert action.startswith("https://idp.example.com/")
    path = action[len("https://idp.example.com"):]

    posted = await flux_client.post(
        path,
        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        data="username=admin&password=Winter2026%21&credentialId=",
    )
    # Re-renders the form, which is what keeps a brute loop submitting.
    assert posted.status == 200
    assert 'name="password"' in await posted.text()

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "oidc-login-credential-post"
    assert entry["oidcEndpointFields"]["username"] == "admin"
    assert entry["oidcEndpointSecrets"]["password"]["length"] == len("Winter2026!")
    assert "Winter2026!" not in json.dumps(entry)


@pytest.mark.parametrize("secret", [
    "x", "hunter2", "Winter2026!", "correct-horse-battery",
    "a" * 31,
])
def test_short_secrets_are_never_echoed_by_the_preview(secret):
    """A first-n/last-n preview of a short value is the whole value.

    Most submitted passwords are shorter than the preview window, so
    without this rule the digest would record in clear exactly what it
    claims not to. Caught by the credential-capture test on its first
    run; pinned here per-length so it cannot come back.
    """
    digest = tbenv._oidc_secret_digest(secret)
    assert digest["length"] == len(secret)
    assert "preview" not in digest
    assert secret not in json.dumps(digest)


def test_long_tokens_keep_a_readable_fragment():
    """The preview earns its place on machine-issued tokens, where a
    fragment is enough to recognise a format in triage."""
    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + "z" * 60
    digest = tbenv._oidc_secret_digest(token)
    assert digest["preview"] == f"{token[:8]}…{token[-4:]}"
    assert token not in json.dumps(digest)


async def test_logout_never_becomes_an_open_redirect(flux_client, oidc_on):
    """Honouring `post_logout_redirect_uri` would hand out a working
    redirector pointed wherever the caller likes. The address is logged;
    it is never issued as a Location."""
    resp = await flux_client.get(
        "/oauth/logout?post_logout_redirect_uri=https://attacker.example.net/x",
        headers=HEADERS,
    )
    assert resp.status == 400
    assert "Location" not in resp.headers
    assert "attacker.example.net" not in await resp.text()


async def test_endpoints_404_when_the_document_would_also_404(
    flux_client, monkeypatch,
):
    """A deployment with no issuing key 404s the discovery document. Its
    endpoints must 404 too — a live IdP surface in front of an absent
    document is the inconsistency this trap removes, inverted."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "OIDC_ENDPOINTS_ENABLED", True)
    for path in ("/.well-known/openid-configuration", "/oauth/certs", "/oauth/token"):
        resp = await flux_client.get(path, headers=HEADERS)
        assert resp.status == 404, path


async def test_switch_off_disables_the_endpoints_but_not_the_document(
    flux_client, monkeypatch,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    monkeypatch.setattr(tbenv, "OIDC_DISCOVERY_ENABLED", True)
    monkeypatch.setattr(tbenv, "OIDC_ENDPOINTS_ENABLED", False)
    assert (await flux_client.get(
        "/.well-known/openid-configuration", headers=HEADERS,
    )).status == 200
    assert (await flux_client.get("/oauth/certs", headers=HEADERS)).status == 404


async def test_no_credential_shaped_literal_is_fixed_across_renders(
    flux_client, oidc_on,
):
    """Two renders of the login form must share no nonce, session code
    or tab id — the form is issued per hit, so a fixed one would be a
    fleet fingerprint."""
    seen = []
    for _ in range(2):
        resp = await flux_client.get(
            "/realms/acme/protocol/openid-connect/auth?client_id=account",
            headers=HEADERS,
        )
        body = await resp.text()
        seen.append(body.split('action="', 1)[1].split('"', 1)[0])
    assert seen[0] != seen[1]
