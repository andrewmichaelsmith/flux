"""Tests for the WordPress `oembed/1.0` namespace trap.

The defect this closes is narrower than a missing trap: the REST
discovery document has always *named* `oembed/1.0` among the registered
namespaces while nothing underneath it answered. That is the same
advertised-but-dead shape the index trap was built to remove, one level
up — in the namespace list rather than the routes map — and the routes
guard could not see it, because the guard walks the routes map.

So the load-bearing tests here are the two consistency guards:
`test_every_advertised_namespace_has_a_served_route` ties the namespace
list to the routes table, and the roster test ties the author this
surface discloses to the author the user-enumeration surface lists. A
scanner that reads two surfaces and finds two different rosters has
learned the site is not real.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- matching (pure) ---------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("/wp-json/oembed/1.0/embed", "/oembed/1.0/embed"),
    ("/wp-json/oembed/1.0/embed/", "/oembed/1.0/embed"),
    ("/wp-json/oembed/1.0/proxy", "/oembed/1.0/proxy"),
    # Query strings never steer route resolution.
    ("/wp-json/oembed/1.0/embed?url=https://x/", "/oembed/1.0/embed"),
    # Install subdirectories collapse onto the canonical route, free from
    # the REST layer's normalisation.
    ("/blog/wp-json/oembed/1.0/embed", "/oembed/1.0/embed"),
    ("/wordpress/wp-json/oembed/1.0/proxy", "/oembed/1.0/proxy"),
])
def test_route_extraction(path, expected):
    assert tbenv.wp_oembed_route_of(path) == expected


@pytest.mark.parametrize("path", [
    "/wp-json/oembed/1.0/embed",
    "/wp-json/oembed/1.0/proxy",
    "/blog/wp-json/oembed/1.0/embed",
])
def test_matches(path):
    assert tbenv.is_wp_oembed_path(path)


@pytest.mark.parametrize("path", [
    # Routes the namespace does not register. A real install 404s these.
    "/wp-json/oembed/1.0",
    "/wp-json/oembed/1.0/",
    "/wp-json/oembed/1.0/embeds",
    "/wp-json/oembed/2.0/embed",
    # Belongs to another namespace's trap.
    "/wp-json/wp/v2/posts",
    "/wp-json/batch/v1",
    # The prefix-less spelling: a real install serves REST only under its
    # rest_url_prefix, so answering this would be a fleet-wide tell.
    "/oembed/1.0/embed",
    # Near-miss spellings.
    "/wp-jsonoembed/1.0/embed",
    "/embed",
])
def test_does_not_match(path):
    assert not tbenv.is_wp_oembed_path(path)


def test_disabled_switch_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_OEMBED_ENABLED", False)
    assert not tbenv.is_wp_oembed_path("/wp-json/oembed/1.0/embed")
    assert not tbenv.is_wp_oembed_path("/wp-json/oembed/1.0/proxy")


def test_default_on():
    assert tbenv.WP_OEMBED_ENABLED is True


# --- the consistency guards -------------------------------------------

def test_every_advertised_namespace_has_a_served_route():
    """The guard this trap exists to install. Every namespace the index
    names must have at least one route in the advertised table, and
    every advertised route's namespace must be named. Either half
    failing is the drift that let `oembed/1.0` sit in the namespace list
    with nothing behind it."""
    base = "shop.example.com"
    from_routes = {
        tbenv._wp_rest_route_entry(base, route, methods)["namespace"]
        for route, methods in tbenv._wp_rest_advertised_routes()
    }
    from_routes.discard("")
    assert from_routes == set(tbenv._WP_REST_NAMESPACES)


def test_guard_catches_a_namespace_nothing_serves(monkeypatch):
    """Mutation check on the guard above: name a namespace no route
    covers and the guard must fail."""
    monkeypatch.setattr(
        tbenv, "_WP_REST_NAMESPACES",
        tbenv._WP_REST_NAMESPACES + ("wp-site-health/v1",),
    )
    with pytest.raises(AssertionError):
        test_every_advertised_namespace_has_a_served_route()


def test_disclosed_author_comes_from_the_user_roster():
    """The author this surface names must be one the user list also
    names. Two surfaces disagreeing about who exists is a tell, and
    restating the roster here is how that happens."""
    name, url = tbenv._wp_oembed_author("shop.example.com")
    roster = {s["name"]: s["slug"] for s in tbenv._WP_USER_ENUM_FAKE_USERS}
    assert name in roster
    assert url.endswith(f"/author/{roster[name]}/")


def test_disclosed_author_is_the_resolved_items_own_author():
    """Core names the author of the item behind the URL, so this must
    follow the item rather than a fixed choice.

    This replaced a test asserting the disclosed name was never the one
    the user list leads with. That property was real when written and
    was removed by the fidelity fix: once an unresolvable URL returns
    Not Found, every answered embed names its item's author, and the
    first fake post happens to share the user list's first slot. The
    old test kept passing because it called the renderer with no
    resolved item — exercising a fallback dispatch can no longer reach,
    while reading as a guarantee about live behaviour."""
    for slot in tbenv._WP_REST_FAKE_POSTS:
        name, url = tbenv._wp_oembed_author(
            "shop.example.com", str(slot["author"]))
        expected = next(u for u in tbenv._WP_USER_ENUM_FAKE_USERS
                        if u["id"] == str(slot["author"]))
        assert name == expected["name"]
        assert url.endswith(f"/author/{expected['slug']}/")


def test_the_fake_posts_do_not_all_share_one_author():
    """What is left of the separation signal: the disclosed name tells
    you which item the caller knew to ask for. If every post gained the
    same author, the embed route would stop distinguishing them and
    `wpOembedMatchedSlug` would be carrying that alone."""
    authors = {str(s["author"]) for s in tbenv._WP_REST_FAKE_POSTS}
    assert len(authors) > 1


# --- local-URL resolution (pure) --------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://shop.example.com/hello-world/", True),
    ("http://shop.example.com/hello-world/", True),
    ("//shop.example.com/", True),
    ("https://shop.example.com:443/x", True),
    ("https://www.shop.example.com/x", True),
    ("/hello-world/", True),
    ("https://evil.example.net/", False),
    ("https://shop.example.com.evil.net/", False),
    # Credentials in the authority must not be read as the host.
    ("https://shop.example.com@evil.example.net/", False),
    ("", False),
])
def test_url_locality(url, expected):
    assert tbenv._wp_oembed_url_is_local("shop.example.com", url) is expected


def test_matched_slug_resolves_a_known_post_or_page():
    slug = tbenv._wp_oembed_matched_slug(
        "shop.example.com", "https://shop.example.com/2026/hello-world/")
    assert slug == "hello-world"
    assert tbenv._wp_oembed_matched_slug(
        "shop.example.com", "https://shop.example.com/sample-page/") == \
        "sample-page"
    assert tbenv._wp_oembed_matched_slug(
        "shop.example.com", "https://shop.example.com/nothing-here/") is None


# --- rendered documents (pure) ----------------------------------------

def test_embed_document_is_oembed_shaped():
    doc = json.loads(tbenv.render_wp_oembed_embed(
        "shop.example.com", "https://shop.example.com/2026/hello-world/",
        slug="hello-world", fmt="json"))
    assert doc["version"] == "1.0"
    assert doc["type"] == "rich"
    assert doc["title"] == "Hello world!"
    assert doc["provider_url"].startswith("https://")
    assert "/author/" in doc["author_url"]
    assert "wp-embedded-content" in doc["html"]


def test_embed_names_the_matched_posts_own_author():
    """Core names the author of the post behind the URL. The second fake
    post is authored by a different roster slot than the first, so the
    two must not render the same author."""
    first = json.loads(tbenv.render_wp_oembed_embed(
        "shop.example.com", "https://shop.example.com/2026/hello-world/",
        slug="hello-world", fmt="json"))["author_name"]
    second = json.loads(tbenv.render_wp_oembed_embed(
        "shop.example.com",
        "https://shop.example.com/2026/scheduled-maintenance-window/",
        slug="scheduled-maintenance-window", fmt="json"))["author_name"]
    assert first != second


def test_xml_format_renders_an_oembed_element():
    body = tbenv.render_wp_oembed_embed(
        "shop.example.com", "https://shop.example.com/2026/hello-world/",
        slug="hello-world", fmt="xml")
    text = body.decode()
    assert text.startswith("<?xml")
    assert "<oembed>" in text and "</oembed>" in text
    assert "<author_name>" in text
    # The embedded HTML must be escaped, not emitted as live markup.
    assert "<blockquote" not in text


def test_no_credential_shaped_field_appears():
    """`secret` is deliberately absent from the marker list: core's embed
    markup carries a `data-secret` nonce for the postMessage handshake,
    so emitting one is authenticity rather than leakage. That it is
    per-response rather than fixed is asserted separately below."""
    bodies = [
        tbenv.render_wp_oembed_embed(
            "shop.example.com", "https://shop.example.com/", slug=None,
            fmt=f)
        for f in ("json", "xml")
    ]
    bodies.append(tbenv.render_wp_oembed_error("rest_forbidden", "no", 401))
    joined = b"".join(bodies).lower()
    for marker in (b"password", b"passwd", b"api_key", b"apikey",
                   b"token", b"aws_", b"private"):
        assert marker not in joined, f"{marker!r} appears in an oembed body"


def test_embed_secret_is_per_response_not_fixed():
    """The repo rule: nothing secret-shaped may be a fixed literal, or
    the same string ships from every host and fingerprints the fleet."""
    def secret_of(body):
        text = body.decode()
        return text.split('data-secret=', 1)[1].split('"')[1]

    first = secret_of(tbenv.render_wp_oembed_embed(
        "shop.example.com", "https://shop.example.com/", slug=None,
        fmt="json"))
    second = secret_of(tbenv.render_wp_oembed_embed(
        "shop.example.com", "https://shop.example.com/", slug=None,
        fmt="json"))
    assert first and second and first != second


# --- dispatch ----------------------------------------------------------

@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "WP_OEMBED_ENABLED", True)
    monkeypatch.setattr(tbenv, "WP_REST_INDEX_ENABLED", True)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _last_entry(log_path):
    return json.loads(log_path.read_text().splitlines()[-1])


async def _site_url(flux_client):
    """The site's own base URL, as the server publishes it in the index.
    Using the server's own value keeps these tests correct whatever the
    external-host fallback resolves to behind the test transport."""
    resp = await flux_client.get("/wp-json/")
    return json.loads(await resp.read())["url"].rstrip("/")


async def test_embed_with_a_local_url_discloses_an_author(flux_client):
    base = await _site_url(flux_client)
    resp = await flux_client.get(
        f"/wp-json/oembed/1.0/embed?url={base}/2026/hello-world/")
    assert resp.status == 200
    doc = json.loads(await resp.read())
    assert doc["author_name"]
    entry = _last_entry(flux_client.log_path)
    assert entry["result"] == "wp-oembed-embed"
    assert entry["wpOembedRoute"] == "embed"
    assert entry["wpOembedUrlOnHost"] is True
    assert entry["wpOembedMatchedSlug"] == "hello-world"
    assert entry["wpOembedAuthor"] == doc["author_name"]


async def test_embed_records_a_foreign_url_and_refuses_it(flux_client):
    """A caller that brings somebody else's URL is testing the route,
    not reading this site. Core returns Not Found; the URL is what we
    keep."""
    resp = await flux_client.get(
        "/wp-json/oembed/1.0/embed?url=https://collab.example.net/x")
    assert resp.status == 404
    assert json.loads(await resp.read())["code"] == "oembed_invalid_url"
    entry = _last_entry(flux_client.log_path)
    assert entry["result"] == "wp-oembed-embed-foreign-url"
    assert entry["wpOembedRequestedUrl"] == "https://collab.example.net/x"
    assert entry["wpOembedUrlOnHost"] is False


async def test_embed_refuses_an_on_host_url_that_resolves_to_nothing(flux_client):
    """The fingerprint this trap exists to remove, applied to itself:
    core requires the URL to name a post or page and returns Not Found
    otherwise — including for a posts front page — so answering an
    arbitrary on-host URL would be a visible difference from a real
    install. Distinct tag from the off-host refusal: both are 404s, but
    one caller read our content index and the other did not."""
    base = await _site_url(flux_client)
    for target in (f"{base}/", f"{base}/no-such-post/"):
        resp = await flux_client.get(
            f"/wp-json/oembed/1.0/embed?url={target}")
        assert resp.status == 404, target
        assert json.loads(await resp.read())["code"] == "oembed_invalid_url"
        entry = _last_entry(flux_client.log_path)
        assert entry["result"] == "wp-oembed-embed-unknown-post"
        assert entry["wpOembedUrlOnHost"] is True
        assert "wpOembedMatchedSlug" not in entry


async def test_embed_answers_a_page_as_well_as_a_post(flux_client):
    base = await _site_url(flux_client)
    resp = await flux_client.get(
        f"/wp-json/oembed/1.0/embed?url={base}/sample-page/")
    assert resp.status == 200
    assert json.loads(await resp.read())["title"] == "Sample Page"
    assert _last_entry(flux_client.log_path)["wpOembedMatchedSlug"] == \
        "sample-page"


async def test_embed_without_a_url_returns_the_missing_param_envelope(flux_client):
    resp = await flux_client.get("/wp-json/oembed/1.0/embed")
    assert resp.status == 400
    doc = json.loads(await resp.read())
    assert doc["code"] == "rest_missing_callback_param"
    assert doc["data"]["params"] == ["url"]
    assert _last_entry(flux_client.log_path)["result"] == \
        "wp-oembed-embed-missing-url"


async def test_embed_rejects_an_unsupported_format(flux_client):
    """Core validates parameters before resolving the URL, so the format
    error wins even over a URL that would resolve."""
    base = await _site_url(flux_client)
    resp = await flux_client.get(
        f"/wp-json/oembed/1.0/embed?url={base}/2026/hello-world/&format=yaml")
    assert resp.status == 400
    assert json.loads(await resp.read())["code"] == "rest_invalid_param"
    entry = _last_entry(flux_client.log_path)
    assert entry["result"] == "wp-oembed-embed-invalid-format"
    assert entry["wpOembedFormat"] == "yaml"


async def test_proxy_refuses_anonymously_and_keeps_the_target(flux_client):
    """The measurement: a caller probing the server-side fetcher has to
    name the host it wants contacted. The refusal is core's own, and no
    outbound request is made."""
    resp = await flux_client.get(
        "/wp-json/oembed/1.0/proxy?url=http://169.254.169.254/latest/meta-data/")
    assert resp.status == 401
    assert json.loads(await resp.read())["code"] == "rest_forbidden"
    entry = _last_entry(flux_client.log_path)
    assert entry["result"] == "wp-oembed-proxy-unauthorized"
    assert entry["wpOembedRoute"] == "proxy"
    assert entry["wpOembedRequestedUrl"] == \
        "http://169.254.169.254/latest/meta-data/"


async def test_proxy_refuses_before_validating_params(flux_client):
    """Core's capability check runs ahead of parameter validation, so a
    proxy call with no URL is still a 401 rather than a 400."""
    resp = await flux_client.get("/wp-json/oembed/1.0/proxy")
    assert resp.status == 401
    assert _last_entry(flux_client.log_path)["result"] == \
        "wp-oembed-proxy-unauthorized"


async def test_wrong_method_is_405_with_allow(flux_client):
    """A method the route does not register gets core's own 405 envelope
    and the per-route Allow — not a 404, which would claim the route is
    not registered at all."""
    resp = await flux_client.post("/wp-json/oembed/1.0/embed")
    assert resp.status == 405
    assert resp.headers["Allow"] == "GET, HEAD"
    assert json.loads(await resp.read())["code"] == "rest_invalid_method"
    assert _last_entry(flux_client.log_path)["result"] == \
        "wp-oembed-method-not-allowed"


@pytest.mark.parametrize("method", ["put", "delete"])
async def test_methods_the_server_never_accepts_stop_at_the_global_gate(
        flux_client, method):
    """PUT and DELETE are refused server-wide before any route is
    consulted, so they carry the server's Allow set rather than this
    route's. Asserted so a future change to the global gate does not
    silently start routing them here."""
    resp = await getattr(flux_client, method)("/wp-json/oembed/1.0/embed")
    assert resp.status == 405
    assert "GET" in resp.headers["Allow"]
    assert _last_entry(flux_client.log_path)["result"] != \
        "wp-oembed-method-not-allowed"


async def test_head_sends_headers_without_a_body(flux_client):
    base = await _site_url(flux_client)
    resp = await flux_client.head(
        f"/wp-json/oembed/1.0/embed?url={base}/2026/hello-world/")
    assert resp.status == 200
    assert await resp.read() == b""


async def test_install_subdirectory_spelling_reaches_the_trap(flux_client):
    base = await _site_url(flux_client)
    resp = await flux_client.get(
        f"/blog/wp-json/oembed/1.0/embed?url={base}/2026/hello-world/")
    assert resp.status == 200
    assert _last_entry(flux_client.log_path)["result"] == "wp-oembed-embed"


async def test_percent_encoded_separator_reaches_the_trap(flux_client):
    """The namespace has been asked for with the dot in `1.0` encoded —
    a rule-bypass shape rather than a typo. Path normalisation decodes
    it before dispatch, so it must land on the same handler."""
    resp = await flux_client.get("/wp-json/oembed/1%2e0/proxy?url=http://x/")
    assert resp.status == 401
    assert _last_entry(flux_client.log_path)["result"] == \
        "wp-oembed-proxy-unauthorized"


async def test_query_form_of_the_route_resolves(flux_client):
    """`?rest_route=` is the route's address when permalinks are off."""
    resp = await flux_client.get("/?rest_route=/oembed/1.0/proxy")
    assert resp.status == 401
    assert _last_entry(flux_client.log_path)["result"] == \
        "wp-oembed-proxy-unauthorized"


async def test_namespace_is_named_by_the_index_and_served(flux_client):
    """End to end on the original defect: the namespace the index names
    must now resolve to a trap rather than the generic 404."""
    resp = await flux_client.get("/wp-json/")
    doc = json.loads(await resp.read())
    assert "oembed/1.0" in doc["namespaces"]
    advertised = [r for r in doc["routes"] if r.startswith("/oembed/")]
    assert advertised
    for route in advertised:
        href = doc["routes"][route]["_links"]["self"][0]["href"]
        target = "/" + href.split("/", 3)[3]
        await flux_client.get(target)
        assert _last_entry(flux_client.log_path)["result"] != "not-handled", (
            f"advertised namespace route {route} fell through to the 404")


async def test_disabled_switch_falls_through_to_the_generic_404(flux_client,
                                                               monkeypatch):
    monkeypatch.setattr(tbenv, "WP_OEMBED_ENABLED", False)
    resp = await flux_client.get("/wp-json/oembed/1.0/proxy")
    assert resp.status == 404
    assert _last_entry(flux_client.log_path)["result"] == "not-handled"
