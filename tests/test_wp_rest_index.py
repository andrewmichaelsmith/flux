"""Tests for the WordPress REST discovery document and the routes it
advertises.

The defect this trap fixes is a dead index: flux answered
`/wp-json/wp/v2/users` and `/wp-json/batch/v1` while `/wp-json/` — the
document a REST-aware client reads *first* to find out whether REST is
reachable — returned the generic 404. A client that asks the index and
gets nothing concludes REST is disabled and never sends the follow-up.

So the load-bearing test here is not "the index renders". It is
`test_following_the_index_reaches_every_route`, which walks every self
link the index publishes over the real dispatch path and fails on the
first one that falls through to the generic 404 — the same guard shape
the actuator index uses, for the same reason.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- route extraction (pure) -------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("/wp-json", "/"),
    ("/wp-json/", "/"),
    ("/wp-json/wp/v2", "/wp/v2"),
    ("/wp-json/wp/v2/", "/wp/v2"),
    ("/wp-json/wp/v2/posts", "/wp/v2/posts"),
    ("/wp-json/wp/v2/posts/", "/wp/v2/posts"),
    ("/wp-json/wp/v2/posts/999999", "/wp/v2/posts/999999"),
    ("/wp-json/wp/v2/users/me", "/wp/v2/users/me"),
    # Query strings never steer route resolution.
    ("/wp-json/wp/v2/posts?per_page=100", "/wp/v2/posts"),
    # Install subdirectories collapse onto the canonical route.
    ("/blog/wp-json/", "/"),
    ("/wordpress/wp-json/wp/v2/pages", "/wp/v2/pages"),
    ("/staging/wp-json", "/"),
    # Case-insensitive, like every other WP matcher here.
    ("/WP-JSON/WP/V2/POSTS", "/wp/v2/posts"),
    # Not a REST address at all.
    ("/wp-jsonx", None),
    ("/wp-admin/", None),
    ("/", None),
])
def test_route_extraction(path, expected):
    assert tbenv.wp_rest_route_of(path) == expected


@pytest.mark.parametrize("path", [
    "/wp-json",
    "/wp-json/",
    "/wp-json/wp/v2",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/posts/8",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/categories",
    "/wp-json/wp/v2/tags",
    "/wp-json/wp/v2/comments",
    "/wp-json/wp/v2/types",
    "/wp-json/wp/v2/taxonomies",
    "/wp-json/wp/v2/statuses",
    "/wp-json/wp/v2/search",
    "/wp-json/wp/v2/settings",
    "/wp-json/wp/v2/plugins",
    "/wp-json/wp/v2/themes",
    "/wp-json/wp/v2/users/me",
    "/blog/wp-json/wp/v2/posts",
])
def test_matches(path):
    assert tbenv.is_wp_rest_index_path(path)


@pytest.mark.parametrize("path", [
    # Owned by the user-enum trap, dispatched ahead of this one. Claiming
    # them here would silently take the roster away from that trap.
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/users/1",
    # Owned by the batch trap.
    "/wp-json/batch/v1",
    # Routes WordPress does not register. A real install 404s these, and
    # answering them would make this host distinguishable from one.
    "/wp-json/wp/v2/custom-css",
    "/wp-json/wp/v2/attachments",
    "/wp-json/wp/v2/global-styles",
    "/wp-json/wp/v2/font-faces",
    # Third-party namespaces belong to their own traps or to the 404.
    "/wp-json/wc/v3/payment_gateways",
    "/wp-json/elementor/v1/globals",
    # Near-miss spellings.
    "/wp-jsonwp/v2/posts",
    "/wpjson/wp/v2/posts",
    # The prefix-less spelling some tooling emits. A real WordPress
    # serves REST only under its rest_url_prefix, so this 404s there and
    # must 404 here; answering it would be a fleet-wide tell.
    "/wp/v2/posts",
    "/wp/v2/users",
])
def test_does_not_match(path):
    assert not tbenv.is_wp_rest_index_path(path)


def test_disabled_switch_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_REST_INDEX_ENABLED", False)
    assert not tbenv.is_wp_rest_index_path("/wp-json/")
    assert not tbenv.is_wp_rest_index_path("/wp-json/wp/v2/posts")


def test_default_on():
    assert tbenv.WP_REST_INDEX_ENABLED is True


# --- rendered documents (pure) -----------------------------------------

def test_index_is_wordpress_shaped():
    doc = json.loads(tbenv.render_wp_rest_index("shop.example.com"))
    assert doc["namespaces"] == ["oembed/1.0", "batch/v1", "wp/v2"]
    assert doc["authentication"] == {}
    assert doc["routes"]["/"]["_links"]["self"][0]["href"].endswith("/wp-json")
    posts = doc["routes"]["/wp/v2/posts"]
    assert posts["namespace"] == "wp/v2"
    assert "GET" in posts["methods"]


def test_site_name_is_derived_from_the_host():
    """Per-sensor variation: the same document on every host would be a
    fleet fingerprint even though nothing in it is secret-shaped."""
    a = json.loads(tbenv.render_wp_rest_index("shop.example.com"))["name"]
    b = json.loads(tbenv.render_wp_rest_index("intranet.example.net"))["name"]
    assert a == "Shop" and b == "Intranet"


def test_index_falls_back_when_host_is_unusable():
    doc = json.loads(tbenv.render_wp_rest_index(""))
    assert doc["name"]
    assert doc["url"].startswith("https://")


def test_namespace_index_only_lists_its_own_namespace():
    doc = json.loads(tbenv.render_wp_rest_namespace_index("example.com"))
    assert doc["namespace"] == "wp/v2"
    assert all(r.startswith("/wp/v2") for r in doc["routes"])
    assert "/batch/v1" not in doc["routes"]


def test_single_post_hit_and_miss():
    body, status = tbenv.render_wp_rest_single("example.com", "posts", 1)
    assert status == 200
    assert json.loads(body)["slug"] == "hello-world"

    body, status = tbenv.render_wp_rest_single("example.com", "posts", 999999)
    assert status == 404
    doc = json.loads(body)
    # The envelope, not a bare 404 page: it is what tells the scanner
    # REST is live and that id simply is not.
    assert doc["code"] == "rest_post_invalid_id"
    assert doc["data"]["status"] == 404


def test_term_miss_uses_the_term_envelope():
    body, status = tbenv.render_wp_rest_single("example.com", "categories", 77)
    assert status == 404
    assert json.loads(body)["code"] == "rest_term_invalid"


def test_empty_collections_are_arrays_not_errors():
    for name in ("media", "tags", "comments"):
        assert json.loads(tbenv.render_wp_rest_collection("example.com", name)) == []


def test_no_credential_shaped_field_in_any_rendered_document():
    """This trap issues no canary, so nothing it serves may look like a
    secret — a fixed credential-shaped literal here would ship the same
    string from every host and detect nothing on replay."""
    blobs = [
        tbenv.render_wp_rest_index("example.com"),
        tbenv.render_wp_rest_namespace_index("example.com"),
        tbenv.render_wp_rest_descriptor("example.com", "types"),
    ]
    for name in tbenv._WP_REST_COLLECTIONS:
        blobs.append(tbenv.render_wp_rest_collection("example.com", name))
    joined = b"\n".join(blobs).lower()
    for marker in (b"akia", b"password", b"secret", b"api_key", b"apikey",
                   b"token", b"aws_"):
        assert marker not in joined, f"{marker!r} appears in a wp-rest body"


# --- dispatch ----------------------------------------------------------

@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "WP_REST_INDEX_ENABLED", True)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _last_entry(log_path):
    return json.loads(log_path.read_text().splitlines()[-1])


async def test_following_the_index_reaches_every_route(flux_client):
    """The guard. Fetch the index, then fetch everything it advertises
    over the real dispatch path. An advertised route that falls through
    to the generic 404 fails here and nowhere else."""
    resp = await flux_client.get("/wp-json/")
    assert resp.status == 200
    doc = json.loads(await resp.read())

    for route, entry in doc["routes"].items():
        href = entry["_links"]["self"][0]["href"]
        target = "/" + href.split("/", 3)[3] if href.count("/") > 2 else "/wp-json"
        follow = await flux_client.get(target)
        # The invariant is "a trap answered", not a particular status:
        # `/batch/v1` advertises POST only, and WordPress's own answer to
        # a GET on it is the `rest_no_route` 404.
        entry_log = _last_entry(flux_client.log_path)
        assert entry_log["result"] != "not-handled", (
            f"advertised route {route} -> {target} fell through to the "
            f"generic 404 instead of a trap")
        if "GET" in entry["methods"]:
            assert follow.status in (200, 401), (
                f"advertised route {route} -> {target} returned {follow.status}")


@pytest.mark.parametrize("path,tag,marker", [
    ("/wp-json/", "wp-rest-index", b'"namespaces"'),
    ("/wp-json/wp/v2", "wp-rest-namespace-index", b'"namespace"'),
    ("/wp-json/wp/v2/posts", "wp-rest-collection", b"hello-world"),
    ("/wp-json/wp/v2/posts/8", "wp-rest-single", b"maintenance"),
    ("/wp-json/wp/v2/types", "wp-rest-descriptor", b'"rest_base"'),
    ("/wp-json/wp/v2/search", "wp-rest-search", b"[]"),
    ("/wp-json/wp/v2/settings", "wp-rest-auth-required", b"rest_forbidden"),
    ("/wp-json/wp/v2/plugins", "wp-rest-auth-required", b"rest_cannot_view_plugins"),
    ("/wp-json/wp/v2/users/me", "wp-rest-auth-required", b"rest_not_logged_in"),
])
async def test_dispatch_serves_the_branch_the_matcher_chose(
        flux_client, path, tag, marker):
    resp = await flux_client.get(path)
    body = await resp.read()
    assert marker in body, f"{path} did not take the {tag} branch"
    assert _last_entry(flux_client.log_path)["result"] == tag


async def test_auth_required_routes_answer_401_not_404(flux_client):
    """401 is the stronger response: it proves the route is registered,
    which is what the client is testing for. A 404 reads as 'no REST'."""
    for path in ("/wp-json/wp/v2/settings", "/wp-json/wp/v2/themes",
                 "/wp-json/wp/v2/plugins", "/wp-json/wp/v2/users/me"):
        resp = await flux_client.get(path)
        assert resp.status == 401, path
        assert json.loads(await resp.read())["data"]["status"] == 401


async def test_collections_carry_the_pagination_headers(flux_client):
    """Real WordPress emits X-WP-Total on every collection; a collection
    response without them is a tell on its own."""
    resp = await flux_client.get("/wp-json/wp/v2/posts")
    assert resp.headers["X-WP-Total"] == "2"
    assert resp.headers["X-WP-TotalPages"] == "1"
    resp = await flux_client.get("/wp-json/wp/v2/tags")
    assert resp.headers["X-WP-Total"] == "0"


async def test_write_to_a_collection_is_refused_and_logged(flux_client):
    resp = await flux_client.post("/wp-json/wp/v2/posts", data=b'{"title":"x"}')
    assert resp.status == 401
    assert b"rest_cannot_create" in await resp.read()
    assert _last_entry(flux_client.log_path)["result"] == "wp-rest-collection-write"


async def test_every_route_returns_parseable_json(flux_client):
    for route, _ in tbenv._wp_rest_advertised_routes():
        target = "/wp-json" + ("" if route == "/" else route)
        resp = await flux_client.get(target)
        json.loads(await resp.read())


async def test_guard_catches_an_advertised_route_nothing_serves(flux_client, monkeypatch):
    """Mutation check on the guard above. A test that walks a list can
    look like coverage while proving nothing, so: add a route to the
    advertised table that no branch answers, and the guard must fail."""
    real = tbenv._wp_rest_advertised_routes

    monkeypatch.setattr(
        tbenv, "_wp_rest_advertised_routes",
        lambda: real() + (("/wp/v2/not-a-real-route", ("GET",)),),
    )
    resp = await flux_client.get("/wp-json/")
    doc = json.loads(await resp.read())
    assert "/wp/v2/not-a-real-route" in doc["routes"]

    href = doc["routes"]["/wp/v2/not-a-real-route"]["_links"]["self"][0]["href"]
    target = "/" + href.split("/", 3)[3]
    follow = await flux_client.get(target)
    assert follow.status == 404
    assert _last_entry(flux_client.log_path)["result"] == "not-handled"


async def test_query_form_of_the_index_resolves(flux_client):
    """`/?rest_route=/` is the index's address when permalinks are off,
    and it was returning the site root redirect."""
    resp = await flux_client.get("/?rest_route=/")
    assert resp.status == 200
    assert json.loads(await resp.read())["namespaces"]
    assert _last_entry(flux_client.log_path)["result"] == "wp-rest-index"


async def test_head_sends_headers_without_a_body(flux_client):
    resp = await flux_client.head("/wp-json/")
    assert resp.status == 200
    assert await resp.read() == b""
    assert resp.headers["Content-Length"] != "0"


async def test_unregistered_route_still_404s(flux_client):
    """The negative half of the plausibility contract: routes real
    WordPress does not have must keep the response real WordPress
    gives."""
    for path in ("/wp-json/wp/v2/custom-css", "/wp-json/wp/v2/attachments",
                 "/wp/v2/posts"):
        resp = await flux_client.get(path)
        assert resp.status == 404, path


async def test_user_enum_still_owns_its_routes(flux_client):
    """Regression: the new matcher sits next to a trap whose routes look
    exactly like the ones it claims."""
    resp = await flux_client.get("/wp-json/wp/v2/users")
    assert resp.status == 200
    assert _last_entry(flux_client.log_path)["result"] == "wp-user-enum-rest-list"


# --- install subdirectory consistency ----------------------------------
#
# The index serves subdirectory-prefixed routes, so the user roster has
# to as well: `/blog/wp-json/wp/v2/posts` answering while
# `/blog/wp-json/wp/v2/users` 404s under the same prefix is a split no
# real install produces, and it is a split this trap would have
# introduced.

@pytest.mark.parametrize("prefix", ["", "/blog", "/wordpress", "/staging"])
async def test_one_install_prefix_answers_consistently(flux_client, prefix):
    posts = await flux_client.get(f"{prefix}/wp-json/wp/v2/posts")
    users = await flux_client.get(f"{prefix}/wp-json/wp/v2/users")
    index = await flux_client.get(f"{prefix}/wp-json/")
    assert (posts.status, users.status, index.status) == (200, 200, 200), prefix


@pytest.mark.parametrize("prefix", ["/blog", "/wordpress"])
async def test_subdirectory_indexed_user_is_json_not_a_sitemap(
        flux_client, prefix):
    """The failure this guards: a subdirectory-prefixed REST path that
    misses both REST branches of the user-enum handler falls through to
    the sitemap renderer, answering a JSON route with XML."""
    resp = await flux_client.get(f"{prefix}/wp-json/wp/v2/users/1")
    assert resp.status == 200
    assert json.loads(await resp.read())["slug"] == "admin"
    assert _last_entry(flux_client.log_path)["result"] == "wp-user-enum-rest-single"

    resp = await flux_client.get(f"{prefix}/wp-json/wp/v2/users/99")
    assert resp.status == 404
    assert json.loads(await resp.read())["code"] == "rest_user_invalid_id"


async def test_sitemap_variants_are_untouched_by_subdirectory_stripping(
        flux_client):
    """Regression: the strip must only fire on a `/wp-json` address, or
    it would start eating prefixes off unrelated paths."""
    assert tbenv.is_wp_user_enum_path("/wp-sitemap-users-1.xml")
    assert not tbenv.is_wp_user_enum_path("/blog/wp-sitemap-users-1.xml")
    assert tbenv._wp_rest_strip_subdir("/blog/anything/else") == "/blog/anything/else"
    assert tbenv._wp_rest_strip_subdir("/blogger/wp-json/") == "/blogger/wp-json/"
