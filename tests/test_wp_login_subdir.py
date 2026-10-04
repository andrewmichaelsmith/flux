"""WordPress installs that do not live at the webroot.

`/wp-login.php` was matched at the webroot only, so a sweep probing a
subdirectory install (`/blog/wp-login.php`, `/wp/wp-login.php`) got the
generic 404 and never reached the credential POST — which is the sharpest
signal this trap produces. The install dictionary was already in the
module, driving the REST aliaser and the setup wizard; these matchers
just did not read it.

The distinction the tests below pin is the one that makes this safe to
widen: an install subdirectory is a single leading segment from that
dictionary, and `wp-login.php` under an *asset* directory is not an
install at all — it is a hunt for a webshell somebody else dropped, and
answering it with a login form would assert a shape no deployment has.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- matching (pure) ---------------------------------------------------

@pytest.mark.parametrize("path,prefix", [
    ("/wp-login.php", ""),
    ("/blog/wp-login.php", "/blog"),
    ("/wp/wp-login.php", "/wp"),
    ("/wordpress/wp-login.php", "/wordpress"),
    ("/cms/wp-login.php", "/cms"),
    ("/staging/wp-login.php", "/staging"),
    ("/BLOG/WP-LOGIN.PHP", "/blog"),
])
def test_install_prefix_split(path, prefix):
    assert tbenv.is_wp_login_path(path)
    assert tbenv.wp_install_prefix(path)[0] == prefix


@pytest.mark.parametrize("path", [
    # Asset directories. A scanner asking here expects a file somebody
    # else uploaded, not a login form.
    "/wp-includes/images/wp-login.php",
    "/wp-content/uploads/wp-login.php",
    "/wp-admin/css/wp-login.php",
    "/wp-includes/SimplePie/wp-login.php",
    "/cgi-bin/wp-login.php",
    # Not in the install dictionary.
    "/shop/wp-login.php",
    "/portal/wp-login.php",
    # Two levels deep is not an install root either.
    "/blog/sub/wp-login.php",
    # Near misses.
    "/blogwp-login.php",
    "/blog/wp-login.php.bak",
    "/blog/wp-login",
])
def test_does_not_match(path):
    assert not tbenv.is_wp_login_path(path)


@pytest.mark.parametrize("path,prefix", [
    ("/wp-admin/", ""),
    ("/blog/wp-admin/", "/blog"),
    ("/wp/wp-admin/index.php", "/wp"),
])
def test_admin_paths_take_the_same_dictionary(path, prefix):
    assert tbenv.is_wp_admin_path(path)
    assert tbenv.wp_install_prefix(path)[0] == prefix


def test_disabled_switch_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_LOGIN_ENABLED", False)
    assert not tbenv.is_wp_login_path("/blog/wp-login.php")
    assert not tbenv.is_wp_admin_path("/blog/wp-admin/")


# --- rendered page (pure) ---------------------------------------------

def test_form_posts_back_to_the_install_that_served_it():
    """A form served from a subdirectory install that posts to the root
    one is not a shape any deployment produces."""
    body = tbenv.render_wp_login_html(
        nonce="abc1234567", redirect_to="/blog/wp-admin/",
        base_path="/blog").decode()
    assert 'action="/blog/wp-login.php"' in body
    assert 'action="/wp-login.php"' not in body
    assert "/blog/wp-login.php?action=lostpassword" in body


def test_root_install_renders_unchanged():
    body = tbenv.render_wp_login_html(
        nonce="abc1234567", redirect_to="/wp-admin/").decode()
    assert 'action="/wp-login.php"' in body
    assert "//wp-login.php" not in body


# --- dispatch ----------------------------------------------------------

@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "WP_LOGIN_ENABLED", True)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _entries(log_path):
    return [json.loads(l) for l in log_path.read_text().splitlines()]


async def test_subdirectory_login_serves_the_page(flux_client):
    resp = await flux_client.get("/blog/wp-login.php")
    assert resp.status == 200
    body = await resp.read()
    assert b'name="log"' in body
    assert b'action="/blog/wp-login.php"' in body
    entry = _entries(flux_client.log_path)[-1]
    assert entry["result"] == "wp-login-probe"
    assert entry["wpLoginInstallPrefix"] == "/blog"


async def test_subdirectory_login_captures_the_credential_post(flux_client):
    """The whole point: the POST is what this trap exists to record, and
    a 404 on the GET meant it never arrived."""
    resp = await flux_client.get("/wp/wp-login.php")
    nonce = _entries(flux_client.log_path)[-1]["wpLoginNonceIssued"]

    resp = await flux_client.post(
        "/wp/wp-login.php",
        data=f"log=siteadmin&pwd=hunter2&_wpnonce={nonce}&testcookie=1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=False,
    )
    assert resp.status == 302
    assert resp.headers["Location"] == "/wp/wp-login.php?reauth=1"
    entry = _entries(flux_client.log_path)[-1]
    assert entry["result"] == "wp-login-credentials"
    assert entry["wpLoginUsername"] == "siteadmin"
    assert entry["wpLoginHasPwd"] is True
    assert entry["wpLoginNonceMatch"] is True
    assert entry["wpLoginInstallPrefix"] == "/wp"
    # The credential contract is unchanged at depth: the password gets no
    # field of its own, only the boolean. (The shared log context records
    # a body preview for every POST, which is a separate and deliberate
    # capture — this test is about the login fields.)
    assert "wpLoginPwd" not in entry
    assert entry["wpLoginHasPwd"] is True


async def test_root_install_redirect_is_unchanged(flux_client):
    resp = await flux_client.get("/wp-login.php")
    nonce = _entries(flux_client.log_path)[-1]["wpLoginNonceIssued"]
    resp = await flux_client.post(
        "/wp-login.php",
        data=f"log=admin&pwd=x&_wpnonce={nonce}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=False,
    )
    assert resp.headers["Location"] == "/wp-login.php?reauth=1"


async def test_subdirectory_admin_redirects_into_the_same_install(flux_client):
    resp = await flux_client.get("/blog/wp-admin/", allow_redirects=False)
    assert resp.status == 302
    assert resp.headers["Location"].startswith("/blog/wp-login.php?redirect_to=")
    entry = _entries(flux_client.log_path)[-1]
    assert entry["result"] == "wp-admin-redirect"
    assert entry["wpLoginInstallPrefix"] == "/blog"


async def test_asset_directory_spelling_keeps_its_404(flux_client):
    resp = await flux_client.get("/wp-includes/images/wp-login.php")
    assert _entries(flux_client.log_path)[-1]["result"] != "wp-login-probe"
