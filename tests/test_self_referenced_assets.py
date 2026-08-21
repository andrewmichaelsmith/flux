"""Every URL a rendered page names must be a URL that page's own server
answers.

An appliance login page is not just its HTML. A real one ships a
stylesheet, a logo and a favicon, and its login form posts somewhere that
exists. Rendering the page while 404ing everything it references produces
a shape no real deployment has — and, because the same code runs
everywhere, the *same* wrong shape on every host. That is a fleet
fingerprint rather than a coverage gap, which is why this is asserted
rather than left to the path tables to get right by hand.

Two of the references this file locked down were `<form action=...>`
targets, not assets. Those surfaces rendered a login form whose
submission fell through to a 404, so the credential each trap exists to
collect was dropped on arrival.

The load-bearing test is `test_every_referenced_url_is_answered`. It is
the HTML analogue of the operational-endpoint index guard, which follows
advertised `_links` but only ever looked at a JSON index. This one walks
the rendered HTML instead, and — importantly — asserts on the **dispatched
response**, not on whether some `is_*_path` predicate returns True. A
predicate claiming a path proves only that the request reaches a handler;
it says nothing about whether that handler then falls into its own
`*-miss` 404 branch. Asking the app is the only check that covers both.
"""

import inspect
import re

import pytest
import pytest_asyncio

from flux import server as tbenv


# `href`/`src`/`action` on any element. Deliberately not an HTML parser:
# the point is to see what a scanner scraping the body with a regex sees,
# and a lenient match errs toward checking more URLs rather than fewer.
ASSET_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)["']""", re.I)

# Arguments for the renderers that take them. Values are shape-only --
# no renderer under test branches on them.
_ARG_HINTS = (
    ("host", "vpn.example.com"),
    ("version", "7.4.3"),
    ("build", "2573"),
)


def _render_all_html() -> list[tuple[str, str]]:
    """`(renderer_name, html)` for every renderer we can drive with
    simple positional arguments. Renderers needing a live request or a
    canary dict are exercised by their own trap's tests."""
    out = []
    for name, fn in sorted(vars(tbenv).items()):
        if not name.startswith("render_") or not callable(fn):
            continue
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            continue
        args, drivable = [], True
        for param in sig.parameters.values():
            if param.default is not inspect.Parameter.empty:
                continue
            lowered = param.name.lower()
            for needle, value in _ARG_HINTS:
                if needle in lowered:
                    args.append(value)
                    break
            else:
                if any(k in lowered for k in
                       ("path", "name", "url", "uri", "file", "id", "token", "key", "user")):
                    args.append("x")
                else:
                    drivable = False
                    break
        if not drivable:
            continue
        try:
            body = fn(*args)
        except Exception:
            continue
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        if isinstance(body, str) and "<" in body:
            out.append((name, body))
    return out


def _referenced_urls() -> dict[str, set[str]]:
    """Absolute same-origin paths -> the renderers that name them.

    Relative and protocol-relative references are skipped: the former
    resolve against whatever directory the scanner happened to request
    (so there is no single path to check), and the latter point off-host
    by definition.
    """
    found: dict[str, set[str]] = {}
    for name, html in _render_all_html():
        for raw in ASSET_RE.findall(html):
            url = raw.strip()
            if not url.startswith("/") or url.startswith("//"):
                continue
            path = url.split("?")[0].split("#")[0]
            if not path or path == "/":
                continue
            found.setdefault(path, set()).add(name)
    return found


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    import json
    return [json.loads(line) for line in log_path.read_text().splitlines()]


# --- the guard ----------------------------------------------------------


def test_renderers_actually_reference_something():
    """Guard the guard: if the renderer sweep silently stopped finding
    pages, every assertion below would pass vacuously."""
    referenced = _referenced_urls()
    assert len(referenced) >= 40, (
        f"only {len(referenced)} referenced URLs found -- the renderer "
        "sweep is probably broken, not the traps"
    )


async def test_every_referenced_url_is_answered(flux_client):
    """The load-bearing assertion of this file.

    Asserts on the dispatched status, not on a path predicate: a
    predicate returning True only proves the request reaches a handler,
    and a handler can still take its own `*-miss` 404 branch.
    """
    referenced = _referenced_urls()
    unanswered = []
    for path in sorted(referenced):
        resp = await flux_client.get(path)
        if resp.status != 200 or not await resp.read():
            unanswered.append(
                f"{path} -> {resp.status} (named by {', '.join(sorted(referenced[path]))})"
            )
    assert not unanswered, (
        "rendered pages reference URLs the server does not answer:\n  "
        + "\n  ".join(unanswered)
    )


async def test_referenced_assets_carry_a_plausible_content_type(flux_client):
    """A stylesheet served as `text/plain` is its own tell."""
    expected_by_suffix = {
        ".css": "text/css",
        ".js": "javascript",
        ".png": "image/png",
        ".ico": "image/",
        ".svg": "image/svg",
    }
    wrong = []
    for path in sorted(_referenced_urls()):
        for suffix, expected in expected_by_suffix.items():
            if not path.lower().endswith(suffix):
                continue
            resp = await flux_client.get(path)
            got = resp.headers.get("Content-Type", "")
            if expected not in got.lower():
                wrong.append(f"{path} -> {got!r}, expected {expected!r}")
    assert not wrong, "assets served with an implausible Content-Type:\n  " + "\n  ".join(wrong)


# --- the assets that were missing --------------------------------------


@pytest.mark.parametrize("path,result_tag", [
    ("/remote/fgt_favicon", "fortigate-favicon"),
    ("/remote/fortinet.png", "fortigate-logo"),
    ("/vpn/images/AccessGateway.ico", "citrix-favicon"),
    ("/dana-na/css/ds.css", "ivanti-ds-css"),
    ("/RDWeb/Pages/Site.css", "rdweb-asset"),
    ("/console/framework/skins/wlsconsole/css/master.css", "weblogic-console-asset"),
    ("/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png",
     "weblogic-console-asset"),
    ("/vendor/telescope/app.js", "telescope-asset-js"),
    ("/vendor/telescope/app-dark.css", "telescope-asset-css"),
    ("/vendor/telescope/favicon.svg", "telescope-asset-svg"),
])
async def test_asset_answers_under_its_own_result_tag(flux_client, path, result_tag):
    """Assets get their own tags so an asset fetch is never counted as a
    portal visit -- otherwise a scanner loading one login page would look
    like several."""
    resp = await flux_client.get(path)
    assert resp.status == 200
    assert await resp.read()
    assert _log_entries(flux_client.log_path)[-1]["result"] == result_tag


def test_generated_png_is_a_decodable_image():
    """The logo bytes are built rather than embedded, so the construction
    is what needs checking: a scanner that decodes the asset must get a
    real image out of it."""
    png = tbenv._png_solid((218, 41, 40), size=16)
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert png.endswith(b"IEND\xae\x42\x60\x82")
    # Width and height live in the IHDR payload, 8 bytes past the marker.
    ihdr = png.index(b"IHDR") + 4
    assert int.from_bytes(png[ihdr:ihdr + 4], "big") == 16
    assert int.from_bytes(png[ihdr + 4:ihdr + 8], "big") == 16


def test_generated_ico_wraps_the_png_at_the_declared_offset():
    ico = tbenv._ico_from_png(tbenv._png_solid((0, 0, 0), size=16), size=16)
    assert ico[:4] == b"\x00\x00\x01\x00"
    offset = int.from_bytes(ico[18:22], "little")
    assert ico[offset:offset + 8] == b"\x89PNG\r\n\x1a\n"


# --- the form actions that were dropping credentials -------------------


async def test_confluence_login_form_action_captures_the_submission(flux_client):
    """The page's own form posts here. Before it was matched, everything
    submitted to it hit a 404 and was never logged."""
    resp = await flux_client.post(
        "/dologin.action",
        data={"os_username": "svc_backup", "os_password": "hunter2!",
              "atl_token": "a" * 32},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "confluence-credential-post"
    assert entry["confluenceUsername"] == "svc_backup"
    assert entry["confluenceHasPwd"] is True
    assert entry["confluencePwdLen"] == "8"
    assert entry["confluenceAtlTokenPresent"] is True


async def test_confluence_credential_field_carries_length_not_the_password(flux_client):
    """The dedicated field records presence and length only.

    `bodyPreview` still retains the raw body, exactly as every other
    credential-POST surface here does -- that is the established
    convention, not an oversight, and it is asserted so a future reader
    does not "fix" one half of the pair and leave the other. What the
    dedicated field must never become is a second copy of the secret.
    """
    await flux_client.post(
        "/dologin.action",
        data={"os_username": "admin", "os_password": "S3cr3t-Passphrase"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["confluencePwdLen"] == "17"
    assert "S3cr3t-Passphrase" not in str(entry.get("confluenceUsername", ""))
    assert not any(
        "S3cr3t-Passphrase" in str(value)
        for key, value in entry.items()
        if key.startswith("confluence")
    )


async def test_confluence_missing_token_is_distinguishable(flux_client):
    """A client that echoes the per-render nonce parsed our HTML; one
    that does not is replaying a canned request. Keeping the two apart is
    the point of logging the field at all."""
    await flux_client.post(
        "/dologin.action", data={"os_username": "root", "os_password": "toor"},
    )
    assert _log_entries(flux_client.log_path)[-1]["confluenceAtlTokenPresent"] is False


async def test_confluence_error_notice_renders_on_the_rejected_post(flux_client):
    resp = await flux_client.post(
        "/dologin.action", data={"os_username": "u", "os_password": "p"},
    )
    assert "incorrect" in (await resp.text()).lower()


@pytest.mark.parametrize("path", [
    "/dologin.action", "/confluence/dologin.action", "/wiki/dologin.action",
])
async def test_confluence_form_action_under_each_install_prefix(flux_client, path):
    """The login page is served under all three prefixes, so its submit
    target has to exist under all three too."""
    resp = await flux_client.post(path, data={"os_username": "a", "os_password": "b"})
    assert resp.status == 200
    assert _log_entries(flux_client.log_path)[-1]["result"] == "confluence-credential-post"


async def test_aspera_form_action_captures_the_rails_bracketed_pair(flux_client):
    resp = await flux_client.post(
        "/aspera/faspex/session",
        data={"user[email]": "ops@example.com", "user[password]": "correct-horse"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "aspera-faspex-credential-post"
    assert entry["asperaFaspexUsername"] == "ops@example.com"
    assert entry["asperaFaspexHasPwd"] is True
    assert entry["asperaFaspexPwdLen"] == "13"
    # Same contract as Confluence above: the dedicated fields carry
    # length and presence, while `bodyPreview` keeps the raw body.
    assert not any(
        "correct-horse" in str(value)
        for key, value in entry.items()
        if key.startswith("aspera")
    )


async def test_aspera_accepts_the_generic_spelling_too(flux_client):
    """Credential-stuffing kits post `username`/`password` regardless of
    what the form asked for. Capturing those as well is the difference
    between recording the submission and losing it."""
    await flux_client.post(
        "/aspera/faspex/session",
        data={"username": "generic@example.com", "password": "pw"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["asperaFaspexUsername"] == "generic@example.com"
    assert entry["asperaFaspexHasPwd"] is True


async def test_geoserver_form_action_captures_the_submission(flux_client):
    """The third dropped-credential surface, and the one the static pass
    missed: `is_geoserver_path` claims everything under `/geoserver/`, so
    a matcher-only check said this path was handled while the handler
    itself fell through to a 404."""
    resp = await flux_client.post(
        "/geoserver/j_spring_security_check",
        data={"username": "admin", "password": "geoserver"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "geoserver-credential-post"
    assert entry["geoserverUsername"] == "admin"
    assert entry["geoserverHasPwd"] is True
    assert entry["geoserverPwdLen"] == "9"


async def test_geoserver_accepts_the_spring_security_spelling(flux_client):
    """Scanners targeting Spring Security rather than this page post
    `j_username`/`j_password`."""
    await flux_client.post(
        "/geoserver/j_spring_security_check",
        data={"j_username": "spring", "j_password": "pw"},
    )
    assert _log_entries(flux_client.log_path)[-1]["geoserverUsername"] == "spring"


async def test_owa_favicon_is_an_image_not_the_login_page(flux_client):
    """The `/owa/` prefix match used to swallow this and answer with the
    login HTML. A favicon returning `text/html` is a tell by itself."""
    resp = await flux_client.get("/owa/auth/15.2.1118/themes/resources/favicon.ico")
    assert resp.status == 200
    assert "image/" in resp.headers.get("Content-Type", "")
    assert (await resp.read()).startswith(b"\x00\x00\x01\x00")


@pytest.mark.parametrize("path,get_tag,post_tag", [
    ("/dologin.action", "confluence-login", "confluence-credential-post"),
    ("/geoserver/j_spring_security_check", "geoserver-web-landing", "geoserver-credential-post"),
    ("/aspera/faspex/session", "aspera-faspex-landing", "aspera-faspex-credential-post"),
])
async def test_only_a_real_post_counts_as_a_credential_submission(
    flux_client, path, get_tag, post_tag,
):
    """None of these three endpoints has a GET route on the real product,
    and the counts only mean something if every row in them is an actual
    submission -- otherwise a link-follower or an uptime check inflates
    the credential numbers."""
    await flux_client.get(path)
    assert _log_entries(flux_client.log_path)[-1]["result"] == get_tag

    await flux_client.post(path, data={"username": "u", "password": "p"})
    assert _log_entries(flux_client.log_path)[-1]["result"] == post_tag


# --- non-collision ------------------------------------------------------


@pytest.mark.parametrize("path", [
    # Neighbours of the new exact-match asset paths. The WebLogic entries
    # matter most: the console matcher deliberately does not take a
    # `/console/` prefix, because encoded-traversal payloads under it
    # belong to other handlers, and adding assets must not have widened it.
    "/console/framework/skins/wlsconsole/css/other.css",
    "/console/css/%252e%252e/consolejndi.portal",
    "/vendor/telescope/app-light.css",
    "/remote/fortinet.jpg",
    "/dana-na/css/other.css",
])
def test_added_asset_paths_did_not_widen_their_matchers(path):
    """Each asset was added as an exact path. A near-miss spelling must
    not be claimed, or the addition has quietly become a prefix rule."""
    claimed = [
        name for name, fn in vars(tbenv).items()
        if name in (
            "is_weblogic_console_path", "is_telescope_path",
            "is_fortigate_vpn_path", "is_ivanti_vpn_path",
        ) and fn(path)
    ]
    assert not claimed, f"{path} unexpectedly claimed by {claimed}"
