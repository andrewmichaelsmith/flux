# Self-referenced assets and form actions

Every URL a rendered page names is answered by the server that rendered it.

## Why

A vendor login page is not just its HTML. A real one ships a stylesheet, a
logo and a favicon, and its login form posts to somewhere that exists.
Rendering the page while 404ing everything it references produces a shape
no real deployment has — and because the same code runs on every host, it
produces the *same* wrong shape everywhere. That is a fleet fingerprint,
not a coverage gap.

It also costs signal in two concrete ways:

- **Gated scanners stop early.** Tooling that confirms a vendor before
  spending an exploit commonly fetches a known static asset — a themed
  icon, a stylesheet under a versioned path — and treats a 404 as "not
  really that appliance". Those clients never reach the stage where they
  send the thing worth capturing.
- **Credentials were being dropped.** Three of the unresolved references
  were `<form action=...>` targets rather than assets. Those surfaces
  rendered a login form whose submission fell through to a 404, so the
  credential each trap exists to collect was lost on arrival — while the
  page kept looking like it worked.

This is the same defect the operational-endpoint index guard was written
for (an index advertising `_links` that nothing served), except that guard
only ever walked a JSON index and never looked at rendered HTML.

## Form actions

| Path | Surface | Result tag | Logged |
| --- | --- | --- | --- |
| `/dologin.action` (+ `/confluence/`, `/wiki/` prefixes) | Confluence | `confluence-credential-post` | `confluenceUsername`, `confluenceHasPwd`, `confluencePwdLen`, `confluenceAtlTokenPresent` |
| `/geoserver/j_spring_security_check` | GeoServer | `geoserver-credential-post` | `geoserverUsername`, `geoserverHasPwd`, `geoserverPwdLen` |
| `/aspera/faspex/session` | Aspera Faspex | `aspera-faspex-credential-post` | `asperaFaspexUsername`, `asperaFaspexHasPwd`, `asperaFaspexPwdLen` |

Each re-renders its own login page with an auth-failure notice, which is
both what the real product does on a rejected credential and the only
honest response available. The dedicated fields record presence and
length; the raw body stays in `bodyPreview`, matching every other
credential-POST surface here.

Two of the extractors accept more than one field spelling on purpose.
Confluence's form posts `os_username`/`os_password`, GeoServer's posts
plain `username`/`password`, and Aspera's posts Rails-bracketed
`user[email]`/`user[password]` — but credential-stuffing kits submit a
generic pair regardless of what the form asked for. Accepting both means
the submission is recorded either way, and `confluenceAtlTokenPresent`
keeps the two populations apart: a client that echoes the per-render CSRF
nonce parsed our HTML, while one that omits it is replaying a canned
request.

## Assets

| Path | Surface | Result tag | Type |
| --- | --- | --- | --- |
| `/remote/fgt_favicon` | FortiGate | `fortigate-favicon` | `image/x-icon` |
| `/remote/fortinet.png` | FortiGate | `fortigate-logo` | `image/png` |
| `/vpn/images/AccessGateway.ico` | Citrix Gateway | `citrix-favicon` | `image/x-icon` |
| `/dana-na/css/ds.css` | Ivanti | `ivanti-ds-css` | `text/css` |
| `/RDWeb/Pages/Site.css` | RDWeb | `rdweb-asset` | `text/css` |
| `/console/framework/skins/wlsconsole/css/master.css` | WebLogic | `weblogic-console-asset` | `text/css` |
| `/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png` | WebLogic | `weblogic-console-asset` | `image/png` |
| `/vendor/telescope/app.js` | Telescope | `telescope-asset-js` | `application/javascript` |
| `/vendor/telescope/app-dark.css` | Telescope | `telescope-asset-css` | `text/css` |
| `/vendor/telescope/favicon.svg` | Telescope | `telescope-asset-svg` | `image/svg+xml` |
| `/geoserver/wicket/resource/**/*.css` | GeoServer | `geoserver-asset` | `text/css` |
| `/owa/auth/**/*.ico` | Exchange | `exchange-owa-asset` | `image/x-icon` |

Assets carry their own result tags so an asset fetch is never counted as a
portal visit — otherwise one scanner loading one login page would look
like several.

The Exchange entry is a correction rather than an addition: the `/owa/`
prefix match was broad enough to swallow the themed favicon URL the login
page names, so it was already being answered — with the login page's own
HTML. A favicon that returns `text/html` is a tell by itself.

Bodies are deliberately small and generic; they exist so the reference
resolves, not to be interesting. None carries anything credential-shaped,
so none spends a canary. The PNG and ICO bytes are constructed
(`_png_solid`, `_ico_from_png`) rather than embedded as base64 blobs, so
the bytes stay reviewable — and a scanner that actually decodes the asset
gets a real image.

The WebLogic and Telescope entries are matched as **exact paths**, not
prefixes. The WebLogic console matcher deliberately does not claim
`/console/` wholesale, because encoded-traversal payload targets under it
belong to other handlers; a `test_added_asset_paths_did_not_widen_their_matchers`
case pins that.

## The guard

`tests/test_self_referenced_assets.py::test_every_referenced_url_is_answered`
renders every drivable HTML renderer, scrapes every same-origin
`href`/`src`/`action` out of the result, and asserts the server answers
each one with a 200 and a non-empty body.

It asserts on the **dispatched response**, not on whether some
`is_*_path` predicate returns `True`. That distinction is load-bearing:
a predicate claiming a path proves only that the request reaches a
handler, and a handler can still fall into its own `*-miss` 404 branch.
A matcher-only version of this check passed on `/geoserver/j_spring_security_check`
— `is_geoserver_path` claims everything under `/geoserver/` — while the
handler behind it returned 404 and dropped the credential. Asking the app
is the only check that covers both.

The guard is mutation-checked three ways: removing a served path from its
table, adding a new reference nothing serves, and disabling a handler
branch while leaving its path table intact. Each mutant fails the guard
naming the exact path.
