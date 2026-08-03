# Fake cPanel / WebHost Manager (WHM) login trap

Serves the cPanel WHM 11.x login page on any of the canonical entry
aliases scanner dictionaries fan out on, then captures any credential
POST that follows. Real WHM (WebHost Manager) is cPanel's tenant-root
admin console — one tier above the per-account `/cpanel` login — so a
working credential capture is root-tier hosting-account access, which
separates a hosting-provider-targeting actor from the generic MySQL /
Adminer brute cohort.

| Path | Methods | Response |
| --- | --- | --- |
| `/whm`, `/whm/`, `/whm/index`, `/whm/index.html`, `/2086`, `/2086/`, `/2086/login`, `/2086/login/`, `/2087`, `/2087/`, `/2087/login`, `/2087/login/`, `/cpanel`, `/cpanel/`, `/2082`, `/2082/`, `/2083`, `/2083/`, `/session/login`, `/session/login/` | `GET`, `HEAD` | WHM 11.x login HTML with per-request `cpsess<hex>` token embedded in form action + asset URLs and a per-request `cprelogin=<hex>` cookie |
| `/___proxy_subdomain_whm`, `/___proxy_subdomain_whm/login`, `/___proxy_subdomain_whm/login/`, `/___proxy_subdomain_cpanel`, `/___proxy_subdomain_cpanel/login`, `/___proxy_subdomain_webmail` (and trailing-slash forms), `/openid_connect/cpanelid` | `GET`, `HEAD` | Same login HTML. These are cpsrvd's internal proxy-subdomain entry points — the rewrite target when a host is reached via its `whm.` / `cpanel.` / `webmail.` service subdomain rather than by port |
| `/cpsess<16-64 hex>/whm/`, `/cpsess<hex>/whm/<subpath>`, `/cpsess<hex>/cpanel/`, `/cpsess<hex>/cpanel/<subpath>`, `/cpsess<hex>/session/login/` | `GET`, `HEAD` | Same login HTML — cpsess token from the URL is preserved through the form action so a follow-on POST keeps the same session context |
| Any of the above | `POST` | Captures `user`, `pass` length (never the password itself), `goto_uri`, `goto_app`; re-serves the login HTML with the standard `The login is invalid.` error notice and the submitted username echoed back into the value attribute |

All matched paths return `200` with `Server: cpsrvd/<version>`,
`X-Frame-Options: SAMEORIGIN`, `Strict-Transport-Security`, and the
standard WHM no-cache headers. Disabled deployments and unmatched
paths return `404`. Path matching is case-insensitive; query strings
are stripped before matching so `/whm?login_theme=cpanel` still
dispatches.

The handler logs:

- `result` tags (`whm-login`, `whm-credential-post`)
- `whmPath` (exact request path)
- `whmMethod` (HTTP verb, GET/HEAD only — POST captures land under
  the credential-post branch)
- `whmUsername` for any POST to a matched path
- `whmHasPwd` and `whmPwdLen` — password value is never stored,
  only presence and length, so common-dictionary vs random-blob
  brute strategies are separable
- `whmGotoUri`, `whmGotoApp` — the hidden `goto_uri` + `goto_app`
  redirect targets brute clients submit; real WHM uses these to
  route the post-login user to a specific WHM sub-app so seeing
  `whostmgrd` vs `cpaneld` separates WHM-targeting from
  cPanel-user-targeting clients on the same form
- `whmSessionCookiePresent` — whether the request carried a prior
  `cprelogin` / `cpsession` cookie, so cookie-replay scanners
  separate from fresh probes
- `whmCpsessFromPath` — whether the scanner hit a
  `/cpsess<hex>/…` URL directly (a scanner that follows a real
  redirect target) vs a bare `/whm` entry
- `bodyPreview` (first 4096 bytes of the credential POST, decoded
  best-effort) and `bytes` (response payload length)

## Why

`/whm` sits in the trap 404 tail alongside `/adminer.php` and
`/.DS_Store` under `python-requests/2.32.5` clients — the same
scripted DB-admin-hunter kit that already probes those two paths
(both trapped) walks WHM as a fingerprint slot. Every hit was
previously 404'd, so root-tier credential-brute fleets walking WHM
dictionaries bailed before POSTing any credential bytes and we lost
the username material.

WHM is architecturally more dangerous than cPanel-user brute — a
working WHM credential is `root` on the whole shared-host box, not
just one hosting account — so the same POST here captures a
distinctly higher-value credential than the surrounding traps in
this cohort's kit. That combination — high-value target,
distinctive scripted-kit signature, known miss called out in the
Adminer and DS_Store comment blocks — motivates the dedicated trap
rather than folding into a generic form handler.

The `___proxy_subdomain_*` prefixes were a follow-on miss. cpsrvd
exposes the same panels two ways: by port (`:2086` / `:2087` for WHM,
`:2082` / `:2083` for cPanel) and via service subdomains
(`whm.<domain>`, `cpanel.<domain>`, `webmail.<domain>`), which cpsrvd
rewrites onto these internal prefixes. The port-based aliases were
already covered; credential-stuffing tooling that targets the subdomain
form emits the rewritten prefix verbatim and so kept landing on the 404
fallback instead of the login capture. Recurring probe volume against
the proxy-subdomain form runs ahead of the port-based aliases, which
makes it the broader of the two entry surfaces rather than a long-tail
variant.

## Canary placement

None — the real WHM login page has no natural credential-shaped
slot to embed a canary into (unlike Adminer, which has a
`<datalist>` server-history preset that can carry AWS key/secret
attributes). Shoehorning one into the WHM page would break the
fingerprint scanners expect. The primary success signal for this
trap is the captured `user` value on POST plus the observed
`goto_app` (`whostmgrd` for WHM-targeting, `cpaneld` for
cPanel-user-targeting) so the two attacker populations remain
separable.

## Config

- `HONEYPOT_WHM_ENABLED` — master switch, defaults on.
- `HONEYPOT_WHM_VERSION` — displayed in the footer and in the
  `Server: cpsrvd/<version>` header, defaults to `11.126.0.5`
  (a real released WHM build).
- `HONEYPOT_WHM_PATHS_CSV` — comma-separated exact-match path
  set. Defaults to the built-in list above; override for
  site-specific dictionaries. The cpsess-tokenised path shape
  (`/cpsess<hex>/whm/…`) is matched via a separate regex and is
  not overridable via env.
- `HONEYPOT_WHM_BODY_DECODE_LIMIT` — bytes of a POST body decoded
  into `bodyPreview`, defaults to 4096.
