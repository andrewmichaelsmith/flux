# Fake Drupal user-registration + settings.php trap (CVE-2018-7600 / "Drupalgeddon2" bait)

Captures the unauthenticated form-based RCE payload that Drupal 7/8/9
scanners ship at `/user/register?element_parents=...` and ships a fully
shaped `sites/default/settings.php` with a Tracebit AWS canary and a
per-hit synthetic DB password.

## Routed paths

| Path | Methods | Response |
| --- | --- | --- |
| `/user/register` | GET, HEAD | Minimal Drupal 8/9 user-registration HTML with per-request `form_build_id` and `form_token` values; `drupal-user-register-probe`; `X-Generator: Drupal …` |
| `/user/register` | POST, PUT | Drupal AJAX-form JSON envelope; logs body / query previews and triage flags; result tag depends on the indicator set (see below) |
| `/?q=user/register`, `/drupal/user/register`, `/cms/user/register` | both | Same response shape — covers the `?q=` legacy query-parameter routing and the two reverse-proxy webroot-prefix layouts |
| `/sites/default/settings.php` (+ `.bak` / `.save` / `.swp` / `~` / `.old` / `.orig` / `.txt` variants) | GET, HEAD | `settings.php` body with per-hit synthetic DB password and Tracebit AWS canary in the `s3fs.settings` block; `drupal-settings-php` |
| `/sites/default/settings.php%00`, `/sites/default/settings.php%20` | GET, HEAD | Same response — covers null-byte / space truncation suffix variants some scanner dictionaries probe |
| `/sites/default/default.settings.php`, `/sites/all/settings.php` | GET, HEAD | Same response — covers the unconfigured-template and multisite-layout filenames |
| `/drupal/sites/default/settings.php`, `/cms/sites/default/settings.php` | GET, HEAD | Same response — webroot-prefix variants |

`/user/login` and `/user/password` remain owned by the generic web-app
form responder; the Drupal handler intentionally does not shadow them.

## Result tags

- `drupal-user-register-probe` — GET on `/user/register`; no payload.
- `drupal-user-register-post` — POST with no Drupalgeddon2 indicators.
- `drupal-user-register-drupalgeddon2` — POST with at least one of
  `element_parents=`, `_wrapper_format=drupal_ajax`, `ajax_form=1`,
  `#post_render`, `#markup`, `#type`, `#lazy_builder`, `#pre_render`
  in the query string or body — fingerprint of the CVE-2018-7600
  trigger chain.
- `drupal-user-register-rce-attempt` — Drupalgeddon2 shape plus a
  PHP exec primitive (`passthru`, `system(`, `exec(`, `shell_exec`,
  `phpinfo`, `file_get_contents`, `base64_decode`, `assert(`,
  `eval(`) in the body — the actual command-execution branch of
  the exploit.
- `drupal-settings-php` — `settings.php` canary served.

## Logged fields

Standard request metadata plus:

- `drupalPath`, `drupalMethod`
- `drupalHasDrupalgeddon2` — boolean, the trigger-chain flag
- `drupalHasRcePayload` — boolean, PHP exec primitive present
- `bodyPreview` (first 400 bytes), `queryPreview` (first 400 chars)
- `X-Generator` response header on every Drupal HTML response

The handler also sanitises the rendered HTML so that a configured
Drupal version string with HTML metacharacters cannot bleed into
flux's response.

## Per-hit uniqueness

Every credential-shaped value in the rendered `settings.php` is
randomised per request:

- AWS access key id / secret / session token come from Tracebit's
  per-issuance canary (`_aws()`).
- The Drupal DB password is a per-hit `_fake_db_password()` value —
  never a fixed literal across the fleet.
- `$settings['hash_salt']` and the config-sync directory token are
  per-hit `secrets.token_urlsafe(43)` / `secrets.token_hex(20)`.
- `form_build_id` and `form_token` in the registration form are
  per-request — so a static-fingerprint scanner cannot use either
  as a cross-sensor identifier.

## Why

`/user/register` is the URL surface for **CVE-2018-7600**
("Drupalgeddon2") — an unauthenticated remote code execution
vulnerability in Drupal 6, 7, and 8 disclosed in March 2018. The
exploit ships a form-encoded POST whose form fields exploit Drupal's
Form API render-array processing: an attacker-controlled
`mail[#post_render]` callback runs an attacker-controlled
`mail[#markup]` value through a PHP function such as `passthru` or
`system`, achieving unauthenticated RCE.

Eight years post-disclosure the path remains a top scanner target
because:

- It is the most reliable Drupal fingerprint short of `CHANGELOG.txt`.
- The exploit requires no authentication and works against any Drupal
  build that has not applied the SA-CORE-2018-002 / SA-CORE-2018-004
  patches.
- Many Drupal 6 / 7 deployments are EOL and unpatchable.

The settings.php family is the credential-leak twin: a Drupal site
that accidentally serves the file leaks the database credentials and
(in deployments using `s3fs` or the `drupal-aws-cloudfront` module)
the S3 backup credentials in plain text. Scanner dictionaries walk
every common suffix variant (`.bak`, `.save`, `.swp`, `~`, `%00`,
`%20`) because all of them have been observed on real sloppy
deploys. A scanner that GETs any variant gets a fully shaped Drupal
config with a replay-fireable canary.

The handler runs in front of the CanaryTrap dispatch, so the
`/user/register` path-match wins regardless of any future canary
file additions at the same path.
