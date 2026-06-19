# Fake phpMyAdmin login trap

Serves a canonical phpMyAdmin 5.x cookie-auth login page across the
classic install-path aliases scanner dictionaries fan out on, then
captures any credential POST that follows. Real installs return 200 on
both the bare directory GET and on a failed login POST, so the trap
matches the on-the-wire shape banner-grab plus brute clients expect.

| Path | Methods | Response |
| --- | --- | --- |
| `/phpmyadmin/`, `/phpMyAdmin/`, `/PMA/`, `/pma/`, `/myadmin/`, `/MyAdmin/`, `/dbadmin/`, `/mysql/`, `/mysqladmin/`, `/sqladmin/`, `/sqlmanager/`, `/admin/phpmyadmin/`, `/admin/pma/`, `/admin/mysql/`, `/_phpmyadmin/`, `/db/`, `/database/`, `/web/phpmyadmin/` | `GET`, `HEAD` | PMA 5.x login HTML with per-request hidden `token` + per-request `phpMyAdmin=<session>` cookie |
| `<any-of-above>/...` (e.g. `/phpmyadmin/index.php`, `/PMA/sql.php`) | `GET`, `HEAD` | Same login HTML; `bodyPreview`/`phpMyAdminPath` records the exact probed path |
| `<any-of-above>/setup/...` | `GET`, `HEAD` | Same login HTML; logged as `phpmyadmin-setup-probe` so the setup-page fanout is separable in slicers |
| `<any-of-above>/...` | `POST` | Captures `pma_username`, `pma_password` length (never the password itself), `server`, submitted `token`; re-serves the login HTML with the canonical `Cannot log in to the MySQL server` error notice and the submitted username echoed back into the form |
| `/phpmyadmin4.8.1/`, `/PMA2018/`, `/pma-5.2/`, … per-version aliases | `GET`/`HEAD`/`POST` | Same handling — version-suffix variants matched by regex |

All matched paths return `200` with `Server: Apache/2.4.41 (Ubuntu)`,
`X-Powered-By: PHP/8.1.27 phpMyAdmin/<version>`, and the standard PMA
no-cache headers. Disabled deployments and unmatched paths return `404`.

Path matching is case-insensitive — scanner dictionaries send both
`/phpmyadmin/` and `/phpMyAdmin/` and route to the same handler.

The handler logs:

- `result` tags (`phpmyadmin-login`, `phpmyadmin-setup-probe`,
  `phpmyadmin-credential-post`)
- `phpMyAdminPath` (exact request path)
- `phpMyAdminMethod` (HTTP verb)
- `phpMyAdminUsername` and `phpMyAdminHasPwd` for any POST to a
  matched path. Password value is never stored — only presence and
  length (`phpMyAdminPwdLen`) so common-dictionary vs random-blob
  brute strategies are separable.
- `phpMyAdminServer` — the `server` form selector (real PMA assigns
  one integer per configured server; the trap accepts any value).
- `phpMyAdminTokenSubmitted` — the hidden `token` returned with the
  POST; truncated to 48 chars.
- `phpMyAdminSessionCookiePresent` — whether the request carried a
  prior `phpMyAdmin` cookie, so cookie-replay scanners separate from
  fresh probes.
- `bodyPreview` (first 4096 bytes of the credential POST, decoded
  best-effort) and `bytes` (response payload length).

## Why

phpMyAdmin install-path aliases were the single highest-volume miss
family in the trap-events corpus (`/phpmyadmin/index.php`,
`/phpMyAdmin/index.php`, `/PMA/index.php`, `/myadmin/index.php` —
four of the top eight `not-handled` paths). Every prior hit 404'd, so
credential-brute fleets walking PMA dictionaries bailed before
posting any login bytes — losing both the username/password material
and the chance to plant a per-hit session-cookie marker that
attributes any subsequent cookie replay back to the trap.

The trap is keyless — it captures already-submitted credentials, it
does not issue replay-fireable Tracebit canaries, so it adds no API
quota cost and stays on by default on every sensor.

Per the [`every-credential-per-hit-unique`](https://github.com/andrewmichaelsmith/flux#design-principle-every-credential-is-per-hit-unique)
design principle, both the hidden form `token` and the `phpMyAdmin`
session cookie are per-hit `uuid4().hex` randomness — never a fixed
literal across the sensor fleet.
