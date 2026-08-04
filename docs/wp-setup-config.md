# WordPress setup-config.php install-hijack trap

Serves the WordPress pre-install wizard through its real multi-step
flow, so that a scanner probing for an unfinished install submits the
database endpoint it wants that install to connect to — and that
endpoint is infrastructure the scanner controls.

| Path | Methods | Response |
| --- | --- | --- |
| `/wp-admin/setup-config.php` and the multi-install subdirectory forms (`/wordpress/`, `/blog/`, `/wp/`, `/wp1/`, `/wp2/`, `/site/`, `/shop/`, `/news/`, `/test/`, `/cms/`, `/web/`, `/media/`, `/sito/`, `/website/`, `/new/`, `/old/`, `/main/`, `/home/`, `/public/`, `/portal/`) | `GET`, `HEAD` | "Before getting started" welcome page listing the five items the wizard needs, with the `?step=1` hop |
| Same paths with `?step=1` (or `?step=2` reached by `GET`) | `GET`, `HEAD` | The database connection form — `dbname`, `uname`, `pwd`, `dbhost`, `prefix` — posting to `?step=2` within the same install directory |
| Same paths | `POST` | Captures the submitted database fields, then serves the real "All right, sparky!" successful-connection page linking on to `install.php` |

All matched paths return `200` with WordPress's install-time cache
headers (`Expires: Wed, 11 Jan 1984 05:00:00 GMT`). Matching is
case-insensitive and strips the query string, so every wizard step
dispatches. Disabled deployments and unmatched paths return `404`.

The handler logs:

- `result` tags (`wp-setup-config-welcome`, `wp-setup-config-dbform`,
  `wp-setup-config-db-post`)
- `wpSetupConfigPath`, `wpSetupConfigStep`, `wpSetupConfigMethod`
- `wpSetupConfigDbHost` — the database endpoint the client wants this
  install to dial
- `wpSetupConfigDbHostIsRemote` — whether that endpoint is anything
  other than a loopback address. A client that leaves `localhost` in
  place submitted the form untouched; anything else is a host it
  controls, and is the reason this trap exists
- `wpSetupConfigDbUser` and `wpSetupConfigDbPassword` — recorded in
  full, see below
- `wpSetupConfigHasPwd`, `wpSetupConfigPwdLen`
- `wpSetupConfigDbName`, `wpSetupConfigPrefix`,
  `wpSetupConfigPrefixIsDefault` — default values (`wordpress`,
  `wp_`) versus bespoke ones separate an untouched off-the-shelf
  script from a hand-driven one
- `bodyPreview` (first 4096 bytes, decoded best-effort) and `bytes`

## Why

`setup-config.php` is the wizard WordPress serves while `wp-config.php`
is still absent. It is not a credential-brute surface; it is the
opposite direction. A host that answers here is one where the visitor
can complete the installation themselves: the database step writes
their connection details into `wp-config.php`, and the following step
creates the first administrator account. That is takeover of an
unfinished install with no credential required, which is why scanner
kits carry it as a standing dictionary entry alongside the
`/wp-admin/install.php` liveness check this server already traps.

The capture is inverted from every other login trap here. Those record
what an attacker guesses about *our* credentials. This one records a
database host, username and password that are valid on infrastructure
the *attacker* controls — a piece of their own estate rather than a
guess about ours. That makes the password the one credential in this
codebase that is correct to retain in full: it is not our secret, and
its reuse across otherwise-unrelated probes is a linkage signal that a
length-only record would destroy.

Eliciting it requires the flow to be walkable. A single static page
ends the interaction at the welcome screen, before any database
details are on the wire, so the handler implements all three steps and
serves the genuine "successful connection" page on POST — which also
routes the client onward to `install.php`, an endpoint this server
already answers, keeping the wizard coherent instead of dead-ending.

The subdirectory fan-out reuses the same prefix list as the
wlwmanifest trap. Recurring probe volume against the `/wordpress/`
form runs at close to the webroot form's level, which is unsurprising:
a half-finished install parked in a subdirectory is precisely the case
that stays half-finished.

Dispatch is ordered ahead of the generic `/wp-admin/*` redirect, which
would otherwise bounce the wizard to the login page and make the flow
unreachable.

## Canary placement

None. The only values this trap emits are stock WordPress form
defaults (`localhost`, `wp_`, `wordpress`), which are not secrets and
must stay at their real defaults — changing them would break the tell
that distinguishes an untouched submission from a supplied one. The
success signal here is inbound: the captured `dbhost` / `uname` /
`pwd` triple, filtered on `wpSetupConfigDbHostIsRemote`.

## Config

- `HONEYPOT_WP_SETUP_CONFIG_ENABLED` — master switch, defaults on.
- `HONEYPOT_WP_SETUP_CONFIG_VERSION` — version referenced in the
  install stylesheet URL, defaults to `6.8.2`.
- `HONEYPOT_WP_SETUP_CONFIG_BODY_DECODE_LIMIT` — bytes of a POST body
  decoded into `bodyPreview`, defaults to 4096.
