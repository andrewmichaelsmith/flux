# flux

[![tests](https://github.com/andrewmichaelsmith/flux/actions/workflows/tests.yml/badge.svg)](https://github.com/andrewmichaelsmith/flux/actions/workflows/tests.yml)

An evolving HTTP honeypot, actively maintained by an LLM working off
observations from a live honeypot sensor network. Fresh scanner
behaviour in the corpus drives new traps; existing traps get tuned or
retired as the logs show what's eliciting follow-up and what's being
ignored.

Small async Python behind nginx. Python 3.11+; one runtime dep —
[aiohttp](https://docs.aiohttp.org/). Async so the tarpit and
fake-git drip paths can hold thousands of concurrent slow-drip
connections at ~8 KB each instead of one OS thread each.

> **Experimental — no guarantees about safety or value.** Every line
> was written by an LLM from natural-language prompts, smoke-tested
> against a live sensor, and continuously reshaped by the same loop.
> It has not been audited line-by-line by a human. The author makes
> no claim that flux is safe to run, produces useful intel, or won't
> do something surprising under load. Before deploying anywhere that
> matters, read [`flux/server.py`](./flux/server.py) end-to-end, run
> the test suite, and think hard about what
> `HONEYPOT_WEBSHELL_PATHS_CSV` or `FAKE_GIT_*` hitting a real webroot
> would do. No warranties.

## Traps

Each family is independently toggleable via env var; all default to
on (see [`CONFIG.md`](./CONFIG.md)). Keyless deployments still 404
the canary-backed rows — dispatch requires `TRACEBIT_API_KEY` on top
of the master switch. We use [Tracebit Community](https://community.tracebit.com)
for the canaries: free tier, sign up and drop the key in the env var.

| Trap | What it does | Key |
| --- | --- | --- |
| Fake `/.env` canary issuer | Mints a per-request Tracebit Community canary and returns it as a `.env`-style payload | yes |
| Fake `/.git/` repository | Serves a loose-object git tree whose `config/secrets.yml` embeds a canary AND whose `.git/config` `[remote "origin"] url` embeds the same canary as HTTP Basic userinfo — so scrapers that only fetch `.git/config` (without cloning) still walk away with a live canary. Matches `<prefix>/.git/*` (apps deployed at subpaths) and is case-insensitive on the `.git` segment; ships a minimal-valid `/.git/index` (DIRC header) so `git-dumper`-style tools don't bail on a missing index. Per-IP cached so fan-out sees a consistent tree | yes |
| Canary file traps | Plausible file-format responses for `/wp-config.php`, `/backup.sql`, `/id_rsa`, `/.aws/credentials`, `/api/v4/user`, `/users/sign_in`, `/actuator/env`, `/.vscode/sftp.json`, GCP service-account JSON variants (`/.config/gcloud/application_default_credentials.json`, `/firebase-adminsdk.json`, …), CI/CD config files, Terraform tfstate (`/.terraform/terraform.tfstate`, `/terraform.tfstate(.backup)` — [docs](./docs/terraform-tfstate.md)), PaaS / .NET / IIS / Docker source-config (`/Procfile`, `/heroku.yml`, `/app.json`, `/appsettings.json`, `/web.config`, `/auth.json`, `/Dockerfile` — [docs](./docs/heroku-config.md)), niche cloud-provider CLI configs (OCI, Hetzner, Civo, Exoscale, Scaleway, Fly.io, OVH, OpenStack, Terraform Cloud, Pulumi, DigitalOcean, Linode, s3cmd, s3fs, Cargo, RubyGems, GitHub CLI, 1Password, Cloudflare Tunnel, WireGuard, Headscale — [docs](./docs/niche-cloud-credentials.md)), … — full table [below](#canary-file-trap-table) | yes |
| Backup-archive canary — [docs](./docs/backup-archive.md) | Pattern-match `<base>.<ext>` backup-archive filenames against a ~95-name base dictionary × 17 compression extensions (`tar.gz`, `zip`, `sql.gz`, `7z`, …), plus IP-octet- and date-derived filename synthesis (`/65.20.84.180.tar.gz`, `/84.tar.gz`, `/2026.zip`, `/202603.tar.gz`). Serves a real archive in the matching format containing `.env` + `backup.sql` with embedded Tracebit AWS canary. Catches generic backup hunters plus the per-target filename synthesis pattern from newer scanner tools | yes |
| AI-credential-file canaries | AI editor / coding-assistant configs (`/.claude/{settings,settings.local,config,history.jsonl,.credentials,CLAUDE.md}`, `/.claude.json`, `/.codex/auth.json`, `/.gemini/{oauth_creds,settings}.json`, `/.cline/{settings,mcp_settings}.json`, `/.continue/config.json`, `/.cursor/mcp.json`, `/.cursor/User/globalStorage/state.vscdb`, `/.cursorrules`, `/.windsurfrules`, `/.clinerules`, `/.aider.conf.yml`, `/.sourcegraph/cody.json`, `/.config/open-interpreter/config.yaml`, `/AGENTS.md`, …) plus per-vendor LLM API-key files (`/.anthropic/api_key`, `/.dashscope/api_key`, `/.deepseek/config.json`, `/.kimi/`, `/.moonshot/settings.json`) plus AI infrastructure / proxy configs (`/litellm_config.yaml`, `/langsmith.env`, `/.huggingface/token`, `/.streamlit/secrets.toml`, `/baseten.yaml`, generic MCP configs, `/.bito/`, `/.codeium/`, `/.roost/`, `/cohere_config.json`, …) and niche coding-agent tooling (`/.openclaw/`, `/root/.config/opencode/`, `/root/.config/vastai/`, `/root/.nerve/`, `/root/.spawnrc`, `/root/.config/moltbook/`) — listed in the same table; broken out in the footnote because Tracebit has no LLM canary type yet | yes |
| Fake webshell | Plausible File Manager on known `*.php` shell probe paths plus shell-jacking regex families (`/.well-known/<name>.php`, `/.trash<N>/*`, `/.tmb/`, `/.dj/`, `/.alf/`, …); simulates `id` / `whoami` / `uname -a` / `cat /etc/passwd` on follow-up commands — [docs](./docs/fake-webshell.md) | no |
| Fake file-upload responder | Prefix-tolerant matchers for the legacy PHP file-upload libraries scanners walk (`<prefix>/kcfinder/upload.php`, `<prefix>/jquery.filer/php/upload.php`, `<prefix>/jquery-file-upload/server/php/`); GET returns presence-detection-friendly HTML/JSON/README, POST parses multipart parts and returns the per-family "uploaded OK" envelope. Logs `fileUploadFamily` / filenames / per-part content-types / `fileUploadHasPhpShell` so payload-bearing uploads are easy to triage. (CVE-2018-15706 / CVE-2018-9206 bait) — [docs](./docs/fake-file-upload.md) | no |
| Modular tarpit + fingerprinting | Slow-drip response plus six fingerprinting modules (cookie, ETag, redirect chain, variable drip, Content-Length mismatch, DNS callback); fires on `.env` variants and on configurable first-contact paths (`/`, `/index.html`, `/robots.txt`, …) | no |
| Fake LLM-API endpoint | Ollama / OpenAI / Anthropic-proxy JSON on `/v1/models`, `/v1/chat/completions`, `/anthropic/v1/messages`, `/api/chat`, … ; returns native SSE / NDJSON streaming when the client sets `"stream": true` so SDK-based callers read through to completion; logs model, prompt prefix, bearer / x-api-key token (sha256 + first-12 + last-4 preview) for cross-IP key-replay grouping — [docs](./docs/fake-llm-api.md) | no |
| Fake OpenAPI / Swagger spec | OpenAPI 3.0.3 JSON/YAML document on the SpringDoc / FastAPI / Swashbuckle / drf-yasg / NSwag canonical paths (`/swagger.json`, `/v3/api-docs`, `/openapi.json`, `/openapi.yaml`, `/swagger/v1/swagger.json`, `/api-docs`, `/webjars/swagger-ui/index.html`, …) plus Swagger UI / ReDoc bootstrap HTML; embeds the canary in `securitySchemes.{bearer,apiKey}Auth.x-example`, `servers[].variables.adminApiKey.default`, and the `info.description` text so credential scrapers that grab any of those slots get a replay-fireable key — [docs](./docs/fake-openapi-swagger.md) | yes |
| Fake GraphQL endpoint | GraphiQL HTML on `GET /graphql` (+ `/api/graphql`, `/graphql/api`, `/api/gql`, `/v1/graphql`, `/query`, …). `POST` body is classified: `__schema` / `IntrospectionQuery` returns a plausible schema listing `User.apiToken` / `awsAccessKeyId` / `secretKey` / `refreshToken` / `webhookSecret` fields. Follow-on data query against any credential-shaped field returns a per-hit Tracebit AWS canary in `apiToken` / `accessToken` / `awsAccessKeyId` / `awsSecretAccessKey` / `secretKey` slots (per-hit-random `refreshToken` and `webhookSecret`). Auth mutations (`login`, `signIn`, `signUp`, `register`, `createUser`, `authenticate`, `resetPassword`) return `AuthPayload` with the canary as `token`, capture the submitted username from inline literals or `variables`, and log `graphqlHasPassword` without storing the value. Unknown queries return a plausible `Syntax Error` / `permission denied` error envelope so the scanner keeps probing — [docs](./docs/fake-graphql.md) | yes |
| Fake SonicWall SSL VPN | SonicOS 7 JSON responses on the three paths in the CVE-2024-53704 auth-bypass chain; logs submitted username, body sha + preview, and replayed session cookies — [docs](./docs/fake-sonicwall.md) | no |
| Fake Cisco WebVPN endpoint | Cisco SSL VPN landing page + launcher assets on `/+CSCOE+/...` and `/+CSCOL+/...`; also recognizes AnyConnect `config-auth` XML POSTs to `/` and logs submitted usernames without storing passwords — [docs](./docs/fake-cisco-webvpn.md) | no |
| Fake Ivanti Connect Secure / Pulse Secure VPN | Ivanti SSL VPN welcome + login POST + HostChecker installer assets on `/dana-na/...` and `/dana-cached/hc/...`; mints a per-request `DSID` cookie, logs username + has-password, and flips `ivantiHasCmdInjection` on shell-meta payloads aimed at `/dana-ws/namedusers` (CVE-2023-46805 / CVE-2024-21887 / CVE-2025-22457 chain bait) — [docs](./docs/fake-ivanti-vpn.md) | no |
| Fake FortiGate SSL VPN | FortiOS SSL VPN login + `/remote/logincheck` credential POST (mints per-request `SVPNCOOKIE`) plus `/api/v2/cmdb/system/{admin,status,global}` and `/api/v2/monitor/router/policy` REST stubs; flips `fortigateHasCmdInjection` on shell-meta payloads aimed at the REST surface (CVE-2024-21762 / CVE-2023-27997 / CVE-2024-48887 bait) — [docs](./docs/fake-fortigate-vpn.md) | no |
| Fake Palo Alto GlobalProtect | GlobalProtect portal + gateway prelogin XML on `/global-protect/prelogin.esp` and `/ssl-vpn/prelogin.esp`, login form + credential POST on `/global-protect/login.esp` (mints per-request `PHPSESSID`), gateway config on `/global-protect/getconfig.esp`; `Server: PanWeb Server/` matches real appliance fingerprint (CVE-2024-3400 bait) — [docs](./docs/fake-globalprotect.md) | no |
| Fake Sophos XG SSL VPN | Sophos XG Firewall SSL VPN login portal on `/svpn/index.cgi` and `/userportal/webpages/myaccount/login.jsp`; credential POST captures username + has-password, mints per-request `JSESSIONID` cookie (CVE-2022-1040 bait) — [docs](./docs/fake-sophos-vpn.md) | no |
| Fake Barracuda SSL VPN | Barracuda Networks VPN tunnel negotiation on `/myvpn` (returns CONNECT + ipv4/ipv6 flags) and login portal on `/cgi-mod/index.cgi` (CVE-2023-7102 / CVE-2023-7101 reconnaissance surface) — [docs](./docs/fake-barracuda-vpn.md) | no |
| Fake F5 BIG-IP APM / TMUI | BIG-IP Access Policy login on `/my.policy` (mints per-request `MRHSession` cookie), TMUI Configuration Utility on `/tmui/login.jsp` (prefix-matches `/tmui/*` to catch CVE-2020-5902 path-traversal), SSL VPN client negotiation on `/sslvpnclient`; flags `f5HasPathTraversal` on `/../` indicators, `Server: BigIP` header (CVE-2023-46747 / CVE-2022-1388 bait) — [docs](./docs/fake-f5-bigip.md) | no |
| Fake Docker Registry V2 API | Docker Distribution Registry HTTP API V2 surface: version check (`/v2/`), catalog listing (`/v2/_catalog`), tag enumeration (`/v2/<name>/tags/list`), manifest retrieval (`/v2/<name>/manifests/<ref>`), blob download (`/v2/<name>/blobs/<digest>`); logs `Authorization` headers, mutation attempts (PUT/PATCH/POST/DELETE), and repo/tag/digest per request. Multi-step protocol reveals scanner sophistication — [docs](./docs/fake-docker-registry.md) | no |
| Fake Docker Engine API (daemon on 2375) | Docker Engine API surface: `/version`, `/info`, `/_ping`, `/containers/json`, `/images/json`, plus the takeover chain `POST /containers/create` → `POST /containers/<id>/start` → `POST /containers/<id>/exec` → `POST /exec/<id>/start`. Mints a fake 64-hex container/exec ID per `create` so the scanner ships its follow-up `/start` against the same trap. Strips a `/vX.Y` API-version prefix and a `:2375` / `%3a2375` / `%253a2375` SSRF colon-port shim from the path before dispatching, and flags the SSRF shape as `dockerDaemonHasSsrfPrefix`. Parses the create body for `Image` / `Cmd` / `Entrypoint` and flips `dockerDaemonHasPrivileged` / `dockerDaemonHasHostMount` / `dockerDaemonHasHostPid` / `dockerDaemonHasHostNetwork` / `dockerDaemonHasDangerousCap` / `dockerDaemonHasShellPayload` for fast triage of cryptominer / host-takeover payloads — [docs](./docs/fake-docker-daemon.md) | no |
| Fake Citrix NetScaler / Gateway portal | NetScaler ADC / Gateway login HTML on `/vpn/index.html`, `/logon/LogonPoint/index.html`, `/Citrix/XenApp/auth/login.aspx`; credential POST sinks at `/cgi/login` and `/p/u/doAuthentication.do` mint a per-request `NSC_AAAC` session cookie (CVE-2023-4966 "CitrixBleed" leak shape — never a fixed literal). Flips `citrixHasCmdInjection` on shell-meta and CVE-2019-19781 path-traversal indicators (`Shitrix`); also covers CVE-2023-3519 / CVE-2022-27510 / CVE-2023-24486 fingerprint chains — [docs](./docs/fake-citrix-gateway.md) | no |
| Fake Microsoft RDWeb (RD Web Access) | RDWeb login page + `/RDWeb/Pages/en-US/login.aspx` credential POST (mints per-request `TSWAAuthHttpOnlyCookie`) plus `/RDWeb/Pages/en-US/Default.aspx` post-auth resource list. After a "successful" landing-path POST (and on direct Default.aspx fetches), the resource list ships a single `Cloud Console` RemoteApp tile whose `RDPFileContents` HTML comment embeds a per-hit Tracebit AWS canary — credential-scrapers walking post-auth content harvest a key that fires on AWS replay. Logs `DomainUserName` / `UserPass`-presence so password-spraying credential rotations land in the access log; advertises `Server: Microsoft-IIS/10.0` to match real Server 2019 RDWeb — [docs](./docs/fake-rdweb.md) | no |
| Fake Microsoft Exchange (OWA / ECP / autodiscover / PSRemoting) | Multi-step Exchange surface: OWA login on `/owa/auth/logon.aspx` (mints per-request `cadata` cookie), ECP login on `/ecp/` (mints `msExchEcpCanary`), eDiscovery exporttool ClickOnce manifest on `/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application` (build version stamped in `<assemblyIdentity>` for fingerprint diff), autodiscover JSON on `/autodiscover/autodiscover.json` (per-request `MailboxGuid` + `Bearer` literal), and a 401 + `WWW-Authenticate: Negotiate, Kerberos, NTLM` on `/powershell/`. Flips `exchange-autodiscover-proxyshell-ssrf` on the literal `?@<spoof>` query shape, logs `exchangeXRpsCatPresent` + `exchangeHasPowershellCmdlet` on PSRemoting POSTs, captures OWA / ECP usernames (`username` / `j_username` / `UserName` variants) without storing passwords. Headers pin `Server: Microsoft-IIS/10.0` + `X-OWA-Version` (CVE-2021-34473 / CVE-2021-34523 / CVE-2021-31207 ProxyShell bait) — [docs](./docs/fake-exchange.md) | no |
| Fake IBM Aspera Faspex portal | Aspera Faspex login/logout/relay surfaces on `/aspera/faspex/...`; emits plausible HTML/JSON, logs follow-on payload previews on logout/relay endpoints, and keeps scanner chains alive past initial fingerprinting (CVE-2022-47986 bait) — [docs](./docs/fake-aspera-faspex.md) | no |
| Fake Hikvision IP camera | Hikvision ISAPI surface (`/SDK/webLanguage`, `/ISAPI/Security/userCheck`, `/ISAPI/System/deviceInfo`); returns plausible XML with `Server: App-webs/` and a CVE-2021-36260-window firmware banner, flips `hikvisionHasCmdInjection` on shell-meta indicators in body/query so language-parameter command-injection payloads are easy to triage — [docs](./docs/fake-hikvision.md) | no |
| Fake ONVIF device_service | ONVIF SOAP banner at `/onvif/device_service` (`/onvif/services`, `/onvif/device`, bare `/device_service`); returns a Dahua-class `<GetDeviceInformationResponse>` envelope with `Server: lighttpd/` and a firmware version sitting in the public-disclosure window for the Dahua-class CVEs (CVE-2024-7029 auth-bypass cmd-injection, CVE-2023-43261, CVE-2021-33044). Logs `onvifSoapActionHeader`/`onvifSoapActionBody` and flips `onvifHasCmdInjection` on shell-meta or `FirmwareUpgrade` / `UpgradeUrl` sink-element indicators — [docs](./docs/fake-onvif.md) | no |
| Fake D-Link / Linksys HNAP1 router | SOAP-over-HTTP HNAP1 control endpoint at `/HNAP1`; GETs return a `<DeviceSettings>` envelope with vendor / model / `Server: Mathopd/` banner, POSTs return a generic SOAP `OK` whose response element name tracks the SOAPAction header. Logs the raw `SOAPAction` value and flips `hnap1HasCmdInjection` on shell-meta indicators in the header / query / body so CVE-2015-2051 dropper payloads are easy to triage — [docs](./docs/fake-hnap1.md) | no |
| Fake Apache `mod_status` | `/server-status` (`/server-status/`, `?auto`, `?refresh=N`); returns a plausible Apache 2.4 `mod_status` page (HTML or the `?auto` text format) with a worker scoreboard whose recent-request URLs embed the per-hit Tracebit AWS canary in `aws_access_key_id` / `aws_secret_access_key` query-string slots — the slot credential-scrapers grep `AKIA…` from. `Server: Apache/2.4.58 (Ubuntu)` banner pinned inside the public-disclosure window for the 2024 mod_proxy / mod_rewrite CVEs so version-gated scanners don't bail — [docs](./docs/fake-server-status.md) | yes |
| Fake GeoServer admin / OGC | GeoServer 2.x admin shell + About page + OGC `*_Capabilities` on `/geoserver/...`; flags OGNL/expression-language indicators in query string + body so CVE-2024-36401 payloads are easy to triage — [docs](./docs/fake-geoserver.md) | no |
| Fake Liferay Portal JSON Web Services | Liferay 7.x JSON-WS discovery surface on `/api/jsonws`, `/api/jsonws/`, `/api/jsonws?serviceClassName=...`, and the `/api/jsonws/invoke` JSON-RPC sink. Landing HTML lists fake registered services and embeds the per-request Tracebit AWS canary in a `DLAppService` S3-backed Document Library config slot (the scanner-grep slot for `portal-ext.properties` leaks); per-service signature JSON embeds the same canary in `getConfiguredS3Bucket.default.{accessKey,secretKey}`. POST `/invoke` captures the JSON-RPC body and flips `liferayHasMarshallerPayload` on the canonical CVE-2020-7961 sink indicators (`WrapperConnectionPoolDataSource` / `userOverridesAsString` / `ldap://` / `rmi://` JNDI URLs / `jodd.bean`). `Server: Apache-Coyote/1.1` + `Liferay-Portal:` headers pinned inside the CVE-2020-7961 public-disclosure window — [docs](./docs/fake-liferay-jsonws.md) | yes |
| Fake Gravity SMTP plugin (WordPress REST) | Gravity SMTP plugin's WP-REST namespace at `/wp-json/gravitysmtp/v1/settings`, `/v1/config`, `/v1/connector/{amazonses,mailgun,sendgrid,sparkpost,smtp,office365,gmail}`, `/v1/tests/mock-data`, `/v1/data/debug` — plus WordPress install sub-directory placements (`/{blog,wordpress,wp,site,news,cms,press}/wp-json/gravitysmtp/v1/...`) that dispatch identically. `/v1/config` returns a populated per-connector config JSON; the AWS SES block embeds the per-request Tracebit AWS canary in `aws_access_key_id` / `aws_secret_access_key` (the same slot WP-REST authorisation-gap scrapers grep for after walking `/wp-json/`). Other connectors ship per-hit synthetic credentials in the published shape for each provider (`key-<32hex>` Mailgun, `SG.<22>.<43>` SendGrid, 40-hex SparkPost, `ya29.…` / `GOCSPX-…` Gmail OAuth) so the namespace looks realistic without leaking a fleet-wide fixed string. Anything else under `/v1/...` 404s with the WP-REST-shaped `rest_no_route` envelope — [docs](./docs/fake-gravity-smtp.md) | yes (`/config` + `/connector/amazonses` only) |
| Fake Laravel Telescope debug panel | Laravel Telescope SPA + JSON-API surface at `/telescope/<panel>` (HTML Vue-app shell) and `/telescope/telescope-api/<panel>` (paginated entries JSON; `/telescope/api/<panel>` proxy-rewrite alias also dispatches). The `requests` panel ships a captured admin `POST /admin/settings/s3` whose `content.payload` embeds the per-request Tracebit AWS canary in `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (the slot a real `RequestWatcher` row stores); `queries` ships an `insert into settings ...` row with the canary in `content.bindings`; `exceptions` ships an `Illuminate\Database\QueryException` whose `content.context.env` carries the canary in the `$_ENV` dump (same slot Ignition leaks via HTML); `mail` ships a `PasswordResetMail` with the canary in `content.transport.{key,secret}` for the SES driver; `logs` ships an `error`-level entry with the canary in `content.context.AWS_*`. Other known panels (`cache`, `redis`, `gates`, `dumps`, `schedule`, `jobs`, `batches`, `views`, `models`, `events`, `commands`, `notifications`, `monitored-tags`, `clients`) return an empty `{"entries":[]}` — the empty state a fresh install renders. Bearer tokens, CSRF, session cookies, `APP_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD`, and the captured `/api/v1/login` password are all per-hit `secrets.token_urlsafe`/`token_hex` synthetics — no fixed literals. Sub-directory placements (`/admin/telescope/...`, `/dashboard/telescope/...`, `/panel/...`, `/backend/...`, `/app/...`, `/laravel/...`, `/monitor/...`, `/dev/...`, `/internal/...`) dispatch identically to the bare path — [docs](./docs/fake-laravel-telescope.md) | yes (`requests` / `queries` / `exceptions` / `mail` / `logs` panels only) |
| Fake ColdFusion admin / component browser | ColdFusion public `.cfm` anchors plus `/CFIDE/componentutils/`, Administrator, and AdminAPI surfaces; logs method, auth/session hints, and exploit payload indicators — [docs](./docs/fake-coldfusion.md) | no |
| Fake Atlassian Confluence + Apache Struts OGNL | Confluence 7.x login surface on `pages/createpage-entervariables.action`, `pages/doenterpagevariables.action`, `templates/editor-preload-container`, `users/user-dark-features`, `login.action` / `index.action` (bare, `/confluence/`, `/wiki/` prefixes); also matches URL-encoded `${@...}` OGNL in the path (CVE-2022-26134) and `${#...ProcessBuilder...}` / `redirect:${...}` / `redirectAction:` / `xwork.MethodAccessor` / `_memberAccess` Struts S2-053/S2-061/S2-066 OGNL carried in the query or body; extracts the OAST/Interactsh callback hostname and preserves the full payload preview so the embedded `sh -c <cmd>` is recoverable for triage — [docs](./docs/fake-confluence.md) | no |
| Fake OIDC / OAuth discovery endpoint | Keycloak-shaped OpenID Connect / OAuth 2.0 Authorization Server metadata JSON on every prefix scanners walk for IdP discovery: `/.well-known/openid-configuration` (bare, `/oauth/`, `/oauth2/`, `/oauth/idp/`, `/idp/`, `/auth/`, `/auth/realms/<realm>/`, `/realms/<realm>/`), the `/.well-known/oauth-authorization-server` RFC-8414 sibling, the `openid_configuration` underscore-typo variant, leading-slash URL-encoding (`/%2F.well-known/...` / `/%252F.well-known/...`) and `%00` / `.txt` / `~` / `?v=1` suffix noise. Keycloak realm name extracted from the path and reflected in the `issuer` + endpoints; embeds the per-request Tracebit AWS canary in non-standard `_aws_metadata_signing_*` extension fields so credential-harvester grep loops scraping discovery JSON for `AKIA…` walk away with a replay-fireable canary; OAuth-sibling responses drop OIDC-only fields (`userinfo_endpoint`, `id_token_*`, `claims_supported`) per RFC-8414 — [docs](./docs/fake-oidc-discovery.md) | yes |
| Fake phpMyAdmin login page | phpMyAdmin 5.x cookie-auth login page across the classic install-path aliases (`/phpmyadmin/`, `/phpMyAdmin/`, `/PMA/`, `/myadmin/`, `/dbadmin/`, `/mysql/`, `/admin/phpmyadmin/`, …) plus per-version directory variants (`/phpmyadmin4.8.1/`, `/PMA2018/`). GET / HEAD renders the canonical PMA login HTML with a per-request hidden `token` + per-request `phpMyAdmin=<session>` cookie; POST captures `pma_username`, `pma_password` length (never the password itself), `server` selector, and submitted `token`, then re-serves the login HTML with the standard `Cannot log in to the MySQL server` error notice and the submitted username echoed back the way real PMA does. `/setup/` probes get their own `phpmyadmin-setup-probe` result tag so the setup-page fanout is separable — [docs](./docs/fake-phpmyadmin.md) | no |
| Fake SAP NetWeaver Visual Composer MetadataUploader | NetWeaver Visual Composer servlet at `/developmentserver/metadatauploader` (plus `/irj/`, `/nwa/`, `/sap/` webroot prefixes); GET returns the SAP-formatted XML error envelope, POST parses the multipart body, logs filename / content-type / `sapMetadataUploaderHasJspShell` / `sapMetadataUploaderHasXxe`, and returns the plaintext "OK: stored …" receipt with the uploaded filename echoed back (CVE-2025-31324 unauth file-upload + CVE-2017-9844 XXE bait) — [docs](./docs/fake-sap-metadatauploader.md) | no |
| Fake Drupal `/user/register` + settings.php | Drupalgeddon2 trigger surface at `/user/register` (also `/?q=user/register`, `/drupal/`, `/cms/` prefixes); GET returns a Drupal 8/9 user-registration form with per-request `form_build_id` / `form_token`, POST captures the `mail[#post_render]` / `element_parents` chain and flags `drupalHasDrupalgeddon2` / `drupalHasRcePayload` for triage. Twin canary at `/sites/default/settings.php` (+ `.bak` / `.swp` / `~` / `%00` / `%20` / `default.settings.php` / `/sites/all/` / `/drupal/` / `/cms/` variants) ships a fully shaped Drupal config with per-hit synthetic DB password + Tracebit AWS canary in the `s3fs.settings` block (CVE-2018-7600 bait) — [docs](./docs/fake-drupal.md) | yes (settings.php only) |
| Fake Spring Cloud Gateway Actuator extension | `/actuator/gateway/routes`, `/actuator/gateway/routes/{id}`, `/actuator/gateway/refresh`, `/actuator/gateway/globalfilters`, `/actuator/gateway/routefilters`, `/actuator/gateway/routepredicates` (plus `/manage/gateway/`, `/management/gateway/`, `/api/actuator/gateway/` reverse-proxy aliases); GET returns a fake route list with the Tracebit AWS canary embedded in `metadata.adminApiKey` + `metadata.adminApiSecret` and inside an `AddRequestHeader` filter named `X-Admin-Api-Key`. POST to a route id captures the SpEL body, flips `springGatewayHasSpel` on `#{T(…)` / `T(java.lang.*)` / `getRuntime` / `ProcessBuilder` indicators, and returns 201 Created. `/refresh` returns 200 (matches real CVE-2022-22947 chain step); `Server: Spring Cloud Gateway/3.1.0` banner pinned inside the public-disclosure window — [docs](./docs/fake-spring-gateway.md) | yes |
| Fake Next.js + SSJS-injection responder | Empty page-data JSON on `/_next/data/<buildId>/*.json` and Next.js-conventional `/api/*` routes; on a `?cmd=<base64>` payload that decodes to a JS-eval shape (`require('child_process').execSync(cmd)`), extracts the inner `var cmd = "echo X"` literal and reflects the simulated output back, falling back to the scanner's own `ERROR` catch-block sentinel for unrecognised commands. Also covers the dev-mode internal endpoints (`/__nextjs_action`, `/__nextjs_launch-editor`, `/__nextjs_error_overlay`, `/__nextjs_original-stack-frame`, `/__nextjs_stack_frame`) with shape-appropriate responses: empty RSC for Server Actions (POST body captured), `{"opened":true}` for the IDE-launch endpoint (with `file=/line=` query args captured), and a per-hit HTML stack frame for the overlay endpoints. URL-encoded leading-slash bypasses (`/%2f__nextjs_action`, `/%252f__nextjs_action%2f`) normalise back to the same dispatch — [docs](./docs/fake-nextjs.md) | no |
| Cmd-injection / printenv responder | `/admin/config?cmd=…` and `/admin/config.php?cmd=…` (admin-shell exploit shape) plus `/printenv`, `/cgi-bin/printenv`, `/cgi-bin/test-cgi`; classifies the cmd value, returns a plausible `cat /etc/passwd` / `id` / `uname` body, and mints a per-request Tracebit AWS canary when the cmd asks for `~/.aws/credentials` or env vars — [docs](./docs/cmd-injection.md) | yes |
| PHP/body-RCE responders | Body-driven exploit responders for PHPUnit `eval-stdin.php`, PHP-CGI `auto_prepend_file=php://input` (CVE-2024-4577), and Apache CGI path-traversal `/bin/sh`; logs request-body payloads and decoded base64 command hints. Bare GET/HEAD against `/cgi-bin/php`, `/cgi-bin/php-cgi`, `/cgi-bin/php{5,7,8}{,-cgi,.cgi}`, `/cgi-bin/`, and `/cgi-bin` returns the canonical `<br />\n<b>No input file specified.</b>` 200 page with `Server: Apache/2.4.41 (Win64) … PHP/7.4.33` + `X-Powered-By: PHP/7.4.33` so the gated CVE-2024-4577 scanner population (the one that liveness-probes before sending the exploit) follows up with the exploit POST, which then lands in the body-RCE handler above — [docs](./docs/cmd-injection.md) | no |
| Web-app form responder | Plausible HTML forms on `/login`, `/signin`, `/signup`, `/register`, `/checkout`, `/cart`, `/contact`, `/subscribe`, `/newsletter`, `/dashboard`, `/profile`, `/settings`, `/admin`, `/auth/*`, `/api/{login,signup,contact,…}`; GET returns the form with a per-request hidden CSRF token, POST returns a `302` back to the form (auth-failure shape) with a per-request `session_id` cookie. Logs extracted username/email, has-password/email flags, the submitted field-name list, and the body preview/sha256 so credential-stuffing payload rotations land in the access log — [docs](./docs/webapp-form.md) | no |
| Framework dev-mode debug surfaces | Symfony Web Profiler phpinfo (`/_profiler/phpinfo`, `/app_dev.php/_profiler/phpinfo`, `/symfony/_profiler/phpinfo`, `/frontend_dev.php/_profiler/phpinfo`) plus profiler dashboard (`/_profiler/latest`, `/_profiler/search`, `/_profiler/` with the same `/app_dev.php/`, `/symfony/`, `/frontend_dev.php/` prefixes) returns a phpinfo-shaped page with `$_ENV` carrying the AWS canary + per-hit `APP_SECRET` / `DATABASE_URL` / `MAILER_DSN`; Symfony `parameters.yml` (`/parameters.yml`, `/config/parameters.yml`, `/app/config/parameters.yml`) and the dev-mode `/_profiler/open` local-file-read endpoint return a YAML body with the canary in `aws_*` keys plus per-hit `database_password` / `mailer_password` / `secret`; Yii2 debug toolbar (`/debug/default/view`, `/web/debug/default/view`, `/frontend/web/debug/default/view`, `/backend/web/debug/default/view`, `/sapi/debug/default/view`, `/debug/default/db-explain`) returns an HTML page mimicking `yii\debug\Module` `ConfigPanel` with `$_ENV` and `components.db.*` / `components.mailer.*` carrying the same canary set; Django debug toolbar (`/__debug__/render_panel/`, `/__debug__/sql_select/`, `/__debug__/sql_explain/`, `/__debug__/sql_profile/`, `/__debug__/template_source/`) returns `SECRET_KEY` + `DATABASE_URL` + AWS canary in a SettingsPanel-shaped page; Laravel `facade/ignition` error page (`/_ignition/execute-solution` plus `/api/_ignition/...` / `/backend/_ignition/...` reverse-proxy aliases, `/_ignition/health-check`, `/_ignition/scripts/ignition.js`, `/_ignition/styles/ignition.css`) returns an Ignition stack-trace HTML page whose "Environment" panel carries `APP_KEY` / `DB_PASSWORD` / `REDIS_PASSWORD` / `MAIL_PASSWORD` (per-hit) + the AWS canary triple; CVE-2021-3129 POST exploit bodies captured via `bodySha256` — [docs](./docs/framework-debug.md) | yes |
| Fake WordPress wp-login.php canary | WordPress 6.x login page on `/wp-login.php` with per-hit `_wpnonce` hidden field + `wordpress_test_cookie`; POST captures `log`/`pwd` and checks whether the submitted nonce matches one previously issued to the same IP (nonce-harvesting vs blind-POST attribution); `/wp-admin/*` paths redirect to the login page. Logs `wpLoginUsername`, `wpLoginNonceMatch`, `wpLoginTestcookiePresent` — [docs](./docs/wp-login-canary.md) | no |
| Fake Vite dev-server env-leak | `/@vite/env` returns a Vite client-module body whose `context.define` flat-key block exposes `VITE_*` env vars — `VITE_AWS_ACCESS_KEY_ID` / `VITE_AWS_SECRET_ACCESS_KEY` / `VITE_AWS_SESSION_TOKEN` / `VITE_API_KEY` carry the per-hit Tracebit AWS canary, so frontend-env scanners that grep raw bytes for `VITE_` / `AKIA` patterns harvest a replay-fireable key. Per-hit-unique `VITE_SENTRY_DSN` public key / `VITE_S3_BUCKET` suffix / `VITE_APP_ID` keep the body from acting as a fleet fingerprint. Companion `/@fs/` arbitrary-file-read entries (under `bash-history` / `zsh-history`) cover the FS-walk pivot scanners chain after the env probe — [docs](./docs/vite-env.md) | yes |

All traps log one JSON line per event to the configured log path. See
[`LOGS.md`](./LOGS.md) for the schema.

## Install

```bash
pip install .
```

Or in place (needs `aiohttp` on the path):

```bash
pip install aiohttp
python -m flux
```

## Run

Flux listens on `127.0.0.1:18081` by default. The expected deployment puts
nginx in front and proxies a set of trap paths (e.g. `/.env`, `/.git/*`,
`/shell.php`, etc.) to it; nginx handles TLS, `X-Forwarded-*` headers, and
all non-trap routing.

```bash
export TRACEBIT_API_KEY=...  # optional — enables canary-backed traps (/.env, /.git/*, etc)
python -m flux
```

Docs: [`CONFIG.md`](./CONFIG.md) (env vars) ·
[`LOGS.md`](./LOGS.md) (JSONL schema + `result` tags) ·
[`BENCH.md`](./BENCH.md) (throughput + tarpit saturation numbers).

## Canary file trap table

### Design principle: every credential is per-hit unique

A trap renderer that ships a **fixed literal** credential (hardcoded
DB password, hardcoded API key) provides no detection value — a
replay triggers nothing — and ships the same string across every
sensor in the fleet, which becomes a cross-sensor fingerprint. Every
secret-shaped field in a rendered response must therefore be per-hit
unique. We back it with Tracebit when that adds detection value
(replay against AWS STS, the Tracebit-hosted gitlab URL, the Tracebit
sshIp); when there's no matching canary type we fall back to a
per-hit random synthetic. Concretely, every secret-shaped field is
either:

1. **A per-request Tracebit canary** — `_aws(r)` or
   `_gitlab_creds(r, ...)`. Fires when replayed against the matching
   target (AWS STS globally, the Tracebit-hosted gitlab URL for u/p
   and cookie, the Tracebit sshIp for ssh).
2. **A per-hit random synthetic** — `_fake_db_password()` or similar.
   Does *not* fire (no Tracebit path exists for the cred type, e.g.
   MySQL/Postgres), but is unique per rendering so the rendered body
   can't be fingerprinted across the fleet.

Hardcoded literals in the "plausible filler" around the canary are
fine when the value isn't credential-shaped — usernames like
`wp_prod`, host names like `db.internal`, bucket names, comments.
What must never be fixed is anything that looks like a password,
token, or key.

When the canary type doesn't exist in Tracebit Community yet (LLM
API keys, Google service accounts), the trap must either (a) dress
an AWS canary in plausible shape so a field-name-keyed harvester
still exfils a live canary value (see the AI-credential traps below)
or (b) emit a per-hit random synthetic so the response isn't
fingerprintable — never a fixed literal.

### Trap table

All gated on `TRACEBIT_API_KEY`, with per-IP TTL caching to protect quota.
Toggle the whole category with `CANARY_TRAPS_ENABLED`. Paths are
case-insensitive exact matches.

| Trap | Paths | Canary type | Log tag |
| --- | --- | --- | --- |
| AWS credentials file (INI) | `/.aws/credentials` | `aws` | `aws-credentials-file` |
| AWS SDK config (INI) | `/.aws/config` | `aws` | `aws-config-file` |
| AWS Console-downloaded `credentials.csv` (IAM-user-creation) — [docs](./docs/aws-credentials-csv.md) | `/credentials.csv`, `/aws-credentials.csv`, `/aws_credentials.csv`, `/new_user_credentials.csv`, `/iam-credentials.csv`, `/iam_credentials.csv`, plus webroot-prefix `/admin/`, `/users/`, `/iam/`, `/app/`, `/backend/`, `/api/`, `/private/`, `/backup/` variants | `aws` | `aws-credentials-csv` |
| AWS Console "Create access key" CSV (two-column) — [docs](./docs/aws-credentials-csv.md) | `/accesskeys.csv`, `/access_keys.csv`, `/access-keys.csv`, `/accesskey.csv`, `/rootkey.csv`, `/root_key.csv`, `/root-key.csv`, `/aws-access-keys.csv`, `/aws_access_keys.csv` | `aws` | `aws-access-keys-csv` |
| AWS Python SDK / `gsutil` boto config | `/.boto`, `/.boto3`, `/root/.boto`, `/home/.boto` | `aws` | `boto-config` |
| AWS Amplify CLI project config | `/.amplifyrc` | `aws` | `amplifyrc` |
| Terraform tfstate (JSON) — [docs](./docs/terraform-tfstate.md) | `/.terraform/terraform.tfstate`, `/terraform.tfstate`, `/terraform.tfstate.backup` | `aws` | `terraform-tfstate` |
| Terraform tfvars (HCL + JSON) — [docs](./docs/terraform-tfvars.md) | `/terraform.tfvars`, `/.terraform/terraform.tfvars`, `/terraform.tfvars.json`, `/.terraform/terraform.tfvars.json` | `aws` | `terraform-tfvars`, `terraform-tfvars-json` |
| GCP service-account JSON (generic webroot aliases) — [docs](./docs/gcp-credentials-json.md) | `/gcp-credentials.json`, `/config/gcp-credentials.json`, `/private/gcp-credentials.json`, `/api/credentials.json`, `/private/credentials.json`, `/backend/credentials.json`, `/app/credentials.json` | `aws` | `gcp-credentials-json` |
| Niche cloud CLI configs — [docs](./docs/niche-cloud-credentials.md) | OCI (`/.oci/config`, `/.oci/oci_api_key.pem`), Hetzner (`/.config/hcloud/cli.toml`), Civo, Exoscale, Scaleway, Fly.io, OVH, OpenStack, Terraform Cloud (`/.terraform.d/credentials.tfrc.json`, `/.terraformrc`), Pulumi, DigitalOcean doctl, Linode, s3cmd, s3fs, Cargo, RubyGems, GitHub CLI, 1Password, Cloudflare Tunnel, WireGuard, Headscale | `aws` | `oci-config`, `hcloud-cli`, `civo-cli`, `exoscale-cli`, `scaleway-cli`, `fly-cli`, `ovh-conf`, `openstack-clouds-yaml`, `terraform-credentials-tfrc`, `terraformrc`, `pulumi-credentials`, `doctl-config`, `linode-cli`, `s3cfg`, `passwd-s3fs`, `cargo-credentials`, `gem-credentials`, `gh-hosts-yml`, `1password-config`, `cloudflared-config`, `wireguard-conf`, `headscale-config` |
| Azure CLI credential / profile cache — [docs](./docs/azure-cli-creds.md) | `/.azure/azureProfile.json`, `/.azure/accessTokens.json`, `/.azure/msal_token_cache.json`, `/.azure/service_principal_entries.json`, `/.azure/config`, `/.azure/clouds.config` | `aws` | `azure-cli-profile`, `azure-cli-access-tokens`, `azure-cli-msal-cache`, `azure-cli-service-principal`, `azure-cli-config`, `azure-cli-clouds-config` |
| Postgres pgpass | `/.pgpass` | `gitlab-username-password` | `pgpass` |
| Apache `.htpasswd` — [docs](./docs/htpasswd-canary.md) | `/.htpasswd` | `gitlab-username-password` | `htpasswd` |
| WordPress config | `/wp-config.php` plus editor-leftover suffix variants (`.bak`, `.save`, `.swp`, `.swo`, `.old`, `.orig`, `.txt`, `~`, `::$DATA`) and short/relocation forms (`/wp-config.bak`, `/wp-config.old`, `/wp-config.txt`, `/wp-config-backup.php`, `/backup/wp-config.php`); also matches the observed double-encoded `.bak` form | `aws` | `wp-config` |
| Drupal settings.php — [docs](./docs/fake-drupal.md) | `/sites/default/settings.php` plus editor-leftover suffix variants (`.bak`, `.save`, `.swp`, `.swo`, `.old`, `.orig`, `.txt`, `~`), short/null-byte/space-truncation forms (`/sites/default/settings.bak/.old/.txt`, `/sites/default/settings.php%00`, `/sites/default/settings.php%20`), the unconfigured-template name (`/sites/default/default.settings.php`), the multisite `/sites/all/settings.php` shape, and webroot-prefix `/drupal/`, `/cms/` variants | `aws` | `drupal-settings-php` |
| SQL dump | `/backup.sql`, `/db.sql`, `/dump.sql`, `/database.sql`, `/backup/db.sql`, `/sql/backup.sql` | `aws` | `sql-dump` |
| Generic JSON config | `/config.json`, `/settings.json`, `/credentials.json`, `/secrets.json` | `aws` | `config-json` |
| SFTP deploy config | `/.vscode/sftp.json`, `/sftp-config.json`, `/sftp.json`, `/.ftpconfig` | `gitlab-username-password` | `sftp-config` |
| Firebase / GCP SA | `/firebase.json`, `/google-services.json`, `/serviceaccount.json`, `/service-account.json`, `/firebase-adminsdk.json`, `/gcp-service-account.json`, `/.config/gcloud/application_default_credentials.json` | `aws` | `firebase-json` |
| Docker client | `/.docker/config.json`, `/docker/config.json`, `/root/.docker/config.json`, `/home/.docker/config.json` | `aws` | `docker-config` |
| Docker Compose | `/docker-compose.yml`, `/docker-compose.yaml`, `/compose.yml`, `/compose.yaml`, plus `.prod`, `.production`, `.dev`, `.staging`, `.override` variants (both `.yml` and `.yaml`) | `aws` | `docker-compose` |
| GitHub Actions workflows | `/.github/workflows/{deploy,main,ci,build,test,docker,release,cd}.yml` plus `.yaml` variants | `aws` | `github-actions-workflow` |
| GitLab CI config | `/.gitlab-ci.yml`, `/.gitlab-ci.yaml`, `/.gitlab/.gitlab-ci.yml` | `aws` | `gitlab-ci` |
| Jenkins Pipeline | `/Jenkinsfile`, `/Jenkinsfile.bak` | `aws` | `jenkinsfile` |
| Bitbucket Pipelines | `/bitbucket-pipelines.yml`, `/bitbucket-pipelines.yaml` | `aws` | `bitbucket-pipelines` |
| Generic CI deploy config | `/appveyor.yml`, `/.circleci/config.yml`, `/azure-pipelines.yml`, `/deployment.yml`, `/deploy.yml`, `/drone.yml`, `/.drone.yml` plus `.yaml` variants where applicable | `aws` | `generic-ci-config` |
| Spring properties | `/application.properties` | `aws` | `application-properties` |
| Spring YAML | `/application.yml`, `/application.yaml` | `aws` | `application-yml` |
| Spring Boot Actuator `/env` | `/actuator/env`, `/actuator/env.json`, `/env`, `/manage/env`, `/management/env`, `/api/actuator/env`, `/app/actuator/env`, `/backend/actuator/env` | `aws` | `actuator-env` |
| Spring Boot Actuator surface — [docs](./docs/actuator-surface.md) | `/actuator/{heapdump,configprops,health,mappings,threaddump,logfile,trace,httptrace}` plus `/manage`, `/management`, `/api/actuator`, `/app/actuator`, `/backend/actuator` reverse-proxy aliases | `aws` | `actuator-heapdump` / `actuator-configprops` / `actuator-health` / `actuator-mappings` / `actuator-threaddump` / `actuator-logfile` / `actuator-trace` |
| Production .env and its sibling rotation/backup/per-env variants | `/.env.{production,prod,live,local,dev,development[.local],test[.local],staging,stage,uat,preprod,qa,ci,save,private,docker,override,example[.local],sample,remote,dist,bak,backup[1\|2],old,orig,swp,~,json,yaml,yml,txt}`, `/.env{1,2,_bak,_old,_orig,_copy,_priv,_example}`, `/.environ`, `/env.{bak,txt,old,save,backup}`, plus the cross-product against ~140 webroot prefixes (`/{wp,wordpress,laravel,symfony,magento,drupal,api,backend,frontend,public,www,html,admin,dashboard,dev,prod,staging,docker,k8s,terraform,jenkins,mysql,postgres,redis,vendor,vite,nuxt,next,…}/.env*`) so off-the-shelf env-harvester dictionary walks land on a canary on first match | `aws` | `env-production` |
| Mail-service `.env` — [docs](./docs/mail-service-env.md) | `/{sendgrid,postmark,mailjet,brevo,mailgun,mailing,mail,mailserver}/.env` — service-specific API key formats (SendGrid `SG.xxx`, Postmark token, Mailjet key pair, Brevo `xkeysib-`, Mailgun `key-`) alongside AWS canary | `aws` | `mail-service-env` |
| dotenv-vault file — [docs](./docs/env-vault.md) | `/.env.vault`, `/.env.vault.bak`, `/.env.vault.example` | `aws` | `env-vault` |
| Vite dev-server env-leak — [docs](./docs/vite-env.md) | `/@vite/env` — ES-module body with `context.define` flat-keys exposing `VITE_*` env vars; AWS canary lives in `VITE_AWS_*` and `VITE_API_KEY` slots | `aws` | `vite-env` |
| Go pprof debug endpoint — [docs](./docs/pprof-dump.md) | `/debug/pprof[/heap\|/cmdline\|/goroutine\|/profile\|/symbol\|/trace\|/threadcreate\|/block\|/mutex\|/allocs]` plus `/api`-prefixed variants | `aws` | `pprof-dump` |
| phpinfo() | `/phpinfo.php`, `/info.php`, `/php.php`, `/test.php` | `aws` | `phpinfo` |
| SSH private key | `/id_rsa`, `/.ssh/id_rsa`, `/ssh/id_rsa`, `/ssh/id_rsa.key`, `/keys/id_rsa`, `/private.key`, `/deploy_key`, `/deploy.key`, `/.ssh/id_ed25519`, `/.ssh/id_dsa`, `/.ssh/id_ecdsa`, `/id_ed25519`, `/id_dsa`, `/id_ecdsa`, `/root/.ssh/id_rsa`, `/home/.ssh/id_rsa` | `ssh` | `ssh-private-key` |
| SSH public key | `/id_rsa.pub`, `/.ssh/id_rsa.pub` | `ssh` | `ssh-public-key` |
| SSH client config | `/.ssh/config` | `ssh` | `ssh-config` |
| known_hosts | `/.ssh/known_hosts`, `/known_hosts` | `ssh` | `known-hosts` |
| authorized_keys | `/authorized_keys`, `/.ssh/authorized_keys`, `/.ssh/authorized_keys2`, `/static/.ssh/authorized_keys`, `/downloads/.ssh/authorized_keys`, `/blog/.ssh/authorized_keys` | `ssh` | `authorized-keys` |
| .netrc | `/.netrc`, `/_netrc` | `gitlab-username-password` | `netrc` |
| git credential store | `/.git-credentials`, `/root/.git-credentials`, `/home/.git-credentials`; fake-git also serves `/.git/credentials` | `gitlab-username-password` | `git-credentials` / `fake-git` |
| .npmrc | `/.npmrc`, `/root/.npmrc`, `/home/.npmrc` | `gitlab-username-password` | `npmrc` |
| Node.js dependency manifests — [docs](./docs/node-deps-canary.md) | `/yarn.lock(.bak\|.old)`, `/package-lock.json(.bak\|.old)`, `/var/backups/npm/package-lock.json.old`, `/package.json`, `/.yarnrc`, `/.yarnrc.yml` | `gitlab-username-password` | `yarn-lock` / `package-lock-json` / `package-json` / `yarnrc` / `yarnrc-yml` |
| .pypirc | `/.pypirc` | `gitlab-username-password` | `pypirc` |
| GitLab API user | `/api/v4/user` | `gitlab-username-password` | `gitlab-api-user` |
| GitLab sign-in | `/users/sign_in` | `gitlab-cookie` | `gitlab-sign-in` |
| Heroku Procfile — [docs](./docs/heroku-config.md) | `/Procfile` | `aws` | `procfile` |
| Heroku container manifest — [docs](./docs/heroku-config.md) | `/heroku.yml`, `/heroku.yaml` | `aws` | `heroku-yml` |
| Heroku app metadata — [docs](./docs/heroku-config.md) | `/app.json` | `aws` | `heroku-app-json` |
| .NET Core appsettings — [docs](./docs/heroku-config.md) | `/appsettings.json` plus `.production.json`, `.development.json`, `.staging.json`, `.local.json` variants | `aws` | `appsettings-json` |
| IIS web.config — [docs](./docs/heroku-config.md) | `/web.config` plus editor-leftover suffix variants (`.bak`, `.old`, `.orig`, `.save`) | `aws` | `iis-web-config` |
| PHP Composer auth.json — [docs](./docs/heroku-config.md) | `/auth.json` | `gitlab-username-password` | `composer-auth-json` |
| Dockerfile source — [docs](./docs/heroku-config.md) | `/Dockerfile` plus environment-suffixed variants (`.prod`, `.production`, `.dev`, `.development`, `.local`, `.staging`, `.worker`, `.build`) and `/Containerfile` | `aws` | `dockerfile` |
| OpenAI config file | `/.openai/config.json` | `aws` (†) | `openai-config` |
| Anthropic config file | `/.anthropic/config.json` | `aws` (†) | `anthropic-config` |
| Cursor MCP config | `/.cursor/mcp.json` | `aws` (†) | `cursor-mcp` |
| Claude Code credentials | `/.claude/.credentials.json` | `aws` (†) | `claude-credentials` |
| Claude Desktop settings | `/.claude/settings.json` | `aws` (†) | `claude-settings` |
| Cline settings | `/.cline/settings.json` | `aws` (†) | `cline-settings` |
| Generic MCP server configs | `/.cline/mcp_settings.json`, `/mcp_settings.json`, `/mcp.json`, `/.mcp/mcp.json` | `aws` (†) | `mcp-config` |
| Continue.dev config | `/.continue/config.json` | `aws` (†) | `continue-config` |
| Sourcegraph Cody config | `/.sourcegraph/cody.json` | `aws` (†) | `cody-config` |
| Aider config | `/.aider.conf.yml` | `aws` (†) | `aider-conf` |
| Open-Interpreter config | `/.config/open-interpreter/config.yaml` | `aws` (†) | `open-interpreter-config` |
| LiteLLM proxy config | `/litellm_config.yaml`, `/litellm/config.yaml`, `/proxy_config.yaml` | `aws` (†) | `litellm-config` |
| LangSmith env | `/langsmith.env` | `aws` (†) | `langsmith-env` |
| HuggingFace token | `/.huggingface/token`, `/.cache/huggingface/token` | `aws` (†) | `huggingface-token` |
| Streamlit secrets | `/.streamlit/secrets.toml` | `aws` (†) | `streamlit-secrets` |
| OpenAI flat config | `/openai.json` | `aws` (†) | `openai-config-flat` |
| Anthropic flat config | `/anthropic.json` | `aws` (†) | `anthropic-config-flat` |
| Generic AI provider config | `/cohere_config.json`, `/tabnine_config.json`, `/.bito/config.json`, `/.codeium/config.json`, `/.roost/config.json`, `/pinecone_config.json`, `/.lobechat/config.json`, `/chatgpt-next-web.json` | `aws` (†) | `ai-provider-config` |
| Baseten model deploy config | `/baseten.yaml` | `aws` (†) | `baseten-config` |
| OpenAI Codex CLI auth | `/.codex/auth.json`, `/root/.codex/auth.json` | `aws` (†) | `codex-auth` |
| Gemini CLI OAuth creds | `/.gemini/oauth_creds.json`, `/root/.gemini/oauth_creds.json` | `aws` (†) | `gemini-oauth-creds` |
| Gemini CLI settings | `/.gemini/settings.json`, `/root/.gemini/settings.json` | `aws` (†) | `gemini-settings` |
| AI-IDE workspace rules | `/.cursorrules`, `/.clinerules`, `/.windsurfrules` | `aws` (†) | `ai-ide-rules` |
| Cursor IDE state DB | `/.cursor/User/globalStorage/state.vscdb` | `aws` (†) | `cursor-state-vscdb` |
| DashScope plain api_key | `/.dashscope/api_key` | `aws` (†) | `dashscope-api-key` |
| Anthropic plain api_key | `/.anthropic/api_key` | `aws` (†) | `anthropic-api-key` |
| DeepSeek config | `/.deepseek/config.json` | `aws` (†) | `deepseek-config` |
| Kimi / Moonshot credentials | `/.kimi/credentials/kimi-code.json`, `/.kimi/kimi-code.json`, `/.moonshot/settings.json` | `aws` (†) | `kimi-credentials` |
| OpenClaw config | `/.openclaw/openclaw.json`, `/root/.openclaw/openclaw.json` | `aws` (†) | `openclaw-config` |
| OpenCode config | `/root/.config/opencode/config.json` | `aws` (†) | `opencode-config` |
| vast.ai credentials | `/root/.config/vastai/credentials.json` | `aws` (†) | `vastai-credentials` |
| Nerve agent config | `/root/.nerve/config.yaml` | `aws` (†) | `nerve-config` |
| Spawn CLI rc | `/root/.spawnrc` | `aws` (†) | `spawnrc` |
| MoltBook credentials | `/root/.config/moltbook/credentials.json` | `aws` (†) | `moltbook-credentials` |
| Claude Code top-level config | `/.claude.json`, `/root/.claude.json`, `/.claude/config.json`, `/.claude/settings.local.json` | `aws` (†) | `claude-config` |
| Claude Code history | `/.claude/history.jsonl` | `aws` (†) | `claude-history` |
| Root-home Claude credentials | `/root/.claude/.credentials.json` | `aws` (†) | `claude-credentials-root` |
| Agent instruction files | `/AGENTS.md`, `/.claude/CLAUDE.md`, `/root/.claude/CLAUDE.md` | `aws` (†) | `agents-md` |

`/users/sign_in` returns the cookie canary as `Set-Cookie:
_gitlab_session=<value>`. `/api/v4/user` embeds the username/password
canary as a plausible GitLab API user response.

The `ssh` canary fires only when the stolen key is replayed against
Tracebit's ``sshIp`` (returned alongside the keypair). That's why
``ssh-config`` and ``known-hosts`` exist — without a target-host hint,
a harvested ``/id_rsa`` points at nothing, so an attacker runs
``ssh -i id_rsa <arbitrary-host>`` and the canary never fires. The
three traps together (``id_rsa`` → ``config`` → ``known_hosts``) give
a scanner walking an exposed ``.ssh/`` the full key + `Host bastion
HostName <sshIp>` mapping, which resolves to an ``ssh bastion`` replay
the canary can catch.

† **The AI-credential-file traps probably don't make sense yet.**
Tracebit Community doesn't expose an OpenAI / Anthropic / LLM canary
type, so these traps dress an `aws` canary in OpenAI / Anthropic /
Cursor / Claude-shaped JSON. A scanner that filters by key-format prefix
(`sk-...`, `sk-ant-...`) will correctly decide the key is fake and
drop it; a scanner that harvests by field name (`api_key`, `auth_token`,
`accessToken`, `GITHUB_PERSONAL_ACCESS_TOKEN`) will still serialize the
value and ship it, and *that* side-channel trips the AWS canary if it's
ever used as AWS credentials. Shipped anyway because the probe itself
is what we want to log. Swap the renderers to real LLM canaries when
Tracebit ships them.

The four canary types (`aws`, `ssh`, `gitlab-username-password`,
`gitlab-cookie`) are everything Tracebit Community currently exposes via
[`/openapi.json`](https://community.tracebit.com/openapi.json). Email
and LLM canaries are hinted at in Tracebit marketing but not yet in the
API; new trap surfaces for those will land when the API does.

## Tests

```bash
pip install -e '.[dev]'
python -m pytest
```

Two test files:

- `tests/test_server.py` — pure-function tests (renderers, path matchers,
  parsers) + dispatch tests via aiohttp's in-process `TestClient`.
- `tests/test_integration.py` — binds flux to a random port on 127.0.0.1
  and hits it with a real HTTP client over the kernel loopback. Catches
  anything that only breaks on a real socket.

## Per-trap docs

Response shape, parsed fields, and rationale for the novel traps live
under [`docs/`](./docs/):

- [Fake LLM-API endpoint](./docs/fake-llm-api.md)
- [Fake GraphQL endpoint](./docs/fake-graphql.md)
- [Fake SonicWall SSL VPN endpoint](./docs/fake-sonicwall.md)
- [Fake Cisco WebVPN endpoint](./docs/fake-cisco-webvpn.md)
- [Fake Ivanti Connect Secure / Pulse Secure VPN endpoint](./docs/fake-ivanti-vpn.md)
- [Fake FortiGate SSL VPN endpoint](./docs/fake-fortigate-vpn.md)
- [Fake Palo Alto GlobalProtect gateway](./docs/fake-globalprotect.md)
- [Fake Sophos XG SSL VPN](./docs/fake-sophos-vpn.md)
- [Fake Barracuda SSL VPN](./docs/fake-barracuda-vpn.md)
- [Fake F5 BIG-IP APM / TMUI](./docs/fake-f5-bigip.md)
- [Fake Citrix NetScaler / Gateway portal](./docs/fake-citrix-gateway.md)
- [Fake Microsoft RDWeb (RD Web Access) trap](./docs/fake-rdweb.md)
- [Fake Microsoft Exchange (OWA / ECP / autodiscover / PSRemoting) trap](./docs/fake-exchange.md)
- [Fake IBM Aspera Faspex trap](./docs/fake-aspera-faspex.md)
- [Fake Hikvision IP camera trap](./docs/fake-hikvision.md)
- [Fake ONVIF device_service trap](./docs/fake-onvif.md)
- [Fake D-Link / Linksys HNAP1 router trap](./docs/fake-hnap1.md)
- [Fake GeoServer admin / OGC](./docs/fake-geoserver.md)
- [Fake Liferay Portal JSON Web Services](./docs/fake-liferay-jsonws.md)
- [Fake Gravity SMTP plugin (WordPress REST)](./docs/fake-gravity-smtp.md)
- [Fake Laravel Telescope debug panel](./docs/fake-laravel-telescope.md)
- [Fake ColdFusion admin / component browser](./docs/fake-coldfusion.md)
- [Fake Atlassian Confluence + Apache Struts OGNL](./docs/fake-confluence.md)
- [Fake OIDC / OAuth discovery endpoint](./docs/fake-oidc-discovery.md)
- [Fake phpMyAdmin login page](./docs/fake-phpmyadmin.md)
- [Fake Drupal `/user/register` + settings.php](./docs/fake-drupal.md)
- [Fake Spring Cloud Gateway Actuator extension](./docs/fake-spring-gateway.md)
- [Cmd-injection / printenv responder](./docs/cmd-injection.md)
- [CI/CD config canaries](./docs/ci-cd-config.md)
- [Node.js dependency-manifest canary set](./docs/node-deps-canary.md)
- [Fake webshell](./docs/fake-webshell.md)

The other traps (`.env`, `/.git/`, canary file traps, tarpit +
fingerprinting) are documented in [`CONFIG.md`](./CONFIG.md) and the
canary table above.

## License

MIT. See [LICENSE](./LICENSE).
