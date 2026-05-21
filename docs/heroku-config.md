# Heroku / .NET / IIS / Composer / Dockerfile canary traps

Canary file-trap entries for the deploy-config files scanners
enumerate alongside `.env` and `wp-config.php` but for stacks
outside the LAMP/WP centric set the existing canaries cover.

| Trap | Paths | Canary type | Log tag |
|---|---|---|---|
| Heroku Procfile | `/Procfile` | `aws` | `procfile` |
| Heroku container manifest | `/heroku.yml`, `/heroku.yaml` | `aws` | `heroku-yml` |
| Heroku app metadata | `/app.json` | `aws` | `heroku-app-json` |
| .NET Core appsettings | `/appsettings.json` + `.production.json`, `.development.json`, `.staging.json`, `.local.json` | `aws` | `appsettings-json` |
| IIS web.config | `/web.config` + `.bak`, `.old`, `.orig`, `.save` siblings | `aws` | `iis-web-config` |
| PHP Composer auth.json | `/auth.json` | `gitlab-username-password` | `composer-auth-json` |
| Dockerfile source | `/Dockerfile` + `.prod`, `.production`, `.dev`, `.development`, `.local`, `.staging`, `.worker`, `.build`; also `/Containerfile` | `aws` | `dockerfile` |

All paths are case-insensitive exact matches (CanaryTrap shape). Each
renderer embeds the canary in the slot a real misconfiguration would
leak it from:

- **Procfile / heroku.yml / app.json** — the AWS canary triple lives
  in the leading-comment config-vars block (`Procfile`), the
  `setup.config` + `build.config` YAML maps (`heroku.yml`), and the
  `env.<NAME>.value` slot (`app.json`). Real Heroku deployments stash
  AWS creds in all three locations when the team forgets the
  Heroku-managed config-vars UI.
- **appsettings.json** — flat `AWS` block at the root holds
  `AccessKey` / `SecretKey` / `SessionToken`; the `ConnectionStrings`
  block carries a per-hit-unique SQL Server password and a per-hit
  Azure Blob Storage account key.
- **web.config** — `appSettings` block holds the AWS canary triple
  under `add key="AWS_..."` XML elements; `connectionStrings` and
  `machineKey` are per-hit-unique.
- **auth.json** — every `http-basic`, `github-oauth`, `gitlab-token`,
  and `bearer` slot carries the same Tracebit
  `gitlab-username-password` canary credential pair.
- **Dockerfile** — `ARG AWS_ACCESS_KEY_ID=...` + `ARG
  AWS_SECRET_ACCESS_KEY=...` defaults plus `ENV` assignments. Real
  Dockerfile leaks plant secrets in exactly these two shapes.

## Why

These paths land in our access logs at steady high-IP-fanout
cadence, all currently 404. Adding the canary entries closes the
attribution gap for actor populations whose dictionaries cover .NET
shops (`appsettings.json`, `web.config`) and PaaS/container shops
(`Procfile`, `heroku.yml`, `app.json`, `Dockerfile`) which is most
of the modern web that isn't WordPress.

Per-hit-unique DB password / Azure key / machine key keep each
rendered body unique so the response can't be cross-sensor
fingerprinted. The credential-shaped slots are either Tracebit-backed
canaries (AWS for most, gitlab-username-password for Composer
auth.json) or per-hit random synthetic.
