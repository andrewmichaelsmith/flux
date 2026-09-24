# Rails service initializers + `airflow.cfg`

A Rails app keeps one initializer per third-party integration, and that
integration's API key is the reason the file exists. So a dictionary walking
`config/initializers/` is not asking *is this Rails* — it already knows, it
asked for `config/secrets.yml` two requests ago — it is asking **which
vendor's key this app holds**, one filename per vendor.

That is why every initializer answers under its own log tag instead of one
family tag. Which services a sweep asks for, and which one it takes before
it stops, is only countable if the log separates them.

| Path | Method | Response | Log tag |
| --- | --- | --- | --- |
| `/config/initializers/stripe.rb` | GET/HEAD | `Rails.configuration.stripe` block: `pk_live_…`, `sk_live_…`, `whsec_…` | `rails-initializer-stripe` |
| `/config/initializers/sendgrid.rb` | GET/HEAD | ActionMailer SMTP block, `user_name: 'apikey'` + `SG.<id>.<secret>` | `rails-initializer-sendgrid` |
| `/config/initializers/twilio.rb` | GET/HEAD | `Twilio.configure` — `AC…` account SID + 32-hex auth token | `rails-initializer-twilio` |
| `/config/initializers/aws.rb` | GET/HEAD | `Aws.config.update` with an **AWS canary** | `rails-initializer-aws` |
| `/config/initializers/carrierwave.rb` | GET/HEAD | `fog_credentials` with an **AWS canary** | `rails-initializer-carrierwave` |
| `/config/initializers/devise.rb` | GET/HEAD | `Devise.setup` — 128-hex `secret_key` + `pepper` | `rails-initializer-devise` |
| `/config/initializers/omniauth.rb` | GET/HEAD | `OmniAuth::Builder` — Google (`GOCSPX-…`) and GitHub (`Iv1.…`) client secrets | `rails-initializer-omniauth` |
| `/config/initializers/smtp_settings.rb` | GET/HEAD | Generic ActionMailer SMTP — SES-relay user/password pair | `rails-initializer-smtp` |
| `/config/initializers/secret_token.rb` | GET/HEAD | Rails 3 / early-4 `secret_token` + `secret_key_base`, 128-hex each | `rails-initializer-secret-token` |
| `/airflow.cfg`, `/airflow/airflow.cfg`, `/opt/airflow/airflow.cfg`, `/config/airflow.cfg` | GET/HEAD | Full Airflow config — DB URI with inline password, Fernet key, webserver `secret_key`, **AWS canary** in the remote-logging block | `airflow-cfg` |

Every path also answers its editor/backup spellings (`.bak`, `.old`,
`.save`, `~`) and the shared `_app_layout_variants` webroot-prefix matrix —
the same sweep asks for those in the same pass, and a webroot that serves
the file but insists it has no `.bak` is describing a filesystem that does
not exist.

## Credentials

Two legs carry a live canary: `aws.rb` and `carrierwave.rb`. Those are the
two initializers where a real Rails app genuinely holds AWS keys — the SDK
client and the fog/S3 upload storage — so a replay against STS is
attributable back to the request that issued it. `airflow.cfg` is the third,
for the same reason: real Airflow deployments put S3 credentials in the
remote-logging block.

The rest have no matching Tracebit type, so they mint per-hit synthetics in
the vendor's own key format. The format matters because a harvester greps
for the prefix — a credential that doesn't look like `sk_live_` or `SG.` is
not collected at all. The per-hit part matters because a fixed literal
detects nothing on replay and ships one string across every sensor, which
turns the fleet into a single fingerprint.

`airflow.cfg` is in the dictionary for three separate primitives in one
file: `sql_alchemy_conn` is a full DB URI with the password inline,
`fernet_key` decrypts every Connection secret stored in that database, and
the webserver `secret_key` signs the Flask session — forging one lands an
authenticated Airflow UI, where a DAG is arbitrary code execution.

## Why

The families that dominate the unanswered queue by distinct source IP are
internet-wide research scanners and commercial crawlers, which have enormous
IP counts and take nothing. An actor running a config dictionary has a small
IP count and takes everything. Ranking candidate traps by distinct sources
therefore selects against the population the traps exist for.

This trap was picked the other way: from the observed dictionary of a
credential-harvesting sweep, against the part of it that was landing in the
catch-all 404. Each leaf appeared on every day of the retained window, and
the directory was answered nowhere — Flux served the Rails *secrets* family
(`secrets.yml`, `master.key`, `credentials.yml.enc`) while 404ing the
directory next to it that holds the third-party keys.

## Correction: what the Java build-layout routing actually fixed

The commit that introduced `_JAVA_BUILD_LAYOUT_PREFIXES` described the
webroot spelling of `application.properties` as the only one answered. That
is not accurate, and the correction is worth keeping because it changes what
the change is for.

Probed against a live instance before the change:

| path | before |
| --- | --- |
| `/src/main/resources/application.properties` | **200** — resolved incidentally by the generic app-layout walk |
| `/target/classes/application.properties` | **200** — same |
| `/WEB-INF/classes/application.properties` | 404 |
| `/BOOT-INF/classes/application.properties` | 404 |
| `/database.properties`, `/spring.properties`, `/src/main/resources/{database,secrets,aws,smtp,cloud}.properties` | 404 |

So two of the five prefixes already worked, and they worked by accident: the
app-layout walk strips a leading segment and re-resolves, which covers the
source-tree layouts and misses the two deployed-artifact layouts. The real
unanswered surface was the **topic-named siblings** — the files a JVM
project splits its config across — at every spelling including the webroot.

Stating the prefixes explicitly is still the right shape: it makes coverage
a property of the family rather than a side effect of how many path segments
a spelling happens to have, and it closes `WEB-INF` / `BOOT-INF`.
