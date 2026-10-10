# Apache `.htaccess`

Serves a plausible per-directory Apache config carrying a per-request
canary.

| Path | Method | Response |
| --- | --- | --- |
| `/.htaccess` | GET | `200`, `text/plain`, Apache directives |
| `/.htaccess.{bak,old,save,orig,swp,tmp,txt,temp,backup,copy}`, `/.htaccess~` | GET | same body |
| `<webroot-prefix>/.htaccess` | GET | same body |

The leftover siblings and the webroot-prefix matrix come from the
`_APP_CONFIG_SUFFIX_FAMILY` rule rather than a hand-written list, so the
set cannot drift out of step with the rest of the config family.

## What it serves

Rewrite rules, an `Options` line, a Basic-auth block, and a `FilesMatch`
stanza denying `.env` / `.git` — the furniture that makes the file read as
a real one. The credentials sit where Apache documents them: a `mod_env`
block of `SetEnv` directives holding a per-request Tracebit AWS canary
(`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`) and
a per-hit random `DB_PASSWORD`. Nothing credential-shaped is fixed.

The `AuthUserFile` line names `/var/www/.htpasswd` — the sibling the
`htpasswd` trap already answers — so the file suggests its own next
request.

Log tag: `htaccess`. Canary type: `aws`.

## Why

`SetEnv` is the documented way to hand an application a credential
without a `.env` file, so this is a credential file in practice however
it is classified — and a harvester grepping it for key material is not
being unreasonable. Its sibling `.htpasswd` already answered while this
one 404ed, and the secrets-dredge dictionaries that walk `.env` and
`wp-config.php` ask for both in the same pass. Sustained demand across
months from a wide source population, not a one-off spelling: answering
one member of a pair and 404ing the other splits a single sweep across
two outcomes for no reason the caller could see.
