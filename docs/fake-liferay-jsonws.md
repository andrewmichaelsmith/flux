# Fake Liferay Portal JSON Web Services trap

Simulates the Liferay Portal `/api/jsonws` discovery surface — landing
HTML, per-service signature JSON, and the `/api/jsonws/invoke`
JSON-RPC sink — to absorb both banner-grab fingerprinting and the
marshaller-RCE payload that targets CVE-2020-7961.

| Path | Methods | Response |
| --- | --- | --- |
| `/api/jsonws`, `/api/jsonws/` | `GET`, `HEAD` | `200` HTML index page listing fake registered services |
| `/api/jsonws?serviceClassName=<class>` | `GET`, `HEAD` | `200` JSON method-signature catalog |
| `/api/jsonws/invoke` | `POST`, `GET`, `HEAD` | `500` Liferay-formatted JSON error envelope; body captured for triage |
| `/api/jsonws/<anything else>` | any | `404` Liferay-formatted JSON `Path not mapped` envelope |

The handler mints a per-request Tracebit AWS canary and embeds the
key + secret in:

- the landing HTML, inside the `DLAppService` row description (the slot
  where Liferay operators sometimes paste S3-backed Document Library
  credentials from `portal-ext.properties`)
- the per-service signature JSON, inside the `getConfiguredS3Bucket`
  method's `default` return slot (`accessKey` / `secretKey`)

These are the slots credential-scrapers grep for `AKIA…` / `aws_secret`
pairs after walking the discovery page; harvesting them yields a
replay-fireable key.

The handler logs:

- `result` tags (`liferay-jsonws-landing`,
  `liferay-jsonws-service-signature`, `liferay-jsonws-invoke`,
  `liferay-jsonws-miss`)
- `liferayPath` (exact request path)
- `liferayMethod` (HTTP verb)
- `liferayServiceClassName` (parsed from `?serviceClassName=…`, if set)
- `liferayHasMarshallerPayload` (bool — body contains any of
  `WrapperConnectionPoolDataSource`, `userOverridesAsString`,
  `com.mchange.v2.c3p0`, `javax.naming`, `JndiLookup`, `ldap://`,
  `rmi://`, `Runtime.getRuntime`, `ProcessBuilder`, `jodd.bean`)
- `liferayPayloadPreview` (only present when `liferayHasMarshallerPayload`
  is true; up to 400 chars of the request body)
- `canaryTypes` and `bytes`

Reported version is pinned via the `HONEYPOT_LIFERAY_VERSION` env var
(default `7.2.0 GA1`) and build number via
`HONEYPOT_LIFERAY_BUILD_NUMBER` (default `7200`) so version-gated
scanners ship the marshaller exploit instead of bailing on a patched
banner. Response headers carry
`Server: Apache-Coyote/1.1` and `Liferay-Portal: Liferay Community
Edition <version> (Build <build>)` to match a real install's
fingerprint shape.

## Why

`/api/jsonws` is the auto-generated JSON Web Services discovery surface
on Liferay Portal 6.x / 7.x. Two scanner shapes consistently probe it:

1. **Backup / config / discovery dictionary** scanners walk
   `/api/jsonws` alongside `/.env`, `/php-info.php`, `/backup.zip`, and
   the rest of the secret-file dictionary to look for any developer or
   admin endpoint that leaks credentials in plaintext. The landing page
   row description is the harvest slot.
2. **CVE-2020-7961 marshaller-RCE** tools POST a JSON-RPC payload to
   `/api/jsonws/invoke` whose entries declare `{className, args}`; on a
   vulnerable build the JODD marshaller instantiates arbitrary classes.
   The canonical sink is
   `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` with a
   `userOverridesAsString` JNDI lookup that points at an
   attacker-controlled LDAP/RMI server, which then loads a remote
   class.

Returning a plausible HTML / JSON / JSON-error response on each shape
keeps the probe alive past the fingerprint stage so the marshaller
payload body is captured. The `liferayHasMarshallerPayload` flag exists
so analysis can sort CVE-2020-7961 follow-on probes from generic
discovery walks without parsing every body.
