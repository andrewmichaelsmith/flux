# Fake Cisco WebVPN endpoint trap

Simulates a Cisco SSL VPN login surface so reconnaissance flows continue past the
initial fingerprint request and reveal follow-on asset fetches.

| Path | Methods | Response |
| --- | --- | --- |
| `/` with AnyConnect `config-auth` XML body | `POST` | AnyConnect-style XML auth challenge pointing at `/+CSCOE+/logon.html` |
| `/+CSCOE+/logon.html` | `GET`, `HEAD`, `POST` | HTML login page with script include for `logon_forms.js`; POST logs submitted username and password presence |
| `/+CSCOE+/portal.html` | `GET`, `HEAD` | Same HTML login scaffold as `logon.html` |
| `/+CSCOE+/logon_forms.js` | `GET`, `HEAD` | JavaScript stub exporting `window.webvpn` helpers |
| `/+CSCOL+/Java.jar` | `GET`, `HEAD` | JAR-like payload stub (`PK\x03\x04...`) |
| `/+CSCOL+/a1.jar` | `GET`, `HEAD` | JAR-like payload stub (`PK\x03\x04...`) |

All matched paths return `200` with `Cache-Control: no-store`.

The handler logs:

- `result` tags (`cisco-anyconnect-config-auth`, `cisco-webvpn-logon`,
  `cisco-webvpn-logon-forms-js`,
  `cisco-webvpn-java-jar`, `cisco-webvpn-a1-jar`)
- `ciscoWebvpnPath` (exact request path)
- `ciscoWebvpnMethod` (HTTP verb)
- `ciscoWebvpnUsername` and `ciscoWebvpnHasPassword` for login POSTs
- `ciscoAnyconnectVersion` for AnyConnect XML POSTs when present
- `bytes` (response payload length)

## Why

Fleet traffic included repeated multi-step probing of Cisco WebVPN URL families
(`+CSCOE+` and `+CSCOL+`) where clients request a login page and then
platform assets. The body-enabled access index also showed AnyConnect clients
POSTing `config-auth` XML to `/` with VPN client versions and device metadata.
Returning plausible responses lets the probe continue so we can distinguish
one-off liveness checks from full workflow emulation.
