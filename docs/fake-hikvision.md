# Fake Hikvision IP-camera trap

Flux ships a lightweight Hikvision deception surface aimed at the long
tail of unauthenticated IP-camera scanners — particularly chains that
fingerprint a Hikvision device before shipping a CVE-2021-36260
command-injection payload at `/SDK/webLanguage`.

## Routed paths

| Path | Methods | Response |
| --- | --- | --- |
| `/SDK/webLanguage` | `GET`, `HEAD`, `POST` | XML `<Language>` body, `Server: App-webs/` header |
| `/ISAPI/System/deviceInfo` | `GET`, `HEAD` | XML `<DeviceInfo>` with model + firmware version |
| `/ISAPI/Security/userCheck` | `GET`, `HEAD` | XML `<userCheck>` returning activated, non-default-password |

Path matching is case-insensitive on both the `/SDK/...` and `/ISAPI/...`
segments — real-world probe traffic mixes capitalisation.

## Logged fields

Standard request metadata is logged for every event plus:

- `result` (`hikvision-sdk-weblanguage`, `hikvision-isapi-deviceinfo`, `hikvision-isapi-usercheck`)
- `hikvisionPath`
- `hikvisionMethod`
- `hikvisionHasCmdInjection` — `true` when the body or query string
  contains shell-meta indicators (`$(`, backtick, `&&`, `||`, `;`,
  `wget`, `curl`, `/bin/sh`, raw `<language>` body, …); flips on
  CVE-2021-36260 PUT/POST bodies that ship the command in the
  language XML element.
- `bodyPreview` for requests with payload bodies

## Tuning

- `HONEYPOT_HIKVISION_ENABLED` (default: enabled)
- `HONEYPOT_HIKVISION_PATHS_CSV` to override matched path set
- `HONEYPOT_HIKVISION_FIRMWARE_VERSION` to change the firmware banner
  in `deviceInfo` (default: a release in the public-disclosure window
  for CVE-2021-36260, so scanners gating exploit delivery on a
  vulnerable banner don't bail)

## Why this trap exists

A long-running family of IP-camera scanners persistently fetches only
`/SDK/webLanguage` to identify Hikvision firmware before deciding
whether to ship the exploit body. Without a 200 response these
scanners walk away after the banner-grab; with a plausible XML
response and the `App-webs/` server header they stay long enough to
ship the follow-on body, which is where the actual intel lives.

The two ISAPI paths cover the wider banner-grab repertoire that
multi-step scanners use to confirm device type + firmware version
before committing to a payload.
