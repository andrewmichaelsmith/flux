# Fake ONVIF device_service trap

Flux ships a lightweight ONVIF deception surface aimed at IP-camera /
NVR / DVR scanners that fingerprint a device via the SOAP
`GetDeviceInformation` action before deciding whether to ship a
follow-on CVE payload (CVE-2024-7029 Dahua auth-bypass command
injection, CVE-2023-43261 exposed RTSP cred leak, CVE-2021-33044 Dahua
identity-auth bypass).

## Routed paths

| Path | Methods | Response |
| --- | --- | --- |
| `/onvif/device_service` | any | SOAP `<GetDeviceInformationResponse>` |
| `/onvif/services` | any | same SOAP body |
| `/onvif/device` | any | same SOAP body |
| `/device_service` | any | same SOAP body (stripped-prefix variant) |

Path matching is case-insensitive — real-world probe traffic mixes
capitalisation (`/onvif/Device_Service`, `/ONVIF/Device`).

## Logged fields

Standard request metadata plus:

- `result = "onvif-device-service"`
- `onvifPath`
- `onvifMethod`
- `onvifSoapActionHeader` — value of the `SOAPAction` request header
  (where set)
- `onvifSoapActionBody` — recognised action name extracted from the
  body element (`GetDeviceInformation`, `GetSystemDateAndTime`,
  `GetCapabilities`, `GetServices`, `GetUsers`, `GetHostname`,
  `GetNetworkInterfaces`, `GetWsdlUrl`, `FirmwareUpgrade`,
  `SystemReboot`); empty string if unrecognised
- `onvifHasCmdInjection` — `true` when the body carries shell-meta
  (`$(`, backtick, `&&`, `||`, `;`, `|`, `wget`, `curl`, `/bin/sh`,
  …) or the `FirmwareUpgrade` / `UpgradeUrl` element name (CVE-2024-7029
  sink)
- `bodyPreview` for requests with payload bodies

## Tuning

- `HONEYPOT_ONVIF_ENABLED` (default: enabled)
- `HONEYPOT_ONVIF_PATHS_CSV` to override matched path set
- `HONEYPOT_ONVIF_MANUFACTURER` (default `Dahua`)
- `HONEYPOT_ONVIF_MODEL` (default `DH-IPC-HFW1230S`)
- `HONEYPOT_ONVIF_FIRMWARE_VERSION` — firmware string in the SOAP
  response; default sits in the public-disclosure window for the
  Dahua-class CVEs above, so scanners gating exploit delivery on a
  vulnerable banner don't bail
- `HONEYPOT_ONVIF_HARDWARE_ID` / `HONEYPOT_ONVIF_SERIAL` to swap
  the hardware-id / serial filler

## No credentials emitted

`GetDeviceInformation` does not carry credential-shaped values — only
manufacturer, model, firmware version, hardware ID and serial. The
fixed fingerprint strings are plausible non-credential filler per the
design principle. `GetUsers` would emit credential-shaped values; it
is not part of the default off-the-shelf banner-grab probe and is not
handled separately. If scanner behaviour shifts to walking `GetUsers`,
add a per-hit canary username/password to the response then.

## Why this trap exists

Recurring ONVIF banner-grab traffic on `/onvif/device_service` from a
broad cross-organisation fleet was 100% 404'd before this trap shipped
— roughly two-dozen distinct source IPs / day reaching only the
fingerprinting endpoint, walking away on the 404, and never returning
with a payload. A plausible Dahua-class GetDeviceInformation response
gives multi-step scanners somewhere to ship the actual CVE-2024-7029
`FirmwareUpgrade` body, which is where the intel lives, and converts
single-path banner-grab fleets into recurring repeat visitors that
populate the actor graph instead of vanishing.
