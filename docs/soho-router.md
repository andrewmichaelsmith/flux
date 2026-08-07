# SOHO router / GPON-ONT web-admin trap

Fake embedded-httpd admin surface for consumer routers, fibre ONTs and
NVR gateways. Sibling of the [HNAP1 trap](./fake-hnap1.md), which covers
the D-Link SOAP dialect of the same scanner dictionary.

## Paths

| Group | Paths | Methods | Response |
|---|---|---|---|
| Login forms | `/boaform/admin/formLogin`, `/boaform/formLogin`, `/boaform/admin/formLogin.cgi`, `/goform/login`, `/login.cgi`, `/cgi-bin/login.cgi`, `/cgi/login.cgi`, `/index/login.cgi`, `/web/cgi-bin/hi3510/login.cgi`, `/login.rsp`, `/cgi-bin/webproc`, `/cgi-bin/adm.cgi` | GET, POST | Login page (no creds) or success-shaped meta-refresh (creds present) |
| BOA / Realtek ONT forms | `/boaform/admin/formPing`, `/boaform/formPing`, `/boaform/admin/formTracert`, `/boaform/admin/formSysCmd`, `/boaform/admin/formWsc`, `/boaform/admin/formDMZ`, `/boaform/admin/formFilter` | any | Diagnostic `<pre>` output |
| Netgear DGN | `/setup.cgi` | any | Diagnostic `<pre>` output |
| TP-Link LuCI | `/cgi-bin/luci/`, `/cgi-bin/luci/;stok=<token>…` (prefix match) | any | Diagnostic `<pre>` output |
| Tenda / ZTE | `/goform/formJsonAjaxReq`, `/goform/setSysAdm`, `/goform/goform_get_cmd_process`, `/goform/set_hidessid_cfg`, `/goform/setmac`, `/goform/formWsc`, `/goform/aspForm`, `/goform/formping`, `/goform/telnet`, `/goform/SetVirtualServerCfg`, `/goform/setUsbUnload`, `/goform/downloadSyslog/syslog.log` | any | Diagnostic `<pre>` output |
| Linksys "TheMoon" | `/tmUnblock.cgi`, `/hndUnblock.cgi` | any | Diagnostic `<pre>` output |
| D-Link CGI | `/soap.cgi` | any | Diagnostic `<pre>` output |

All responses are `200` with `Server: Boa/0.94.14rc21`. Matching is
case-insensitive and exact, except the LuCI prefix rule — TP-Link's path
carries a per-request session token (`;stok=<hex>`), so an exact set
alone would miss every real probe.

Env vars: `HONEYPOT_SOHO_ROUTER_ENABLED` (default on),
`HONEYPOT_SOHO_ROUTER_PATHS_CSV`, `HONEYPOT_SOHO_ROUTER_VENDOR`,
`HONEYPOT_SOHO_ROUTER_MODEL`, `HONEYPOT_SOHO_ROUTER_FIRMWARE`.

## What the handler parses and logs

Result tags: `soho-router-login`, `soho-router-credential`,
`soho-router-diag`.

The query string and urlencoded body are decoded with `unquote_plus`
(`+` is the space encoding in both) and then scanned for:

- **Credentials** — across the dialects in use: `username`/`psd` is the
  BOA/ONT spelling, plus `user`/`pwd`, `luci_username`/`luci_password`
  and the other embedded-httpd variants. Logged as
  `sohoRouterUsername` / `sohoRouterPassword` / `sohoRouterCredSource`
  (`query` or `body`). Body wins when both carry a pair.
- **Command injection** — shell metacharacters and fetch-tool names, as
  `sohoRouterHasCmdInjection`.
- **Stage-2 payload URLs** — `sohoRouterPayloadUrls`, via
  `_extract_payload_urls`. Both the schemed form
  (`wget http://host/bin`) and the scheme-less
  `tftp -g -r <file> <host>` form are recognised, the latter normalised
  to `tftp://host/file` so consumers see one shape.
- **Downloaders** — `sohoRouterDownloaders`, which fetch tool the command
  reached for (`wget`, `curl`, `tftp`, `busybox`, `ftpget`, `nc`).

Nothing fixed: the only credential-shaped field the trap emits is the
post-login `SESSIONID` cookie, which is a fresh `secrets.token_hex(16)`
per hit. The login page itself carries no secret-shaped literal.

## Why

The router/ONT admin dictionary is not a fingerprint sweep — the probe
*is* the exploit, and the exploit names its own stage-2 host. A 404 on
these paths therefore discards the most useful field in the request.

Two behaviours the trap is built to separate:

1. **Default-credential login.** Workers walk a small per-device-family
   credential list. Capturing the pairs distinguishes an ONT dictionary
   from a DVR or IP-camera one, which is a cheap actor-family split.
2. **Command injection carrying a dropper URL.** The Netgear
   `todo=syscmd` hole and the CVE-2020-8958 `formPing` `target_addr`
   hole both concatenate an operand into a shell command. Existing traps
   set only a boolean cmd-injection flag, so the URL survived just inside
   a truncated body preview; `_extract_payload_urls` lifts it into a
   structured field.

Answering `200` with a success-shaped login result is deliberate. The
interesting request is usually the *second* one — a worker that gets a
404 on login never sends the exploit that follows it.

Success signal: payload/C2 URL capture and credential-dictionary
capture, not canary issuance. The trap needs no Tracebit key and burns
no canary quota.
