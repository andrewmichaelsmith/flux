# Fake Cisco IOS XE WebUI + WSMA agent

Imitates the IOS XE web management UI and the Web Services Management Agent
behind it — the two halves of the CVE-2023-20198 / CVE-2023-20273 chain.

| Path | Method | Response |
|---|---|---|
| `/webui`, `/webui/`, `/webui/index.html` | GET | IOS XE WebUI login shell (HTML) |
| `/webui/logoutconfirm.html` | GET | logout confirmation page |
| `/webui/gui_states/index.json` | GET | UI state document; reports `netconf` / `restconf` / `wsma` present |
| `/webui/application/get_saml_request` | GET | `{"error":"sso-not-configured"}` — what a box without SSO answers |
| `/webui/login` | POST | `401` auth-failure JSON; submitted username logged |
| `/webui_wsma_Http`, `/webui_wsma_https` | POST | WSMA `exec` success envelope, correlator echoed |
| `/webui_wsma_*` | GET | `405` with `Allow: POST`, as the POST-only agent returns |

Matching is **exact**, case-insensitive, with at most one trailing slash
removed. It is deliberately not a `/webui/` prefix test: `/webui/.env`,
`/open-webui/.env` and the `stable-diffusion-webui` / `text-generation-webui`
spellings are a different population — frontend credential dredging — already
answered by the env-canary and tarpit modules. A prefix match here would
capture that traffic and retag it as appliance exploitation.

The WSMA handler parses the `<exec>` command text out of the request
envelope, tolerating the element spellings exploit tooling actually uses
(`exec`, `execCmd`, `cmd`), optional namespace prefixes, and CDATA or bare
text. It logs `ciscoIosxeWsmaCommands`, the command count, the body sha256
and a bounded preview, and flags `ciscoIosxeWsmaHasAccountCreation` and
`ciscoIosxeWsmaHasImplantIndicator` so the escalation step and the
persistence step separate in triage. The request's `correlator` is echoed
back, because a WSMA client matches the response to its request on that
value and a mismatched one can end the exchange before the next `exec`.

Result tags: `cisco-iosxe-webui-probe`, `cisco-iosxe-webui-state`,
`cisco-iosxe-webui-logout`, `cisco-iosxe-webui-login`,
`cisco-iosxe-wsma-exec`, `cisco-iosxe-wsma-probe`,
`cisco-iosxe-wsma-method-not-allowed`.

## Why

The WebUI login page is one of the most consistently requested unserved
paths on the public internet, and it is requested by sources running the
broad exposed-appliance dictionary — the SSL VPN, mail and gateway login
vocabulary — rather than by anything web-application shaped. Those walks
also ask for the WebUI's own internals (the state document, the SSO probe,
the logout page), which is what distinguishes a scanner checking for this
product from one replaying a generic path list.

Answering only the login page would stop at the fingerprint. The point of
the trap is the second leg: in the documented chain the operator reaches the
agent and POSTs an `exec` envelope that creates a privileged local account
and then installs a Lua implant. That POST is the only request in the whole
sequence carrying attacker-authored content, so capturing its command text
is what turns a path hit into intelligence about what the operator wants.

The agent deliberately answers without a prior successful login. That is the
vulnerability: an authentication bypass means a real affected box serves the
agent unauthenticated, so gating it behind the login form would make the
trap less realistic than the bug it imitates — and would discard the exec.

No credential-shaped value is emitted anywhere in this trap: no password,
token, key or session cookie. There is nothing here to ship identically
across hosts, and nothing a replay could use to recognise it.
