# Fake Next.js + SSJS-injection probe responder

Catches server-side-JavaScript (SSJS) injection probes against
Next.js-conventional routes. Decodes the base64 `cmd=` payload, logs
the probe shape, and reflects a simulated `echo` result back when the
inner literal is a safe `echo <token>` — designed to invite a
follow-up exploitation request that we capture in the next event.

| Path | Methods | Response |
| --- | --- | --- |
| `/api/endpoint`, `/api/test`, `/api/[[...slug]]`, `/api/v2/about` | any | Empty Next.js JSON `{}`; `nextjs-api` (or `nextjs-ssjs-probe` when `cmd=` decodes to a JS-eval shape) |
| `/_next/data/<buildId>/*.json` | any | Plausible page-data JSON `{ "pageProps": {}, "__N_SSG": true }`; `nextjs-page-data` (or `nextjs-ssjs-probe`) |
| `/_next/static/chunks/pages/*.js` | any | Minimal valid webpack chunk; `nextjs-static-chunk` |
| `/__nextjs_action`, `/__nextjs_action/<sub>` | any (esp. POST) | Empty `text/x-component` 200 — the shape a real `void`-returning Server Action emits. POST body captured in `bodyPreview` (likely contains the serialised RSC payload + base64-encoded `child_process` calls); `nextjs-server-action` |
| `/__nextjs_launch-editor` | any | `{"opened":true}` JSON — the IDE-launch dev-mode endpoint has been a pre-auth RCE shape in older Next.js versions. The `file=` / `line=` query args are captured in `nextjsDevModeQuery`; `nextjs-launch-editor` |
| `/__nextjs_error_overlay`, `/__nextjs_original-stack-frame`, `/__nextjs_stack_frame` | any | Per-hit synthetic dev-mode error-overlay HTML (random source file name + line/column from a small project-shaped pool) so the response varies per hit; `nextjs-error-overlay` |
| any other `/__nextjs_*` | any | Empty `{}` JSON 200 captured under `nextjs-devmode-other` so the operator can see what new dev-mode endpoints scanners probe next |

URL-encoded leading slashes (`/%2f__nextjs_action`,
`/%252f__nextjs_action%2f`) — a path-normalisation bypass some scanners
use — are decoded before dispatch, so the same predicates match both
the clean and the encoded shape; the rest of the path is preserved so
renderers still see exactly what the scanner sent.

When a `cmd=` query parameter is present, the handler:

1. Base64-decodes the value (URL-safe + padding-tolerant).
2. Falls back to the raw value if the decode is empty / non-text — so
   plaintext probes (`?cmd=id`) still get logged.
3. Scans for SSJS-eval indicators (`require(`, `child_process`,
   `child-process`, `execSync`, `(function()`, `process.env`, …).
4. Extracts the inner `var cmd = "..."` literal so the operator's own
   probe-marker token can be reflected.
5. If the inner literal is `echo <printable-ascii>`, returns the token
   followed by `\n` — a working SSJS RCE shape from the scanner's
   point of view, inviting the follow-up exploitation request.
6. Anything else (including shell-meta / `$(...)` / backticks) returns
   the literal `ERROR` — matches the canonical scanner catch-block
   sentinel and avoids reflecting attacker bytes verbatim.

The handler logs:

- `result` tags (`nextjs-api`, `nextjs-page-data`, `nextjs-static-chunk`,
  `nextjs-ssjs-probe`, `nextjs-server-action`, `nextjs-launch-editor`,
  `nextjs-error-overlay`, `nextjs-devmode-other`)
- `nextjsPath`
- `nextjsHasSsjs` — true when the decoded `cmd=` body contains an
  SSJS-eval indicator
- `nextjsCmdDecoded` — first 512 chars of the decoded `cmd=` payload
- `nextjsCmdLiteral` — extracted `var cmd = "..."` literal (if present)
- `nextjsDevModeQuery` — extracted `{file, line, column, name, args, path}`
  query args on dev-mode endpoints (`/__nextjs_launch-editor` etc.)
- `bodyPreview` — first 400 chars of the request body for non-GET probes

No Tracebit key is required. The trap does not emit credential-shaped
values; the goal is probe-payload capture and follow-on exploitation
bait.

## Why

A scanner observed in early May 2026 was probing Node.js / Next.js
applications for SSJS injection by base64-encoding a small JS IIFE
into a `cmd=` query parameter and aiming it at Next.js-conventional
routes (`/_next/data/<buildId>/page.json`, `/api/[[...slug]]`,
`/api/endpoint`). The decoded payload looked like:

```javascript
(function(){
    try {
        var cmd = "echo VULN_TEST";
        var result = require('child-process').execSync(cmd).toString();
        return result;
    } catch (err) {
        return 'ERROR';
    }
})()
```

Note the `require('child-process')` (with a hyphen) — this is not a
real Node module, so a vulnerable target running this payload always
hits the catch and returns `ERROR`. The scanner uses the response
shape to distinguish three states:

- **404 / generic body** → server is not evaluating `cmd=` server-side
  → no SSJS exposure.
- **Body is `ERROR`** → `cmd=` is being evaluated as JS, `require()`
  failed → SSJS works, scanner can ship a fixed payload next.
- **Body is the `echo` literal** → `cmd=` is evaluated AND
  `child_process` is reachable → working RCE.

A bare 404 leaks "this is not Next.js" and the scanner moves on. The
trap returns the simulated echo for safe-token probes and falls back
to `ERROR` for unrecognised payloads, so a scanner walking the
fingerprint chain receives the same response shape it would from a
real vulnerable target — and any follow-up exploitation request
arrives at our log pipeline.

The `var cmd = "..."` extraction is regex-only on the decoded string;
nothing attacker-controlled is ever evaluated. The reflected token is
constrained to `[\w\-.: /]{0,256}` to keep arbitrary attacker bytes
out of the response and the log.
