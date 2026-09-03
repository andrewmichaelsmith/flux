# `php://filter` local file read

The third surface that hands a client an arbitrary file read, after the
Vite `/@fs/` dev-server prefix and the appliance body traversal. Here the
path never appears in the request target — it rides inside a PHP
stream-wrapper URL in a query parameter.

| | |
| --- | --- |
| Matches | any query string containing `php://filter`, on any path and any method |
| Resource | resolved through the shared `resolve_fs_read` walk — the same one `/@fs/` uses |
| Encoding | the requested filter chain is executed against the response body |
| Hit | `200`, body encoded as asked (`convert.base64-encode`, `string.rot13`, `zlib.deflate`, …) |
| Miss | `200` with an empty body, `text/html` |
| Canary | inherited from the resolved trap; none for a system file |
| Log tags | `php-filter-<trap>`, `php-filter-issued`, `php-filter-etc-passwd`, `php-filter-etc-php-ini`, `php-filter-miss` |
| Switch | `HONEYPOT_PHP_FILTER_LFI_ENABLED` (default on) |

## What it parses

The handler decodes the query (twice — the argument-injection vector
percent-encodes `=` inside an already-encoded query), finds the wrapper,
and splits everything after `php://filter/` using PHP's own grammar:
slash-separated segments, each either a `|`-separated filter list —
optionally prefixed `read=` / `write=` — or the terminal `resource=<path>`.
The resource is the awkward part, since its value is a filesystem path
containing the same slash the segments split on, so everything from
`resource=` onward is rejoined as the resource.

Logged per hit: `phpFilterEntry` (the script the wrapper rode on),
`phpFilterParam` (the parameter that carried it), `phpFilterResource`
(as written, before traversal collapse), `phpFilterRequestedPath` (after),
`phpFilterChain` / `phpFilterCount`, and two flags set only when true —
`phpFilterIconv` and `phpFilterCgiArg`.

## Why

Three client populations converge on this one wrapper syntax, and
`phpFilterParam` is what separates them afterwards:

1. **Include-sink discovery** — one script name walked across a
   dictionary of parameter names (`page`, `path`, `file`, `template`,
   `p`, `f`, `include`, `document`, `0`, …) looking for the one that
   reaches an `include()`. Every probe is a distinct request, so a sweep
   is large and completely uniform.
2. **Named-advisory reads**, where the sink parameter is already known
   from the disclosure, so the client asks once per candidate install
   path rather than once per parameter.
3. **PHP-CGI argument injection** (the CVE-2024-4577 family), which
   smuggles `-d auto_prepend_file=php://filter/...` into the query. Not
   an application bug at all — same wrapper, different vulnerability
   class, and it must not be counted as sink discovery.

Answering matters more here than for a bare `/.env` probe, because **the
wrapper names its own encoding**. A client that asked for
`convert.base64-encode` and gets plaintext back has a response that
cannot have come from the filter it requested: it learns the sink is
fake and never reads the credential. Honouring the chain is therefore
not decoration — it is the difference between a canary that gets
harvested and replayed and one that gets discarded.

`convert.iconv.*` gets its own flag because it has no purpose in a plain
read: a client that wants file bytes asks for base64-encode and stops.
Its presence marks a client running one of the published filter-chain
generators, which is the smaller and more interesting half of this
population.

The miss is an empty `200` rather than a `404`. A missing include on a
host with `display_errors` off emits nothing and the script still
returns; a `404` would claim the *script* does not exist, contradicting
the `200` the same client just got from another parameter on the same
script and marking the host as instrumented.
