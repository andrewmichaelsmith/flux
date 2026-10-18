# Path-parameter traversal fold

Normalisation, not a trap. Runs inside `normalize_path` ahead of every
path matcher, so no handler has to know about it.

## What it folds

| Shape | Resolves to |
| --- | --- |
| `/static/..;/..;/..;/..;/proc/self/environ` | `/proc/self/environ` |
| `/assets/..;/../var/www/html/wp-config.php` | `/var/www/html/wp-config.php` |
| `/..;/wp-config.php` | `/wp-config.php` |
| `/x/..;jsessionid=0123456789abcdef/.env` | `/.env` |
| `/static/%2e%2e;/.env`, `/static/%252e%252e;/.env` | `/.env` |

A segment that is exactly `..` followed by an RFC 3986 path parameter is
folded onto plain `..`; step 4 of `normalize_path` then resolves it like
any other traversal.

## Why the shape exists

A servlet container strips `;name=value` off a path segment before it
resolves the segment, so `..;` is a path-up token there. That is the
whole basis of the bypass: a fronting proxy that gates on a URL prefix
sees an ordinary directory name and forwards the request, and the
container then walks up out of the gated prefix. The CVE-2020-1938
("Ghostcat") era surfaced it; scanner populations still walk
`/..;/<sensitive>` against anything that looks like a fronted Java
application.

## Behaviour

Folds after the percent-decode — which runs to a fixed point, so the
shape is caught however many encoding layers it arrived under — and after
the injected-prefix and NTFS strips, for the same reason those run in
that order: a stripped path still gets `..` resolved normally afterwards.

The evasion attempt is not lost. `rawPath` carries the request as it
arrived, and `pathParamTraversal` records how many such segments it
carried, present **only** when one fired, so the field's presence is
exactly the bypass signal and every other request keeps its existing log
shape.

## What it deliberately does not fold

- **`/admin;jsessionid=0123456789abcdef/index.jsp`** — a parameter on an
  ordinary segment is not a traversal token, and the session id in it is
  worth keeping in the path the handler sees.
- **`/a/.;/.env`** — a single dot with a parameter is not a path-up
  token either.

## Handlers that had been matching the raw shape

Two surfaces were matching `..;` directly, each for a single
destination, and both keep their routes:

- The **`env*.js` bypass handler** exists to separate a bypass-shaped
  frontend-bundle harvest from a plain one, so folding the segment must
  not collapse it into the generic env route. It now reads the parameters
  from the raw path and the filename from the normalised one, and keeps
  its own `tomcat-path-bypass-env` result tag.
- The **F5 BIG-IP TMUI file-read** is written with `..;` in its own
  CVE-2020-5902 payload. The normalised destination keeps both `/tmui/`
  segments — the `..` cancels `login.jsp` and the payload names the
  directory twice — so that spelling is registered alongside the
  unresolved one, which is retained because it is the form the probe
  arrives in and because an operator-supplied path list may carry it.
  `f5HasPathTraversal` now reads `pathParamTraversal` as well as the
  residue of an unresolved `/..`, so the flag still fires once the
  traversal resolves cleanly.

## Why

Before the fold, every traversal spelled this way stayed unresolved and
404ed even where the file it named already had a renderer — the two
hand-written literals above were the only coverage, and the families
these requests actually name (`/proc/self/environ`, `wp-config.php`,
`.env`) each 404ed on the bypass spelling while answering the plain one.
The same sweep that took a canary from the direct spelling took nothing
from the bypass spelling, so the prefix, not the trap coverage, decided
whether an evasion-aware read walked away with something traceable.

Folding in normalisation rather than per-trap is the point: the whole
table gains the spelling at once. It is the same reasoning the NTFS
alternate-data-stream strip is built on.

The second reason is measurement. A request that spells its traversal
this way is evasion-aware — it is specifically targeting the
proxy-versus-container normalisation gap — and `pathParamTraversal`
keeps that population separable at one log field even though dispatch now
resolves the shape away.
