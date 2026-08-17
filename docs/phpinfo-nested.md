# phpinfo() under an arbitrary parent

Lets the phpinfo trap answer when the file arrives nested under a parent
directory the app-layout walk does not recognise — `/wp-admin/phpinfo.php`,
`/cgi-bin/info.cgi`, `/crm/backend/phpinfo.php`. Default-on via
`HONEYPOT_PHPINFO_NESTED_ENABLED`.

| Property | Value |
| --- | --- |
| Resolution order | exact table entry → app-layout walk → this |
| Max depth | 4 parent segments (`PHPINFO_NESTED_MAX_DEPTH`) |
| Gate | the **leaf** filename, not the parent |
| Renderer | the existing `phpinfo` trap, unchanged |
| Canary | `aws` (inherited from that trap) |
| Log tag | `phpinfo`, with `trapWalkDepth` stamped |

Eligible leaves: `phpinfo.php`, `phpinfo.cgi`, `phpinfo`, `php-info.php`,
`php_info.php`, `phpinfo2.php`, `old_phpinfo.php`,
`linusadmin-phpinfo.php`, `info.php`, `info.cgi`, `infophp.php`,
`infos.php`, `iinfo.php`, `pinfo.php`, `phpversion.php`,
`php_version.php`.

Every eligible leaf also exists as a root-level entry in the canary trap
table — the resolver looks the leaf up there rather than hardcoding a
target, so a leaf with no entry would silently resolve to nothing. A test
pins that invariant.

## Why

[`trap-path-walk.md`](./trap-path-walk.md) gates on the *parent*, and for
a credential leaf that is the right test: `/admin/aws.json` is a file a
real deployment could plausibly have, `/9f2a1c/aws.json` is not, and
answering the second would advertise that this host says yes to anything.

phpinfo inverts the test. A phpinfo page is not part of any framework's
layout — it is a file an operator drops by hand, wherever they happened
to be standing, and then forgets. The parent therefore carries no
information about plausibility, and scanners behave accordingly: observed
sweeps walk this one leaf under hundreds of distinct parents, most
appearing exactly once, so a parent vocabulary can never be extended fast
enough to cover them. Widening the shared vocabulary to try would have
been the wrong fix twice over — it would still miss the tail, and it
would widen the surface for every *other* trap at the same time.

So the leaf becomes the gate, and the leaf list is what has to be tight.
Only names that are unambiguously a phpinfo probe are eligible. The
generic stems the root-level trap also answers — `test.php`, `x.php`,
`1.php`, `temp.php`, `i.php`, `php.php` — are deliberately excluded:
they collide with webshell-drop dictionaries, and answering those under
any parent would turn this into an answer-everything switch, which is
its own tell.

The payoff is that the response was already written. The renderer, the
canary and the log tag are the phpinfo trap's own; the only thing that
changed is that the sweep now reaches them.
