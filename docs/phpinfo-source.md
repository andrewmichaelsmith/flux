# Diagnostic-script source, via the editor-backup spellings

Answers `phpinfo.php.bak` / `.old` / `.save` / `~` and siblings with the
*source* of a diagnostic script, rather than the page the live path
renders.

| Property | Value |
| --- | --- |
| Leaves | `phpinfo.php`, `info.php`, `php.php`, `test.php` |
| Suffixes | `.bak`, `.old`, `.save`, `~`, `.orig`, `.swp`, `.backup`, `.txt`, `.bak~`, `.old~`, `.save~`, `.tmp` |
| Matching | exact entries (leaf × suffix cross-product), case-insensitive |
| Canary | `aws`, in the `putenv('AWS_…')` block |
| Other secrets | DB password, per-hit random |
| Content type | `text/plain` |
| Log tag | `phpinfo-source` |

The body is a deployment-diagnostics script: error reporting turned on, an
inline `$db` array, a `putenv` block for the S3 target, a PDO connectivity
check, then `phpinfo()`. The credentials sit where an operator would have
typed them.

## Why

A backup suffix takes the filename outside the PHP handler's match, so the
server stops executing it and starts serving it. That makes the backup
spelling a **different disclosure** from the live one, not an alias for it:
`/phpinfo.php` leaks whatever the runtime happens to hold, `/phpinfo.php.bak`
leaks whatever the operator wrote down. Returning the rendered HTML table
here would be wrong twice — no real host can execute a `.bak`, so rendered
output is a tell that the response is fabricated.

This family also cannot be reached by the shell-jacking sweep gate
([`webshell-sweep.md`](./webshell-sweep.md)), whose matcher requires the
name to end in `.php`. Every suffix here ends past that, so no amount of
sweep width opens the gate — only an entry answers. That is why these
paths kept 404ing while their `.php` neighbours were served.

The credential block is the reason the trap is worth having at all. A real
`phpinfo.php` is often a bare `<?php phpinfo();` and holds nothing to grep
for; the scripts that actually get renamed-and-kept are the ones an
operator extended with a connectivity check, which is exactly the version
that carries an inline credential. The shape follows the `wp-config.php.bak`
precedent already in the trap table.
