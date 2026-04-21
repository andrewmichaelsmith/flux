# Fake webshell

Matches known PHP webshell probe paths (full list in
`HONEYPOT_WEBSHELL_PATHS_CSV`, e.g.
`/wp-content/plugins/hellopress/wp_filemanager.php`, `/shell.php`,
short-named `*.php` shells). Returns a plausible File Manager page
that invites a follow-up command.

Simulated command outputs:

- `id`, `whoami`, `uname -a`, `cat /etc/passwd` → deliberately boring
  canned outputs (`www-data`, stock `/etc/passwd`, Linux 5.15 `uname`).
- Everything else → empty output. Same thing a real shell produces
  for `cd foo` or a variable assignment — safer than a
  "command not found" that outs the trap on the first probe.

## Why

Post-compromise scanners walk a list of PHP shell paths looking for
"is my planted shell still here". They don't care whether your site
ever ran WordPress. A plausible response makes them send their *next*
command, which is the actual intel worth logging: the argument they
pass, their cookie jar, their UA rotation, whether they escalate.
