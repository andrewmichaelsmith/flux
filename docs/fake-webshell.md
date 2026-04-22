# Fake webshell

Matches known PHP webshell probe paths. Two matchers, both default-on:

- **Exact paths** (full list in `HONEYPOT_WEBSHELL_PATHS_CSV`, e.g.
  `/wp-content/plugins/hellopress/wp_filemanager.php`, `/shell.php`,
  short-named `*.php` shells).
- **Regex families** (not env-configurable; set in source):
  - `/.well-known/<name>.php` — attackers use the `/.well-known/`
    directory as a shell-drop location because it's often writable
    by the certbot user. Observed filenames include `rk2.php`
    (r57 lineage), `gecko-litespeed.php`, `admin.php`, `error.php`.
    `/.well-known/acme-challenge/*` is excluded (nginx routes it
    elsewhere; the regex explicitly requires a `.php` leaf).
  - `/.trash<N>/*` and `/.tmb/<name>.php` — numbered "trash" staging
    directories used by specific malware families.
  - `/.tresh/`, `/.dj/`, `/.alf/`, `/.mopj.*`, `/.info.*` — more
    dot-directory shell-drop conventions.

Returns a plausible File Manager page that invites a follow-up command.

Simulated command outputs:

- `id`, `whoami`, `uname -a`, `cat /etc/passwd` → deliberately boring
  canned outputs (`www-data`, stock `/etc/passwd`, Linux 5.15 `uname`).
- Everything else → empty output. Same thing a real shell produces
  for `cd foo` or a variable assignment — safer than a
  "command not found" that outs the trap on the first probe.

## Why

Post-compromise scanners walk a list of PHP shell paths looking for
"is my planted shell still here". This is often called **shell
jacking**: rather than finding a new RCE, the operator enumerates
filenames that *other* attackers drop as persistence and tries to
take over that access cheaply. They don't care whether your site
ever ran WordPress. A plausible response makes them send their *next*
command, which is the actual intel worth logging: the argument they
pass, their cookie jar, their UA rotation, whether they escalate.

The regex families above exist because shell-drop conventions are
parameterized (numbered `/.trash<N>/` dirs, rotating `/.well-known/`
filenames) and can't be enumerated as literal strings.
