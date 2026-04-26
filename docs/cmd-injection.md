# cmd-injection trap

Responds to "exposed admin endpoint that runs a shell command" probes
and to classic CGI environment-leak scripts.

| Path                | Method | Response                                                                           |
| ------------------- | ------ | ---------------------------------------------------------------------------------- |
| `/admin/config`     | GET/POST | landing HTML if no `cmd=` param; otherwise simulated command output (see below) |
| `/printenv`         | GET    | fake env-block whose `AWS_*` values are a Tracebit canary                          |
| `/cgi-bin/printenv` | GET    | same as `/printenv`                                                                |
| `/cgi-bin/test-cgi` | GET    | same as `/printenv`                                                                |

The handler reads the `cmd` value from `?cmd=…`, the equivalent
`POST` form param (`cmd`, `command`, `exec`, `c`), and classifies it
into one of the families below. Per-IP cache bounds Tracebit issuance
the same way the fake-git trap does.

| `cmdFamily`         | Trigger                                       | Response body                                                              |
| ------------------- | --------------------------------------------- | -------------------------------------------------------------------------- |
| `creds-aws`         | `cat …/.aws/credentials`                       | per-request Tracebit AWS canary in `~/.aws/credentials` INI shape          |
| `creds-aws-config`  | `cat …/.aws/config`                            | per-request Tracebit AWS canary in `~/.aws/config` INI shape               |
| `env`               | `printenv`, `env`, or any `/printenv` route   | per-request Tracebit AWS canary in a `printenv`-shape env block            |
| `passwd`            | `cat /etc/passwd` / `/etc/shadow`              | static fake `/etc/passwd` matching the webshell trap                       |
| `id` / `whoami` / `uname` / `hostname` / `pwd` / `ls` | matching builtin   | static fake output (`uid=33(www-data) …`, etc.)                            |
| `unknown`           | anything else                                  | empty body — matches shell behaviour for builtins/assignments               |

Logged fields per event (in addition to the standard `LOGS.md` schema):
`result` (`cmd-injection-probe` / `cmd-injection-command` /
`cmd-injection-creds-leak` / `cmd-injection-printenv`),
`cmdInjectionPath`, `cmdSource` (`query` / `form` / `""`), `cmdKey`,
`cmd`, `cmdFamily`, `outputBytes`, and `canaryStatus` (`issued` /
`issue-failed`) when a Tracebit canary was minted.

## Why

Two observed shapes drove this trap:

1. Scanner fleets escalating from passive credential-file harvesting
   (`/.env`, `/.aws/credentials`) to active command-injection probes
   against admin-config endpoints — typified by GET requests like
   `/admin/config?cmd=cat%20/root/.aws/credentials`. A 404 here teaches
   the scanner there's no exploit; a plausible response with canary
   credentials in the body keeps them on the line and gives us a
   replay alert if they ship the value to AWS.
2. The 1990s-era CGI demo scripts `/printenv` and `/cgi-bin/printenv`
   are still hunted because exposed env blocks routinely carry
   `AWS_ACCESS_KEY_ID`, `DATABASE_URL`, etc. Returning a fake env
   block whose AWS values are a Tracebit canary lets us measure
   "how often does this class of scanner replay env-harvested AWS
   creds, and how fast?".
