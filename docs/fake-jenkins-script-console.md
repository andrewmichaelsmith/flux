# Fake Jenkins Groovy script console

Answers Jenkins' built-in Groovy script console, the unauthenticated-RCE
surface scanners probe on exposed Jenkins instances.

| Path | Method | Response |
| --- | --- | --- |
| `/script`, `/jenkins/script`, `/.jenkins/script` | GET | Console HTML page with a `<textarea name="script">` and a per-request CSRF crumb |
| `/computer/<node>/script` (e.g. `(master)`, `(built-in)`, an agent name) | GET | Same console page |
| any of the above | POST | Captures the `script` Groovy field, returns the console page with an empty `Result` block |
| `/scriptText` (+ webroot / node spellings) | POST | Captures the `script` field, returns an empty `text/plain` result body |

Matching is exact on the lower-cased path with at most one trailing slash
removed — never a `/script` prefix. `/scripts/.env`, `/script/<asset>` and
the `/scriptResource/...` static tree are a different population (credential
dredging / static assets) already served by the canary and tarpit modules;
a prefix match would steal that traffic and retag it as RCE.

## What it parses / logs

The console and the `scriptText` API both carry the program in the `script`
form field (`script=<urlencoded groovy>`). The handler url-decodes it with
the shared form parser — correct here, because the body is genuinely
form-urlencoded, so `+` is a space and `%2B` a literal plus — and logs:

- `jenkinsScriptSource` (bounded preview), `jenkinsScriptLen`
- `jenkinsScriptHasExec` — `.execute()`, `Runtime.getRuntime`,
  `ProcessBuilder`, shell/`cmd.exe`/`powershell` idioms
- `jenkinsScriptHasCredentialAccess` — the Jenkins credential-store and
  `Secret.decrypt` idioms
- `jenkinsScriptHasDownload` — `new URL(...)`, `.getText()`, `wget`/`curl`,
  thread-spawn / `newInstance` persistence idioms
- `jenkinsScriptBodySha256`, `jenkinsScriptBodyLen`

The three flags split the recon, RCE, credential-theft and persistence
steps in triage. `result` is `jenkins-script-exec` when a `script` field is
present, `jenkins-script-probe` for a bare POST, and
`jenkins-script-console-probe` for a GET fingerprint.

## Why

The Groovy console is a straight remote-code-execution surface on any
Jenkins whose authorization is misconfigured (anonymous Overall/RunScripts,
or a release predating the CSRF/permission hardening), so the console path
family is one of the most consistently requested paths this server did not
answer — GET fingerprints followed, on the senders that proceed, by a
`POST script=<groovy>`. The whole family 404'd, so the walk ended at the
fingerprint and the one request carrying attacker-authored content — the
Groovy — was lost.

It also completes a chain the server already half-answered: the Jenkins
`config.xml`, `credentials.xml` and `secrets/master.key` canary files are
served by the canary-file table, so a sweep that read those and then posted
to the console got a convincing config read followed by a dead 404 at the
step that matters.

The console answers without a prior login on purpose — a misconfigured
instance serves it to anonymous, and that is the vulnerability being
imitated. Gating it behind an invented login would make the trap less
realistic than the bug and would drop the POST body. No credential-shaped
value is emitted: the CSRF crumb in the page is minted per request, never a
fixed literal.
