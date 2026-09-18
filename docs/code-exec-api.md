# Code-execution and file-read API surface

Answers the low-code-platform and web-IDE API endpoints that take their
argument in a request body, and records that argument before deciding
anything about the response.

| Path | Family | Response |
| --- | --- | --- |
| `/api/fs/exec` | `exec` | `{"ok":true,"exitCode":0,"stdout":…}` — recon commands get the same boring output the shell traps serve, everything else an empty result |
| `<prefix>/lib/terminal-xhr.php` | `exec` | the raw command output, not JSON — the web-IDE terminal answers in plain text |
| `/api/v1/validate/code` | `validate` | `{"valid":true,"errors":[],…}` |
| `/api/templates/preview` | `template` | `{"rendered":…,"engine":"nunjucks"}` — see below |
| `/api/designer/v1/file-content`, `/read-document` | `read` | `{"path":…,"content":…}` with a plausible non-secret document |

The argument is read from a JSON body, a form encoding or the query
string, under any of the key spellings these endpoints use (`cmd`,
`command`, `code`, `template`, `path`, `file`, …), because the probes
send all three without knowing which the server wants. A body that
matches none of those shapes is still recorded rather than dropped.

## The template endpoint answers arithmetic

A server-side template injection probe is arithmetic: the sender writes a
product it can recognise and reads the response to find out whether the
expression was evaluated. `{{7*7}}`, `${7*7}`, `#{7*7}` and `<%= 7*7 %>`
are answered with `49`.

Only an integer product, sum, difference or quotient inside one of those
wrappers is computed, with bounded operands and a cap on substitutions
per body. **Nothing is evaluated as code.** A probe that is not that exact
shape — a class walk, a `Runtime.exec` chain, mismatched wrappers — comes
back as it arrived, which is what an engine that did not interpolate
emits. `codeExecApiTemplateEvaluated` records which of the two happened.

## Logging

- `result`: `code-exec-api-exec` / `-validate` / `-template` / `-read`
- `codeExecApiFamily`, `codeExecApiPath`, `codeExecApiMethod`
- `codeExecApiArgument` + `codeExecApiArgumentLen` — the recovered payload
- `codeExecApiCommand` (exec), `codeExecApiRequestedPath` (read),
  `codeExecApiTemplateEvaluated` + `codeExecApiRenderedPreview` (template)
- `bodyPreview`, `contentType`

Config: `HONEYPOT_CODE_EXEC_API_ENABLED` (default on),
`HONEYPOT_CODE_EXEC_API_BODY_PREVIEW_LIMIT` (2048).

## Why

These addresses are walked by a distributed fleet whose sources present
themselves as AI assistants and search crawlers — a rotating set of
assistant and search-bot user agents. No real crawler of any of those
names POSTs to an exec endpoint, so the user agent is cover, and the
address list is a capability list: run a command, validate source, render
a template, read a file.

The reason to answer rather than 404 is narrower than usual here. A 404 is
decided from the address alone, before the body is read — so for this
whole family the payload, which is the entire content of the request, was
the one thing never recorded. Answering costs nothing upstream and turns a
path count into the operator's actual command, template or traversal
target.

Answering also keeps the ladder going. These probes escalate: a validator
that accepts invites a longer payload, and a template endpoint that
returns `49` is the signal that says the next payload should be the real
one. The arithmetic oracle is worth implementing precisely because it is
the step the operator is testing for, and it can be given honestly without
interpreting anything.

Credential-shaped answers deliberately stay out of this trap. The file-read
family returns an ordinary document; when a probe asks for a credential
file, minting a canary for it belongs to the traps built around that, not
to a generic reader.
