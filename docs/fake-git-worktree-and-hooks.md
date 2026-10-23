# Fake `/.git/` — installed hooks, worktree config, submodule map

Three additions to the `/.git/` tree, all answering spellings a repo-dumping
dictionary walks and all previously 404.

| Path | Method | Response |
| --- | --- | --- |
| `/.git/hooks/{pre-commit,pre-push,post-receive}` | GET / HEAD | `#!/bin/sh` script. `post-receive` carries an AWS canary in its deploy `export` block; the other two carry no credential |
| `/.git/hooks/<other 16 names>` | GET | **404** — the `.sample` exists, the enabled hook does not |
| `/.git/hooks/` | GET | autoindex naming the 19 `.sample` stubs **plus** the 3 installed hooks |
| `/.git/config.worktree` | GET / HEAD | worktree-scoped config: `core.worktree`, `[remote "upstream"]` with a GitLab username/password canary as HTTPS userinfo |
| `/.git/config` | GET | now also declares `[extensions] worktreeConfig = true` |
| `/.git/refs/remotes/upstream/{HEAD,main}`, `/.git/logs/refs/remotes/upstream/main` | GET | the refs the upstream remote implies |
| `/.git/refs/heads/trunk` | GET | branch-name alias |
| `/.gitmodules` (+ `/root/`, `/home/`) | GET / HEAD | two submodules; the private one's URL carries the GitLab canary |
| `/.gitattributes` (any parent) | GET / HEAD | worktree attributes file, no credential |
| `/awsconfig.json`, `/aws-config.json`, `/aws_config.json` (+ `/config/`, `/src/`, `/assets/`) | GET / HEAD | flat SDK-config JSON with the AWS canary in `accessKeyId` / `secretAccessKey` |

Lookup lowercases, so `/AwsConfig.json` and `/.GIT/CONFIG.WORKTREE` resolve
through the same rows.

The handler logs `fakeGitInstalledHook` — the hook leaf name on an installed-hook
fetch, empty otherwise. `.gitattributes` logs under its own `gitattributes`
result tag; `.gitmodules` and the AWS config file log as `gitmodules` and
`aws-config-json`.

## Why

**Installed hooks.** A stock `git init` leaves every hook as a `.sample`, so the
nineteen non-suffixed names are the second half of the same dictionary — and 404
is the *correct* answer for a stock repo. That is why this was never simply a
missed route. The repository worth presenting is the one with hooks installed,
because an installed hook is a script the deployment actually runs, and a deploy
script holds credentials attached to the release pipeline rather than to the
application. Only three are installed: a repo with all nineteen active does not
exist, and fabricating it would be a louder tell than the 404s.

The listing is the measurement. `hooks/` names exactly what resolves, so a
client that read the autoindex asks for three names and gets three answers,
while a client replaying a path list asks for nineteen and takes sixteen 404s.
Both sets are derived from the same constants, so they cannot drift apart —
which is the failure the loose-object fan-out directories had, where the listing
denied the existence of objects the tree was serving.

**`config.worktree`.** Served as a genuinely different file from `config` rather
than a byte-copy of it — which is what the `config.bak` / `config.old` aliases
correctly are, since those are editor leftovers of the same file. It holds what
real worktree config holds, and `config` declares the
`extensions.worktreeConfig` flag that makes git read it at all; without the flag
the file would sit on disk and be ignored by every git command, which is the
incoherence a careful reader spots. The upstream remote carries a *different*
canary type than origin, so which canary comes back on a replay says which of
the two files the client actually parsed — the worktree-scoped one being the one
only a reader that understands the extension bothers with.

**`.gitmodules`.** The one worktree dotfile that names other repositories, and
it names them as URLs — which is where a credential ends up when a submodule is
added over HTTPS with a helper that writes userinfo into the file. That makes it
both a credential placement and the only part of the git surface that offers a
next *target* rather than another file of the same repo. The public submodule
deliberately carries no credential: a `.gitmodules` where every entry has inline
userinfo is not a shape that occurs, and the contrast is what makes the private
one worth following.

**The AWS config file.** A different file from the Amplify artifact already
answered beside it, and the flat shape is load-bearing — a collector greping for
`accessKeyId` gets nothing out of the Amplify document, so answering this path
with that shape would waste the answer.

Three spellings stay 404 on purpose: `/.git/shallow` (exists only in a shallow
clone, and this tree advertises full reflogs), the all-zero object id, and
`objects/info/commit-graph` (optional in real git — a malformed binary would be
a worse tell than absence).
