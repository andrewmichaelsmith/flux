# Jenkins build-server state files

Three files a Jenkins controller keeps on disk, answered under every
spelling the sweeps use — the webroot forms (`/jenkins/…`,
`/.jenkins/…`, `/config/jenkins.xml`) and the absolute `$JENKINS_HOME`
forms (`/var/jenkins_home/…`, `/var/lib/jenkins/…`).

| File | Paths | Canary | Log tag |
| --- | --- | --- | --- |
| `credentials.xml` | `/credentials.xml`, `/jenkins/credentials.xml`, `/.jenkins/credentials.xml`, `/jenkins_home/credentials.xml`, `/var/jenkins_home/credentials.xml`, `/var/lib/jenkins/credentials.xml` | `aws` | `jenkins-credentials-xml` |
| `secrets/master.key` | the same six prefixes, plus bare `/secrets/master.key` | — | `jenkins-master-key` |
| root `config.xml` | `/jenkins/config.xml(.bak)`, `/.jenkins/config.xml`, `/config/jenkins.xml`, `/jenkins_home/config.xml`, `/var/jenkins_home/config.xml`, `/var/lib/jenkins/config.xml` | — | `jenkins-config-xml` |

They are entries in the canary file table rather than a handler, which
means one entry answers every route into the same file: the bare
webroot probe, the layout walk (`/admin/credentials.xml`), the
dev-server `/@fs/` read primitive and the appliance body-traversal read
all land on one document.

## Why

**`/Jenkinsfile` answered; the credential store the pipeline draws from
did not.** The same dictionaries walk both, in the same sweep, and a
host that serves one and 404s the other is showing its routing table
rather than its filesystem. The absolute spellings made it plainer
still: `/@fs/home/runner/.aws/credentials` answered while
`/@fs/var/jenkins_home/credentials.xml` missed.

**The credential store is mixed on purpose.** The username/password and
SSH entries carry `{…}` ciphertext, which is what a correctly configured
instance writes and what makes the document read as real. The AWS entry
carries the canary in the clear: its `accessKey` field genuinely is
plaintext in a real file, and rendering the secret half as ciphertext too
would leave the trap decorative — nothing in it could be replayed, so a
harvest would produce no signal at all. An instance whose store was
restored from a plaintext backup looks exactly like this, and it is the
shape the harvesters that grep these files for `AKIA` expect.

**`master.key` measures intent.** It unlocks nothing here — the
ciphertext in the store is random, not encrypted under it. What it
records is whether a source that took the credential store comes back
for the means to decrypt it, which is the difference between something
hoovering files and someone reading them. It is minted per hit, because
a constant would be the same key material on every host running this
software.

**The root config carries no credential and spends no canary.** Its job
is to be the file that makes the credential store the obvious next
request, and to say which Jenkins this claims to be.

## CI-runner home spellings

Shipped alongside, same defect class: CI providers other than GitHub
Actions name the build agent's home after themselves
(`/home/gitlab-runner/…`, `/home/circleci/…`), and the dictionaries that
walk `/home/runner/<file>` walk those in the same sweep. Every
`/home/runner/` entry in the trap table is now derived into both aliases
rather than hand-listed, so a file added to one home cannot be missing
from the others; `.gitconfig` lives in its own path set and is asserted
separately.
