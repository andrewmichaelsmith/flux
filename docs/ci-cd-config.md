# CI/CD config canaries

Responds to scanners that fetch build and deployment configuration files from
the web root. These requests appeared repeatedly in the April 2026 lab logs:
GitHub Actions workflow files, `.gitlab-ci.yml`, `Jenkinsfile`, and Bitbucket
Pipelines files were all present in recent config-leak dictionaries.

## Paths

| Family | Paths |
| --- | --- |
| GitHub Actions | `/.github/workflows/deploy.yml`, `main.yml`, `ci.yml`, `build.yml`, `test.yml`, `docker.yml`, `release.yml`, `cd.yml`, `publish.yml` plus `.yaml` variants |
| GitLab CI | `/.gitlab-ci.yml`, `/.gitlab-ci.yaml`, `/.gitlab/.gitlab-ci.yml` |
| Jenkins | `/Jenkinsfile`, `/Jenkinsfile.bak` |
| Bitbucket | `/bitbucket-pipelines.yml`, `/bitbucket-pipelines.yaml` |
| Generic CI YAML | `/appveyor.yml`, `/.circleci/config.yml`, `/azure-pipelines.yml`, `/deployment.yml`, `/deploy.yml`, `/drone.yml`, `/.drone.yml`, `/.travis.yml`, `/cloudbuild.yaml` plus `.yaml`/`.yml` variants where applicable |

## Response

Each response is a plausible build/deploy config with inline production deploy
environment variables:

- Tracebit `aws` canary values in AWS credential fields.
- `AWS_DEFAULT_REGION=us-east-1`.
- A per-render synthetic `DATABASE_URL` password so the output does not carry
  a fixed fleet-wide secret literal.

## Log Fields

These are canary file traps, so the normal trap log includes:

- `result`: one of `github-actions-workflow`, `gitlab-ci`, `jenkinsfile`,
  `bitbucket-pipelines`, or `generic-ci-config`
- `canaryTypes`: includes `aws` when credential issuance succeeds
- `path`, `rawTarget`, `clientIp`, `userAgent`, `requestId`, `bytes`

## Measurement Goal

The trap tests whether config-file scanners harvest deploy credentials from CI
files, not just from `.env` and framework config files. A Tracebit replay from
one of these rows means a scanner treated a CI/CD config leak as credential
material and attempted to use the AWS key.

## Coverage notes

The list is a named-leaf dictionary, not a `*.yml` catch-all, so it rots in
one specific way: a hosted-CI product whose siblings are all present but
which nobody added. Travis was exactly that — `appveyor`, `drone` and
`circleci` all answered while `.travis.yml` 404'd, so a single dictionary
pass split across served and unserved names for no reason a scanner could
see. `publish.yml` was the same gap inside the GitHub Actions list, and it
is the workflow most likely to hold registry and cloud push credentials.

The `.env`-shaped sibling of these files (`/.github/secrets.env`) is not
served here — it is owned by the `env-production` trap, which generates the
`<dotdir>/<name>.env` cross-product. `.github` is registered as one of those
dot-directories for that reason.
