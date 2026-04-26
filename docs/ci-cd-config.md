# CI/CD config canaries

Responds to scanners that fetch build and deployment configuration files from
the web root. These requests appeared repeatedly in the April 2026 lab logs:
GitHub Actions workflow files, `.gitlab-ci.yml`, `Jenkinsfile`, and Bitbucket
Pipelines files were all present in recent config-leak dictionaries.

## Paths

| Family | Paths |
| --- | --- |
| GitHub Actions | `/.github/workflows/deploy.yml`, `main.yml`, `ci.yml`, `build.yml`, `test.yml`, `docker.yml`, `release.yml`, `cd.yml` plus `.yaml` variants |
| GitLab CI | `/.gitlab-ci.yml`, `/.gitlab-ci.yaml`, `/.gitlab/.gitlab-ci.yml` |
| Jenkins | `/Jenkinsfile`, `/Jenkinsfile.bak` |
| Bitbucket | `/bitbucket-pipelines.yml`, `/bitbucket-pipelines.yaml` |
| Generic CI YAML | `/appveyor.yml`, `/.circleci/config.yml`, `/azure-pipelines.yml`, `/deployment.yml`, `/deploy.yml`, `/drone.yml`, `/.drone.yml` plus `.yaml` variants where applicable |

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
