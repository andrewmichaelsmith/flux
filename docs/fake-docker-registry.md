# Fake Docker Registry V2 API

Serves a plausible Docker Distribution Registry HTTP API V2 surface that
invites multi-step enumeration from container-registry scanners.

## Paths

| Path | Method | Response |
|------|--------|----------|
| `/v2/` | GET | `{}` with `Docker-Distribution-Api-Version: registry/2.0` header (version check) |
| `/v2/_catalog` | GET | `{"repositories":["internal/api-gateway","internal/auth-service",…]}` |
| `/v2/<name>/tags/list` | GET | `{"name":"<name>","tags":["latest","v1.2.3","stable","main"]}` |
| `/v2/<name>/manifests/<ref>` | GET | Schema-2 manifest JSON with deterministic config + layer digests |
| `/v2/<name>/blobs/sha256:<digest>` | GET | Fake gzip-header blob (68 bytes) |

All responses include `Docker-Distribution-Api-Version: registry/2.0` and
`X-Content-Type-Options: nosniff`.

## Logging

Every request logs `dockerPath`, `dockerMethod`, and a `result` tag
(`docker-registry-version`, `docker-registry-catalog`, `docker-registry-tags`,
`docker-registry-manifest`, `docker-registry-blob`, `docker-registry-miss`).

Follow-on fields for enumeration:
- `dockerRepo` — the repository name segment from the path
- `dockerRef` — the tag or digest from manifest requests
- `dockerDigest` — the blob digest

Mutation attempts (PUT/PATCH/POST/DELETE) additionally log
`dockerMutationMethod`, `dockerBodySha256`, and `dockerBodyPreview`.

If the scanner sends an `Authorization` header (Basic or Bearer), it is
captured in `dockerAuthHeader`.

## Why

Exposed private Docker registries are a high-value target: they often
contain application images with embedded secrets, database credentials,
and API keys in environment variables or config files baked into layers.
The registry enumeration protocol is multi-step, so each progression
reveals scanner sophistication and intent — catalog-only scanners differ
from those that pull manifests and blobs.

## Config

| Env var | Default | Description |
|---------|---------|-------------|
| `HONEYPOT_DOCKER_REGISTRY_ENABLED` | `true` | Master switch |
| `HONEYPOT_DOCKER_REGISTRY_REPOS_CSV` | `internal/api-gateway,internal/auth-service,deploy/worker,staging/web-app,backup/db-migrator` | Fake repository names in catalog |
