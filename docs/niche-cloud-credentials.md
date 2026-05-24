# Niche cloud-provider credential canary traps

Flux serves format-accurate credential/config files for cloud CLI tools
beyond the mainstream AWS/GCP/Azure set. Each file embeds a Tracebit AWS
canary in the field a credential-extractor would grab, so replay fires
an alert regardless of which provider the scanner thinks the token is for.

## Routed paths

| Trap name | Paths | Format |
| --- | --- | --- |
| `oci-config` | `/.oci/config` | INI — OCI CLI config with canary in `pass_phrase` |
| `oci-api-key-pem` | `/.oci/oci_api_key.pem` | PEM — RSA private key with canary in key material |
| `hcloud-cli` | `/.config/hcloud/cli.toml`, `/.hcloud.toml`, `/hcloud.yml`, `/root/…`, `/home/ubuntu/…` | TOML — Hetzner Cloud CLI with canary as `token` |
| `civo-cli` | `/.config/civo/civo.json`, `/root/…` | JSON — Civo CLI with canary as API key |
| `exoscale-cli` | `/.config/exoscale/exoscale.toml`, `/root/…` | TOML — Exoscale CLI with canary as `key`+`secret` |
| `scaleway-cli` | `/.config/scw/config.yaml`, `/.config/scaleway/config.yaml`, `/root/…` | YAML — Scaleway CLI with canary as `access_key`+`secret_key` |
| `fly-cli` | `/.fly/auth.yml`, `/.config/fly/config.yml` | YAML — Fly.io CLI with canary as `access_token` |
| `ovh-conf` | `/.ovh.conf`, `/root/…`, `/home/ubuntu/…` | INI — OVHcloud CLI with canary as `application_key`+`application_secret`+`consumer_key` |
| `openstack-clouds-yaml` | `/.config/openstack/clouds.yaml`, `/clouds.yaml`, `/root/…` | YAML — OpenStack `clouds.yaml` with canary as application credentials |
| `terraform-credentials-tfrc` | `/.terraform.d/credentials.tfrc.json`, `/root/…` | JSON — Terraform Cloud credentials with canary as HCP token |
| `terraformrc` | `/.terraformrc`, `/root/…` | HCL — `.terraformrc` with canary as HCP token |
| `pulumi-credentials` | `/.pulumi/credentials.json`, `/root/…` | JSON — Pulumi credentials with canary as access token |
| `doctl-config` | `/.config/doctl/config.yaml`, `/root/…` | YAML — DigitalOcean CLI with canary as `access-token` |
| `linode-cli` | `/.linode-cli`, `/root/…` | INI — Linode CLI with canary as `token` |
| `s3cfg` | `/.s3cfg`, `/root/…` | INI — s3cmd config with canary as `access_key`+`secret_key` |
| `passwd-s3fs` | `/.passwd-s3fs`, `/root/…` | Text — s3fs credentials with canary as `key:secret` |
| `cargo-credentials` | `/.cargo/credentials` | TOML — Cargo/crates.io with canary as registry token |
| `gem-credentials` | `/.gem/credentials` | YAML — RubyGems with canary as API key |
| `gh-hosts-yml` | `/.config/gh/hosts.yml`, `/root/…` | YAML — GitHub CLI with canary as `oauth_token` |
| `1password-config` | `/.config/op/config`, `/root/…` | JSON — 1Password CLI with canary as `accountKey` |
| `cloudflared-config` | `/etc/cloudflared/config.yml`, `/etc/cloudflared/cert.pem` | YAML — Cloudflare Tunnel with canary as `secret` |
| `wireguard-conf` | `/etc/wireguard/wg0.conf` | INI — WireGuard with canary as `PresharedKey` |
| `headscale-config` | `/etc/headscale/config.yaml`, `/etc/headscale/private.key` | YAML — Headscale with canary as `private_key` |

## Why

Credential scanners increasingly enumerate smaller cloud providers'
CLI config files alongside standard AWS/GCP/Azure paths. The same
scanner sweep often hits OCI, Hetzner, Civo, Exoscale, Scaleway,
Fly.io, OVH, OpenStack, Terraform Cloud, Pulumi, and DigitalOcean
CLI configs in a single dictionary pass. Covering these paths turns
every probe into a canary issuance opportunity and gives visibility
into which providers attackers prioritize for credential theft.
