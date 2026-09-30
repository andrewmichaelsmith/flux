"""Completion of the mail-service `.env` family and its non-mail siblings.

Credential-harvesting dictionaries walk a service-name list crossed with a
qualifier list (`<service>.env`, `<service>_config.env`,
`<service>_api_key.env`) under every app-layout prefix. Most of that grid
already answered; the members added here were the 404s inside the same
pass, which meant one sweep collected a canary for some spellings of the
same file and nothing for others.

Three groups:
  * new providers whose bodies need their own key name (`ses`, `mandrill`,
    `elasticemail`),
  * the vendor-neutral spellings (`smtp.env`, `mailer.env`,
    `mail_config.env`),
  * non-mail service leaves that belong to the generic dotenv trap
    (`stripe`, `twilio`, `azure`, `heroku`, `bucket`, `aws_config`,
    `db_config`, `db_credentials`, `application`, `env`).
"""
from __future__ import annotations

import pytest
import pytest_asyncio

from flux import server as tbenv

from .test_server import _fake_issue_credentials  # noqa: F401


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "test-key")
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_issue_credentials)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


NEW_PROVIDERS = ("ses", "mandrill", "elasticemail")
GENERIC_LEAVES = ("smtp", "smtp_config", "mailer", "mail", "mail_config")
NON_MAIL_LEAVES = (
    "stripe", "twilio", "azure", "heroku", "bucket",
    "aws_config", "db_config", "db_credentials", "application", "env",
)


# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("svc", NEW_PROVIDERS)
def test_new_providers_route_to_their_own_config(svc):
    trap, _ = tbenv.resolve_canary_trap(f"/{svc}.env")
    assert trap is not None, svc
    assert trap.name == "mail-service-env"
    assert tbenv._MAIL_SERVICE_PATH_MAP[f"/{svc}.env"][0] == svc


@pytest.mark.parametrize("svc", NEW_PROVIDERS)
def test_new_providers_get_the_dedicated_directory_spelling(svc):
    """`/<service>/.env` alongside the `<service>.env` leaf."""
    assert tbenv._MAIL_SERVICE_PATH_MAP[f"/{svc}/.env"][0] == svc


@pytest.mark.parametrize("leaf", GENERIC_LEAVES)
def test_generic_leaves_render_the_default_provider_shape(leaf):
    assert tbenv._MAIL_SERVICE_PATH_MAP[f"/{leaf}.env"] == (
        tbenv._MAIL_SERVICE_CONFIGS["sendgrid"]
    )


@pytest.mark.parametrize("svc", ("sendgrid", "postmark", "mailjet", "brevo",
                                 "mailgun", "ses", "mandrill", "elasticemail"))
@pytest.mark.parametrize("qual", ("_config", "_api_key", "_credentials", "_key"))
def test_qualified_spellings_keep_their_provider(svc, qual):
    """`mailgun_config.env` must render the Mailgun shape, not the default."""
    cfg = tbenv._MAIL_SERVICE_PATH_MAP.get(f"/{svc}{qual}.env")
    assert cfg is not None, f"/{svc}{qual}.env"
    assert cfg[0] == svc


@pytest.mark.parametrize("leaf", NON_MAIL_LEAVES)
def test_non_mail_leaves_resolve_to_the_generic_dotenv_trap(leaf):
    trap, _ = tbenv.resolve_canary_trap(f"/{leaf}.env")
    assert trap is not None, leaf
    assert trap.name != "mail-service-env"


def test_existing_owners_are_not_stolen():
    """`setdefault` everywhere, so nothing already routed may move."""
    assert tbenv._MAIL_SERVICE_PATH_MAP["/sendgrid.env"][0] == "sendgrid"
    assert tbenv._MAIL_SERVICE_PATH_MAP["/mailgun/.env"][0] == "mailgun"
    # `/aws.env` stays with its dedicated trap, not the env-leaf family.
    assert "aws" not in tbenv._ENV_LEAF_NAMES


def test_nested_spellings_resolve_through_the_layout_walk():
    for path in ("/config/ses.env", "/api/smtp/mandrill.env", "/app/smtp.env"):
        trap, _ = tbenv.resolve_canary_trap(path)
        assert trap is not None, path


@pytest.mark.parametrize("path", ("/9f2a1c/ses.env", "/junkdir/smtp.env",
                                  "/zzz/mandrill.env"))
def test_junk_parents_still_get_nothing(path):
    """The vocabulary gate is unchanged -- an unknown parent stays a 404."""
    trap, _ = tbenv.resolve_canary_trap(path)
    assert trap is None, path


# --------------------------------------------------------------------------
# Rendered bodies
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "svc,key_name",
    [
        ("ses", "AWS_SES_ACCESS_KEY_ID"),
        ("mandrill", "MANDRILL_API_KEY"),
        ("elasticemail", "ELASTICEMAIL_API_KEY"),
    ],
)
def test_new_provider_bodies_carry_the_provider_key_name(svc, key_name):
    body = tbenv.render_mail_service_env(
        {"aws": {"awsAccessKeyId": "AKIATEST", "awsSecretAccessKey": "s",
                 "awsSessionToken": "t"}},
        path=f"/{svc}.env",
    ).decode()
    assert f"{key_name}=" in body
    assert "SMTP_PASSWORD=" in body


@pytest.mark.parametrize("svc", NEW_PROVIDERS)
def test_new_provider_credentials_are_per_hit_unique(svc):
    """No fixed credential literals: two renders must not share a secret."""
    r = {"aws": {"awsAccessKeyId": "AKIATEST", "awsSecretAccessKey": "s",
                 "awsSessionToken": "t"}}
    a = tbenv.render_mail_service_env(r, path=f"/{svc}.env").decode()
    b = tbenv.render_mail_service_env(r, path=f"/{svc}.env").decode()

    def creds(body):
        out = set()
        for line in body.splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            name, _, value = line.partition("=")
            if not value:
                continue
            if name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                        "AWS_SESSION_TOKEN"):
                continue  # the canary triple is fixed by the stub
            if name.endswith(("_API_KEY", "_TOKEN", "_KEY", "_ID",
                              "SMTP_PASSWORD")):
                out.add(value)
        return out

    shared = creds(a) & creds(b)
    assert not shared, f"{svc} emitted a fixed credential literal: {shared}"


@pytest.mark.parametrize("svc", NEW_PROVIDERS)
def test_new_provider_key_shapes_are_per_hit_random(svc):
    key = tbenv._fake_mail_api_key(svc)
    assert key
    assert key != tbenv._fake_mail_api_key(svc)


def test_ses_key_is_akia_shaped():
    """SES has no key of its own -- the SMTP credential is an IAM key, so a
    harvester can test it against the AWS API as well as the relay."""
    assert tbenv._fake_mail_api_key("ses").startswith("AKIA")


# --------------------------------------------------------------------------
# Dispatch over HTTP
# --------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [f"/{s}.env" for s in NEW_PROVIDERS]
    + [f"/{g}.env" for g in GENERIC_LEAVES]
    + [f"/{n}.env" for n in NON_MAIL_LEAVES]
    + ["/config/ses.env", "/ses/.env", "/.smtp.env", "/mailgun_config.env"],
)
async def test_dispatch_serves_the_family(flux_client, path):
    resp = await flux_client.get(path, headers={"Host": "traceenv-x.netqale.com"})
    assert resp.status == 200, path
    assert await resp.read()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ("/9f2a1c/ses.env", "/junkdir/smtp.env"))
async def test_dispatch_leaves_junk_parents_unhandled(flux_client, path):
    resp = await flux_client.get(path, headers={"Host": "traceenv-x.netqale.com"})
    assert resp.status == 404, path
