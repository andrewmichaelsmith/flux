"""The INI spelling of the generic app config, and `.htaccess`.

Both were the one missing member of a set this honeypot otherwise
answers in full. The app-config family carried `.php`, `.py`, `.yaml`,
`.toml`, `.json` and `.properties` but not `.ini` -- the most
conventional extension of the seven -- so a dictionary walking the
format set got six canaries and one 404. `.htaccess` is the same shape
one family over: `.htpasswd` answered, its sibling did not, while the
same secrets-dredge dictionaries ask for both beside `.env` and
`wp-config.php`.
"""
import pytest

import flux.server as tbenv
from tests.test_server import flux_client, _log_entries  # noqa: F401


# --- routing -----------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/config.ini", "/conf.ini", "/settings.ini", "/app.ini",
    "/database.ini", "/db.ini", "/secrets.ini", "/credentials.ini",
    "/config/config.ini", "/config/database.ini", "/config/settings.ini",
    "/app.config",
])
def test_ini_paths_resolve_to_the_ini_family(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} resolves to nothing"
    assert trap.name == "app-config-ini"


@pytest.mark.parametrize("path", [
    "/.htaccess", "/.htaccess.bak", "/.htaccess.old",
    "/.htaccess.txt", "/.htaccess~",
])
def test_htaccess_paths_resolve_to_the_htaccess_family(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} resolves to nothing"
    assert trap.name == "htaccess"


@pytest.mark.parametrize("path", [
    "/.flaskenv", "/app/.flaskenv",
])
def test_flaskenv_takes_the_env_renderer(path):
    """Flask reads it with the same `python-dotenv` that reads `.env`,
    and projects put secrets in either file, so it is the same body."""
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} resolves to nothing"
    assert trap.name == "env-production"


@pytest.mark.parametrize("path", ["/.env.1", "/.env.2", "/.env.3"])
def test_dotted_numeric_env_siblings_are_canaries_not_tarpit(path):
    """`1`/`2` were covered but `.1`/`.2` were not, so the separator
    decided whether a canary was served."""
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} resolves to nothing"
    assert trap.name == "env-production"
    assert not tbenv.is_tarpit_path(path)


@pytest.mark.parametrize("path", [
    "/conf.json", "/config/database.json", "/config/mail.json",
    "/config/smtp.json",
])
def test_topic_named_json_configs_resolve(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} resolves to nothing"
    assert trap.name == "app-config-json"


@pytest.mark.parametrize("path", [
    # Owned by the dedicated cloud families. Claiming these under
    # `/config/` would shadow the layout walk that resolves
    # `/admin/config/aws.json` to the AWS renderer.
    "/config/aws.json", "/config/credentials.json",
])
def test_cloud_credential_json_names_are_not_claimed_by_app_config(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    if trap is not None:
        assert trap.name != "app-config-json"


def test_ini_family_inherits_the_editor_leftovers(path="/config.ini"):
    """Membership of the suffix family is the point -- the siblings are a
    property of the family, not a list each new table re-types."""
    assert "app-config-ini" in tbenv._APP_CONFIG_SUFFIX_FAMILY
    assert "htaccess" in tbenv._APP_CONFIG_SUFFIX_FAMILY
    for suffix in (".bak", ".old", "~", ".tmp"):
        assert tbenv._TRAP_BY_PATH.get(path + suffix) is not None, suffix


@pytest.mark.parametrize("path", [
    "/config.ini", "/app.config", "/.htaccess", "/.flaskenv", "/.env.1",
])
def test_new_paths_are_not_shadowed_by_the_tarpit(path):
    """Tarpit dispatch runs before CanaryTrap lookup; a path it claims
    drips junk and issues no canary."""
    assert not tbenv.is_tarpit_path(path)


# --- rendered bodies ---------------------------------------------------

def test_ini_body_parses_as_ini_and_carries_no_fixed_secret():
    import configparser
    first = tbenv.render_generic_config_ini({}).decode()
    second = tbenv.render_generic_config_ini({}).decode()

    cp = configparser.ConfigParser()
    cp.read_string(first)
    assert {"app", "database", "redis", "aws", "smtp"} <= set(cp.sections())

    # Every credential-shaped field must differ per hit.
    for section, key in [
        ("app", "secret_key"), ("database", "password"),
        ("redis", "password"), ("smtp", "password"),
    ]:
        a = cp[section][key]
        cp2 = configparser.ConfigParser(); cp2.read_string(second)
        assert a and a != cp2[section][key], f"{section}.{key} is fixed"


def test_htaccess_body_has_the_apache_furniture_and_no_fixed_secret():
    first = tbenv.render_htaccess({}).decode()
    second = tbenv.render_htaccess({}).decode()
    assert "RewriteEngine On" in first
    assert "SetEnv AWS_ACCESS_KEY_ID" in first
    # Names the sibling the family already answers, so the file suggests
    # its own next request.
    assert "AuthUserFile" in first and ".htpasswd" in first

    def db_password(doc):
        line = [l for l in doc.splitlines() if "DB_PASSWORD" in l][0]
        return line.split()[-1]
    assert db_password(first) != db_password(second), "DB_PASSWORD is fixed"


# --- end to end --------------------------------------------------------

async def test_config_ini_serves_a_canary(flux_client):
    resp = await flux_client.get(
        "/config.ini", headers={"X-Forwarded-For": "203.0.113.21"}
    )
    assert resp.status == 200
    body = await resp.text()
    assert "[database]" in body and "aws_access_key_id" in body


async def test_htaccess_serves_a_canary(flux_client):
    resp = await flux_client.get(
        "/.htaccess", headers={"X-Forwarded-For": "203.0.113.22"}
    )
    assert resp.status == 200
    body = await resp.text()
    assert "SetEnv AWS_ACCESS_KEY_ID" in body
