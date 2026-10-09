"""Embedded-database canary trap.

The dredging dictionaries that walk `<base>.<archive ext>` also walk
`<base>.db` / `.sqlite` / `.sqlite3`, because an embedded database left
in the webroot carries the user table and the service credentials in one
file. Those spellings used to 404: the archive matcher deliberately owns
only compressed and dump extensions, and answering a database request
with a tarball would be a tell rather than a trap.

What makes this worth serving is that the body is a real database. The
GCP credential table declined `credentials.db` on the grounds that a
malformed SQLite is more revealing than a 404 — true of a stub, and the
reason these tests check that every flavour actually opens and that the
canary is readable through a SQL query rather than only present in the
bytes.
"""
import sqlite3
import tempfile
from pathlib import Path

import pytest

import flux.server as tbenv

from tests.test_server import FAKE_TRACEBIT


def _open(body: bytes) -> sqlite3.Connection:
    """Write the served bytes out and open them the way a harvester would."""
    handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    handle.write(body)
    handle.close()
    return sqlite3.connect(Path(handle.name))


def test_sqlite_db_enabled_by_default():
    assert tbenv.SQLITE_DB_ENABLED


@pytest.mark.parametrize("path,flavour", [
    # Root-level database names.
    ("/database.sqlite", "sqlite"),
    ("/db.sqlite", "sqlite"),
    ("/data.sqlite", "sqlite"),
    ("/dump.sqlite", "sqlite"),
    ("/app.sqlite", "sqlite"),
    ("/database.sqlite3", "sqlite3"),
    ("/db.sqlite3", "sqlite3"),
    ("/app.db", "db"),
    ("/data.db", "db"),
    ("/prod.db", "db"),
    ("/production.db", "db"),
    ("/users.db", "db"),
    ("/main.db", "db"),
    ("/local.db", "db"),
    ("/sessions.db", "db"),
    # A trailing index is how the second database on a box gets named.
    ("/db1.sqlite", "sqlite"),
    ("/db2.db", "db"),
    # One directory segment, when the directory is one a database really
    # lives in.
    ("/db/data.sqlite", "sqlite"),
    ("/storage/database.sqlite", "sqlite"),
    ("/data/app.db", "db"),
    ("/writable/db.sqlite3", "sqlite3"),
    ("/sites/default/files/db.sqlite", "sqlite"),
    # The gcloud CLI's own two SQLite files, in every spelling the
    # credential table already lifts for their JSON sibling.
    ("/.config/gcloud/credentials.db", "gcloud-credentials"),
    ("/.config/gcloud/access_tokens.db", "gcloud-tokens"),
    ("/gcloud/credentials.db", "gcloud-credentials"),
    ("/.gcloud/credentials.db", "gcloud-credentials"),
    ("/root/.config/gcloud/credentials.db", "gcloud-credentials"),
    ("/home/ubuntu/.config/gcloud/access_tokens.db", "gcloud-tokens"),
])
def test_sqlite_db_match(path, flavour):
    assert tbenv.is_sqlite_db_path(path), f"expected match: {path}"
    assert tbenv._sqlite_db_match(path) == flavour


@pytest.mark.parametrize("path", [
    # Not a database extension.
    "/database.sql",
    "/backup.zip",
    "/db.php",
    "/db",
    # Unknown stem.
    "/qzzzzzzzzz.sqlite",
    "/tracking-pixel.db",
    # A directory no database lives in, and more than one segment.
    "/wp-content/uploads/app.db",
    "/assets/vendor/data.db",
    # The 1.7+ SVN working copy is a real database with its own
    # renderer; this trap must not take it.
    "/.svn/wc.db",
    # Double-slash spellings a normaliser leaves behind.
    "//app.db",
    "/db//data.sqlite",
    # Empty / degenerate.
    "/.db",
    "/",
])
def test_sqlite_db_non_match(path):
    assert not tbenv.is_sqlite_db_path(path), f"unexpected match: {path}"


def test_sqlite_db_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "SQLITE_DB_ENABLED", False)
    assert not tbenv.is_sqlite_db_path("/database.sqlite")


@pytest.mark.parametrize(
    "flavour", ["db", "sqlite", "sqlite3", "gcloud-credentials", "gcloud-tokens"]
)
def test_body_is_a_real_openable_database(flavour):
    """The whole premise of the trap: a client that opens it survives."""
    body, content_type = tbenv._build_sqlite_db_body(FAKE_TRACEBIT, flavour)
    assert body.startswith(b"SQLite format 3\x00"), "not a SQLite file"
    assert content_type == "application/vnd.sqlite3"
    connection = _open(body)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        connection.close()
    assert tables, "database has no tables"


def test_application_database_carries_the_canary_in_settings():
    body, _ = tbenv._build_sqlite_db_body(FAKE_TRACEBIT, "db")
    connection = _open(body)
    try:
        settings = dict(connection.execute("SELECT key, value FROM settings"))
        users = list(connection.execute("SELECT username, role FROM users"))
    finally:
        connection.close()
    assert settings["aws_access_key_id"] == "AKIAFAKEEXAMPLE01"
    assert (
        settings["aws_secret_access_key"]
        == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    assert settings["aws_session_token"] == "FwoGZXIvYXdzEXAMPLEFAKE="
    assert users, "no user rows"


def test_gcloud_credentials_carries_a_refresh_token_in_its_own_schema():
    body, _ = tbenv._build_sqlite_db_body(FAKE_TRACEBIT, "gcloud-credentials")
    connection = _open(body)
    try:
        rows = list(connection.execute("SELECT account_id, value FROM credentials"))
    finally:
        connection.close()
    assert len(rows) == 1
    account, value = rows[0]
    assert "@" in account
    assert '"refresh_token"' in value and "1//0g" in value


def test_gcloud_tokens_carries_an_access_token_in_its_own_schema():
    body, _ = tbenv._build_sqlite_db_body(FAKE_TRACEBIT, "gcloud-tokens")
    connection = _open(body)
    try:
        rows = list(
            connection.execute(
                "SELECT account_id, access_token FROM access_tokens"
            )
        )
    finally:
        connection.close()
    assert len(rows) == 1
    assert rows[0][1].startswith("ya29.")


@pytest.mark.parametrize(
    "flavour", ["db", "gcloud-credentials", "gcloud-tokens"]
)
def test_every_secret_shaped_field_is_per_hit(flavour):
    """No fixed literal may ship in a credential-shaped field: a constant
    would give zero detection on replay and make one string the same
    across every host serving this trap."""
    first, _ = tbenv._build_sqlite_db_body(FAKE_TRACEBIT, flavour)
    second, _ = tbenv._build_sqlite_db_body(FAKE_TRACEBIT, flavour)
    assert first != second, f"{flavour} renders identically twice"


def test_application_database_password_fields_differ_between_hits():
    def _secrets(body: bytes) -> tuple[str, ...]:
        connection = _open(body)
        try:
            settings = dict(connection.execute("SELECT key, value FROM settings"))
            hashes = [
                row[0]
                for row in connection.execute("SELECT password_hash FROM users")
            ]
        finally:
            connection.close()
        return (
            settings["db_password"],
            settings["smtp_password"],
            settings["app_key"],
            *hashes,
        )

    first = _secrets(tbenv._build_sqlite_db_body(FAKE_TRACEBIT, "db")[0])
    second = _secrets(tbenv._build_sqlite_db_body(FAKE_TRACEBIT, "db")[0])
    for a, b in zip(first, second):
        assert a != b, f"credential-shaped field is a fixed literal: {a}"


def test_stem_vocabulary_is_shared_with_the_archive_dictionary():
    """The two dictionaries are the same dictionary with a different
    suffix column, so a base added for one must not go missing from the
    other. `.env` is the deliberate exception: a leading-dot stem is a
    config filename the canary table owns, not a database name."""
    missing = (tbenv._BACKUP_ARCHIVE_BASES - {".env", "env"}) - tbenv._SQLITE_DB_BASES
    assert not missing, f"archive bases missing from the database list: {sorted(missing)}"
