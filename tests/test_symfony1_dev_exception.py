"""symfony 1.x dev front-controller exception page, and the leak -> login
replay attribution that rides on every canary-trap DB password."""

from __future__ import annotations

import re

import pytest

from flux import server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401

AWS = FAKE_TRACEBIT["aws"]

MUST_MATCH = ("/frontend_dev.php/$", "/frontend_dev.php/%24", "/FRONTEND_DEV.PHP/$", "/frontend_dev.php/")
MUST_NOT_MATCH = ("/frontend_dev.php/foo", "/backend_dev.php/$", "/frontend.php/$", "/app_dev.php/$")


def _render(path="/frontend_dev.php/$"):
    return tbenv.render_symfony1_dev_exception(
        {**FAKE_TRACEBIT, "_requestPath": path, "_requestHost": "shop.example", "_clientIp": "198.51.100.7"},
    ).decode()


def _db_password(page: str) -> str:
    m = re.search(r"DB_PASSWORD: (\S+)", page)
    assert m, "premise: the page must carry a DB password"
    return m.group(1)


@pytest.mark.parametrize("path", MUST_MATCH)
def test_paths_resolve(path):
    trap = tbenv.find_canary_trap(tbenv.normalize_path(path))
    assert trap is not None and trap.name == "symfony1-dev-exception"


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
def test_other_paths_do_not_resolve(path):
    trap = tbenv.find_canary_trap(tbenv.normalize_path(path))
    assert trap is None or trap.name != "symfony1-dev-exception"


def test_bare_controller_stays_with_its_existing_handler():
    assert tbenv.find_canary_trap("/frontend_dev.php") is None


def test_page_is_the_sf1_exception_with_the_canary_in_app_settings():
    page = _render()
    assert "<h1>[sfError404Exception]</h1>" in page
    assert "Action &quot;$/index&quot; does not exist." in page
    assert "symfony v.1.4.20" in page
    assert f"access_key: {AWS['awsAccessKeyId']}\n" in page
    assert f"secret_key: {AWS['awsSecretAccessKey']}\n" in page
    assert "HTTP_HOST: shop.example" in page
    assert "SCRIPT_NAME: /frontend_dev.php" in page


def test_trailing_slash_renders_the_empty_module_message():
    assert "Empty module and/or action" in _render("/frontend_dev.php/")


def test_no_fixed_secret_material():
    a, b = _render(), _render()
    assert _db_password(a) != _db_password(b)
    pick = lambda p, k: re.search(rf"{k}: (\S+)", p).group(1)  # noqa: E731
    assert pick(a, "    password") != pick(b, "    password")
    assert pick(a, "csrf_secret") != pick(b, "csrf_secret")


@pytest.fixture
def canary(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    monkeypatch.setattr(tbenv, "_ISSUED_SECRET_INDEX", type(tbenv._ISSUED_SECRET_INDEX)())


async def _leak(flux_client, ip="203.0.113.50"):  # noqa: F811
    resp = await flux_client.get("/frontend_dev.php/$", headers={"X-Forwarded-For": ip})
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/html")
    page = (await resp.read()).decode()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "symfony1-dev-exception"
    return page, entry


async def test_served_leak_logs_a_fingerprint_per_minted_password(flux_client, canary):  # noqa: F811
    page, entry = await _leak(flux_client)
    fps = entry["syntheticSecretFps"]
    assert len(fps) == 2  # DB + mailer
    assert tbenv._secret_fp(_db_password(page)) in fps
    # The fingerprint is not the password.
    assert _db_password(page) not in str(entry)


async def test_adminer_replay_of_a_leaked_password_is_attributed(flux_client, canary):  # noqa: F811
    page, leak_entry = await _leak(flux_client)
    pwd = _db_password(page)
    body = (
        "auth%5Bdriver%5D=server&auth%5Bserver%5D=db.internal&auth%5Busername%5D=sfapp"
        f"&auth%5Bpassword%5D={pwd}&auth%5Bdb%5D=sfapp_prod&token=x"
    ).encode()
    resp = await flux_client.post(
        "/adminer.php", data=body,
        headers={"X-Forwarded-For": "203.0.113.50", "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "adminer-credential-post"
    assert entry["pwdFp"] == tbenv._secret_fp(pwd)
    assert entry["pwdFp"] in leak_entry["syntheticSecretFps"]
    replay = entry["pwdReplayOf"]
    assert replay["trap"] == "symfony1-dev-exception"
    assert replay["requestId"] == leak_entry["requestId"]
    assert replay["sameClient"] is True


async def test_phpmyadmin_replay_from_another_client_is_attributed(flux_client, canary, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tbenv, "PHPMYADMIN_ENABLED", True)
    page, _ = await _leak(flux_client)
    pwd = _db_password(page)
    resp = await flux_client.post(
        "/phpmyadmin/index.php",
        data=f"pma_username=sfapp&pma_password={pwd}&server=1&token=t".encode(),
        headers={"X-Forwarded-For": "198.51.100.99", "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "phpmyadmin-credential-post"
    assert entry["pwdReplayOf"]["trap"] == "symfony1-dev-exception"
    assert entry["pwdReplayOf"]["sameClient"] is False


async def test_dictionary_password_is_not_fingerprinted(flux_client, canary):  # noqa: F811
    resp = await flux_client.post(
        "/adminer.php",
        data=b"auth%5Busername%5D=root&auth%5Bpassword%5D=123456&auth%5Bdriver%5D=server",
        headers={"X-Forwarded-For": "203.0.113.9", "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert "pwdFp" not in entry and "pwdReplayOf" not in entry


def test_issued_index_is_bounded(monkeypatch):
    monkeypatch.setattr(tbenv, "_ISSUED_SECRET_INDEX", type(tbenv._ISSUED_SECRET_INDEX)())
    monkeypatch.setattr(tbenv, "_ISSUED_SECRET_INDEX_MAX", 3)
    for i in range(5):
        tbenv._register_issued_secrets([f"pw{i}"], "t", f"r{i}", "ip")
    assert len(tbenv._ISSUED_SECRET_INDEX) == 3
    assert tbenv._secret_fp("pw0") not in tbenv._ISSUED_SECRET_INDEX


def test_password_minted_outside_a_trap_is_not_collected():
    assert tbenv._ISSUED_SECRETS.get() is None
    tbenv._fake_db_password()
    assert tbenv._ISSUED_SECRETS.get() is None
