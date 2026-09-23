"""System files answered by their own absolute path, and the log line's
record of which deployment answered.

Two defects, both found by probing a running server rather than by
reading the code, and both invisible to a unit test that calls a
renderer directly.

1. **The system-file table was reachable only behind `/@fs/`.** A read
   primitive delivers an absolute path two ways: under the dev-server
   prefix, and as the bare name once the traversal spelling
   (`/static../etc/passwd`, `/js../etc/passwd`) has been collapsed by
   path normalisation — or with no traversal at all, which is how a
   dictionary asks. Every entry in the table answered the first and
   404'd the other two, so the surface written to make an arbitrary-read
   bypass behave like a real one declined the commonest way of
   exercising it. The trap table has answered bare `/proc/self/environ`
   since it shipped, which is the precedent and also the inconsistency:
   a process with an environment block and no command line is a sharper
   tell than either body.

2. **`effectiveHost` was never recorded.** Where TLS is terminated by a
   front end proxying to a loopback upstream, `Host` and
   `X-Forwarded-Host` both arrive as that upstream's own address. The
   renderers have resolved past it since `_appliance_display_host`
   landed; the log had not, so the row recording a canary issuance could
   not be joined back to the name the client was served.
"""
import pytest

from flux import server as tbenv
from .test_server import _log_entries, flux_client  # noqa: F401


# The names a container-recon sweep reads in one pass. `environ` is in
# the list because it is the leg that already worked — the others are
# only interesting relative to it.
CONTAINER_RECON_READS = [
    "/.dockerenv",
    "/proc/self/cgroup",
    "/proc/self/cmdline",
    "/proc/self/environ",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
]

# A representative entry from each renderer family in the table.
SYSTEM_FILE_READS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/nginx/nginx.conf",
    "/etc/php/8.2/fpm/php.ini",
    "/usr/local/etc/php/php.ini",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    "/.dockerenv",
    "/proc/self/cgroup",
    "/proc/1/cgroup",
    "/proc/self/cmdline",
    "/proc/1/cmdline",
]

# Traversal spellings observed carrying `/etc/passwd`. `normalize_path`
# collapses each to the bare absolute name before dispatch sees it, so
# they are the same lookup — the point of asserting them is that the
# collapse and the new branch actually meet.
TRAVERSAL_SPELLINGS = [
    "/static../etc/passwd",
    "/js../etc/passwd",
    "/css../etc/passwd",
    "/assets../etc/passwd",
    "/public../etc/passwd",
    "/media../etc/passwd",
    "/files../etc/passwd",
]

# Names that must stay 404. Absolute system paths do not move with a
# project, so the layout walk that serves `/app/.env` must not serve
# `/app/etc/passwd`; and the table is a fixed list, not a switch that
# says yes to anything under `/etc`.
MUST_NOT_MATCH = [
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/group",
    "/app/etc/passwd",
    "/var/www/html/etc/passwd",
    "/proc/self/maps",
    "/proc/self/status",
    "/dockerenv",
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/var/run/secrets/kubernetes.io/serviceaccount/key",
]


@pytest.mark.parametrize("path", SYSTEM_FILE_READS)
async def test_absolute_system_path_is_answered(flux_client, path):
    resp = await flux_client.get(path)
    assert resp.status == 200, f"{path} 404'd by its own absolute name"


@pytest.mark.parametrize("path", SYSTEM_FILE_READS)
def test_absolute_system_path_resolves_without_the_fs_prefix(path):
    assert tbenv.find_system_file(path) is not None


@pytest.mark.parametrize("path", TRAVERSAL_SPELLINGS)
async def test_collapsed_traversal_reaches_the_same_file(flux_client, path):
    resp = await flux_client.get(path)
    assert resp.status == 200
    assert b"root:x:0:0:" in await resp.read()


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
async def test_near_miss_names_stay_404(flux_client, path):
    assert tbenv.find_system_file(path) is None
    resp = await flux_client.get(path)
    assert resp.status == 404, f"{path} was answered and should not be"


async def test_case_is_folded(flux_client):
    """Every other credential route folds case; this one has to as well
    or the same file has two outcomes for no reason the caller can see."""
    resp = await flux_client.get("/ETC/Passwd")
    assert resp.status == 200


@pytest.mark.parametrize("path", SYSTEM_FILE_READS)
async def test_disable_switch_404s_every_entry(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "SYSTEM_FILE_READS_ENABLED", False)
    resp = await flux_client.get(path)
    assert resp.status == 404


@pytest.mark.parametrize("path", SYSTEM_FILE_READS)
async def test_answered_without_an_issuing_key(flux_client, monkeypatch, path):
    """None of these bodies carries a canary, so a keyless deployment —
    where almost nothing else answers — keeps the read oracle."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(path)
    assert resp.status == 200


@pytest.mark.parametrize("path", CONTAINER_RECON_READS)
async def test_container_recon_sweep_is_answered_whole(flux_client, path):
    """The four-file read that decides "is this a container, under what,
    running what" plus the cluster identity it leads to. One leg
    answered and three 404ing describes a machine that does not exist."""
    resp = await flux_client.get(path)
    assert resp.status == 200


async def test_dockerenv_is_empty(flux_client):
    """Real `/.dockerenv` is zero bytes — its existence is the whole
    message, and a body would be the tell."""
    resp = await flux_client.get("/.dockerenv")
    assert resp.status == 200
    assert await resp.read() == b""


async def test_cgroup_names_a_pod_and_varies_per_hit(flux_client):
    first = (await (await flux_client.get("/proc/self/cgroup")).read()).decode()
    second = (await (await flux_client.get("/proc/self/cgroup")).read()).decode()
    assert first.startswith("0::/kubepods.slice/")
    assert "cri-containerd-" in first
    assert first != second, (
        "a fixed pod/container ID would be one pod shared by every host "
        "running this software"
    )


async def test_cmdline_is_nul_separated_and_agrees_with_environ(flux_client):
    """Read in the same pass as `/proc/self/environ`, so the runtime the
    two name has to be the same one."""
    cmdline = await (await flux_client.get("/proc/self/cmdline")).read()
    assert cmdline.endswith(b"\x00") and b"\n" not in cmdline
    assert b"node" in cmdline
    environ = await (await flux_client.get("/proc/self/environ")).read()
    assert b"NODE_ENV=production" in environ


async def test_read_is_logged_with_its_own_result_tag(flux_client):
    await flux_client.get("/var/run/secrets/kubernetes.io/serviceaccount/token")
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "k8s-serviceaccount-token"
    assert entries[-1]["status"] == 200
    assert entries[-1]["bytes"] > 0


async def test_fs_prefix_read_keeps_its_own_prefixed_tag(flux_client):
    """The two surfaces stay distinguishable in the log: the prefixed tag
    is still what an `/@fs/` read produces, so a pass counting direct
    reads against dev-server reads keeps working."""
    await flux_client.get("/@fs/etc/passwd")
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"].endswith("etc-passwd")
    assert entries[-1]["result"] != "etc-passwd"


async def test_environ_keeps_its_canary_bearing_trap(flux_client, monkeypatch):
    """`/proc/self/environ` has a table entry of its own and must keep
    it — the trap lookup runs first for exactly this reason."""
    assert tbenv.find_canary_trap("/proc/self/environ") is not None
    resp = await flux_client.get("/proc/self/environ")
    entries = _log_entries(flux_client.log_path)
    assert resp.status == 200
    assert entries[-1]["result"] != "proc-cgroup"


# --- effectiveHost -------------------------------------------------------


async def test_effective_host_records_the_name_the_response_used(
    flux_client, monkeypatch
):
    monkeypatch.setattr(tbenv, "SITE_HOST", "shop.example.net")
    await flux_client.get("/.dockerenv", headers={"Host": "127.0.0.1"})
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["host"] == "127.0.0.1"
    assert entry["effectiveHost"] == "shop.example.net"


async def test_effective_host_absent_when_the_request_host_is_usable(
    flux_client, monkeypatch
):
    """Stamped only on the difference, so its presence is exactly the
    "a proxy rewrote the name" signal."""
    monkeypatch.setattr(tbenv, "SITE_HOST", "shop.example.net")
    await flux_client.get("/.dockerenv", headers={"Host": "shop.example.net"})
    assert "effectiveHost" not in _log_entries(flux_client.log_path)[-1]


async def test_effective_host_absent_when_nothing_better_is_known(
    flux_client, monkeypatch
):
    """An unconfigured deployment behind such a proxy has no better name
    to offer, and an empty string is not one."""
    monkeypatch.setattr(tbenv, "SITE_HOST", "")
    await flux_client.get("/.dockerenv", headers={"Host": "127.0.0.1"})
    assert "effectiveHost" not in _log_entries(flux_client.log_path)[-1]


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "localhost", "[::1]", "10.0.0.5", "0.0.0.0:18080"]
)
def test_loopback_and_literal_hosts_are_not_externally_plausible(host, monkeypatch):
    monkeypatch.setattr(tbenv, "SITE_HOST", "shop.example.net")
    assert tbenv._external_host_or_site(host) == "shop.example.net"


def test_appliance_display_host_still_falls_back_to_its_vendor_default(monkeypatch):
    """The refactor must not change what the renderers get."""
    monkeypatch.setattr(tbenv, "SITE_HOST", "")
    assert tbenv._appliance_display_host("127.0.0.1", "rdweb") == "rdweb"
    assert tbenv._appliance_display_host("vpn.example.org", "rdweb") == "vpn.example.org"
