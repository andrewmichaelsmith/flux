"""The route closures a pass over declined trap paths turned up, and the
one new family beside them.

Four defects, all the same shape as the sibling-spelling gaps pinned in
`test_inference_cloud_credentials.py` -- a dictionary walking one file's
spellings split across two outcomes because only some spellings were in
the table:

1. **NTFS alternate-data-stream suffixes were not canonicalised.**
   `/.env::$DATA` names the same file as `/.env`, and IIS has long
   served it past a handler mapping, so source-disclosure dictionaries
   walk the shape against every config family. Flux carried exactly one
   hand-written literal for it (`/wp-config.php::$DATA`) and 404ed it
   everywhere else. Now folded away in `normalize_path`, which gives
   every family in the table the spelling at once.
2. **Provider-scoped dotenv fragments.** `.env.anthropic` and
   `.env.openai` had dedicated traps; every other provider name went to
   the generic variant chain -- the same shadowing those two traps' own
   comment describes, for the same reason. Cloud-provider names now
   reach `env-production`; AI/LLM provider names reach the new
   `ai-provider-dotenv`.
3. **Webroot prefixes missing from the `<prefix>/.env*` matrix**, which
   is what decided whether a prefixed dotenv minted a canary or got a
   redirect.
4. **Two one-file-two-spellings gaps:** `.dev.vars.<environment>`
   beside the bare `.dev.vars` wrangler reads without `--env`, and the
   pre-1.7 `.dockercfg` beside `.docker/config.json`.

Plus `ide-web-servers`, whose point is not the credential it carries but
the next step it names -- see `render_ide_web_servers_xml`.
"""
import xml.dom.minidom

import pytest

import flux.server as tbenv

from tests.test_server import FAKE_TRACEBIT


# --- 1. NTFS alternate-data-stream canonicalisation ----------------------

@pytest.mark.parametrize("raw,expected", [
    ("/.env::$DATA", "/.env"),
    ("/.env.production::$DATA", "/.env.production"),
    ("/.env.local::$DATA", "/.env.local"),
    ("/.env.development::$DATA", "/.env.development"),
    ("/wp-config.php::$DATA", "/wp-config.php"),
    # Case-insensitive: the stream name is not case-sensitive on NTFS and
    # the dictionaries mix spellings.
    ("/.env::$data", "/.env"),
    ("/.env::$Data", "/.env"),
    # The directory stream, which is the same trick for a directory.
    ("/config.php::$INDEX_ALLOCATION", "/config.php"),
    ("/.git::$INDEX_ALLOCATION", "/.git"),
    # A trailing slash after the stream name still resolves.
    ("/.env::$DATA/", "/.env"),
    # Percent-encoded, which is how it arrives as often as not. The
    # decode runs before the strip.
    ("/.env%3A%3A%24DATA", "/.env"),
])
def test_ntfs_stream_suffix_is_folded_onto_the_real_file(raw, expected):
    assert tbenv.normalize_path(raw) == expected


@pytest.mark.parametrize("raw", [
    # Not a stream suffix: `$DATA` must follow a double colon, and the
    # single-colon spelling is a legal filename character on the
    # filesystems that matter.
    "/.env:$DATA",
    "/report::$SUMMARY",
    "/data",
    "/$DATA",
    # Mid-path is not a position a stream name is legal in, so it stays
    # -- folding it would answer a path nothing serves.
    "/a::$DATA/b",
])
def test_non_stream_suffixes_are_left_alone(raw):
    assert tbenv.normalize_path(raw) == raw


@pytest.mark.parametrize("raw,trap_name", [
    ("/.env.production::$DATA", "env-production"),
    ("/.aws/credentials::$DATA", "aws-credentials-file"),
    ("/.env.llm::$DATA", "ai-provider-dotenv"),
])
def test_stream_spelling_reaches_the_same_trap_as_the_plain_name(raw, trap_name):
    """The reason the strip belongs in `normalize_path` and not in each
    table: one change gives the whole table the spelling."""
    trap = tbenv._TRAP_BY_PATH.get(tbenv.normalize_path(raw).lower())
    assert trap is not None, f"{raw} resolves to no trap"
    assert trap.name == trap_name


def test_stream_suffix_does_not_become_a_second_table_key():
    """`normalize_path` owns the folding, so no trap should carry a
    hand-written stream literal -- one did, and it was dead the moment
    the strip landed."""
    offenders = [p for p in tbenv._TRAP_BY_PATH if "::$" in p]
    assert offenders == [], f"stream literals left in the table: {offenders}"


# --- 2. provider-scoped dotenv fragments ---------------------------------

@pytest.mark.parametrize("path,trap_name", [
    # The two with their own vendor-shaped bodies keep them.
    ("/.env.anthropic", "anthropic-dotenv"),
    ("/.env.openai", "openai-dotenv"),
    # Cloud-provider names: the generic renderer's cloud keys are
    # already what these are being asked for.
    ("/.env.aws", "env-production"),
    ("/.env.azure", "env-production"),
    ("/.env.gcp", "env-production"),
    # AI/LLM provider names.
    ("/.env.ai", "ai-provider-dotenv"),
    ("/.env.llm", "ai-provider-dotenv"),
    ("/.env.gpt", "ai-provider-dotenv"),
    ("/.env.claude", "ai-provider-dotenv"),
    ("/.env.gemini", "ai-provider-dotenv"),
    ("/.env.ollama", "ai-provider-dotenv"),
    ("/.env.litellm", "ai-provider-dotenv"),
    ("/.env.vllm", "ai-provider-dotenv"),
    ("/.env.huggingface", "ai-provider-dotenv"),
    ("/.env.openai.local", "ai-provider-dotenv"),
    ("/.env.anthropic.local", "ai-provider-dotenv"),
])
def test_provider_scoped_dotenv_resolves(path, trap_name):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} does not resolve"
    assert trap.name == trap_name


@pytest.mark.parametrize("path", [
    "/.env.anthropic", "/.env.openai", "/.env.aws", "/.env.llm", "/.env.gpt",
])
def test_provider_scoped_dotenv_is_not_tarpitted(path):
    """The defect these entries exist to fix: `is_tarpit_path` claims
    every `.env`-prefixed leaf and exempts only what the table owns, so
    an unregistered spelling got a redirect chain instead of a canary."""
    assert not tbenv.is_tarpit_path(path)


def test_ai_provider_dotenv_carries_the_canary_in_three_provider_keys():
    body = tbenv.render_ai_provider_dotenv(
        {**FAKE_TRACEBIT, "_requestHost": "example.com"},
    ).decode("utf-8")
    aws = FAKE_TRACEBIT["aws"]
    assert f"OPENAI_API_KEY={aws['awsAccessKeyId']}" in body
    assert f"ANTHROPIC_API_KEY={aws['awsSecretAccessKey']}" in body
    assert f"LLM_GATEWAY_TOKEN={aws['awsSessionToken']}" in body


def test_ai_provider_dotenv_is_dotenv_shaped():
    body = tbenv.render_ai_provider_dotenv(
        {**FAKE_TRACEBIT, "_requestHost": "example.com"},
    ).decode("utf-8")
    for line in body.strip().split("\n"):
        assert "=" in line, line
        assert not line.startswith(" "), line
        key = line.split("=", 1)[0]
        assert key == key.upper(), line


def test_ai_provider_dotenv_base_url_names_the_requested_host():
    """What makes the read measurable: the base URL points at inference
    routes this server already answers, so a client configured from this
    file arrives on that trap carrying the key from this file."""
    body = tbenv.render_ai_provider_dotenv(
        {**FAKE_TRACEBIT, "_requestHost": "sensor.example.org"},
    ).decode("utf-8")
    assert "OPENAI_BASE_URL=https://sensor.example.org/v1" in body
    assert "LLM_GATEWAY_URL=https://sensor.example.org/v1" in body
    assert tbenv.llm_endpoint_route("/v1/chat/completions") is not None


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "", "::1", "10.0.0.7"])
def test_ai_provider_dotenv_never_advertises_a_proxy_rewritten_host(host):
    """A loopback or address literal is what a reverse proxy substitutes
    for the requested name. Publishing it would advertise the reader's
    own machine and, being identical everywhere this runs, fingerprint
    the deployment."""
    body = tbenv.render_ai_provider_dotenv(
        {**FAKE_TRACEBIT, "_requestHost": host},
    ).decode("utf-8")
    url = [l for l in body.split("\n") if l.startswith("OPENAI_BASE_URL=")][0]
    assert host not in url or host == ""
    assert "127.0.0.1" not in url and "localhost" not in url


# --- 3. webroot prefixes in the `<prefix>/.env*` matrix -------------------

@pytest.mark.parametrize("prefix", [
    # Plain application-layout names.
    "data", "env", "infra", "packages", "pkg", "root",
    "services", "settings", "static", "utils", "var", "workspace",
    # The AI/ML-themed cohort.
    "agent", "agents", "ai", "bot", "chatbot", "embeddings",
    "inference", "langchain", "llm", "llms", "ml", "mlflow",
    "model", "models", "notebooks", "pipeline", "prompts", "rag",
    "training", "vectordb",
])
def test_prefixed_dotenv_resolves_for_each_added_prefix(prefix):
    trap = tbenv._TRAP_BY_PATH.get(f"/{prefix}/.env")
    assert trap is not None, f"/{prefix}/.env does not resolve"
    assert trap.name == "env-production"


@pytest.mark.parametrize("dotdir", [".next", ".nuxt"])
def test_framework_build_dir_dotenv_resolves(dotdir):
    trap = tbenv._TRAP_BY_PATH.get(f"/{dotdir}/.env")
    assert trap is not None, f"/{dotdir}/.env does not resolve"
    assert trap.name == "env-production"


@pytest.mark.parametrize("suffix", [
    "_sample", "_1", "_2",
    ".testing", ".www", ".config", ".ini", ".php",
    ".secret", ".secrets", ".dev.local",
])
def test_added_dotenv_suffix_resolves(suffix):
    trap = tbenv._TRAP_BY_PATH.get(f"/.env{suffix}")
    assert trap is not None, f"/.env{suffix} does not resolve"
    assert trap.name == "env-production"


@pytest.mark.parametrize("path", [
    # The vocabulary gate still holds: a plausible deployment layout is
    # answered, not any parent. Answering these would advertise a host
    # that says yes to anything.
    "/9f2a1c/.env",
    "/deadbeef/.env",
    "/zzzz/.env.production",
])
def test_junk_prefixes_still_get_nothing(path):
    assert tbenv._TRAP_BY_PATH.get(path) is None
    trap, _ = tbenv.resolve_canary_trap(path)
    assert trap is None, f"{path} wrongly resolved to {trap.name if trap else None}"


# --- 4. the two one-file-two-spellings gaps ------------------------------

@pytest.mark.parametrize("path", [
    "/.dev.vars",
    "/.dev.vars.production",
    "/.dev.vars.staging",
    "/.dev.vars.preview",
    "/.dev.vars.development",
    "/.dev.vars.dev",
    "/.dev.vars.test",
    "/.dev.vars.local",
    "/.dev.vars.bak",
    "/.dev.vars.old",
])
def test_per_environment_dev_vars_resolve(path):
    """`wrangler` reads `.dev.vars.<environment>` when `--env` is passed,
    so a Workers project with more than one environment has these and
    not the bare file."""
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} does not resolve"
    assert trap.name == "cloudflare-dev-vars"


def test_dev_vars_example_template_is_still_not_served():
    """The committed template with placeholder values. A real repo has
    it, so answering it with a credential is the tell."""
    assert tbenv._TRAP_BY_PATH.get("/.dev.vars.example") is None


@pytest.mark.parametrize("path", ["/.dockercfg", "/dockercfg", "/root/.dockercfg"])
def test_legacy_dockercfg_resolves(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} does not resolve"
    assert trap.name == "legacy-dockercfg"


def test_legacy_dockercfg_is_the_legacy_shape_not_the_modern_one():
    """The pre-1.7 file is a flat registry->credential map with an
    `email` field; the modern one wraps everything in `auths`. Serving
    the modern body at the legacy name is a tell to anyone who knows the
    difference."""
    import base64
    import json as _json
    body = _json.loads(tbenv.render_legacy_dockercfg(FAKE_TRACEBIT))
    assert "auths" not in body
    assert "https://index.docker.io/v1/" in body
    entry = body["https://index.docker.io/v1/"]
    assert "email" in entry
    decoded = base64.b64decode(entry["auth"]).decode("utf-8")
    assert FAKE_TRACEBIT["aws"]["awsSecretAccessKey"] in decoded


# --- 5. the IDE deployment config ----------------------------------------

@pytest.mark.parametrize("path", [
    "/.idea/webservers.xml",
    "/.idea/deployment.xml",
    "/idea/webservers.xml",
    "/root/.idea/webservers.xml",
])
def test_ide_web_servers_resolves(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} does not resolve"
    assert trap.name == "ide-web-servers"


@pytest.mark.parametrize("raw", [
    "/.idea/webServers.xml",
    "/.idea/WebServers.xml",
    "/.IDEA/WEBSERVERS.XML",
])
def test_ide_web_servers_matches_either_capitalisation(raw):
    """Current IDEs write `webServers.xml`, older ones wrote
    `WebServers.xml`, and the dictionaries ask for both. One table entry
    covers both because lookup is case-folded -- which is also why
    listing the second spelling would be a duplicate key."""
    trap = tbenv._TRAP_BY_PATH.get(raw.lower())
    assert trap is not None and trap.name == "ide-web-servers"


def test_ide_web_servers_issues_no_canary():
    """Both credential-shaped fields are per-hit synthetics, so the trap
    spends no issuance quota and has no upstream dependency."""
    assert tbenv._TRAP_BY_PATH["/.idea/webservers.xml"].canary_types == ()


def test_ide_web_servers_is_well_formed_xml():
    body = tbenv.render_ide_web_servers_xml({"_requestHost": "example.com"})
    xml.dom.minidom.parseString(body.decode("utf-8"))


def test_ide_web_servers_names_the_requested_host_as_the_target():
    """A config naming an unreachable `deploy.internal` is bait anyone
    can spot; one naming the host the file was just fetched from is what
    a checked-in deploy config looks like -- and it is what makes the
    follow-through observable on this host's SSH surface."""
    body = tbenv.render_ide_web_servers_xml(
        {"_requestHost": "sensor.example.org"},
    ).decode("utf-8")
    assert 'host="sensor.example.org" port="22"' in body
    assert 'accessType="SFTP"' in body


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "", "::1"])
def test_ide_web_servers_never_names_a_proxy_rewritten_host(host):
    body = tbenv.render_ide_web_servers_xml({"_requestHost": host}).decode("utf-8")
    assert "127.0.0.1" not in body
    assert 'host="localhost"' not in body


def test_ide_web_servers_username_is_per_hit_unique_with_a_stable_prefix():
    """The prefix is what makes a login attempt recognisable as "somebody
    acted on a config served from here"; the random suffix is what traces
    one attempt back to one read."""
    import re
    bodies = [
        tbenv.render_ide_web_servers_xml({"_requestHost": "example.com"}).decode("utf-8")
        for _ in range(8)
    ]
    users = [re.search(r'username="([^"]+)"', b).group(1) for b in bodies]
    assert all(u.startswith("deploy_") for u in users), users
    assert len(set(users)) == len(users), f"username repeated across hits: {users}"


def test_ide_web_servers_password_is_per_hit_unique():
    """A fixed literal gives zero detection on replay and ships the same
    string from every host running this, which is a fleet fingerprint."""
    import re
    bodies = [
        tbenv.render_ide_web_servers_xml({"_requestHost": "example.com"}).decode("utf-8")
        for _ in range(8)
    ]
    pws = [re.search(r'password="([^"]+)"', b).group(1) for b in bodies]
    assert len(set(pws)) == len(pws), "password repeated across hits"
    assert all(len(p) >= 16 for p in pws), pws


@pytest.mark.parametrize("host", ["a&b.example.com", "x&amp;y.example.net"])
def test_ide_web_servers_escapes_the_host_into_the_xml(host):
    """`_host_is_externally_plausible` rejects the quote and angle
    brackets but permits `&`, which is enough on its own to make the
    document malformed -- and a deploy config that does not parse reads
    as a trap."""
    body = tbenv.render_ide_web_servers_xml({"_requestHost": host})
    xml.dom.minidom.parseString(body.decode("utf-8"))
