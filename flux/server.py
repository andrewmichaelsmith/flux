#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, quote, unquote

import aiohttp
from aiohttp import web


API_BASE_URL = (os.environ.get("TRACEBIT_API_BASE_URL", "https://community.tracebit.com") or "https://community.tracebit.com").rstrip("/")
API_KEY = (os.environ.get("TRACEBIT_API_KEY") or "").strip()
SENSOR_ID = (os.environ.get("SENSOR_ID") or "").strip()
CANARY_TYPES = [
    value.strip()
    for value in (os.environ.get("TRACEBIT_ENV_CANARY_TYPES_CSV") or "aws,gitlab-username-password").split(",")
    if value.strip()
]
TRACEBIT_SOURCE = (os.environ.get("TRACEBIT_ENV_CANARY_SOURCE") or "flux").strip()
TRACEBIT_SOURCE_TYPE = (os.environ.get("TRACEBIT_ENV_CANARY_SOURCE_TYPE") or "endpoint").strip()
LOG_PATH = Path(os.environ.get("TRACEBIT_ENV_LOG_PATH") or "/var/log/honeypot/tracebit/env-canary.jsonl")
TARPIT_ENABLED = (os.environ.get("TRACEBIT_ENV_TARPIT_ENABLED") or "true").strip().lower() in {"1", "true", "yes", "on"}
TARPIT_SECONDS = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_SECONDS") or "0").strip() or "0"), 0)
TARPIT_CHUNK_BYTES = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_CHUNK_BYTES") or "32").strip() or "32"), 1)
TARPIT_INTERVAL_MS = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_INTERVAL_MS") or "2000").strip() or "2000"), 100)
# Default sized for the async event loop, not a thread pool: each held
# drip is ~8 KB of coroutine state, not an OS thread. 256 is a safe
# ceiling on a 1 GB VM; raise it if scanners ever trip this.
TARPIT_MAX_CONNECTIONS = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_MAX_CONNECTIONS") or "256").strip() or "256"), 1)
_active_slow_drips = 0  # tarpit + fake-git share this cap; bumped per event loop (single-threaded).
HEADER_VALUE_LOG_LIMIT = 512
LOG_HEADER_NAMES = "Host,X-Forwarded-Host,X-Forwarded-For,X-Forwarded-Proto,True-Client-Ip,X-Real-Ip,X-Client-Ip,X-Azure-Clientip,X-Azure-Socketip,X-Originating-Ip,X-Host,Cf-Connecting-Ip,Content-Type,Content-Length".split(",")

# --- Tarpit module configuration ---
# Defaults are ON — flux is a honeypot, the whole point is to fingerprint.
# To disable an individual module, set its env var to "false" / "0".
# DNS callback is a partial exception: enabled by default but a no-op
# unless TARPIT_MOD_DNS_CALLBACK_DOMAIN is also set, since redirecting
# to an empty domain produces garbage URLs.
def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if raw == "":
        return default
    return raw in {"1", "true", "yes", "on"}

MOD_DNS_CALLBACK_ENABLED = _env_bool("TARPIT_MOD_DNS_CALLBACK_ENABLED")
MOD_DNS_CALLBACK_DOMAIN = (os.environ.get("TARPIT_MOD_DNS_CALLBACK_DOMAIN") or "").strip()
MOD_COOKIE_ENABLED = _env_bool("TARPIT_MOD_COOKIE_ENABLED")
MOD_REDIRECT_CHAIN_ENABLED = _env_bool("TARPIT_MOD_REDIRECT_CHAIN_ENABLED")
MOD_REDIRECT_CHAIN_MAX_HOPS = max(int((os.environ.get("TARPIT_MOD_REDIRECT_CHAIN_MAX_HOPS") or "5").strip() or "5"), 1)
MOD_VARIABLE_DRIP_ENABLED = _env_bool("TARPIT_MOD_VARIABLE_DRIP_ENABLED")
MOD_VARIABLE_DRIP_INITIAL_MS = max(int((os.environ.get("TARPIT_MOD_VARIABLE_DRIP_INITIAL_MS") or "500").strip() or "500"), 50)
MOD_VARIABLE_DRIP_MAX_MS = max(int((os.environ.get("TARPIT_MOD_VARIABLE_DRIP_MAX_MS") or "16000").strip() or "16000"), 100)
MOD_CONTENT_LENGTH_MISMATCH_ENABLED = _env_bool("TARPIT_MOD_CONTENT_LENGTH_MISMATCH_ENABLED")
MOD_CONTENT_LENGTH_CLAIMED_BYTES = max(int((os.environ.get("TARPIT_MOD_CONTENT_LENGTH_CLAIMED_BYTES") or "1048576").strip() or "1048576"), 1024)
MOD_ETAG_PROBE_ENABLED = _env_bool("TARPIT_MOD_ETAG_PROBE_ENABLED")

# --- Generic fingerprint paths ---
# The fingerprinting modules (cookie, etag, dns-callback, redirect-chain,
# drip, content-length-mismatch) were originally only invoked on `.env`
# variants. Scanners that aren't hunting `.env` never tripped them. This
# list routes the same module chain at a set of generic paths a scanner
# typically hits on first contact.
_FINGERPRINT_DEFAULT_PATHS = ",".join([
    "/",
    "/index.html",
    "/index.php",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
])
FINGERPRINT_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("FINGERPRINT_PATHS_CSV") or _FINGERPRINT_DEFAULT_PATHS).split(",")
    if value.strip()
}
FINGERPRINT_PATHS_ENABLED = _env_bool("FINGERPRINT_PATHS_ENABLED")

# --- Fake /.git/ tree configuration ---
# Default-on: flux is a honeypot, and the /.git/ tree is one of the most
# valuable traps we have. The per-IP cache (FAKE_GIT_CACHE_TTL_SECONDS)
# keeps scanner fan-out from burning Tracebit quota, and the dispatch
# still requires TRACEBIT_API_KEY to be set (see server.py:2559) — so
# deployments without a key stay 404 regardless of this default.
FAKE_GIT_ENABLED = _env_bool("FAKE_GIT_ENABLED")
FAKE_GIT_CACHE_TTL_SECONDS = max(int((os.environ.get("FAKE_GIT_CACHE_TTL_SECONDS") or "3600").strip() or "3600"), 60)
FAKE_GIT_CACHE_MAX_ENTRIES = max(int((os.environ.get("FAKE_GIT_CACHE_MAX_ENTRIES") or "1024").strip() or "1024"), 16)
FAKE_GIT_DRIP_BYTES = max(int((os.environ.get("FAKE_GIT_DRIP_BYTES") or "1024").strip() or "1024"), 32)
FAKE_GIT_DRIP_INTERVAL_MS = max(int((os.environ.get("FAKE_GIT_DRIP_INTERVAL_MS") or "3000").strip() or "3000"), 100)
FAKE_GIT_AUTHOR = (os.environ.get("FAKE_GIT_AUTHOR") or "ops <ops@internal-tools.lan>").strip()
FAKE_GIT_COMMIT_MESSAGE = (os.environ.get("FAKE_GIT_COMMIT_MESSAGE") or "Initial import of internal-tools").strip()
# If FAKE_GIT_REMOTE_URL is set, it's used verbatim (operator override).
# If unset, the URL is built per-request from the Tracebit canary creds
# issued for this fake repo, so that scrapers who just grep `.git/config`
# (without running `git clone`) still leak a canary credential — the URL
# userinfo is a real Tracebit access key, and any attempt to use it as AWS
# credentials triggers a Tracebit callback. This is a distinct tripwire
# from the `git clone`-then-read-secrets.yml path the rest of the trap
# already covers: some scanning fleets observed in the wild fetch
# `.git/config` in isolation and never progress to a full clone.
FAKE_GIT_REMOTE_URL = (os.environ.get("FAKE_GIT_REMOTE_URL") or "").strip()
FAKE_GIT_REMOTE_HOST = (os.environ.get("FAKE_GIT_REMOTE_HOST") or "github.com").strip()
FAKE_GIT_REMOTE_PATH = (os.environ.get("FAKE_GIT_REMOTE_PATH") or "internal/tools.git").strip().lstrip("/")

# --- Fake webshell configuration (Azure WP Webshell Checker intel, 2026-04-20) ---
# Default-enabled: the trap is cheap, logs are cheap, and we want to see what
# commands the checker follows up with on a positive hit.
WEBSHELL_ENABLED = (os.environ.get("HONEYPOT_WEBSHELL_ENABLED") or "true").strip().lower() in {"1", "true", "yes", "on"}
# Paths known to be probed by scanners looking for pre-existing PHP shells to
# take over — the "shell jacking" pattern (probe candidate paths someone else
# dropped, inherit their persistence) as well as the Azure WP Webshell Checker
# lineage. Overridable via env for quick additions without a republish.
_WEBSHELL_DEFAULT_PATHS = ",".join([
    # Anchor: the hellopress / wp-file-manager planted shell (CVE-2020-25213 lineage)
    "/wp-content/plugins/hellopress/wp_filemanager.php",
    "/hellopress/wp_filemanager.php",
    "/wp_filemanager.php",
    # Short-named PHP shells observed in the 2026-04-20 Azure WP checker burst
    "/doc.php", "/ws80.php", "/bthil.php", "/xminie.php",
    "/inputs.php", "/ioxi-o.php", "/8.php", "/an.php",
    "/kma.php", "/ssh3ll.php", "/new4.php", "/sf.php",
    # Common generic PHP webshell names
    "/shell.php", "/cmd.php", "/c.php", "/up.php", "/upload.php",
    # Named-shell filenames seen as follow-on probes from the same
    # post-compromise fleet (webshell-jacking intel). Grouped by shape:
    #   - single-digit / short numeric names
    "/0.php", "/0x.php", "/1.php", "/7.php", "/12.php", "/222.php", "/404.php",
    "/a.php", "/a1.php",
    #   - generic-shell-looking filenames observed as 404s across sensors
    "/aa.php", "/abcd.php", "/about.php", "/aboute.php", "/adminfuns.php",
    "/as.php", "/autoload_classmap.php", "/av.php", "/chosen.php",
    "/classwithtostring.php", "/dass.php", "/db.php", "/dx.php", "/edit.php",
    "/eetu.php", "/f35.php", "/fs.php", "/gifclass.php", "/lib.php",
    "/ms-edit.php", "/press.php", "/rip.php", "/sid3.php", "/sql.php",
    "/themes.php", "/y.php",
    #   - "ws<N>" numbered series (already had ws80; fleet probes ~50-99)
    "/ws57.php", "/ws66.php", "/ws81.php", "/ws82.php",
    #   - wp-themed backdoor filenames (not real WP core files)
    "/wp-block.php", "/wp-good.php", "/wp-kikikoko.php",
    #   - non-.php backdoors ("dr0v" is a specific observed marker name)
    "/dr0v",
])
WEBSHELL_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_WEBSHELL_PATHS_CSV") or _WEBSHELL_DEFAULT_PATHS).split(",")
    if value.strip()
}
# Regex families for webshell paths that are parameterized and therefore can't
# be enumerated as literal strings. Two observed shapes:
#   - `/.well-known/<name>.php` — attackers abuse the writable acme-challenge
#     area as a shell-drop directory (certbot can create files there as root).
#     Names seen in the wild: rk2.php (r57 lineage), gecko-litespeed.php,
#     admin.php, error.php, index.php. The legitimate `/.well-known/acme-challenge/*`
#     path is excluded by nginx routing (see cloud-init-sensor template), so
#     we don't need to special-case it here.
#   - `/.trash<N>/` and `/.tmb/` — numbered "trash" directories and tmb/ staging
#     paths used by specific malware families as shell-drop locations.
#     `/.tresh/` (typo'd variant) is included via literal list only if seen.
_WEBSHELL_PATH_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/\.well-known/[^/]+\.php$", re.IGNORECASE),
    re.compile(r"^/\.trash\d+/", re.IGNORECASE),
    re.compile(r"^/\.tmb/[^/]+\.php$", re.IGNORECASE),
    re.compile(r"^/\.(tresh|dj|alf|mopj|info)(/|\.php$)", re.IGNORECASE),
)
# Bound the body we decode+log. Scanners can POST large payloads; we still
# want body_sha256 for everything but only need a prefix of decoded content
# to see command strings.
WEBSHELL_BODY_DECODE_LIMIT = max(int((os.environ.get("HONEYPOT_WEBSHELL_BODY_DECODE_LIMIT") or "8192").strip() or "8192"), 512)
# Max body size to actually read off the wire (prevents a slowloris-style
# upload from pinning a handler thread forever).
WEBSHELL_BODY_READ_LIMIT = max(int((os.environ.get("HONEYPOT_WEBSHELL_BODY_READ_LIMIT") or "65536").strip() or "65536"), 1024)
# Param names commonly used by PHP webshells to smuggle commands. Ordered
# by frequency in the wild; first hit wins.
WEBSHELL_COMMAND_KEYS = (
    "cmd", "c", "command", "exec", "e", "x",
    "pass", "password", "key", "p", "execute",
    "do", "run", "shell", "act", "action", "q", "query",
)
WEBSHELL_COMMAND_HEADERS = ("X-Cmd", "X-Exec", "X-Command")

# --- Fake LLM-API endpoint (Ollama / OpenAI / Anthropic-proxy shape) ---
# Motivated by scanner fleets observed probing AI-inference endpoints
# in April 2026 — Ollama-native paths, OpenAI-compatible paths, and
# corporate AI-proxy paths (`/anthropic/v1/models`) with non-overlapping
# HTTP-client fingerprints. The intel we want is what comes next —
# model name requested, prompt body, whether a bearer token is
# presented, UA rotation on a follow-up.
#
# Default-on like the webshell: the trap is cheap, logs are cheap, and a
# plausible response is what makes the scanner send its next command.
LLM_ENDPOINT_ENABLED = _env_bool("HONEYPOT_LLM_ENDPOINT_ENABLED")
# Paths served. All exact lowercase matches — same model as WEBSHELL_PATHS.
_LLM_ENDPOINT_DEFAULT_PATHS = ",".join([
    # Ollama + OpenAI-compatible listings
    "/v1/models",
    "/api/tags",
    "/api/version",
    "/api/ps",
    # Ollama POST endpoints
    "/api/chat",
    "/api/generate",
    "/api/show",
    # OpenAI POST
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    # Anthropic Messages API + corporate AI-proxy paths
    "/v1/messages",
    "/anthropic/v1/models",
    "/anthropic/v1/messages",
])
LLM_ENDPOINT_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_LLM_ENDPOINT_PATHS_CSV") or _LLM_ENDPOINT_DEFAULT_PATHS).split(",")
    if value.strip()
}
# Cap how much of the prompt body we decode into the log line. Scanners that
# find the endpoint may POST large system prompts or tool definitions; we want
# the first chunk (enough to see intent + model + a prompt prefix) without
# bloating the log file.
LLM_BODY_DECODE_LIMIT = max(int((os.environ.get("HONEYPOT_LLM_BODY_DECODE_LIMIT") or "4096").strip() or "4096"), 512)

# --- Fake SonicWall SSL VPN (CVE-2024-53704 bait chain) ------------------
# Two overlapping behaviour patterns observed in mid-April 2026:
#   - A dedicated SonicWall-precondition fleet hitting only
#     `/api/sonicos/is-sslvpn-enabled` — the CVE precondition check.
#   - A broader enterprise-appliance probe running the full three-step
#     sequence `is-sslvpn-enabled` → `auth` → `tfa` on every target.
#
# These paths are SonicWall-specific — no legitimate scanner hits them.
# The trap looks live enough (200 + plausible JSON) that the scanner
# sends its next step, which is where the actual intel is: what usernames
# they try, whether they present harvested session cookies, whether the
# TFA payload carries an exploit.
SONICWALL_ENABLED = _env_bool("HONEYPOT_SONICWALL_ENABLED")
_SONICWALL_DEFAULT_PATHS = ",".join([
    "/api/sonicos/is-sslvpn-enabled",
    "/api/sonicos/auth",
    "/api/sonicos/tfa",
])
SONICWALL_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_SONICWALL_PATHS_CSV") or _SONICWALL_DEFAULT_PATHS).split(",")
    if value.strip()
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def append_log(payload: dict[str, object]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def first_forwarded_ip(header_value: str) -> str:
    if not header_value:
        return ""
    return header_value.split(",", 1)[0].strip()


def clean_host(header_value: str) -> str:
    if not header_value:
        return ""
    value = header_value.strip().lower()
    if not value:
        return ""
    if value.startswith("["):
        bracket_end = value.find("]")
        if bracket_end != -1:
            return value[1:bracket_end]
    if value.count(":") == 1:
        host_value, port_value = value.rsplit(":", 1)
        if port_value.isdigit():
            return host_value
    return value


def header_subset(headers: object) -> dict[str, str]:
    values: dict[str, str] = {}
    for name in LOG_HEADER_NAMES:
        value = headers.get(name)
        if value:
            values[name] = value[:HEADER_VALUE_LOG_LIMIT]
    return values


def normalize_path(raw_path: str) -> str:
    if not raw_path:
        return "/"
    decoded = unquote(raw_path)
    collapsed = re.sub(r"/+", "/", decoded)
    return collapsed if collapsed.startswith("/") else f"/{collapsed}"


def extract_git_path(path: str) -> str | None:
    """Return the canonical `/.git/...` lookup key, or None if `path` isn't
    a request for a /.git tree file.

    Accepts:
      - exact `/.git` (root) and `/.git/` (directory-ish)
      - `/.git/<anything>`
      - `/<any prefix>/.git/<anything>` — scanners enumerate apps deployed
        at subpaths, e.g. `/login/.git/config`, `/project/.git/HEAD`,
        `/api/.git/index`
      - case-insensitive (`/.GiT/CoNfIg` → `/.git/config`)

    Lowercases the result for case-insensitive lookup against the
    canonical `files` map keys (which are all lowercase).
    """
    if not path:
        return None
    lower = path.lower()
    if lower == "/.git" or lower == "/.git/":
        return "/.git/"
    if lower.startswith("/.git/"):
        return lower
    idx = lower.find("/.git/")
    if idx > 0:
        return lower[idx:]
    return None


def is_tarpit_path(path: str) -> bool:
    stripped = path.rstrip("/") or "/"
    if stripped == "/.env":
        return False
    if stripped.endswith("/.env"):
        return True
    leaf = stripped.rsplit("/", 1)[-1]
    return leaf.startswith(".env") and leaf != ".env"


def is_fingerprint_path(path: str) -> bool:
    """Generic paths that route into the tarpit + module chain for
    fingerprinting. Separate from `.env` variants so they can be disabled
    independently (they're much louder — they hit every first-contact scanner)."""
    if not FINGERPRINT_PATHS_ENABLED:
        return False
    normalized = path.lower() or "/"
    if normalized in FINGERPRINT_PATHS:
        return True
    # Allow "/" to match whether the caller passed "/" or "".
    if normalized == "" and "/" in FINGERPRINT_PATHS:
        return True
    return False


def is_webshell_path(path: str) -> bool:
    if not WEBSHELL_ENABLED:
        return False
    lowered = path.lower()
    if lowered in WEBSHELL_PATHS:
        return True
    for pattern in _WEBSHELL_PATH_REGEXES:
        if pattern.match(lowered):
            return True
    return False


def is_llm_endpoint_path(path: str) -> bool:
    if not LLM_ENDPOINT_ENABLED:
        return False
    return path.lower() in LLM_ENDPOINT_PATHS


def is_sonicwall_path(path: str) -> bool:
    if not SONICWALL_ENABLED:
        return False
    return path.lower() in SONICWALL_PATHS


def extract_sonicwall_username(body: bytes, content_type: str) -> str:
    """Pull `user`/`username` out of a SonicOS auth body. SonicOS accepts
    both JSON and form-encoded auth POSTs in the wild; try both. Returns
    "" if neither shape matches or the field is absent.
    """
    if not body:
        return ""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct in {"application/json", ""}:
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            payload = None
        if isinstance(payload, dict):
            for key in ("user", "username", "login"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return value[:120]
    if ct in {"application/x-www-form-urlencoded", ""}:
        try:
            form = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        except (UnicodeDecodeError, ValueError):
            form = {}
        for key in ("user", "username", "login"):
            values = form.get(key) or form.get(key.upper())
            if values and values[0]:
                return values[0][:120]
    return ""


# Models advertised by the listings. Chosen to mix Ollama-native names
# (`llama3.2:latest`) with OpenAI- and Anthropic-branded ids so every scanner
# that filters by model name sees at least one plausible match.
_LLM_MODEL_NAMES: tuple[str, ...] = (
    "llama3.2:latest",
    "llama3.1:8b",
    "qwen2.5-coder:7b",
    "mistral:7b",
    "deepseek-r1:7b",
    "gemma2:9b",
    "gpt-4o",
    "gpt-4o-mini",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
)


def extract_llm_prompt(body: bytes, content_type: str) -> tuple[str, str, str, bool]:
    """Best-effort pull of (model, prompt, action, has_auth_hint) from a JSON body.

    Handles the three wire formats we see probes against:
    - Ollama:         {"model": "...", "prompt": "..."}               /api/generate
                      {"model": "...", "messages": [{"role","content"}]}  /api/chat
                      {"model": "..."}                                 /api/show
    - OpenAI:         {"model": "...", "messages": [{"role","content"}]}  /v1/chat/completions
                      {"model": "...", "prompt": "..."}                /v1/completions
                      {"model": "...", "input": "..."|[..]}            /v1/embeddings
    - Anthropic:      {"model": "...", "messages": [{"role","content"}]}  /v1/messages

    Returns `(model, prompt_prefix, action, has_auth_hint)`. Unknown shape
    returns all-empty. `has_auth_hint` is always False at this layer; the
    caller fills it from the request headers. Prompt is truncated to
    LLM_BODY_DECODE_LIMIT chars.
    """
    if not body:
        return "", "", "", False
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    # Ollama and OpenAI clients usually send application/json; some scanners
    # send no Content-Type at all but still use JSON, so be lenient.
    if ct not in {"application/json", ""}:
        return "", "", "", False
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return "", "", "", False
    if not isinstance(payload, dict):
        return "", "", "", False

    model = ""
    raw_model = payload.get("model")
    if isinstance(raw_model, str):
        model = raw_model[:120]

    # Prefer a chat `messages` list if present, then `prompt`, then `input`.
    prompt = ""
    action = ""
    messages = payload.get("messages")
    if isinstance(messages, list) and messages:
        action = "chat"
        pieces: list[str] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", ""))[:32]
            content = msg.get("content", "")
            if isinstance(content, list):
                # Anthropic content-block form: [{"type":"text","text":"..."}]
                text_pieces = []
                for block in content:
                    if isinstance(block, dict):
                        t = block.get("text") or block.get("content") or ""
                        if isinstance(t, str):
                            text_pieces.append(t)
                content = " ".join(text_pieces)
            if not isinstance(content, str):
                content = str(content)
            pieces.append(f"{role}: {content}" if role else content)
        prompt = "\n".join(pieces)
    elif isinstance(payload.get("prompt"), str):
        action = "completion"
        prompt = payload["prompt"]
    elif "input" in payload:
        action = "embedding"
        val = payload["input"]
        if isinstance(val, list):
            prompt = " ".join(str(x) for x in val if isinstance(x, (str, int, float)))
        else:
            prompt = str(val)

    if len(prompt) > LLM_BODY_DECODE_LIMIT:
        prompt = prompt[:LLM_BODY_DECODE_LIMIT]
    return model, prompt, action, False


# --- LLM renderers --------------------------------------------------------
# Shapes match the wire format the scanner expects well enough that it sends
# its next command. Content is deterministic — we don't need a real LLM.


def render_ollama_version() -> bytes:
    return json.dumps({"version": "0.4.7"}).encode("utf-8")


def render_ollama_tags() -> bytes:
    modified = "2026-01-15T12:00:00.000000000Z"
    payload = {
        "models": [
            {
                "name": name,
                "model": name,
                "modified_at": modified,
                "size": 4_661_211_808,
                "digest": hashlib.sha256(name.encode("utf-8")).hexdigest(),
                "details": {
                    "parent_model": "",
                    "format": "gguf",
                    "family": name.split(":", 1)[0].split("-", 1)[0],
                    "families": None,
                    "parameter_size": "7B",
                    "quantization_level": "Q4_0",
                },
            }
            for name in _LLM_MODEL_NAMES
        ]
    }
    return json.dumps(payload).encode("utf-8")


def render_ollama_ps() -> bytes:
    # "No models currently loaded" — looks like a fresh, idle server.
    return json.dumps({"models": []}).encode("utf-8")


def render_openai_models() -> bytes:
    payload = {
        "object": "list",
        "data": [
            {"id": name, "object": "model", "created": 1_735_689_600, "owned_by": "library"}
            for name in _LLM_MODEL_NAMES
        ],
    }
    return json.dumps(payload).encode("utf-8")


def render_anthropic_models() -> bytes:
    # Anthropic's /v1/models response shape: {"data":[{"type":"model","id":..}],
    # "has_more": false, "first_id": "...", "last_id": "..."}.
    anthropic_ids = [m for m in _LLM_MODEL_NAMES if m.startswith("claude-")] or [
        "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku-20241022",
    ]
    data = [
        {
            "type": "model",
            "id": mid,
            "display_name": mid.replace("-", " ").title(),
            "created_at": "2024-10-22T00:00:00Z",
        }
        for mid in anthropic_ids
    ]
    payload = {
        "data": data,
        "has_more": False,
        "first_id": data[0]["id"],
        "last_id": data[-1]["id"],
    }
    return json.dumps(payload).encode("utf-8")


def render_ollama_show(model: str) -> bytes:
    model = model or "llama3.2:latest"
    payload = {
        "modelfile": f"FROM {model}\nPARAMETER temperature 0.7\n",
        "parameters": "temperature 0.7",
        "template": "{{ .Prompt }}",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "llama",
            "families": ["llama"],
            "parameter_size": "8B",
            "quantization_level": "Q4_0",
        },
    }
    return json.dumps(payload).encode("utf-8")


# Canned assistant reply used for any chat/completion POST. Deliberately
# bland: "plausible but boring" keeps the scanner moving to its next
# command without us having to host a real model.
_LLM_CANNED_REPLY = (
    "I can help with that. Could you share more detail about what you're "
    "trying to accomplish?"
)


def render_ollama_chat(model: str) -> bytes:
    payload = {
        "model": model or "llama3.2:latest",
        "created_at": utc_now(),
        "message": {"role": "assistant", "content": _LLM_CANNED_REPLY},
        "done": True,
        "done_reason": "stop",
        "total_duration": 1_234_567_890,
        "load_duration": 12_345_678,
        "prompt_eval_count": 24,
        "prompt_eval_duration": 123_456_789,
        "eval_count": 32,
        "eval_duration": 987_654_321,
    }
    return json.dumps(payload).encode("utf-8")


def render_ollama_generate(model: str) -> bytes:
    payload = {
        "model": model or "llama3.2:latest",
        "created_at": utc_now(),
        "response": _LLM_CANNED_REPLY,
        "done": True,
        "done_reason": "stop",
    }
    return json.dumps(payload).encode("utf-8")


def render_openai_chat(model: str) -> bytes:
    payload = {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": _LLM_CANNED_REPLY},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 24, "completion_tokens": 32, "total_tokens": 56},
    }
    return json.dumps(payload).encode("utf-8")


def render_openai_completion(model: str) -> bytes:
    payload = {
        "id": f"cmpl-{uuid.uuid4().hex[:24]}",
        "object": "text_completion",
        "created": int(time.time()),
        "model": model or "gpt-4o-mini",
        "choices": [{"text": _LLM_CANNED_REPLY, "index": 0, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 16, "completion_tokens": 24, "total_tokens": 40},
    }
    return json.dumps(payload).encode("utf-8")


def render_openai_embedding(model: str) -> bytes:
    # 8 floats — tiny; scanners that care about dim are probing, not using.
    vec = [0.01, -0.02, 0.03, -0.04, 0.05, -0.06, 0.07, -0.08]
    payload = {
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": vec}],
        "model": model or "text-embedding-3-small",
        "usage": {"prompt_tokens": 4, "total_tokens": 4},
    }
    return json.dumps(payload).encode("utf-8")


def render_anthropic_message(model: str) -> bytes:
    payload = {
        "id": f"msg_{uuid.uuid4().hex[:24]}",
        "type": "message",
        "role": "assistant",
        "model": model or "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": _LLM_CANNED_REPLY}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 24, "output_tokens": 32},
    }
    return json.dumps(payload).encode("utf-8")


# --- SonicWall SSL VPN renderers -----------------------------------------
# Shapes match SonicOS 7.x API responses closely enough that a CVE-2024-53704
# exploit client moves from the precondition check into the auth POST.
# We don't need to mint a real session — the scanner's next payload is the
# intel we want, and SonicOS's success envelope is simple enough to fake.


def render_sonicwall_is_sslvpn_enabled() -> bytes:
    # SonicOS 7 returns a status envelope alongside the boolean. Field names
    # match the documented shape; values are the defaults a live appliance
    # with SSL VPN turned on would emit.
    payload = {
        "is_ssl_vpn_enabled": True,
        "status": {
            "success": True,
            "cli_msg": "",
            "info": [{"level": "info", "code": "E_OK", "message": ""}],
        },
    }
    return json.dumps(payload).encode("utf-8")


def render_sonicwall_auth_success(session_id: str) -> bytes:
    # Minimum-plausible SonicOS auth success: a status envelope, a session
    # token echoed back (so the scanner thinks it has a live session), and a
    # nonce field the CVE-2024-53704 exploit chain reads.
    payload = {
        "status": {
            "success": True,
            "cli_msg": "Login succeeded",
            "info": [{"level": "info", "code": "E_OK", "message": "authenticated"}],
        },
        "auth": {
            "session_id": session_id,
            "user_name": "admin",
            "tfa_required": True,
            "tfa_method": "totp",
        },
    }
    return json.dumps(payload).encode("utf-8")


def render_sonicwall_tfa_success(session_id: str) -> bytes:
    # Mirror the auth response shape; TFA success collapses the `tfa_required`
    # flag to false so the exploit moves on to whatever it does post-auth.
    payload = {
        "status": {
            "success": True,
            "cli_msg": "TFA accepted",
            "info": [{"level": "info", "code": "E_OK", "message": "tfa-accepted"}],
        },
        "auth": {
            "session_id": session_id,
            "user_name": "admin",
            "tfa_required": False,
        },
    }
    return json.dumps(payload).encode("utf-8")


def parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        cookies[name.strip()] = value.strip()
    return cookies


def parse_form_body(body_bytes: bytes, content_type: str) -> dict[str, list[str]]:
    if not body_bytes:
        return {}
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct not in {"application/x-www-form-urlencoded", ""}:
        return {}
    try:
        text = body_bytes.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return {}
    return parse_qs(text, keep_blank_values=True)


def extract_webshell_command(
    query_params: dict[str, list[str]],
    form_params: dict[str, list[str]],
    cookies: dict[str, str],
    headers: object,
) -> tuple[str, str, str]:
    """Return (source, key, command). source='' means no command found."""
    for source, collection in (("query", query_params), ("form", form_params)):
        for key in WEBSHELL_COMMAND_KEYS:
            for candidate in (key, key.upper()):
                values = collection.get(candidate)
                if values and values[0]:
                    return source, candidate, values[0]
    for key in WEBSHELL_COMMAND_KEYS:
        if key in cookies and cookies[key]:
            return "cookie", key, cookies[key]
    for header_name in WEBSHELL_COMMAND_HEADERS:
        value = headers.get(header_name)
        if value:
            return "header", header_name, value
    return "", "", ""


def simulate_command_output(command: str) -> str:
    """Return plausible fake output for common reconnaissance commands.

    The goal is to look convincing enough that a scanner moves on to its next
    command instead of bailing after the first probe. Unknown commands return
    an empty string (which many shells produce for assignments, `cd`, etc.)
    so we don't leak "it's fake" via a canned error message.
    """
    cmd = command.strip()
    if not cmd:
        return ""
    first = cmd.split(None, 1)[0].lower().lstrip("!")
    if first in {"id"}:
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    if first in {"whoami"}:
        return "www-data\n"
    if first in {"hostname"}:
        return "web-01\n"
    if first in {"pwd"}:
        return "/var/www/html/wp-content/plugins/hellopress\n"
    if cmd in {"uname", "uname -a", "uname -r"}:
        return "Linux web-01 5.15.0-86-generic #96-Ubuntu SMP Wed Sep 20 08:23:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
    if cmd.startswith("cat /etc/passwd"):
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "mysql:x:112:116:MySQL Server,,,:/nonexistent:/bin/false\n"
        )
    if first in {"ls", "dir"}:
        return "index.php\nreadme.txt\nwp_filemanager.php\n"
    if cmd in {"w", "who"}:
        return "\n"
    return ""


def render_webshell_page(command: str = "", output: str = "") -> bytes:
    """Minimal but plausible File Manager-ish page. Encourages follow-up POSTs."""
    safe_command = command.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    safe_output = output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    html = (
        "<!doctype html>\n"
        "<html><head><title>File Manager</title></head><body>\n"
        "<h2>File Manager</h2>\n"
        "<form method='POST' action=''>\n"
        f"<input type='text' name='cmd' size='80' value='{safe_command}' autofocus />\n"
        "<input type='submit' value='Execute' />\n"
        "</form>\n"
        f"<pre>{safe_output}</pre>\n"
        "</body></html>\n"
    )
    return html.encode("utf-8")


def _parse_chain_params(query: str) -> tuple[str, int]:
    """Extract redirect-chain tracking params from query string."""
    chain_id = ""
    hop = 0
    for part in query.split("&"):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        if key == "_hp_chain":
            chain_id = value
        elif key == "_hp_hop":
            try:
                hop = int(value)
            except ValueError:
                pass
    return chain_id, hop


# --- Tarpit module framework ---


class TarpitModule:
    """Base class. Subclass and add to TARPIT_MODULES to activate.

    terminal=True  -> module produces a full aiohttp Response (and logs).
    terminal=False -> module returns (extra_headers, meta) for the caller
                      to merge into the tarpit stream's headers.
    """

    name: str = ""
    terminal: bool = False

    def should_run(self, ctx: dict[str, object]) -> bool:
        return False

    async def run_terminal(self, request: "web.Request", ctx: dict[str, object]) -> "web.Response":
        raise NotImplementedError

    def augment(
        self, request: "web.Request", ctx: dict[str, object]
    ) -> tuple[dict[str, str], dict[str, object]]:
        return {}, {}


class DNSCallbackModule(TarpitModule):
    """Redirect to <uuid>.track-domain to fingerprint DNS resolution."""

    name = "dns-callback"
    terminal = True

    def should_run(self, ctx):
        return MOD_DNS_CALLBACK_ENABLED and MOD_DNS_CALLBACK_DOMAIN

    async def run_terminal(self, request, ctx):
        callback_id = str(uuid.uuid4())
        proto = ctx.get("protocol", "https")
        location = f"{proto}://{callback_id}.{MOD_DNS_CALLBACK_DOMAIN}{ctx['path']}"
        append_log({
            **ctx["log_context"],
            "status": 302,
            "result": "tarpit-module",
            "module": self.name,
            "callbackId": callback_id,
            "location": location,
        })
        return web.Response(
            status=302,
            body=b"redirecting\n",
            headers={
                "Location": location,
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-store",
            },
        )


class CookieTrackingModule(TarpitModule):
    """Set a tracking cookie; detect if scanners return it."""

    name = "cookie-tracking"
    terminal = False

    def should_run(self, ctx):
        return MOD_COOKIE_ENABLED

    def augment(self, request, ctx):
        cookie_header = request.headers.get("Cookie", "")
        returned_tid = ""
        if "_hp_tid=" in cookie_header:
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.startswith("_hp_tid="):
                    returned_tid = part[8:]
                    break
        cookie_id = str(uuid.uuid4())
        headers = {"Set-Cookie": f"_hp_tid={cookie_id}; Path=/; HttpOnly; SameSite=Lax"}
        meta: dict[str, object] = {"cookieId": cookie_id}
        if returned_tid:
            meta["cookieReturned"] = returned_tid
        return headers, meta


class RedirectChainModule(TarpitModule):
    """Start a redirect chain to measure follow-depth."""

    name = "redirect-chain"
    terminal = True

    def should_run(self, ctx):
        if not MOD_REDIRECT_CHAIN_ENABLED:
            return False
        return not ctx.get("query") or "_hp_chain" not in ctx["query"]

    async def run_terminal(self, request, ctx):
        chain_id = str(uuid.uuid4())
        location = f"{ctx['path']}?_hp_chain={chain_id}&_hp_hop=1"
        append_log({
            **ctx["log_context"],
            "status": 302,
            "result": "tarpit-module",
            "module": self.name,
            "chainId": chain_id,
            "hop": 0,
        })
        return web.Response(
            status=302,
            body=b"redirecting\n",
            headers={
                "Location": location,
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-store",
            },
        )


class ContentLengthMismatchModule(TarpitModule):
    """Set a large Content-Length to fingerprint client timeout/validation."""

    name = "content-length-mismatch"
    terminal = False

    def should_run(self, ctx):
        return MOD_CONTENT_LENGTH_MISMATCH_ENABLED

    def augment(self, request, ctx):
        return (
            {"Content-Length": str(MOD_CONTENT_LENGTH_CLAIMED_BYTES)},
            {"claimedBytes": MOD_CONTENT_LENGTH_CLAIMED_BYTES},
        )


class ETagProbeModule(TarpitModule):
    """Set ETag/Last-Modified; detect conditional requests on repeat visits."""

    name = "etag-probe"
    terminal = False

    def should_run(self, ctx):
        return MOD_ETAG_PROBE_ENABLED

    def augment(self, request, ctx):
        request_id = ctx.get("request_id", "")
        etag_value = f'"{request_id}"'
        headers = {"ETag": etag_value, "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT"}
        meta: dict[str, object] = {"etag": etag_value}
        if_none_match = request.headers.get("If-None-Match", "")
        if_modified_since = request.headers.get("If-Modified-Since", "")
        if if_none_match:
            meta["conditionalRequest"] = True
            meta["ifNoneMatch"] = if_none_match[:256]
        if if_modified_since:
            meta["conditionalRequest"] = True
            meta["ifModifiedSince"] = if_modified_since[:256]
        return headers, meta


TARPIT_MODULES: list[TarpitModule] = []
if MOD_DNS_CALLBACK_ENABLED and MOD_DNS_CALLBACK_DOMAIN:
    TARPIT_MODULES.append(DNSCallbackModule())
if MOD_REDIRECT_CHAIN_ENABLED:
    TARPIT_MODULES.append(RedirectChainModule())
if MOD_COOKIE_ENABLED:
    TARPIT_MODULES.append(CookieTrackingModule())
if MOD_CONTENT_LENGTH_MISMATCH_ENABLED:
    TARPIT_MODULES.append(ContentLengthMismatchModule())
if MOD_ETAG_PROBE_ENABLED:
    TARPIT_MODULES.append(ETagProbeModule())


def build_tarpit_chunk(request_id: str, path: str, chunk_index: int) -> bytes:
    base = f"TRACEBIT_TARPIT_{chunk_index:06d}={request_id[:8]}:{path}".encode("utf-8", errors="replace")
    if len(base) < TARPIT_CHUNK_BYTES:
        base = base + (b"." * (TARPIT_CHUNK_BYTES - len(base)))
    else:
        base = base[:TARPIT_CHUNK_BYTES]
    return base + b"\n"


# One aiohttp session per process, created on first use. Reusing the session
# pools TCP+TLS connections to Tracebit so rapid cache-miss bursts don't each
# pay the handshake cost.
_http_session: aiohttp.ClientSession | None = None


async def _get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
        )
    return _http_session


async def issue_credentials(
    request_id: str,
    client_ip: str,
    host: str,
    user_agent: str,
    path: str,
    proto: str,
    types: tuple[str, ...] | list[str] | None = None,
) -> dict[str, object]:
    issue_url = f"{API_BASE_URL}/api/v1/credentials/issue-credentials"
    safe_host = re.sub(r"[^0-9a-z._-]+", "-", host or "unknown").strip("-") or "unknown"
    request_name = f"{SENSOR_ID or 'sensor'}-{safe_host}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{request_id[:8]}"
    payload = {
        "name": request_name,
        "types": list(types) if types else CANARY_TYPES,
        "source": TRACEBIT_SOURCE,
        "sourceType": TRACEBIT_SOURCE_TYPE,
        "labels": [
            {"name": "sensor_id", "value": SENSOR_ID or "unknown"},
            {"name": "host", "value": host or "unknown"},
            {"name": "path", "value": path},
            {"name": "client_ip", "value": client_ip or "unknown"},
            {"name": "request_id", "value": request_id},
            {"name": "protocol", "value": proto or "unknown"},
            {"name": "user_agent", "value": (user_agent or "unknown")[:180]},
        ],
    }
    session = await _get_http_session()
    async with session.post(
        issue_url,
        json=payload,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Accept": "application/json",
        },
    ) as response:
        response.raise_for_status()
        return await response.json()


def format_env_payload(tracebit_response: dict[str, object]) -> str:
    # Rendered body is served verbatim on /.env; every string here is
    # visible to the attacker. No headers, no "canary"/"tracebit" tells,
    # no error sentinels — an empty upstream response becomes an empty
    # body, which is indistinguishable from an unremarkable empty .env.
    lines: list[str] = []

    aws = tracebit_response.get("aws")
    if isinstance(aws, dict):
        lines.extend(
            [
                f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}",
                f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}",
                f"AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}",
                f"AWS_CREDENTIAL_EXPIRATION={aws.get('awsExpiration', '')}",
            ]
        )

    ssh = tracebit_response.get("ssh")
    if isinstance(ssh, dict):
        lines.extend(
            [
                f"SSH_HOST={ssh.get('sshIp', '')}",
                f"SSH_PRIVATE_KEY_B64={ssh.get('sshPrivateKey', '')}",
                f"SSH_PUBLIC_KEY_B64={ssh.get('sshPublicKey', '')}",
                f"SSH_KEY_EXPIRATION={ssh.get('sshExpiration', '')}",
            ]
        )

    http = tracebit_response.get("http")
    if isinstance(http, dict):
        for canary_type, details in sorted(http.items()):
            if not isinstance(details, dict):
                continue
            env_key = canary_type.upper().replace("-", "_")
            credentials = details.get("credentials")
            if credentials is not None:
                lines.append(f"{env_key}_CREDENTIALS_JSON={json.dumps(credentials, separators=(',', ':'))}")
            host_names = details.get("hostNames")
            if isinstance(host_names, list):
                lines.append(f"{env_key}_HOSTNAMES={','.join(str(value) for value in host_names)}")
            expires_at = details.get("expiresAt")
            if expires_at:
                lines.append(f"{env_key}_EXPIRATION={expires_at}")

    if not lines:
        return ""
    lines.append("")
    return "\n".join(lines)


# --- Fake /.git/ tree builder ---

_FAKE_GIT_LOCK: asyncio.Lock | None = None
_FAKE_GIT_CACHE: dict[str, tuple[float, dict[str, bytes], dict[str, object]]] = {}


def _get_fake_git_lock() -> asyncio.Lock:
    # Must be created inside a running event loop; lazily initialize so the
    # module can be imported outside an async context (tests, etc.).
    global _FAKE_GIT_LOCK
    if _FAKE_GIT_LOCK is None:
        _FAKE_GIT_LOCK = asyncio.Lock()
    return _FAKE_GIT_LOCK


def _git_loose_object(obj_type: bytes, content: bytes) -> tuple[str, bytes]:
    """Return (sha1_hex, zlib-deflated loose object body)."""
    header = obj_type + b" " + str(len(content)).encode("ascii") + b"\x00"
    raw = header + content
    return hashlib.sha1(raw).hexdigest(), zlib.compress(raw)


def _git_tree_entry(mode: str, name: str, sha_hex: str) -> bytes:
    return mode.encode("ascii") + b" " + name.encode("utf-8") + b"\x00" + bytes.fromhex(sha_hex)


def _format_secrets_yaml(tracebit_response: dict[str, object]) -> str:
    aws = tracebit_response.get("aws") if isinstance(tracebit_response, dict) else None
    if not isinstance(aws, dict):
        aws = {}
    lines = [
        "# config/secrets.yml",
        "# Rotated quarterly per INFRA-218.",
        "# Access restricted to prod deploy role; do not share.",
        "production:",
        "  aws:",
        f"    access_key_id: {aws.get('awsAccessKeyId', '')}",
        f"    secret_access_key: {aws.get('awsSecretAccessKey', '')}",
        f"    session_token: {aws.get('awsSessionToken', '')}",
        f"    expiration: {aws.get('awsExpiration', '')}",
        "    region: us-east-1",
        "",
    ]
    return "\n".join(lines)


def _build_fake_git_remote_url(tracebit_response: dict[str, object]) -> str:
    """Build the `url = …` line for the fake /.git/config [remote].

    If FAKE_GIT_REMOTE_URL is set (operator override), use it verbatim.
    Otherwise embed the Tracebit AWS canary as HTTPS Basic userinfo, so a
    scraper that only reads `.git/config` (no clone) still walks away with
    a live canary key. An attacker who extracts the URL and tries the
    access-key/secret as AWS credentials trips the canary; an attacker who
    actually runs `git clone` against the URL fails (the host is not ours)
    but we still catch them via the rest of the fake-git tree.
    """
    if FAKE_GIT_REMOTE_URL:
        return FAKE_GIT_REMOTE_URL
    aws = _aws(tracebit_response)
    access_key = str(aws.get("awsAccessKeyId") or "").strip()
    secret = str(aws.get("awsSecretAccessKey") or "").strip()
    if not access_key or not secret:
        # Canary mint failed or was incomplete; fall back to a static SSH
        # URL (no secret material) rather than emitting a malformed URL.
        return f"git@{FAKE_GIT_REMOTE_HOST}:{FAKE_GIT_REMOTE_PATH}"
    # Percent-encode the secret — base64 can contain '+' / '/' which break
    # URL parsing by downstream tools. quote() with an empty safe set is
    # RFC 3986 userinfo-safe.
    encoded_secret = quote(secret, safe="")
    return f"https://{access_key}:{encoded_secret}@{FAKE_GIT_REMOTE_HOST}/{FAKE_GIT_REMOTE_PATH}"


def _build_fake_repo(
    secrets_body: str,
    tracebit_response: dict[str, object] | None = None,
) -> tuple[dict[str, bytes], dict[str, object]]:
    """Build a loose-object git repo as a path->bytes map.

    Layout: root/{.env.example, README.md, config/secrets.yml}. One commit.
    The canary creds live inside the secrets.yml blob AND (when the Tracebit
    response is provided) inside the `.git/config` remote-origin URL.
    """
    secrets_sha, secrets_blob = _git_loose_object(b"blob", secrets_body.encode("utf-8"))

    readme_body = (
        "# internal-tools\n\n"
        "Shared ops tooling for production deploys.\n\n"
        "## Setup\n\n"
        "1. Copy `.env.example` to `.env`.\n"
        "2. Fill credentials from `config/secrets.yml` (rotated quarterly).\n"
        "3. Run `./bin/deploy prod`.\n"
    )
    readme_sha, readme_blob = _git_loose_object(b"blob", readme_body.encode("utf-8"))

    env_example_body = (
        "# Copy to .env and populate from config/secrets.yml\n"
        "AWS_ACCESS_KEY_ID=\n"
        "AWS_SECRET_ACCESS_KEY=\n"
        "AWS_SESSION_TOKEN=\n"
        "AWS_REGION=us-east-1\n"
    )
    env_example_sha, env_example_blob = _git_loose_object(b"blob", env_example_body.encode("utf-8"))

    # config/ subtree
    config_tree_entries = _git_tree_entry("100644", "secrets.yml", secrets_sha)
    config_tree_sha, config_tree_blob = _git_loose_object(b"tree", config_tree_entries)

    # Root tree. Entries MUST be sorted lexicographically by name.
    # Order: ".env.example" < "README.md" < "config"
    root_tree_entries = (
        _git_tree_entry("100644", ".env.example", env_example_sha)
        + _git_tree_entry("100644", "README.md", readme_sha)
        + _git_tree_entry("40000", "config", config_tree_sha)
    )
    root_tree_sha, root_tree_blob = _git_loose_object(b"tree", root_tree_entries)

    commit_ts = int(time.time()) - 14 * 86400
    commit_body = (
        f"tree {root_tree_sha}\n"
        f"author {FAKE_GIT_AUTHOR} {commit_ts} +0000\n"
        f"committer {FAKE_GIT_AUTHOR} {commit_ts} +0000\n"
        "\n"
        f"{FAKE_GIT_COMMIT_MESSAGE}\n"
    ).encode("utf-8")
    commit_sha, commit_blob = _git_loose_object(b"commit", commit_body)

    def obj_path(sha: str) -> str:
        return f"/.git/objects/{sha[:2]}/{sha[2:]}"

    remote_url = _build_fake_git_remote_url(tracebit_response or {})
    config_text = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        "[remote \"origin\"]\n"
        f"\turl = {remote_url}\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/main\n"
    )

    reflog_line = (
        f"0000000000000000000000000000000000000000 {commit_sha} "
        f"{FAKE_GIT_AUTHOR} {commit_ts} +0000\tcommit (initial): {FAKE_GIT_COMMIT_MESSAGE}\n"
    )

    # A minimal valid .git/index header: signature "DIRC" + version 2 +
    # entry count 0. Real scanners (git-dumper, gitdumper.sh, etc.) request
    # /.git/index on first contact and treat a 404 there as evidence of a
    # fake repo. Returning zero entries is cheap and convincing: `git
    # ls-files` against the tree just prints nothing.
    git_index_body = b"DIRC" + (2).to_bytes(4, "big") + (0).to_bytes(4, "big") + b"\x00" * 20
    # Keys are lowercased so lookups from extract_git_path() (which returns
    # a lowercased key) match regardless of the case a scanner used on the
    # wire. `/.git/HEAD` on the wire and `/.git/head` on the wire both land
    # on the same response. Real git uses mixed-case filenames on disk, but
    # the on-wire paths are what matter for a dumb-HTTP clone — and no
    # harvester relies on HTTP paths being case-sensitive.
    files: dict[str, bytes] = {
        "/.git/head": b"ref: refs/heads/main\n",
        "/.git/config": config_text.encode("utf-8"),
        "/.git/index": git_index_body,
        "/.git/description": b"Unnamed repository; edit this file 'description' to name the repository.\n",
        "/.git/packed-refs": (
            "# pack-refs with: peeled fully-peeled sorted \n"
            f"{commit_sha} refs/heads/main\n"
        ).encode("utf-8"),
        "/.git/refs/heads/main": f"{commit_sha}\n".encode("utf-8"),
        "/.git/info/refs": f"{commit_sha}\trefs/heads/main\n".encode("utf-8"),
        "/.git/info/exclude": (
            "# git ls-files --others --exclude-from=.git/info/exclude\n"
            "*.log\n.DS_Store\n"
        ).encode("utf-8"),
        "/.git/logs/head": reflog_line.encode("utf-8"),
        "/.git/logs/refs/heads/main": reflog_line.encode("utf-8"),
        "/.git/objects/info/packs": b"",
        # Loose-object paths are already lowercase (hex). No case fold needed.
        obj_path(commit_sha): commit_blob,
        obj_path(root_tree_sha): root_tree_blob,
        obj_path(config_tree_sha): config_tree_blob,
        obj_path(secrets_sha): secrets_blob,
        obj_path(readme_sha): readme_blob,
        obj_path(env_example_sha): env_example_blob,
    }
    meta: dict[str, object] = {
        "commitSha": commit_sha,
        "rootTreeSha": root_tree_sha,
        "configTreeSha": config_tree_sha,
        "secretsBlobSha": secrets_sha,
        "readmeBlobSha": readme_sha,
        "envExampleBlobSha": env_example_sha,
    }
    return files, meta


async def _fake_git_get_or_build(
    client_ip: str,
    request_id: str,
    host: str,
    user_agent: str,
    path: str,
    proto: str,
) -> tuple[dict[str, bytes], dict[str, object]] | None:
    """Return cached repo for this IP, or mint a new canary + repo.

    Cache is keyed by client IP with a TTL so objects stay consistent across
    the many requests a git-dumper-style scanner makes within one session.
    """
    now = time.monotonic()
    cache_key = client_ip or f"_anon-{request_id}"
    lock = _get_fake_git_lock()
    async with lock:
        entry = _FAKE_GIT_CACHE.get(cache_key)
        if entry and entry[0] > now:
            return entry[1], entry[2]

    # Release the lock during the network call so a burst of different IPs
    # can issue in parallel; the cache is only guarded for mutation.
    try:
        tracebit_response = await issue_credentials(request_id, client_ip, host, user_agent, path, proto)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None

    secrets_body = _format_secrets_yaml(tracebit_response)
    files, meta = _build_fake_repo(secrets_body, tracebit_response)
    meta["canaryTypes"] = [key for key, value in tracebit_response.items() if value]

    expiry = now + FAKE_GIT_CACHE_TTL_SECONDS
    async with lock:
        expired = [k for k, v in _FAKE_GIT_CACHE.items() if v[0] <= now]
        for k in expired:
            del _FAKE_GIT_CACHE[k]
        if len(_FAKE_GIT_CACHE) >= FAKE_GIT_CACHE_MAX_ENTRIES:
            oldest_key = min(_FAKE_GIT_CACHE, key=lambda k: _FAKE_GIT_CACHE[k][0])
            del _FAKE_GIT_CACHE[oldest_key]
        _FAKE_GIT_CACHE[cache_key] = (expiry, files, meta)
    return files, meta


# --- Canary-backed file traps ---
#
# Each entry routes a set of exact paths to a render function that embeds
# a freshly-minted Tracebit canary credential into a plausible file format
# (wp-config.php, .aws/credentials, a SQL dump, etc.). Per-IP cache keeps
# repeated scanner fan-out from burning Tracebit quota.

_CANARY_LOCK: asyncio.Lock | None = None
_CANARY_CACHE: dict[tuple[str, tuple[str, ...]], tuple[float, dict[str, object]]] = {}
CANARY_TRAP_CACHE_TTL_SECONDS = max(
    int((os.environ.get("CANARY_TRAP_CACHE_TTL_SECONDS") or "3600").strip() or "3600"), 60,
)
CANARY_TRAP_CACHE_MAX_ENTRIES = max(
    int((os.environ.get("CANARY_TRAP_CACHE_MAX_ENTRIES") or "1024").strip() or "1024"), 16,
)
CANARY_TRAPS_ENABLED = _env_bool("CANARY_TRAPS_ENABLED")


def _get_canary_lock() -> asyncio.Lock:
    global _CANARY_LOCK
    if _CANARY_LOCK is None:
        _CANARY_LOCK = asyncio.Lock()
    return _CANARY_LOCK


async def _get_or_issue_canary(
    types: tuple[str, ...],
    client_ip: str,
    request_id: str,
    host: str,
    user_agent: str,
    path: str,
    proto: str,
) -> dict[str, object] | None:
    """Per-(IP, types) TTL-cached canary issuance.

    A scanner that fans out on the same trap (or different traps needing the
    same canary types) within the TTL gets one canary, not N.
    """
    now = time.monotonic()
    cache_key = (client_ip or f"_anon-{request_id}", types)
    lock = _get_canary_lock()
    async with lock:
        entry = _CANARY_CACHE.get(cache_key)
        if entry and entry[0] > now:
            return entry[1]
    try:
        resp = await issue_credentials(request_id, client_ip, host, user_agent, path, proto, types=types)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None
    expiry = now + CANARY_TRAP_CACHE_TTL_SECONDS
    async with lock:
        expired = [k for k, v in _CANARY_CACHE.items() if v[0] <= now]
        for k in expired:
            del _CANARY_CACHE[k]
        if len(_CANARY_CACHE) >= CANARY_TRAP_CACHE_MAX_ENTRIES:
            oldest_key = min(_CANARY_CACHE, key=lambda k: _CANARY_CACHE[k][0])
            del _CANARY_CACHE[oldest_key]
        _CANARY_CACHE[cache_key] = (expiry, resp)
    return resp


# --- Render functions: (tracebit_response) -> bytes ---

def _aws(r: dict[str, object]) -> dict[str, str]:
    aws = r.get("aws") if isinstance(r, dict) else None
    return aws if isinstance(aws, dict) else {}


def _fake_db_password() -> str:
    # Per-hit synthetic DB password for renderers that embed a plaintext
    # DB cred alongside an AWS canary. NOT a Tracebit-backed canary — a
    # replay against MySQL/Postgres won't fire an alert (Tracebit's
    # gitlab-username-password type only fires against their hosted gitlab
    # URL, which wouldn't be where a wp-config-style probe replays this).
    # The point is to avoid shipping a *fixed literal* across every sensor,
    # which turns into a farm-wide fingerprint.
    return secrets.token_urlsafe(16)


def _gitlab_creds(r: dict[str, object], canary_type: str) -> dict[str, object]:
    http = r.get("http") if isinstance(r, dict) else None
    if not isinstance(http, dict):
        return {}
    details = http.get(canary_type)
    if not isinstance(details, dict):
        return {}
    return details


def render_aws_credentials_ini(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "[default]\n"
        f"aws_access_key_id = {aws.get('awsAccessKeyId', '')}\n"
        f"aws_secret_access_key = {aws.get('awsSecretAccessKey', '')}\n"
        f"aws_session_token = {aws.get('awsSessionToken', '')}\n"
        "region = us-east-1\n"
    ).encode("utf-8")


def render_aws_config_ini(r: dict[str, object]) -> bytes:
    # `~/.aws/config` is the sibling of `~/.aws/credentials`: region / output
    # format / profile definitions. Some SDK setups stash the access key here
    # too (in-profile `aws_access_key_id`), so embedding the canary is valid.
    aws = _aws(r)
    return (
        "[default]\n"
        "region = us-east-1\n"
        "output = json\n"
        f"aws_access_key_id = {aws.get('awsAccessKeyId', '')}\n"
        f"aws_secret_access_key = {aws.get('awsSecretAccessKey', '')}\n"
        "\n"
        "[profile prod]\n"
        "region = us-east-1\n"
        "output = json\n"
        f"aws_session_token = {aws.get('awsSessionToken', '')}\n"
    ).encode("utf-8")


def render_pgpass(r: dict[str, object]) -> bytes:
    # Postgres `.pgpass` format: one line per entry, colon-separated
    # hostname:port:database:username:password. libpq reads this file if it
    # exists and mode 0600. Harvesters typically grep the whole file, so
    # a single plausible line is enough to elicit a follow-up.
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    password = str(creds.get("password", "") or "")
    return (
        f"db.internal:5432:app_prod:{username}:{password}\n"
        f"db-replica.internal:5432:*:{username}:{password}\n"
    ).encode("utf-8")


def render_claude_credentials_json(r: dict[str, object]) -> bytes:
    # Claude Code stores its OAuth tokens at `~/.claude/.credentials.json`.
    # Scanner dictionaries added this path in April 2026 shortly after
    # Claude Code's rollout — tracker-kits follow new developer tooling.
    # Same caveat as the other AI-credential traps: Tracebit Community has
    # no LLM canary type yet, so we embed an AWS canary under
    # Anthropic-shaped field names. A grep-by-field harvester will still
    # serialize the value; a prefix-filter scanner (`sk-ant-...`) will
    # correctly decide the key is fake and drop it. Either way, the probe
    # itself is the intel we want.
    aws = _aws(r)
    return json.dumps({
        "claudeAiOauth": {
            "accessToken": aws.get("awsAccessKeyId", ""),
            "refreshToken": aws.get("awsSecretAccessKey", ""),
            "expiresAt": aws.get("awsExpiration", ""),
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
        },
    }, indent=2).encode("utf-8")


def render_wp_config_php(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    db_password = _fake_db_password()
    return (
        "<?php\n"
        "/** MySQL settings */\n"
        "define('DB_NAME', 'wordpress');\n"
        "define('DB_USER', 'wp_prod');\n"
        f"define('DB_PASSWORD', '{db_password}');\n"
        "define('DB_HOST', 'db.internal:3306');\n"
        "define('DB_CHARSET', 'utf8mb4');\n"
        "\n"
        "/** AWS settings for media uploads + nightly backups */\n"
        f"define('AWS_ACCESS_KEY_ID', '{aws.get('awsAccessKeyId', '')}');\n"
        f"define('AWS_SECRET_ACCESS_KEY', '{aws.get('awsSecretAccessKey', '')}');\n"
        f"define('AWS_SESSION_TOKEN', '{aws.get('awsSessionToken', '')}');\n"
        "define('AWS_DEFAULT_REGION', 'us-east-1');\n"
        "define('S3_UPLOADS_BUCKET', 'wp-uploads-prod');\n"
        "\n"
        "$table_prefix = 'wp_';\n"
        "define('WP_DEBUG', false);\n"
        "if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }\n"
        "require_once ABSPATH . 'wp-settings.php';\n"
    ).encode("utf-8")


def render_sql_dump(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    return (
        "-- MySQL dump 10.13  Distrib 8.0.35\n"
        f"-- Host: db.internal    Database: wp_prod\n"
        f"-- Dumped at: {ts}\n"
        "--\n"
        "-- S3 backup credentials (rotate via Vault; see INFRA-412):\n"
        f"--   AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"--   AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"--   AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        "--\n"
        "\n"
        "LOCK TABLES `wp_options` WRITE;\n"
        "INSERT INTO `wp_options` VALUES (1,'siteurl','https://shop.internal-tools.lan','yes');\n"
        "INSERT INTO `wp_options` VALUES (2,'blogname','Internal Tools','yes');\n"
        "INSERT INTO `wp_options` VALUES (3,'admin_email','ops@internal-tools.lan','yes');\n"
        "INSERT INTO `wp_options` VALUES (4,'s3_backup_bucket','wp-backups-prod','yes');\n"
        f"INSERT INTO `wp_options` VALUES (5,'s3_access_key','{aws.get('awsAccessKeyId', '')}','no');\n"
        f"INSERT INTO `wp_options` VALUES (6,'s3_secret_key','{aws.get('awsSecretAccessKey', '')}','no');\n"
        "UNLOCK TABLES;\n"
    ).encode("utf-8")


def render_config_json(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return json.dumps({
        "app": "internal-tools",
        "env": "production",
        "aws": {
            "access_key_id": aws.get("awsAccessKeyId", ""),
            "secret_access_key": aws.get("awsSecretAccessKey", ""),
            "session_token": aws.get("awsSessionToken", ""),
            "region": "us-east-1",
        },
        "features": {"s3_uploads": True, "dynamodb_sessions": True},
    }, indent=2).encode("utf-8")


def render_firebase_json(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    # We only have AWS canaries from Tracebit Community today. Shape this
    # like a service-account file but label keys in a way that still looks
    # plausible to a grep-based scanner.
    return json.dumps({
        "type": "service_account",
        "project_id": "internal-tools-prod",
        "private_key_id": aws.get("awsAccessKeyId", ""),
        "private_key": f"-----BEGIN PRIVATE KEY-----\n{aws.get('awsSecretAccessKey', '')}\n-----END PRIVATE KEY-----\n",
        "client_email": "deployer@internal-tools-prod.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
        "aws_session_token": aws.get("awsSessionToken", ""),
    }, indent=2).encode("utf-8")


def render_docker_config(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    import base64
    auth = base64.b64encode(
        f"AWS:{aws.get('awsSecretAccessKey', '')}".encode("utf-8"),
    ).decode("ascii")
    return json.dumps({
        "auths": {
            "123456789012.dkr.ecr.us-east-1.amazonaws.com": {
                "auth": auth,
                "identitytoken": aws.get("awsSessionToken", ""),
            },
        },
        "credsStore": "ecr-login",
        "HttpHeaders": {"User-Agent": "Docker-Client/24.0.7 (linux)"},
    }, indent=2).encode("utf-8")


def render_docker_compose_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "version: '3.9'\n"
        "services:\n"
        "  web:\n"
        "    image: internal/tools:prod\n"
        "    environment:\n"
        f"      AWS_ACCESS_KEY_ID: {aws.get('awsAccessKeyId', '')}\n"
        f"      AWS_SECRET_ACCESS_KEY: {aws.get('awsSecretAccessKey', '')}\n"
        f"      AWS_SESSION_TOKEN: {aws.get('awsSessionToken', '')}\n"
        "      AWS_DEFAULT_REGION: us-east-1\n"
        "    ports:\n"
        "      - '8080:8080'\n"
    ).encode("utf-8")


def render_application_properties(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    db_password = _fake_db_password()
    return (
        "# Spring Boot production config\n"
        "spring.application.name=internal-tools\n"
        "server.port=8080\n"
        "\n"
        "spring.datasource.url=jdbc:postgresql://db.internal:5432/prod\n"
        "spring.datasource.username=prod_rw\n"
        f"spring.datasource.password={db_password}\n"
        "\n"
        f"aws.access.key.id={aws.get('awsAccessKeyId', '')}\n"
        f"aws.access.key.secret={aws.get('awsSecretAccessKey', '')}\n"
        f"aws.session.token={aws.get('awsSessionToken', '')}\n"
        "aws.region=us-east-1\n"
    ).encode("utf-8")


def render_application_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    db_password = _fake_db_password()
    return (
        "spring:\n"
        "  application:\n"
        "    name: internal-tools\n"
        "  datasource:\n"
        "    url: jdbc:postgresql://db.internal:5432/prod\n"
        "    username: prod_rw\n"
        f"    password: {db_password}\n"
        "aws:\n"
        f"  access-key-id: {aws.get('awsAccessKeyId', '')}\n"
        f"  access-key-secret: {aws.get('awsSecretAccessKey', '')}\n"
        f"  session-token: {aws.get('awsSessionToken', '')}\n"
        "  region: us-east-1\n"
    ).encode("utf-8")


def render_env_production(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    # Password is URL-safe already (secrets.token_urlsafe emits only
    # `-`, `_`, alphanum) so no extra percent-encoding is needed for the
    # userinfo component of DATABASE_URL.
    db_password = _fake_db_password()
    return (
        "# production .env — rotate quarterly (INFRA-218)\n"
        "NODE_ENV=production\n"
        f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        "AWS_REGION=us-east-1\n"
        f"DATABASE_URL=postgresql://prod_rw:{db_password}@db.internal:5432/prod\n"
    ).encode("utf-8")


def render_actuator_env_json(r: dict[str, object]) -> bytes:
    # Spring Boot Actuator `/env` response shape: activeProfiles + a list of
    # propertySources, each holding `properties: {<key>: {value, origin?}}`.
    # Unmasked values are the misconfiguration we're simulating — the
    # `management.endpoint.env.show-values=ALWAYS` flag (or an ancient 1.x
    # actuator with no masking) is what makes this endpoint a credential
    # leak in the wild. A scanner that reaches this path is expecting the
    # raw credential back; mask it and the response fails the scanner's
    # filter and they move on.
    aws = _aws(r)
    db_password = _fake_db_password()
    payload = {
        "activeProfiles": ["production"],
        "propertySources": [
            {
                "name": "server.ports",
                "properties": {
                    "local.server.port": {"value": 8080},
                },
            },
            {
                "name": "systemEnvironment",
                "properties": {
                    "AWS_ACCESS_KEY_ID": {
                        "value": aws.get("awsAccessKeyId", ""),
                        "origin": 'System Environment Property "AWS_ACCESS_KEY_ID"',
                    },
                    "AWS_SECRET_ACCESS_KEY": {
                        "value": aws.get("awsSecretAccessKey", ""),
                        "origin": 'System Environment Property "AWS_SECRET_ACCESS_KEY"',
                    },
                    "AWS_SESSION_TOKEN": {
                        "value": aws.get("awsSessionToken", ""),
                    },
                    "AWS_DEFAULT_REGION": {"value": "us-east-1"},
                    "JAVA_HOME": {"value": "/usr/lib/jvm/java-17-openjdk"},
                    "PATH": {
                        "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    },
                },
            },
            {
                "name": "applicationConfig: [classpath:/application.yml]",
                "properties": {
                    "spring.application.name": {"value": "internal-tools"},
                    "spring.datasource.url": {
                        "value": "jdbc:postgresql://db.internal:5432/prod",
                    },
                    "spring.datasource.username": {"value": "prod_rw"},
                    "spring.datasource.password": {"value": db_password},
                    "spring.datasource.driver-class-name": {
                        "value": "org.postgresql.Driver",
                    },
                    "management.endpoints.web.exposure.include": {"value": "*"},
                },
            },
        ],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def render_phpinfo(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    ak = aws.get("awsAccessKeyId", "")
    sk = aws.get("awsSecretAccessKey", "")
    st = aws.get("awsSessionToken", "")
    db_password = _fake_db_password()
    return (
        "<!DOCTYPE html>\n"
        "<html><head><title>phpinfo()</title>\n"
        "<style>body{background:#fff;color:#000;font-family:sans-serif}"
        "table{border-collapse:collapse;width:80%;margin:1em auto}"
        "th,td{border:1px solid #000;padding:4px 8px}"
        "h1{background:#9999cc;text-align:center}"
        "h2{background:#ccccff;margin-top:2em}</style></head><body>\n"
        "<h1>PHP Version 8.2.15</h1>\n"
        "<h2>Environment</h2>\n"
        "<table>\n"
        "<tr><th>Variable</th><th>Value</th></tr>\n"
        f"<tr><td>AWS_ACCESS_KEY_ID</td><td>{ak}</td></tr>\n"
        f"<tr><td>AWS_SECRET_ACCESS_KEY</td><td>{sk}</td></tr>\n"
        f"<tr><td>AWS_SESSION_TOKEN</td><td>{st}</td></tr>\n"
        "<tr><td>AWS_DEFAULT_REGION</td><td>us-east-1</td></tr>\n"
        "<tr><td>DB_HOST</td><td>db.internal</td></tr>\n"
        "<tr><td>DB_USER</td><td>prod_rw</td></tr>\n"
        f"<tr><td>DB_PASSWORD</td><td>{db_password}</td></tr>\n"
        "</table>\n"
        "<h2>Loaded Modules</h2>\n"
        "<p>core, date, libxml, openssl, pcre, sqlite3, zlib, ctype, curl, "
        "dom, fileinfo, filter, hash, iconv, json, mbstring, SPL, session, "
        "pdo_mysql, mysqlnd, ftp</p>\n"
        "</body></html>\n"
    ).encode("utf-8")


def _decode_ssh_value(raw: str) -> str:
    # Tracebit Community returns ``sshPrivateKey`` and ``sshPublicKey`` as
    # base64 over the on-wire JSON. If we serve the base64 verbatim to a
    # scanner on /id_rsa, ``ssh -i`` reads "invalid format" and no replay
    # ever fires the canary — which matches the dashboard reality of only
    # ~5 SSH canaries ever issued despite ~700 SSH-path hits/30d (attackers
    # fetch the "key", fail to use it, move on). Decode to the real PEM /
    # OpenSSH-authorized-keys string before serving. If the upstream format
    # changes back to raw PEM someday, a string starting with "-----BEGIN"
    # or "ssh-" base64-decodes to gibberish and UnicodeDecodeError bails
    # us out — fall back to serving the value as-is.
    if not raw:
        return ""
    try:
        decoded = base64.b64decode(raw, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return raw
    return decoded


def render_ssh_private_key(r: dict[str, object]) -> bytes:
    ssh = r.get("ssh") if isinstance(r, dict) else None
    if not isinstance(ssh, dict):
        return b""
    pk = _decode_ssh_value(str(ssh.get("sshPrivateKey", "") or ""))
    return (pk if pk.endswith("\n") else pk + "\n").encode("utf-8")


def render_ssh_public_key(r: dict[str, object]) -> bytes:
    ssh = r.get("ssh") if isinstance(r, dict) else None
    if not isinstance(ssh, dict):
        return b""
    pub = _decode_ssh_value(str(ssh.get("sshPublicKey", "") or ""))
    return (pub if pub.endswith("\n") else pub + "\n").encode("utf-8")


def render_authorized_keys(r: dict[str, object]) -> bytes:
    ssh = r.get("ssh") if isinstance(r, dict) else None
    if not isinstance(ssh, dict):
        return b""
    pub = _decode_ssh_value(str(ssh.get("sshPublicKey", "") or "")).strip()
    return (
        f"# production deploy keys — rotate via scripts/rotate-keys.sh\n"
        f"{pub}\n"
    ).encode("utf-8")


def render_ssh_config(r: dict[str, object]) -> bytes:
    # `~/.ssh/config` maps logical host aliases to real hosts + identity
    # files. Without this, a harvested /id_rsa is useless — the attacker
    # has no signal about which host accepts it. Tracebit's ssh canary
    # pairs the key with an ``sshIp``; pin the config to that IP and point
    # IdentityFile at the sibling /.ssh/id_rsa trap so an attacker running
    # ``ssh bastion`` fires the canary.
    ssh = r.get("ssh") if isinstance(r, dict) else None
    if not isinstance(ssh, dict):
        return b""
    ssh_ip = str(ssh.get("sshIp", "") or "")
    if not ssh_ip:
        return b""
    return (
        "Host bastion\n"
        f"    HostName {ssh_ip}\n"
        "    User root\n"
        "    IdentityFile ~/.ssh/id_rsa\n"
        "    IdentitiesOnly yes\n"
        "    ServerAliveInterval 60\n"
    ).encode("utf-8")


def render_known_hosts(r: dict[str, object]) -> bytes:
    # A real ``~/.ssh/known_hosts`` lists hosts the user has connected to,
    # each with the host key the ssh client saw on first contact. For our
    # purposes it's the second half of the IP↔key pairing: harvesters who
    # grab ``known_hosts`` alongside ``id_rsa`` learn which host the key
    # holder has SSH'd to — sshIp, where the Tracebit canary fires.
    ssh = r.get("ssh") if isinstance(r, dict) else None
    if not isinstance(ssh, dict):
        return b""
    ssh_ip = str(ssh.get("sshIp", "") or "")
    pub = _decode_ssh_value(str(ssh.get("sshPublicKey", "") or "")).strip()
    if not ssh_ip or not pub:
        return b""
    return f"{ssh_ip} {pub}\n".encode("utf-8")


def render_netrc(r: dict[str, object]) -> bytes:
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    password = str(creds.get("password", "") or "")
    host_names = _gitlab_creds(r, "gitlab-username-password").get("hostNames") or []
    host = str(host_names[0]) if host_names else "gitlab.internal-tools.lan"
    return (
        f"machine {host}\n"
        f"  login {username}\n"
        f"  password {password}\n"
    ).encode("utf-8")


def render_git_credentials(r: dict[str, object]) -> bytes:
    """Render a Git credential-store file (`~/.git-credentials`).

    Format: one URL per line, userinfo-form — `https://user:pass@host`.
    Git writes this via `git config --global credential.helper store`.
    Scanners hunting for leaked `.git-credentials` read the file and try
    the embedded credentials against whichever host appears. We embed
    gitlab-username-password canaries (the same pairs used by /.netrc)
    so a hit against the gitlab host triggers the Tracebit callback.
    """
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    password = str(creds.get("password", "") or "")
    host_names = _gitlab_creds(r, "gitlab-username-password").get("hostNames") or []
    host = str(host_names[0]) if host_names else "gitlab.internal-tools.lan"
    encoded_password = quote(password, safe="") if password else ""
    return (
        f"https://{username}:{encoded_password}@{host}\n"
    ).encode("utf-8")


def render_npmrc(r: dict[str, object]) -> bytes:
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    password = str(creds.get("password", "") or "")
    return (
        "registry=https://npm.internal-tools.lan/\n"
        f"//npm.internal-tools.lan/:_authToken={password}\n"
        "always-auth=true\n"
    ).encode("utf-8")


def render_pypirc(r: dict[str, object]) -> bytes:
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    password = str(creds.get("password", "") or "")
    return (
        "[distutils]\n"
        "index-servers = internal\n"
        "\n"
        "[internal]\n"
        "repository = https://pypi.internal-tools.lan/\n"
        f"username = {username}\n"
        f"password = {password}\n"
    ).encode("utf-8")


def render_gitlab_api_user(r: dict[str, object]) -> bytes:
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    return json.dumps({
        "id": 42,
        "username": username,
        "name": "Deploy Bot",
        "state": "active",
        "email": f"{username}@internal-tools.lan",
        "web_url": f"https://gitlab.internal-tools.lan/{username}",
        "is_admin": False,
        "two_factor_enabled": False,
    }, indent=2).encode("utf-8")


def render_gitlab_sign_in(r: dict[str, object]) -> bytes:
    # Body doesn't need the canary; just a plausible login page. The canary
    # goes out as Set-Cookie when we dispatch this trap (see _send_canary_trap).
    return (
        "<!DOCTYPE html>\n"
        "<html><head><title>Sign in &middot; GitLab</title></head>\n"
        "<body>\n"
        "<h1>GitLab</h1>\n"
        "<form method='POST' action='/users/sign_in'>\n"
        "<input name='authenticity_token' type='hidden' value='xxx' />\n"
        "<label>Username or email <input name='user[login]' /></label>\n"
        "<label>Password <input name='user[password]' type='password' /></label>\n"
        "<button type='submit'>Sign in</button>\n"
        "</form>\n"
        "<p><a href='/users/password/new'>Forgot your password?</a></p>\n"
        "</body></html>\n"
    ).encode("utf-8")


# --- AI credential config files (/.openai/config.json, etc.) -------------
#
# Scanner fleets were observed probing `/.openai/config.json`,
# `/.anthropic/config.json`, and `/.cursor/mcp.json` in mid-April 2026 —
# looking for harvestable LLM provider credentials — and appeared to be
# absorbed into standard env-hunter dictionaries shortly after debut.
#
# **This trap probably doesn't make sense yet, and we're shipping it
# anyway.** Tracebit Community only exposes `aws`, `ssh`,
# `gitlab-username-password`, and `gitlab-cookie` canary types today — no
# OpenAI/Anthropic/LLM type. The renderers below therefore dress an AWS
# canary in OpenAI/Anthropic/Cursor-shaped JSON. A grep-based scanner that
# only cares about the field names (`api_key`, `auth_token`) will still
# serialize the value and ship it to its exfil endpoint; a scanner that
# filters by the `sk-...` / `sk-ant-...` key-format prefix will correctly
# decide the key is fake and drop it. Either way we still log the probe,
# which is the primary intel for now.
#
# When Tracebit ships LLM canary types (hinted at in their marketing), swap
# the renderers below over and the trap becomes genuinely trippable.


def render_openai_config_json(r: dict[str, object]) -> bytes:
    # Official OpenAI clients don't actually use `~/.openai/config.json` —
    # the path is a common misconfiguration / leaked-env-var convention,
    # which is why scanners grep for it. We emit a shape that matches what
    # several third-party OpenAI wrapper libs document.
    aws = _aws(r)
    return json.dumps({
        "organization": "org-internal-tools",
        "api_key": aws.get("awsAccessKeyId", ""),
        "api_secret": aws.get("awsSecretAccessKey", ""),
        "session_token": aws.get("awsSessionToken", ""),
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
    }, indent=2).encode("utf-8")


def render_anthropic_config_json(r: dict[str, object]) -> bytes:
    # Same caveat as render_openai_config_json: Anthropic's official SDK
    # doesn't use a config.json, but scanner dictionaries include this path
    # because leaked env files + third-party wrappers often do.
    aws = _aws(r)
    return json.dumps({
        "auth_token": aws.get("awsAccessKeyId", ""),
        "api_key": aws.get("awsSecretAccessKey", ""),
        "session_token": aws.get("awsSessionToken", ""),
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-3-5-sonnet-20241022",
    }, indent=2).encode("utf-8")


def render_cursor_mcp_json(r: dict[str, object]) -> bytes:
    # Cursor's Model Context Protocol config — can contain API keys and
    # tokens passed as env vars to spawned MCP servers. We embed the canary
    # as the auth material on two plausible MCP server entries.
    aws = _aws(r)
    return json.dumps({
        "mcpServers": {
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {
                    "GITHUB_PERSONAL_ACCESS_TOKEN": aws.get("awsAccessKeyId", ""),
                },
            },
            "internal-tools": {
                "command": "uvx",
                "args": ["--from", "internal-tools-mcp", "serve"],
                "env": {
                    "API_KEY": aws.get("awsSecretAccessKey", ""),
                    "SESSION_TOKEN": aws.get("awsSessionToken", ""),
                    "BASE_URL": "https://tools.internal.lan",
                },
            },
        },
    }, indent=2).encode("utf-8")


@dataclass(frozen=True)
class CanaryTrap:
    name: str                      # log tag, e.g. "aws-credentials-file"
    paths: tuple[str, ...]          # exact lowercase matches
    canary_types: tuple[str, ...]   # Tracebit types to request
    render: "Callable[[dict[str, object]], bytes]"
    content_type: str
    # Optional: extra response headers to emit (e.g. Set-Cookie for gitlab-cookie).
    extra_headers: "Callable[[dict[str, object]], tuple[tuple[str, str], ...]]" = field(
        default=lambda _r: ()
    )


def _gitlab_cookie_header(r: dict[str, object]) -> tuple[tuple[str, str], ...]:
    creds = _gitlab_creds(r, "gitlab-cookie").get("credentials")
    if not isinstance(creds, dict):
        return ()
    cookie_name = str(creds.get("name") or creds.get("cookie_name") or "_gitlab_session")
    cookie_value = str(
        creds.get("value") or creds.get("cookie_value") or creds.get("password") or "",
    )
    if not cookie_value:
        return ()
    return (
        ("Set-Cookie", f"{cookie_name}={cookie_value}; Path=/; HttpOnly; SameSite=Lax"),
    )


CANARY_TRAPS: tuple[CanaryTrap, ...] = (
    CanaryTrap(
        "aws-credentials-file",
        ("/.aws/credentials",),
        ("aws",),
        render_aws_credentials_ini,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "aws-config-file",
        ("/.aws/config",),
        ("aws",),
        render_aws_config_ini,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "pgpass",
        ("/.pgpass",),
        ("gitlab-username-password",),
        render_pgpass,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "wp-config",
        ("/wp-config.php", "/wp-config.php.bak", "/wp-config.old", "/wp-config.txt"),
        ("aws",),
        render_wp_config_php,
        "application/x-php; charset=utf-8",
    ),
    CanaryTrap(
        "sql-dump",
        ("/backup.sql", "/db.sql", "/dump.sql", "/database.sql", "/backup/db.sql", "/sql/backup.sql"),
        ("aws",),
        render_sql_dump,
        "application/sql; charset=utf-8",
    ),
    CanaryTrap(
        "config-json",
        ("/config.json", "/settings.json", "/credentials.json", "/secrets.json"),
        ("aws",),
        render_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "firebase-json",
        ("/firebase.json", "/google-services.json", "/serviceaccount.json", "/service-account.json"),
        ("aws",),
        render_firebase_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "docker-config",
        ("/.docker/config.json", "/docker/config.json"),
        ("aws",),
        render_docker_config,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "docker-compose",
        (
            "/docker-compose.yml", "/docker-compose.yaml",
            "/compose.yml", "/compose.yaml",
            # Environment-suffixed variants observed in scanner dictionaries —
            # typical deploys ship separate compose files per env and scanners
            # enumerate the obvious ones.
            "/docker-compose.prod.yml", "/docker-compose.prod.yaml",
            "/docker-compose.production.yml", "/docker-compose.production.yaml",
            "/docker-compose.dev.yml", "/docker-compose.dev.yaml",
            "/docker-compose.staging.yml", "/docker-compose.staging.yaml",
            "/docker-compose.override.yml", "/docker-compose.override.yaml",
        ),
        ("aws",),
        render_docker_compose_yml,
        "application/yaml; charset=utf-8",
    ),
    CanaryTrap(
        "application-properties",
        ("/application.properties",),
        ("aws",),
        render_application_properties,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "application-yml",
        ("/application.yml", "/application.yaml"),
        ("aws",),
        render_application_yml,
        "application/yaml; charset=utf-8",
    ),
    # Spring Boot Actuator `/env` endpoint. A Spring app exposing
    # `management.endpoints.web.exposure.include=*` serves the full
    # environment — system env vars, JVM props, application.yml values —
    # as JSON. Scanners hunt this path specifically because it returns
    # raw `spring.datasource.password` and `AWS_SECRET_ACCESS_KEY` values
    # in one response. Path aliases cover the legacy 1.x actuator
    # (`/env`), common `management.endpoints.web.base-path` overrides
    # (`/manage`, `/management`), and a `/api`-prefixed reverse-proxy
    # shape.
    CanaryTrap(
        "actuator-env",
        (
            "/actuator/env",
            "/actuator/env.json",
            "/env",
            "/manage/env",
            "/management/env",
            "/api/actuator/env",
        ),
        ("aws",),
        render_actuator_env_json,
        "application/vnd.spring-boot.actuator.v3+json; charset=utf-8",
    ),
    CanaryTrap(
        "env-production",
        ("/.env.production", "/.env.prod", "/.env.live"),
        ("aws",),
        render_env_production,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "phpinfo",
        ("/phpinfo.php", "/info.php", "/php.php", "/test.php"),
        ("aws",),
        render_phpinfo,
        "text/html; charset=utf-8",
    ),
    CanaryTrap(
        "ssh-private-key",
        (
            "/id_rsa",
            "/.ssh/id_rsa",
            "/ssh/id_rsa",
            "/ssh/id_rsa.key",
            "/keys/id_rsa",
            "/private.key",
            "/deploy_key",
            "/deploy.key",
            # Tracebit issues ed25519, so the id_ed25519 filename is the
            # most literal match; id_dsa / id_ecdsa covered because
            # scanner dictionaries probe every algo by convention.
            "/.ssh/id_ed25519",
            "/.ssh/id_dsa",
            "/.ssh/id_ecdsa",
            "/id_ed25519",
            "/id_dsa",
            "/id_ecdsa",
            # `/root/.ssh/id_rsa` and `/home/.ssh/id_rsa` are common
            # path-prefix variants — scanners hunt for home-dir leakage
            # below a misconfigured webroot.
            "/root/.ssh/id_rsa",
            "/home/.ssh/id_rsa",
        ),
        ("ssh",),
        render_ssh_private_key,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "ssh-public-key",
        ("/id_rsa.pub", "/.ssh/id_rsa.pub"),
        ("ssh",),
        render_ssh_public_key,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "ssh-config",
        ("/.ssh/config",),
        ("ssh",),
        render_ssh_config,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "known-hosts",
        ("/.ssh/known_hosts", "/known_hosts"),
        ("ssh",),
        render_known_hosts,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "authorized-keys",
        (
            "/authorized_keys",
            "/.ssh/authorized_keys",
            "/.ssh/authorized_keys2",
            # Webroot-prefix variants — common scanner pattern where a
            # directory (e.g. the CMS upload area) is assumed to sit atop
            # an unexpected ``.ssh/`` leak.
            "/static/.ssh/authorized_keys",
            "/downloads/.ssh/authorized_keys",
            "/blog/.ssh/authorized_keys",
        ),
        ("ssh",),
        render_authorized_keys,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "netrc",
        ("/.netrc", "/_netrc"),
        ("gitlab-username-password",),
        render_netrc,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "git-credentials",
        ("/.git-credentials",),
        ("gitlab-username-password",),
        render_git_credentials,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "npmrc",
        ("/.npmrc",),
        ("gitlab-username-password",),
        render_npmrc,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "pypirc",
        ("/.pypirc",),
        ("gitlab-username-password",),
        render_pypirc,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "gitlab-api-user",
        ("/api/v4/user",),
        ("gitlab-username-password",),
        render_gitlab_api_user,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "gitlab-sign-in",
        ("/users/sign_in",),
        ("gitlab-cookie",),
        render_gitlab_sign_in,
        "text/html; charset=utf-8",
        extra_headers=_gitlab_cookie_header,
    ),
    # AI credential config files. See the big comment above
    # render_openai_config_json for the "this probably doesn't make sense
    # yet" caveat — we're logging the probe now, and will swap in real LLM
    # canaries when Tracebit ships them.
    CanaryTrap(
        "openai-config",
        ("/.openai/config.json",),
        ("aws",),
        render_openai_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "anthropic-config",
        ("/.anthropic/config.json",),
        ("aws",),
        render_anthropic_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "cursor-mcp",
        ("/.cursor/mcp.json",),
        ("aws",),
        render_cursor_mcp_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "claude-credentials",
        ("/.claude/.credentials.json",),
        ("aws",),
        render_claude_credentials_json,
        "application/json; charset=utf-8",
    ),
)

_TRAP_BY_PATH: dict[str, CanaryTrap] = {}
for _trap in CANARY_TRAPS:
    for _p in _trap.paths:
        _TRAP_BY_PATH[_p.lower()] = _trap


def find_canary_trap(path: str) -> "CanaryTrap | None":
    if not CANARY_TRAPS_ENABLED:
        return None
    return _TRAP_BY_PATH.get(path.lower())





# ============================================================================
# Async HTTP handler — aiohttp
# ============================================================================


def _log_context_from_request(request: web.Request, request_id: str, body_bytes_read: int, body_sha256: str) -> dict[str, object]:
    host = clean_host(request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or "")
    client_ip = first_forwarded_ip(request.headers.get("X-Forwarded-For", ""))
    user_agent = request.headers.get("User-Agent", "")
    proto = (request.headers.get("X-Forwarded-Proto") or "http").strip().lower()
    url = request.rel_url
    raw_path = url.raw_path
    query_string = url.raw_query_string
    raw_target = raw_path + (("?" + query_string) if query_string else "")
    path = normalize_path(raw_path)
    return {
        "timestamp": utc_now(),
        "requestId": request_id,
        "method": request.method,
        "host": host,
        "path": path,
        "rawPath": raw_path,
        "rawTarget": raw_target,
        "query": query_string,
        "clientIp": client_ip,
        "userAgent": user_agent,
        "protocol": proto,
        "headers": header_subset(request.headers),
        "bodyBytesRead": body_bytes_read,
        "bodySha256": body_sha256,
    }


async def _handle_llm_endpoint(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    """Dispatch a fake LLM-API response by path. Always 200 + JSON; the
    whole point is to look live enough that the scanner keeps going."""
    lpath = path.lower()
    method = request.method
    content_type_req = request.headers.get("Content-Type", "")
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("x-api-key", "") or request.headers.get("X-Api-Key", "")
    has_auth = bool(auth_header) or bool(api_key_header)

    model, prompt, action, _ = extract_llm_prompt(request_body, content_type_req)

    # Route to a renderer.
    if lpath in {"/v1/models"}:
        result_tag = "llm-endpoint-models-list"
        body = render_openai_models()
        if not action:
            action = "models-list"
    elif lpath == "/anthropic/v1/models":
        result_tag = "llm-endpoint-anthropic-models-list"
        body = render_anthropic_models()
        if not action:
            action = "models-list"
    elif lpath == "/api/tags":
        result_tag = "llm-endpoint-ollama-tags"
        body = render_ollama_tags()
        if not action:
            action = "models-list"
    elif lpath == "/api/version":
        result_tag = "llm-endpoint-ollama-version"
        body = render_ollama_version()
        if not action:
            action = "version"
    elif lpath == "/api/ps":
        result_tag = "llm-endpoint-ollama-ps"
        body = render_ollama_ps()
        if not action:
            action = "running-models"
    elif lpath == "/api/show":
        result_tag = "llm-endpoint-ollama-show"
        body = render_ollama_show(model)
        if not action:
            action = "show-model"
    elif lpath == "/api/chat":
        result_tag = "llm-endpoint-ollama-chat"
        body = render_ollama_chat(model)
    elif lpath == "/api/generate":
        result_tag = "llm-endpoint-ollama-generate"
        body = render_ollama_generate(model)
    elif lpath == "/v1/chat/completions":
        result_tag = "llm-endpoint-openai-chat"
        body = render_openai_chat(model)
    elif lpath == "/v1/completions":
        result_tag = "llm-endpoint-openai-completion"
        body = render_openai_completion(model)
    elif lpath == "/v1/embeddings":
        result_tag = "llm-endpoint-openai-embedding"
        body = render_openai_embedding(model)
    elif lpath in {"/v1/messages", "/anthropic/v1/messages"}:
        result_tag = "llm-endpoint-anthropic-message"
        body = render_anthropic_message(model)
    else:
        # Path matched the set but no renderer — shouldn't happen; defensive 404.
        append_log({**log_context, "status": 404, "result": "llm-endpoint-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "llmPath": path,
        "llmAction": action,
        "llmModel": model,
        "llmHasAuth": has_auth,
        "llmAuthScheme": auth_header.split(" ", 1)[0].lower() if auth_header else "",
        "llmMethod": method,
        "bytes": len(body),
    }
    if prompt:
        log_entry["llmPromptPreview"] = prompt
    append_log(log_entry)

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


async def _handle_sonicwall(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    """Dispatch a fake SonicOS SSL VPN response by path. All 200 + JSON; the
    whole point is to look live enough that the exploit chain proceeds."""
    lpath = path.lower()
    method = request.method
    content_type_req = request.headers.get("Content-Type", "")
    auth_header = request.headers.get("Authorization", "")
    cookie_header = request.headers.get("Cookie", "")
    # SonicOS clients sometimes present a prior session as a `swap_session`
    # or `SonicOS-Session` cookie; we don't validate, just log that it exists.
    has_auth = bool(auth_header) or "swap_session" in cookie_header.lower() or "sonicos-session" in cookie_header.lower()

    username = extract_sonicwall_username(request_body, content_type_req) if method == "POST" else ""

    # Deterministic but per-request session_id so the scanner gets a consistent
    # value to replay in the follow-on step.
    session_id = uuid.uuid4().hex

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    if lpath == "/api/sonicos/is-sslvpn-enabled":
        result_tag = "sonicwall-is-sslvpn-enabled"
        body = render_sonicwall_is_sslvpn_enabled()
    elif lpath == "/api/sonicos/auth":
        result_tag = "sonicwall-auth"
        body = render_sonicwall_auth_success(session_id)
    elif lpath == "/api/sonicos/tfa":
        result_tag = "sonicwall-tfa"
        body = render_sonicwall_tfa_success(session_id)
    else:
        # Path matched the set but no renderer — shouldn't happen; defensive 404.
        append_log({**log_context, "status": 404, "result": "sonicwall-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "sonicwallPath": path,
        "sonicwallMethod": method,
        "sonicwallHasAuth": has_auth,
        "sonicwallUsername": username,
        "sonicwallSessionId": session_id,
        "bytes": len(body),
        "contentType": content_type_req[:120],
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview
    append_log(log_entry)

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


async def _handle_webshell(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
) -> web.Response:
    query_params = parse_qs(query_string, keep_blank_values=True) if query_string else {}
    content_type = request.headers.get("Content-Type", "")
    form_params = parse_form_body(request_body, content_type)
    cookies = parse_cookies(request.headers.get("Cookie", ""))
    command_source, command_key, command = extract_webshell_command(
        query_params, form_params, cookies, request.headers,
    )

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    output = simulate_command_output(command) if command else ""
    payload = render_webshell_page(command=command, output=output)

    log_entry = {
        **log_context,
        "status": 200,
        "result": "webshell-command" if command else "webshell-probe",
        "webshellPath": path,
        "commandSource": command_source,
        "commandKey": command_key,
        "command": command,
        "simulatedOutputBytes": len(output),
        "cookieNames": sorted(cookies.keys()),
        "queryParamNames": sorted(query_params.keys()),
        "formParamNames": sorted(form_params.keys()),
        "contentType": content_type[:120],
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview
    append_log(log_entry)

    return web.Response(
        status=200, body=payload,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


async def _send_canary_trap(
    request: web.Request,
    trap: "CanaryTrap",
    request_id: str,
    path: str,
    client_ip: str,
    host: str,
    user_agent: str,
    proto: str,
    log_context: dict[str, object],
) -> web.Response:
    tracebit_response = await _get_or_issue_canary(
        trap.canary_types, client_ip, request_id, host, user_agent, path, proto,
    )
    if tracebit_response is None:
        append_log({**log_context, "status": 502, "result": f"{trap.name}-error"})
        return web.Response(
            status=502, body=b"upstream credential issue failed\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    try:
        body = trap.render(tracebit_response)
    except Exception as exc:  # noqa: BLE001 — render bugs shouldn't crash the sensor
        append_log({
            **log_context, "status": 502, "result": f"{trap.name}-render-error",
            "error": str(exc)[:400],
        })
        return web.Response(
            status=502, body=b"render error\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    response = web.Response(status=200, body=body)
    response.headers["Content-Type"] = trap.content_type
    response.headers["Cache-Control"] = "no-store"
    for header_name, header_value in trap.extra_headers(tracebit_response):
        response.headers[header_name] = header_value

    append_log({
        **log_context,
        "status": 200,
        "result": trap.name,
        "canaryTypes": [k for k, v in tracebit_response.items() if v],
        "bytes": len(body),
    })
    return response


async def _send_fake_git(
    request: web.Request,
    request_id: str,
    path: str,
    git_key: str,
    client_ip: str,
    host: str,
    user_agent: str,
    proto: str,
    log_context: dict[str, object],
) -> web.StreamResponse:
    """Serve the fake /.git tree.

    `path` is the raw (normalized) request path — used only for logging.
    `git_key` is the canonical lowercase `/.git/...` lookup key returned by
    extract_git_path(); it's what we use to look up the response body, so
    prefixed requests (e.g. `/login/.git/config`) find the same file as
    `/.git/config`. See LOGS.md — `path` in the log row is always the raw
    request so analysis can distinguish prefix-probe patterns from direct
    `/.git/` fetches.
    """
    global _active_slow_drips
    result = await _fake_git_get_or_build(client_ip, request_id, host, user_agent, path, proto)
    if result is None:
        append_log({**log_context, "status": 502, "result": "fake-git-error"})
        return web.Response(
            status=502, body=b"upstream credential issue failed\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    files, meta = result
    content = files.get(git_key)
    if content is None:
        append_log({
            **log_context, "status": 404, "result": "fake-git-miss",
            "commitSha": meta.get("commitSha", ""),
            "gitKey": git_key,
        })
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    if git_key.startswith("/.git/objects/") and "/info/" not in git_key:
        content_type = "application/x-git-loose-object"
    else:
        content_type = "text/plain; charset=utf-8"

    if _active_slow_drips >= TARPIT_MAX_CONNECTIONS:
        append_log({**log_context, "status": 503, "result": "fake-git-capacity"})
        return web.Response(
            status=503, body=b"busy\n",
            headers={
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-store",
            },
        )
    _active_slow_drips += 1
    try:
        response = web.StreamResponse(status=200, headers={
            "Content-Type": content_type,
            "Content-Length": str(len(content)),
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        })
        await response.prepare(request)
        append_log({
            **log_context,
            "status": 200,
            "result": "fake-git",
            "commitSha": meta.get("commitSha", ""),
            "rootTreeSha": meta.get("rootTreeSha", ""),
            "secretsBlobSha": meta.get("secretsBlobSha", ""),
            "canaryTypes": meta.get("canaryTypes", []),
            "fakeGitBytes": len(content),
            "fakeGitDripBytes": FAKE_GIT_DRIP_BYTES,
            "fakeGitDripIntervalMs": FAKE_GIT_DRIP_INTERVAL_MS,
        })
        if request.method == "HEAD":
            return response

        interval_s = FAKE_GIT_DRIP_INTERVAL_MS / 1000.0
        bytes_sent = 0
        try:
            for offset in range(0, len(content), FAKE_GIT_DRIP_BYTES):
                chunk = content[offset:offset + FAKE_GIT_DRIP_BYTES]
                await response.write(chunk)
                bytes_sent += len(chunk)
                if offset + FAKE_GIT_DRIP_BYTES < len(content):
                    await asyncio.sleep(interval_s)
        except (ConnectionResetError, asyncio.CancelledError, aiohttp.ClientConnectionError):
            append_log({
                **log_context, "status": 200, "result": "fake-git-disconnect",
                "fakeGitBytesSent": bytes_sent,
                "commitSha": meta.get("commitSha", ""),
            })
        return response
    finally:
        _active_slow_drips -= 1


async def _send_tarpit(
    request: web.Request,
    request_id: str,
    path: str,
    log_context: dict[str, object],
    query: str,
) -> web.StreamResponse:
    global _active_slow_drips
    ctx: dict[str, object] = {
        "log_context": log_context,
        "path": path,
        "query": query,
        "protocol": log_context.get("protocol", "https"),
        "host": log_context.get("host", ""),
        "send_body": request.method != "HEAD",
        "request_id": request_id,
    }

    # Terminal modules (first match wins).
    for mod in TARPIT_MODULES:
        if mod.terminal and mod.should_run(ctx):
            return await mod.run_terminal(request, ctx)

    # Redirect-chain continuation.
    if query:
        chain_id, hop = _parse_chain_params(query)
        if chain_id and MOD_REDIRECT_CHAIN_ENABLED:
            if hop < MOD_REDIRECT_CHAIN_MAX_HOPS:
                location = f"{path}?_hp_chain={chain_id}&_hp_hop={hop + 1}"
                append_log({
                    **log_context,
                    "status": 302,
                    "result": "tarpit-module",
                    "module": "redirect-chain",
                    "chainId": chain_id,
                    "hop": hop,
                })
                return web.Response(
                    status=302, body=b"redirecting\n",
                    headers={
                        "Location": location,
                        "Content-Type": "text/plain; charset=utf-8",
                        "Cache-Control": "no-store",
                    },
                )
            # Chain exhausted — fall through to drip.

    # Concurrency gate (simple int counter — safe in single-threaded event loop).
    if _active_slow_drips >= TARPIT_MAX_CONNECTIONS:
        append_log({**log_context, "status": 503, "result": "tarpit-capacity"})
        return web.Response(
            status=503, body=b"busy\n",
            headers={
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-store",
            },
        )
    _active_slow_drips += 1
    try:
        # Augmenting modules contribute headers + log metadata.
        aug_meta: dict[str, object] = {}
        extra_headers: dict[str, str] = {}
        for mod in TARPIT_MODULES:
            if not mod.terminal and mod.should_run(ctx):
                mod_headers, mod_meta = mod.augment(request, ctx)
                extra_headers.update(mod_headers)
                if mod_meta:
                    aug_meta[mod.name] = mod_meta

        response = web.StreamResponse(status=200, headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            **extra_headers,
        })
        await response.prepare(request)

        log_entry: dict[str, object] = {
            **log_context,
            "status": 200,
            "result": "tarpit",
            "tarpitChunkBytes": TARPIT_CHUNK_BYTES,
            "tarpitIntervalMs": TARPIT_INTERVAL_MS,
            "tarpitSeconds": TARPIT_SECONDS,
        }
        if aug_meta:
            log_entry["modules"] = aug_meta
        append_log(log_entry)

        if request.method == "HEAD":
            return response

        if MOD_VARIABLE_DRIP_ENABLED:
            interval_ms = float(MOD_VARIABLE_DRIP_INITIAL_MS)
        else:
            interval_ms = float(TARPIT_INTERVAL_MS)

        deadline = (time.monotonic() + TARPIT_SECONDS) if TARPIT_SECONDS > 0 else None
        chunks_sent = 0
        try:
            while deadline is None or time.monotonic() < deadline:
                await response.write(build_tarpit_chunk(request_id, path, chunks_sent))
                chunks_sent += 1
                await asyncio.sleep(interval_ms / 1000.0)
                if MOD_VARIABLE_DRIP_ENABLED:
                    interval_ms = min(interval_ms * 1.5, float(MOD_VARIABLE_DRIP_MAX_MS))
        except (ConnectionResetError, asyncio.CancelledError, aiohttp.ClientConnectionError):
            append_log({
                **log_context,
                "status": 200,
                "result": "tarpit-disconnect",
                "tarpitChunksSent": chunks_sent,
            })
        return response
    finally:
        _active_slow_drips -= 1


async def _send_env(
    request: web.Request,
    request_id: str,
    path: str,
    client_ip: str,
    host: str,
    user_agent: str,
    proto: str,
    log_context: dict[str, object],
) -> web.Response:
    try:
        tracebit_response = await issue_credentials(request_id, client_ip, host, user_agent, path, proto)
    except aiohttp.ClientResponseError as exc:
        append_log({
            **log_context,
            "status": 502,
            "result": "tracebit-http-error",
            "tracebitStatus": exc.status,
            "error": (exc.message or "")[:400],
        })
        return web.Response(
            status=502, body=b"upstream credential issue failed\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        append_log({
            **log_context, "status": 502, "result": "tracebit-error",
            "error": str(exc)[:400],
        })
        return web.Response(
            status=502, body=b"upstream credential issue failed\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    payload = format_env_payload(tracebit_response).encode("utf-8")
    append_log({
        **log_context, "status": 200, "result": "issued",
        "types": [key for key, value in tracebit_response.items() if value],
    })
    return web.Response(
        status=200, body=payload,
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )


async def handle(request: web.Request) -> web.StreamResponse:
    method = request.method
    if method not in ("GET", "HEAD", "POST"):
        return web.Response(status=405, body=b"method not allowed\n")

    request_id = str(uuid.uuid4())
    read_body = method == "POST"

    body_bytes_read = 0
    body_sha256 = ""
    request_body = b""
    if read_body:
        # Cap body size off the wire. aiohttp returns exactly N bytes or fewer;
        # the scanner's Content-Length is advisory only, not trusted.
        request_body = await request.content.read(WEBSHELL_BODY_READ_LIMIT)
        body_bytes_read = len(request_body)
        body_sha256 = hashlib.sha256(request_body).hexdigest()

    log_context = _log_context_from_request(request, request_id, body_bytes_read, body_sha256)
    path = str(log_context["path"])
    query_string = str(log_context["query"])
    client_ip = str(log_context["clientIp"])
    host = str(log_context["host"])
    user_agent = str(log_context["userAgent"])
    proto = str(log_context["protocol"])

    if is_webshell_path(path):
        return await _handle_webshell(request, log_context, path, query_string, request_body)

    if is_llm_endpoint_path(path):
        return await _handle_llm_endpoint(request, log_context, path, request_body)

    if is_sonicwall_path(path):
        return await _handle_sonicwall(request, log_context, path, request_body)

    if TARPIT_ENABLED and (is_tarpit_path(path) or is_fingerprint_path(path)):
        return await _send_tarpit(request, request_id, path, log_context, query_string)

    if FAKE_GIT_ENABLED and API_KEY:
        git_key = extract_git_path(path)
        if git_key is not None:
            return await _send_fake_git(
                request, request_id, path, git_key,
                client_ip, host, user_agent, proto, log_context,
            )

    if API_KEY:
        trap = find_canary_trap(path)
        if trap is not None:
            return await _send_canary_trap(
                request, trap, request_id, path, client_ip, host, user_agent, proto, log_context,
            )

    if path != "/.env" or not API_KEY:
        append_log({**log_context, "status": 404, "result": "not-handled"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    return await _send_env(
        request, request_id, path, client_ip, host, user_agent, proto, log_context,
    )


async def _close_http_session(app: web.Application) -> None:
    global _http_session
    if _http_session is not None and not _http_session.closed:
        await _http_session.close()
    _http_session = None


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    app.on_cleanup.append(_close_http_session)
    return app


def main() -> int:
    active = []
    if API_KEY:
        active.append("env-canary")
        if FAKE_GIT_ENABLED:
            active.append("fake-git")
        if CANARY_TRAPS_ENABLED:
            active.append("canary-file-traps")
    else:
        print(
            "flux: TRACEBIT_API_KEY unset — /.env, /.git/*, and canary file traps disabled (all 404)",
            file=sys.stderr,
        )
    if TARPIT_ENABLED:
        active.append("tarpit")
    if WEBSHELL_ENABLED:
        active.append("webshell")
    if LLM_ENDPOINT_ENABLED:
        active.append("llm-endpoint")
    if SONICWALL_ENABLED:
        active.append("sonicwall-ssl-vpn")
    print(
        f"flux: listening on 127.0.0.1:18081 (aiohttp), active traps: {', '.join(active) or 'none'}",
        file=sys.stderr,
    )

    app = create_app()
    web.run_app(app, host="127.0.0.1", port=18081, print=None, access_log=None)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(0)
