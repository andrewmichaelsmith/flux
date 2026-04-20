#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
import zlib
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request, urlopen


API_BASE_URL = (os.environ.get("TRACEBIT_API_BASE_URL", "https://community.tracebit.com") or "https://community.tracebit.com").rstrip("/")
API_KEY = (os.environ.get("TRACEBIT_API_KEY") or "").strip()
SENSOR_ID = (os.environ.get("SENSOR_ID") or "").strip()
ALLOWED_HOSTS = {
    value.strip().lower()
    for value in (os.environ.get("TRACEBIT_ENV_HOSTS_CSV") or "").split(",")
    if value.strip()
}
CANARY_TYPES = [
    value.strip()
    for value in (os.environ.get("TRACEBIT_ENV_CANARY_TYPES_CSV") or "aws").split(",")
    if value.strip()
]
TRACEBIT_SOURCE = (os.environ.get("TRACEBIT_ENV_CANARY_SOURCE") or "flux").strip()
TRACEBIT_SOURCE_TYPE = (os.environ.get("TRACEBIT_ENV_CANARY_SOURCE_TYPE") or "endpoint").strip()
LOG_PATH = Path(os.environ.get("TRACEBIT_ENV_LOG_PATH") or "/var/log/honeypot/tracebit/env-canary.jsonl")
TARPIT_ENABLED = (os.environ.get("TRACEBIT_ENV_TARPIT_ENABLED") or "true").strip().lower() in {"1", "true", "yes", "on"}
TARPIT_SECONDS = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_SECONDS") or "0").strip() or "0"), 0)
TARPIT_CHUNK_BYTES = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_CHUNK_BYTES") or "32").strip() or "32"), 1)
TARPIT_INTERVAL_MS = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_INTERVAL_MS") or "2000").strip() or "2000"), 100)
TARPIT_MAX_CONNECTIONS = max(int((os.environ.get("TRACEBIT_ENV_TARPIT_MAX_CONNECTIONS") or "8").strip() or "8"), 1)
TARPIT_SEMAPHORE = threading.BoundedSemaphore(TARPIT_MAX_CONNECTIONS)
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
# Opt-in: it mints a fresh canary on every cache-miss, so you want to
# know you turned it on before your Tracebit quota starts burning.
FAKE_GIT_ENABLED = _env_bool("FAKE_GIT_ENABLED", default=False)
FAKE_GIT_CACHE_TTL_SECONDS = max(int((os.environ.get("FAKE_GIT_CACHE_TTL_SECONDS") or "3600").strip() or "3600"), 60)
FAKE_GIT_CACHE_MAX_ENTRIES = max(int((os.environ.get("FAKE_GIT_CACHE_MAX_ENTRIES") or "1024").strip() or "1024"), 16)
FAKE_GIT_DRIP_BYTES = max(int((os.environ.get("FAKE_GIT_DRIP_BYTES") or "1024").strip() or "1024"), 32)
FAKE_GIT_DRIP_INTERVAL_MS = max(int((os.environ.get("FAKE_GIT_DRIP_INTERVAL_MS") or "3000").strip() or "3000"), 100)
FAKE_GIT_AUTHOR = (os.environ.get("FAKE_GIT_AUTHOR") or "ops <ops@internal-tools.lan>").strip()
FAKE_GIT_COMMIT_MESSAGE = (os.environ.get("FAKE_GIT_COMMIT_MESSAGE") or "Initial import of internal-tools").strip()
FAKE_GIT_REMOTE_URL = (os.environ.get("FAKE_GIT_REMOTE_URL") or "git@github.com:internal/tools.git").strip()

# --- Fake webshell configuration (Azure WP Webshell Checker intel, 2026-04-20) ---
# Default-enabled: the trap is cheap, logs are cheap, and we want to see what
# commands the checker follows up with on a positive hit.
WEBSHELL_ENABLED = (os.environ.get("HONEYPOT_WEBSHELL_ENABLED") or "true").strip().lower() in {"1", "true", "yes", "on"}
# Paths known to be probed by the Azure WP Webshell Checker and similar
# post-compromise "is my shell still here" scanners. Overridable via env for
# quick additions without a republish.
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
])
WEBSHELL_PATHS = {
    value.strip().lower()
    for value in (os.environ.get("HONEYPOT_WEBSHELL_PATHS_CSV") or _WEBSHELL_DEFAULT_PATHS).split(",")
    if value.strip()
}
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


def discover_local_ip_hosts() -> set[str]:
    hosts = {"127.0.0.1", "::1"}
    try:
        hosts.update(subprocess.check_output(["hostname", "-I"], text=True, stderr=subprocess.DEVNULL).strip().lower().split())
    except (OSError, subprocess.SubprocessError):
        return hosts
    return hosts


LOCAL_IP_HOSTS = discover_local_ip_hosts()


def header_subset(headers: object) -> dict[str, str]:
    values: dict[str, str] = {}
    for name in LOG_HEADER_NAMES:
        value = headers.get(name)
        if value:
            values[name] = value[:HEADER_VALUE_LOG_LIMIT]
    return values


def host_allow_reason(host: str) -> str:
    if not ALLOWED_HOSTS:
        return ""
    if host in ALLOWED_HOSTS:
        return "configured-host"
    if host in LOCAL_IP_HOSTS:
        return "local-ip"
    if host == "localhost":
        return "localhost"
    return ""


def normalize_path(raw_path: str) -> str:
    if not raw_path:
        return "/"
    decoded = unquote(raw_path)
    collapsed = re.sub(r"/+", "/", decoded)
    return collapsed if collapsed.startswith("/") else f"/{collapsed}"


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
    return path.lower() in WEBSHELL_PATHS


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

    terminal=True  -> module sends the full HTTP response itself.
    terminal=False -> module adds headers/metadata; caller streams.
    """

    name: str = ""
    terminal: bool = False

    def should_run(self, ctx: dict[str, object]) -> bool:
        return False

    def execute(self, handler: object, ctx: dict[str, object]) -> dict[str, object]:
        return {}


class DNSCallbackModule(TarpitModule):
    """Redirect to <uuid>.track-domain to fingerprint DNS resolution."""

    name = "dns-callback"
    terminal = True

    def should_run(self, ctx):
        return MOD_DNS_CALLBACK_ENABLED and MOD_DNS_CALLBACK_DOMAIN

    def execute(self, handler, ctx):
        callback_id = str(uuid.uuid4())
        proto = ctx.get("protocol", "https")
        location = f"{proto}://{callback_id}.{MOD_DNS_CALLBACK_DOMAIN}{ctx['path']}"
        handler.send_response(302)
        handler.send_header("Location", location)
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        if ctx.get("send_body", True):
            handler.wfile.write(b"redirecting\n")
        append_log({
            **ctx["log_context"],
            "status": 302,
            "result": "tarpit-module",
            "module": self.name,
            "callbackId": callback_id,
            "location": location,
        })
        return {"terminal": True}


class CookieTrackingModule(TarpitModule):
    """Set a tracking cookie; detect if scanners return it."""

    name = "cookie-tracking"
    terminal = False

    def should_run(self, ctx):
        return MOD_COOKIE_ENABLED

    def execute(self, handler, ctx):
        cookie_header = handler.headers.get("Cookie", "")
        returned_tid = ""
        if "_hp_tid=" in cookie_header:
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.startswith("_hp_tid="):
                    returned_tid = part[8:]
                    break
        cookie_id = str(uuid.uuid4())
        handler.send_header(
            "Set-Cookie",
            f"_hp_tid={cookie_id}; Path=/; HttpOnly; SameSite=Lax",
        )
        meta: dict[str, object] = {"cookieId": cookie_id}
        if returned_tid:
            meta["cookieReturned"] = returned_tid
        return meta


class RedirectChainModule(TarpitModule):
    """Start a redirect chain to measure follow-depth."""

    name = "redirect-chain"
    terminal = True

    def should_run(self, ctx):
        if not MOD_REDIRECT_CHAIN_ENABLED:
            return False
        return not ctx.get("query") or "_hp_chain" not in ctx["query"]

    def execute(self, handler, ctx):
        chain_id = str(uuid.uuid4())
        location = f"{ctx['path']}?_hp_chain={chain_id}&_hp_hop=1"
        handler.send_response(302)
        handler.send_header("Location", location)
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        if ctx.get("send_body", True):
            handler.wfile.write(b"redirecting\n")
        append_log({
            **ctx["log_context"],
            "status": 302,
            "result": "tarpit-module",
            "module": self.name,
            "chainId": chain_id,
            "hop": 0,
        })
        return {"terminal": True}


class ContentLengthMismatchModule(TarpitModule):
    """Set a large Content-Length to fingerprint client timeout/validation."""

    name = "content-length-mismatch"
    terminal = False

    def should_run(self, ctx):
        return MOD_CONTENT_LENGTH_MISMATCH_ENABLED

    def execute(self, handler, ctx):
        handler.send_header("Content-Length", str(MOD_CONTENT_LENGTH_CLAIMED_BYTES))
        return {"claimedBytes": MOD_CONTENT_LENGTH_CLAIMED_BYTES}


class ETagProbeModule(TarpitModule):
    """Set ETag/Last-Modified; detect conditional requests on repeat visits."""

    name = "etag-probe"
    terminal = False

    def should_run(self, ctx):
        return MOD_ETAG_PROBE_ENABLED

    def execute(self, handler, ctx):
        request_id = ctx.get("request_id", "")
        etag_value = f'"{request_id}"'
        handler.send_header("ETag", etag_value)
        handler.send_header("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")
        meta: dict[str, object] = {"etag": etag_value}
        if_none_match = handler.headers.get("If-None-Match", "")
        if_modified_since = handler.headers.get("If-Modified-Since", "")
        if if_none_match:
            meta["conditionalRequest"] = True
            meta["ifNoneMatch"] = if_none_match[:256]
        if if_modified_since:
            meta["conditionalRequest"] = True
            meta["ifModifiedSince"] = if_modified_since[:256]
        return meta


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


def issue_credentials(request_id: str, client_ip: str, host: str, user_agent: str, path: str, proto: str) -> dict[str, object]:
    issue_url = f"{API_BASE_URL}/api/v1/credentials/issue-credentials"
    safe_host = re.sub(r"[^0-9a-z._-]+", "-", host or "unknown").strip("-") or "unknown"
    request_name = f"{SENSOR_ID or 'sensor'}-{safe_host}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{request_id[:8]}"
    payload = {
        "name": request_name,
        "types": CANARY_TYPES,
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
    body = json.dumps(payload).encode("utf-8")
    req = Request(
        issue_url,
        data=body,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def format_env_payload(tracebit_response: dict[str, object]) -> str:
    lines = [
        "# autogenerated honeypot env payload",
        f"# issued_at={utc_now()}",
    ]

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
                f"SSH_CANARY_IP={ssh.get('sshIp', '')}",
                f"SSH_CANARY_PRIVATE_KEY_B64={ssh.get('sshPrivateKey', '')}",
                f"SSH_CANARY_PUBLIC_KEY_B64={ssh.get('sshPublicKey', '')}",
                f"SSH_CANARY_EXPIRATION={ssh.get('sshExpiration', '')}",
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

    if len(lines) <= 2:
        lines.append("TRACEBIT_CANARY_ERROR=empty-response")

    lines.append("")
    return "\n".join(lines)


# --- Fake /.git/ tree builder ---

_FAKE_GIT_LOCK = threading.Lock()
_FAKE_GIT_CACHE: dict[str, tuple[float, dict[str, bytes], dict[str, object]]] = {}


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


def _build_fake_repo(secrets_body: str) -> tuple[dict[str, bytes], dict[str, object]]:
    """Build a loose-object git repo as a path->bytes map.

    Layout: root/{.env.example, README.md, config/secrets.yml}. One commit.
    The canary creds live inside the secrets.yml blob.
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

    config_text = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        "[remote \"origin\"]\n"
        f"\turl = {FAKE_GIT_REMOTE_URL}\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/main\n"
    )

    reflog_line = (
        f"0000000000000000000000000000000000000000 {commit_sha} "
        f"{FAKE_GIT_AUTHOR} {commit_ts} +0000\tcommit (initial): {FAKE_GIT_COMMIT_MESSAGE}\n"
    )

    files: dict[str, bytes] = {
        "/.git/HEAD": b"ref: refs/heads/main\n",
        "/.git/config": config_text.encode("utf-8"),
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
        "/.git/logs/HEAD": reflog_line.encode("utf-8"),
        "/.git/logs/refs/heads/main": reflog_line.encode("utf-8"),
        "/.git/objects/info/packs": b"",
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


def _fake_git_get_or_build(
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
    with _FAKE_GIT_LOCK:
        entry = _FAKE_GIT_CACHE.get(cache_key)
        if entry and entry[0] > now:
            return entry[1], entry[2]

    try:
        tracebit_response = issue_credentials(request_id, client_ip, host, user_agent, path, proto)
    except (HTTPError, URLError, TimeoutError, ValueError):
        return None

    secrets_body = _format_secrets_yaml(tracebit_response)
    files, meta = _build_fake_repo(secrets_body)
    meta["canaryTypes"] = [key for key, value in tracebit_response.items() if value]

    expiry = now + FAKE_GIT_CACHE_TTL_SECONDS
    with _FAKE_GIT_LOCK:
        expired = [k for k, v in _FAKE_GIT_CACHE.items() if v[0] <= now]
        for k in expired:
            del _FAKE_GIT_CACHE[k]
        if len(_FAKE_GIT_CACHE) >= FAKE_GIT_CACHE_MAX_ENTRIES:
            oldest_key = min(_FAKE_GIT_CACHE, key=lambda k: _FAKE_GIT_CACHE[k][0])
            del _FAKE_GIT_CACHE[oldest_key]
        _FAKE_GIT_CACHE[cache_key] = (expiry, files, meta)
    return files, meta


class EnvHandler(BaseHTTPRequestHandler):
    server_version = "flux/0.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_HEAD(self) -> None:
        self._handle(send_body=False)

    def do_GET(self) -> None:
        self._handle(send_body=True)

    def do_POST(self) -> None:
        self._handle(send_body=True, read_body=True)

    def _send_fake_git(
        self,
        *,
        request_id: str,
        path: str,
        client_ip: str,
        host: str,
        user_agent: str,
        proto: str,
        log_context: dict[str, object],
        send_body: bool,
    ) -> None:
        result = _fake_git_get_or_build(client_ip, request_id, host, user_agent, path, proto)
        if result is None:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            append_log({**log_context, "status": 502, "result": "fake-git-error"})
            if send_body:
                self.wfile.write(b"upstream credential issue failed\n")
            return

        files, meta = result
        content = files.get(path)
        if content is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            append_log({
                **log_context,
                "status": 404,
                "result": "fake-git-miss",
                "commitSha": meta.get("commitSha", ""),
            })
            if send_body:
                self.wfile.write(b"not found\n")
            return

        if path.startswith("/.git/objects/") and "/info/" not in path:
            content_type = "application/x-git-loose-object"
        else:
            content_type = "text/plain; charset=utf-8"

        # Share the tarpit semaphore: fake-git is another slow-response path.
        acquired = TARPIT_SEMAPHORE.acquire(blocking=False)
        if not acquired:
            self.send_response(503)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            append_log({**log_context, "status": 503, "result": "fake-git-capacity"})
            if send_body:
                self.wfile.write(b"busy\n")
            return

        bytes_sent = 0
        try:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
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
            if not send_body:
                return
            interval_s = FAKE_GIT_DRIP_INTERVAL_MS / 1000.0
            for offset in range(0, len(content), FAKE_GIT_DRIP_BYTES):
                chunk = content[offset:offset + FAKE_GIT_DRIP_BYTES]
                self.wfile.write(chunk)
                self.wfile.flush()
                bytes_sent += len(chunk)
                if offset + FAKE_GIT_DRIP_BYTES < len(content):
                    time.sleep(interval_s)
        except (BrokenPipeError, ConnectionResetError):
            append_log({
                **log_context,
                "status": 200,
                "result": "fake-git-disconnect",
                "fakeGitBytesSent": bytes_sent,
                "commitSha": meta.get("commitSha", ""),
            })
        finally:
            TARPIT_SEMAPHORE.release()

    def _send_tarpit(self, *, request_id: str, path: str, log_context: dict[str, object], send_body: bool, query: str = "") -> None:
        module_ctx: dict[str, object] = {
            "log_context": log_context,
            "path": path,
            "query": query,
            "protocol": log_context.get("protocol", "https"),
            "host": log_context.get("host", ""),
            "send_body": send_body,
            "request_id": request_id,
        }

        # --- Terminal modules (first match wins) ---
        for mod in TARPIT_MODULES:
            if mod.terminal and mod.should_run(module_ctx):
                mod.execute(self, module_ctx)
                return

        # --- Redirect-chain continuation ---
        if query:
            chain_id, hop = _parse_chain_params(query)
            if chain_id and MOD_REDIRECT_CHAIN_ENABLED:
                if hop < MOD_REDIRECT_CHAIN_MAX_HOPS:
                    location = f"{path}?_hp_chain={chain_id}&_hp_hop={hop + 1}"
                    self.send_response(302)
                    self.send_header("Location", location)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    if send_body:
                        self.wfile.write(b"redirecting\n")
                    append_log({
                        **log_context,
                        "status": 302,
                        "result": "tarpit-module",
                        "module": "redirect-chain",
                        "chainId": chain_id,
                        "hop": hop,
                    })
                    return
                # Chain exhausted — fall through to tarpit stream

        # --- Semaphore gate ---
        acquired = TARPIT_SEMAPHORE.acquire(blocking=False)
        if not acquired:
            self.send_response(503)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            append_log({**log_context, "status": 503, "result": "tarpit-capacity"})
            if send_body:
                self.wfile.write(b"busy\n")
            return

        chunks_sent = 0
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")

            # --- Augmenting modules (add headers / metadata) ---
            aug_meta: dict[str, object] = {}
            for mod in TARPIT_MODULES:
                if not mod.terminal and mod.should_run(module_ctx):
                    result = mod.execute(self, module_ctx)
                    if result:
                        aug_meta[mod.name] = result

            self.end_headers()

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

            if not send_body:
                return

            # --- Stream with optional variable drip ---
            if MOD_VARIABLE_DRIP_ENABLED:
                interval_ms = float(MOD_VARIABLE_DRIP_INITIAL_MS)
            else:
                interval_ms = float(TARPIT_INTERVAL_MS)

            if TARPIT_SECONDS > 0:
                deadline = time.monotonic() + TARPIT_SECONDS
                keep_streaming = lambda: time.monotonic() < deadline
            else:
                keep_streaming = lambda: True

            while keep_streaming():
                self.wfile.write(build_tarpit_chunk(request_id, path, chunks_sent))
                self.wfile.flush()
                chunks_sent += 1
                time.sleep(interval_ms / 1000.0)
                if MOD_VARIABLE_DRIP_ENABLED:
                    interval_ms = min(interval_ms * 1.5, float(MOD_VARIABLE_DRIP_MAX_MS))
        except (BrokenPipeError, ConnectionResetError):
            append_log({**log_context, "status": 200, "result": "tarpit-disconnect", "tarpitChunksSent": chunks_sent})
        finally:
            TARPIT_SEMAPHORE.release()

    def _handle_webshell(
        self,
        *,
        log_context: dict[str, object],
        path: str,
        query_string: str,
        request_body: bytes,
        send_body: bool,
    ) -> None:
        query_params = parse_qs(query_string, keep_blank_values=True) if query_string else {}
        content_type = self.headers.get("Content-Type", "")
        form_params = parse_form_body(request_body, content_type)
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        command_source, command_key, command = extract_webshell_command(
            query_params, form_params, cookies, self.headers,
        )

        body_preview = ""
        if request_body:
            try:
                body_preview = request_body[:WEBSHELL_BODY_DECODE_LIMIT].decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                body_preview = ""

        output = simulate_command_output(command) if command else ""
        payload = render_webshell_page(command=command, output=output)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if send_body:
            self.wfile.write(payload)

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

    def _handle(self, *, send_body: bool, read_body: bool = False) -> None:
        request_id = str(uuid.uuid4())
        host = clean_host(self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "")
        client_ip = first_forwarded_ip(self.headers.get("X-Forwarded-For", ""))
        user_agent = self.headers.get("User-Agent", "")
        proto = (self.headers.get("X-Forwarded-Proto") or "http").strip().lower()
        raw_target = self.path or "/"
        parsed_target = urlsplit(raw_target)
        raw_path = parsed_target.path or "/"
        path = normalize_path(raw_path)
        query_string = parsed_target.query or ""
        host_allow = host_allow_reason(host)
        host_allowed = bool(host_allow)
        body_bytes_expected = None
        body_bytes_read = 0
        body_sha256 = ""
        request_body = b""
        if read_body:
            content_length_value = (self.headers.get("Content-Length") or "").strip()
            if content_length_value:
                try:
                    body_bytes_expected = max(int(content_length_value), 0)
                except ValueError:
                    body_bytes_expected = None
            if body_bytes_expected is not None:
                read_cap = min(body_bytes_expected, WEBSHELL_BODY_READ_LIMIT)
                request_body = self.rfile.read(read_cap)
                body_bytes_read = len(request_body)
                body_sha256 = hashlib.sha256(request_body).hexdigest()

        log_context = {
            "timestamp": utc_now(),
            "requestId": request_id,
            "method": self.command,
            "host": host,
            "hostAllowReason": host_allow or "not-allowed",
            "path": path,
            "rawPath": raw_path,
            "rawTarget": raw_target,
            "query": query_string,
            "clientIp": client_ip,
            "userAgent": user_agent,
            "protocol": proto,
            "headers": header_subset(self.headers),
            "bodyBytesRead": body_bytes_read,
            "bodySha256": body_sha256,
        }

        # Gate webshell on "is this a trap sensor" (ALLOWED_HOSTS non-empty),
        # NOT on host_allowed(this specific request). Scanners routinely send
        # arbitrary/spoofed Host headers (2026-04-20: 172.213.224.85 sent 104
        # probes with Host=staging.porsche.nocadis.com); gating on Host match
        # 404s exactly the actors we want to catch. Control sensors with no
        # ALLOWED_HOSTS still stay clean because the whole check short-circuits.
        if ALLOWED_HOSTS and is_webshell_path(path):
            self._handle_webshell(
                log_context=log_context,
                path=path,
                query_string=query_string,
                request_body=request_body,
                send_body=send_body,
            )
            return

        if TARPIT_ENABLED and host_allowed and (is_tarpit_path(path) or is_fingerprint_path(path)):
            self._send_tarpit(request_id=request_id, path=path, log_context=log_context, send_body=send_body, query=query_string)
            return

        if FAKE_GIT_ENABLED and host_allowed and API_KEY and (path == "/.git" or path.startswith("/.git/")):
            self._send_fake_git(
                request_id=request_id,
                path=path,
                client_ip=client_ip,
                host=host,
                user_agent=user_agent,
                proto=proto,
                log_context=log_context,
                send_body=send_body,
            )
            return

        if path != "/.env" or not API_KEY or not host_allowed:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            append_log({**log_context, "status": 404, "result": "not-handled"})
            if send_body:
                self.wfile.write(b"not found\n")
            return

        try:
            tracebit_response = issue_credentials(request_id, client_ip, host, user_agent, path, proto)
            payload = format_env_payload(tracebit_response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            append_log(
                {
                    **log_context,
                    "status": 200,
                    "result": "issued",
                    "types": [key for key, value in tracebit_response.items() if value],
                }
            )
            if send_body:
                self.wfile.write(payload)
            return
        except HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            append_log({**log_context, "status": 502, "result": "tracebit-http-error", "tracebitStatus": exc.code, "error": error_body[:400]})
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            if send_body:
                self.wfile.write(b"upstream credential issue failed\n")
            return
        except (URLError, TimeoutError, ValueError) as exc:
            append_log({**log_context, "status": 502, "result": "tracebit-error", "error": str(exc)[:400]})
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            if send_body:
                self.wfile.write(b"upstream credential issue failed\n")
            return


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def main() -> int:
    # Single clear startup line about which traps are active. Scanners don't
    # read this, humans reading journalctl do.
    active = []
    if API_KEY:
        active.append("env-canary")
        if FAKE_GIT_ENABLED:
            active.append("fake-git")
    else:
        print("flux: TRACEBIT_API_KEY unset — /.env and /.git/* disabled (both 404)", file=sys.stderr)
    if TARPIT_ENABLED:
        active.append("tarpit")
    if WEBSHELL_ENABLED:
        active.append("webshell")
    if not ALLOWED_HOSTS:
        print("flux: TRACEBIT_ENV_HOSTS_CSV empty — running as control sensor, traps 404", file=sys.stderr)
    print(f"flux: listening on 127.0.0.1:18081, active traps: {', '.join(active) or 'none'}", file=sys.stderr)

    server = ReusableThreadingHTTPServer(("127.0.0.1", 18081), EnvHandler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(0)
