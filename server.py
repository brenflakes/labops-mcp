#!/usr/bin/env python3
"""
Homelab MCP Server

Gives Claude read-only access to homelab infrastructure via SSH and APIs.
Fully config-driven, modular, secure.

Tools:
  Core:
    - ssh_exec(host, command)     Run commands via restricted SSH user
    - api_get(service, endpoint)  Query any configured API
    - health()                    Check connectivity to all hosts/APIs
    - homelab_status()            Quick dashboard overview

  Containers:
    - container_logs(host, container, lines)    Get container logs
    - search_logs(host, pattern)                Search logs across all containers
    - container_mounts(host, container)         Get volume mappings
    - container_status(host, container)         Single container health check
    - containers_recent_restarts(host)          Show recently restarted containers

  Diagnostics:
    - trigger_diagnostic(name)    Trigger a predefined n8n diagnostic webhook

  Monitoring (auto-discovered by type):
    - prom_query(query)           PromQL queries (requires type: prometheus)
    - homelab_alerts()            Firing alerts from Prometheus + Uptime Kuma
    - ollama_models(host)         List Ollama models (requires type: ollama)
    - system_stats(host)          CPU/mem/disk from Glances (requires type: glances)

  NAS (auto-discovered by type):
    - nas_info(host)              Synology DSM system info
    - nas_storage(host)           Volume status and usage
    - nas_disks(host)             Disk health and SMART status
    - nas_utilisation(host)       CPU, memory, network utilisation

  System:
    - get_paths()                 Show configured filesystem paths
    - disk_usage(host)            Disk usage with high-usage warnings
    - top_processes(host, n)      Top CPU and memory consumers
    - service_status(host, svc)   Systemd service status
"""

import os
import subprocess
import json
import re
from pathlib import Path
from collections import deque
from time import time
from datetime import datetime, timedelta
import httpx
import yaml
import jq
from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from fastmcp.exceptions import ToolError

mcp = FastMCP("labops")

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "config/inventory.yml"))
with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

HOSTS = {name: h for name, h in config.get("hosts", {}).items() if h.get("ssh", False)}
APIS = config.get("apis", {})
DIAGNOSTICS = config.get("diagnostics", {})
PATHS = config.get("paths", {})

# Build type indexes for service discovery
APIS_BY_TYPE = {}
for name, api in APIS.items():
    api_type = api.get("type")
    if api_type:
        if api_type not in APIS_BY_TYPE:
            APIS_BY_TYPE[api_type] = {}
        APIS_BY_TYPE[api_type][name] = api

# Health check paths for services that need non-root URL checks
HEALTH_CHECK_PATHS = {
    "glances": "/api/4/quicklook",
    "synology": "/webapi/entry.cgi?api=SYNO.API.Info&method=query&version=1&query=SYNO.API.Auth",
}


def _health_check_url(api: dict) -> str:
    """Get the URL to use for health checks. Uses a type-specific API endpoint
    when the root URL doesn't reliably indicate service health."""
    base = api["url"]
    path = HEALTH_CHECK_PATHS.get(api.get("type", ""), "")
    return f"{base}{path}" if path else base

# Synology session cache: {api_name: {"sid": str, "timestamp": float}}
_synology_sessions = {}
_SYNOLOGY_SESSION_TTL = 3600  # 1 hour (conservative; DSM default is 7 days)

# Synology API error codes
_SYNOLOGY_ERRORS = {
    100: "Unknown error",
    101: "No parameter of API, method, or version",
    102: "Requested API does not exist",
    103: "Requested method does not exist",
    104: "Requested version does not support this functionality",
    105: "Not logged in or session expired",
    106: "Session timeout",
    107: "Session interrupted by duplicate login",
    119: "SID not found",
    400: "No such account or incorrect password",
    401: "Account disabled",
    402: "Permission denied",
    403: "2-step verification required",
    404: "Failed to authenticate 2-step verification code",
}

# =============================================================================
# SECURITY
# =============================================================================

DANGEROUS_PATTERNS = [';', '&&', '||', '`', '$(', '${', '>', '<', '\n', '$']

# Rate limiting: 60 calls per minute
RATE_LIMIT = 60
RATE_WINDOW = 60
_call_times = deque()


def _check_rate_limit() -> tuple[bool, str | None]:
    """Check if rate limit exceeded. Returns (allowed, error_message)."""
    now = time()
    while _call_times and _call_times[0] < now - RATE_WINDOW:
        _call_times.popleft()
    if len(_call_times) >= RATE_LIMIT:
        return False, f"Rate limit exceeded ({RATE_LIMIT}/min)."
    _call_times.append(now)
    return True, None


def _sanitize_container_name(name: str) -> bool:
    """Validate container name - alphanumeric, dash, underscore only."""
    return all(c.isalnum() or c in '-_' for c in name)


# =============================================================================
# AUTHENTICATION
# =============================================================================

_auth_token = os.environ.get("MCP_AUTH_TOKEN")


class BearerAuthMiddleware(Middleware):
    """Bearer token auth. Disabled if MCP_AUTH_TOKEN not set."""

    def __init__(self, token: str | None):
        self.token = token

    async def on_request(self, context: MiddlewareContext, call_next):
        if not self.token:
            return await call_next(context)

        headers = get_http_headers() or {}
        auth = headers.get("authorization", "")

        if not auth.startswith("Bearer "):
            raise ToolError("Authentication required")

        if auth.removeprefix("Bearer ").strip() != self.token:
            raise ToolError("Invalid authentication token")

        return await call_next(context)


mcp.add_middleware(BearerAuthMiddleware(_auth_token))

if _auth_token:
    print("🔐 Bearer auth enabled")
else:
    print("⚠️  No MCP_AUTH_TOKEN set — auth disabled")


# =============================================================================
# HELPERS
# =============================================================================

def format_error(service: str, error_type: str, host: str, hint: str) -> str:
    """Format a consistent error message."""
    return f"✗ {service} {error_type}\n\nHost: {host}\n\n→ {hint}"


def _build_auth_headers(api: dict) -> tuple[dict, str | None]:
    """
    Build authentication headers based on api config.
    Returns (headers_dict, error_message).
    
    Supported auth_type values:
      bearer   -> Authorization: Bearer {token}
      api_key  -> X-Api-Key: {token}
      emby     -> X-Emby-Token: {token}
      pve      -> Authorization: PVEAPIToken={token}
      immich   -> x-api-key: {token}
      basic    -> Authorization: Basic base64({token}:)
      custom   -> {auth_header}: {token}
    """
    if not api.get("auth"):
        return {}, None
    
    token_env = api.get("token_env")
    if not token_env:
        return {}, "auth: true but no token_env specified"
    
    token = os.environ.get(token_env)
    if not token:
        return {}, f"Missing environment variable: {token_env}"
    
    auth_type = api.get("auth_type", "bearer")  # Default to bearer
    
    if auth_type == "bearer":
        return {"Authorization": f"Bearer {token}"}, None
    elif auth_type == "api_key":
        header = api.get("auth_header", "X-Api-Key")
        return {header: token}, None
    elif auth_type == "emby":
        return {"X-Emby-Token": token}, None
    elif auth_type == "pve":
        return {"Authorization": f"PVEAPIToken={token}"}, None
    elif auth_type == "immich":
        return {"x-api-key": token}, None
    elif auth_type == "basic":
        import base64
        credentials = base64.b64encode(f":{token}".encode()).decode()
        return {"Authorization": f"Basic {credentials}"}, None
    elif auth_type == "synology":
        # Synology uses session-based auth via query params (_sid), not headers
        return {}, None
    elif auth_type == "custom":
        header = api.get("auth_header")
        if not header:
            return {}, "auth_type: custom requires auth_header to be set"
        return {header: token}, None
    else:
        return {}, f"Unknown auth_type: {auth_type}"


def _http_get(url: str, headers: dict = None, timeout: int = 10, verify: bool = True) -> httpx.Response:
    """Make an HTTP GET request."""
    with httpx.Client(timeout=timeout, verify=verify) as client:
        return client.get(url, headers=headers or {})


def _quick_ssh(host_ip: str, user: str, cmd: str, timeout: int = 5) -> tuple[bool, str]:
    """Quick SSH for status checks. Returns (success, output)."""
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=3", "-o", "BatchMode=yes", f"{user}@{host_ip}", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.returncode == 0, r.stdout.strip()
    except:
        return False, ""


def _apply_jq_filter(data: str, filter_expr: str) -> tuple[bool, str]:
    """
    Apply jq filter to JSON string.
    Returns (success, result_or_error).
    """
    try:
        parsed = json.loads(data)
        result = jq.compile(filter_expr).input_value(parsed).all()
        if len(result) == 1:
            return True, json.dumps(result[0], indent=2)
        return True, json.dumps(result, indent=2)
    except json.JSONDecodeError as e:
        return False, f"JSON parse error: {e}"
    except ValueError as e:
        return False, f"jq filter error: {e}"


def _get_apis_by_type(api_type: str) -> dict:
    """Get all APIs of a specific type."""
    return APIS_BY_TYPE.get(api_type, {})


def _extract_host_from_api_name(api_name: str, prefix: str) -> str:
    """Extract hostname from api name like 'ollama-beast' -> 'beast'."""
    if api_name.startswith(f"{prefix}-"):
        return api_name[len(prefix) + 1:]
    return api_name


def _synology_login(api_name: str, api: dict) -> tuple[str | None, str | None]:
    """
    Authenticate to Synology DSM and cache the session ID.
    Returns (sid, error_message).
    """
    token_env = api.get("token_env")
    if not token_env:
        return None, "No token_env configured for Synology API"

    creds = os.environ.get(token_env)
    if not creds:
        return None, f"Missing environment variable: {token_env}"

    # Format: username:password (split on first colon to allow colons in password)
    if ":" not in creds:
        return None, f"{token_env} must be in username:password format"

    username, password = creds.split(":", 1)
    base_url = api["url"]
    verify = api.get("verify_ssl", True)

    try:
        with httpx.Client(timeout=15, verify=verify) as client:
            resp = client.get(f"{base_url}/webapi/entry.cgi", params={
                "api": "SYNO.API.Auth",
                "version": "6",
                "method": "login",
                "account": username,
                "passwd": password,
                "format": "sid",
            })

        data = resp.json()

        if data.get("success"):
            sid = data["data"]["sid"]
            _synology_sessions[api_name] = {"sid": sid, "timestamp": time()}
            return sid, None

        error_code = data.get("error", {}).get("code", 0)
        error_msg = _SYNOLOGY_ERRORS.get(error_code, f"Unknown error (code {error_code})")
        return None, f"Synology login failed: {error_msg}"

    except httpx.ConnectError:
        return None, f"Cannot connect to Synology at {base_url}"
    except httpx.TimeoutException:
        return None, f"Synology login timed out at {base_url}"
    except Exception as e:
        return None, f"Synology login error: {e}"


def _synology_request(
    api_name: str,
    api: dict,
    api_endpoint: str,
    method: str,
    version: int = 1,
    extra_params: dict = None,
) -> tuple[dict | None, str | None]:
    """
    Make an authenticated request to Synology DSM API.
    Handles session caching and automatic re-login on expiry.
    Returns (data_dict, error_message).
    """
    # Check cached session
    session = _synology_sessions.get(api_name)
    if session and (time() - session["timestamp"]) < _SYNOLOGY_SESSION_TTL:
        sid = session["sid"]
    else:
        # Login (or re-login)
        _synology_sessions.pop(api_name, None)
        sid, error = _synology_login(api_name, api)
        if error:
            return None, error

    base_url = api["url"]
    verify = api.get("verify_ssl", True)
    params = {
        "api": api_endpoint,
        "version": str(version),
        "method": method,
        "_sid": sid,
    }
    if extra_params:
        params.update(extra_params)

    try:
        with httpx.Client(timeout=15, verify=verify) as client:
            resp = client.get(f"{base_url}/webapi/entry.cgi", params=params)

        data = resp.json()

        if data.get("success"):
            return data.get("data", {}), None

        error_code = data.get("error", {}).get("code", 0)

        # Session expired — re-login and retry once
        if error_code in (105, 106, 107, 119):
            _synology_sessions.pop(api_name, None)
            sid, login_error = _synology_login(api_name, api)
            if login_error:
                return None, login_error

            params["_sid"] = sid
            with httpx.Client(timeout=15, verify=verify) as client:
                resp = client.get(f"{base_url}/webapi/entry.cgi", params=params)

            data = resp.json()
            if data.get("success"):
                return data.get("data", {}), None

            error_code = data.get("error", {}).get("code", 0)

        error_msg = _SYNOLOGY_ERRORS.get(error_code, f"Unknown error (code {error_code})")
        return None, f"Synology API error: {error_msg}"

    except httpx.ConnectError:
        return None, f"Cannot connect to Synology at {base_url}"
    except httpx.TimeoutException:
        return None, f"Synology request timed out at {base_url}"
    except Exception as e:
        return None, f"Synology request error: {e}"


# =============================================================================
# CORE TOOLS
# =============================================================================

@mcp.tool()
def ssh_exec(host: str, command: str) -> str:
    """
    Execute read-only command on a host via restricted SSH user.
    Security enforced at OS level via rbash + limited PATH + sudoers.

    This is the low-level escape hatch - use dedicated tools first:
    - Disk info -> disk_usage(host)
    - Process info -> top_processes(host)
    - Service status -> service_status(host, service)
    - Container info -> container_status, container_logs, container_mounts
    - System stats -> system_stats(host)

    Use ssh_exec when no dedicated tool exists for the command needed,
    or when you need raw output for a one-off investigation.

    Args:
        host: Target host (check health() for available hosts)
        command: Command to run (must be in allowed list on target)
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if any(p in command for p in DANGEROUS_PATTERNS):
        return "Error: Command chaining/redirection not allowed"

    if host not in HOSTS:
        available = list(HOSTS.keys()) if HOSTS else ["(no hosts configured)"]
        return f"Unknown host: {host}. Available: {', '.join(available)}"

    h = HOSTS[host]
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}", command],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        return output if output.strip() else "(no output)"
    except subprocess.TimeoutExpired:
        return format_error(host, "Timeout", h['ip'], "Connection timed out.")
    except Exception as e:
        return format_error(host, "SSH Error", h['ip'], str(e))


@mcp.tool()
def api_get(service: str, endpoint: str, filter: str = None) -> str:
    """
    Call a homelab service API. Returns JSON.

    This is the generic API tool - use dedicated wrappers first:
    - Prometheus queries -> prom_query(query)
    - Firing alerts -> homelab_alerts()
    - Ollama models -> ollama_models(host)
    - System stats (Glances) -> system_stats(host)
    - NAS info -> nas_info, nas_storage, nas_disks, nas_utilisation

    Use api_get when no dedicated tool exists, when you need a specific
    endpoint not covered by wrapper tools, or when using jq filters
    to extract precise data from large API responses.

    Args:
        service: API to call (check health() for available services)
        endpoint: API path (e.g., /api/v1/query?query=up)
        filter: Optional jq filter expression (e.g., '.[].title', '.data.result')
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if service not in APIS:
        available = list(APIS.keys()) if APIS else ["(no APIs configured)"]
        return f"Unknown service: {service}. Available: {', '.join(available)}"

    api = APIS[service]
    url = f"{api['url']}{endpoint}"
    verify = api.get("verify_ssl", True)

    # Build auth headers
    headers, auth_error = _build_auth_headers(api)
    if auth_error:
        return format_error(service, "Auth Config Error", api['url'], auth_error)

    try:
        resp = _http_get(url, headers=headers, verify=verify)

        if resp.status_code == 401:
            return format_error(service, "Auth Failed (401)", api['url'],
                                f"Check {api.get('token_env', 'credentials')}")
        if resp.status_code == 403:
            return format_error(service, "Forbidden (403)", api['url'], "Token lacks permissions")

        raw_response = resp.text

        # Apply jq filter if provided
        if filter:
            success, result = _apply_jq_filter(raw_response, filter)
            if success:
                return result
            else:
                preview = raw_response[:500] + "..." if len(raw_response) > 500 else raw_response
                return f"⚠️ Filter failed: {result}\n\nRaw response preview:\n{preview}"

        return raw_response[:10000]

    except httpx.ConnectError:
        return format_error(service, "Connection Failed", api['url'], "Cannot connect.")
    except httpx.TimeoutException:
        return format_error(service, "Timeout", api['url'], "Request timed out")
    except Exception as e:
        return format_error(service, "Error", api['url'], str(e))


@mcp.tool()
def health() -> str:
    """
    Check MCP server health and connectivity to all configured hosts and services.
    Returns JSON with status and available hosts/apis.

    Use this first when starting a session to see what's reachable.
    For a human-readable overview with UPS and container counts, use homelab_status() instead.
    For detailed system metrics, use system_stats(host).
    """
    status = {
        "healthy": True,
        "checks": {},
        "hosts": list(HOSTS.keys()),
        "apis": list(APIS.keys()),
        "types": {t: list(apis.keys()) for t, apis in APIS_BY_TYPE.items()}
    }

    for name, h in HOSTS.items():
        ok, _ = _quick_ssh(h['ip'], h['user'], "echo ok")
        status["checks"][f"ssh_{name}"] = ok
        if not ok:
            status["healthy"] = False

    for name, api in APIS.items():
        try:
            url = _health_check_url(api)
            resp = _http_get(url, timeout=3, verify=api.get("verify_ssl", True))
            status["checks"][f"api_{name}"] = resp.status_code < 500
        except:
            status["checks"][f"api_{name}"] = False

    return json.dumps(status, indent=2)


@mcp.tool()
def homelab_status() -> str:
    """
    Quick status overview of all hosts, UPS units, and APIs.
    Discovers UPS automatically via NUT on each host.

    Best starting point for "how's the lab?" questions. Shows host status,
    container counts, load averages, UPS charge/runtime, and API health
    in a single call.

    For structured JSON (e.g., programmatic checks), use health() instead.
    For deep-dive into a specific host, follow up with:
    - system_stats(host) for CPU/memory/disk
    - disk_usage(host) for filesystem usage
    - top_processes(host) for resource hogs
    - containers_recent_restarts(host) for instability
    """
    out = []

    # Hosts
    out.append("🖥️  HOSTS")
    if not HOSTS:
        out.append("   (no hosts configured)")
    else:
        for name, h in HOSTS.items():
            ok, _ = _quick_ssh(h['ip'], h['user'], "echo ok")
            if not ok:
                out.append(f"   {name:15} ❌ offline")
                continue

            # Container count
            dok, clist = _quick_ssh(h['ip'], h['user'], "sudo docker ps -q")
            ccount = str(len(clist.strip().split('\n'))) if dok and clist else "-"

            # Load average
            lok, loadraw = _quick_ssh(h['ip'], h['user'], "cat /proc/loadavg")
            loadavg = loadraw.split()[0] if lok and loadraw else "-"

            # Uptime
            uok, uptraw = _quick_ssh(h['ip'], h['user'], "cat /proc/uptime")
            if uok and uptraw:
                try:
                    secs = float(uptraw.split()[0])
                    days = int(secs / 86400)
                    uptime = f"{days}d" if days > 0 else "<1d"
                except:
                    uptime = "-"
            else:
                uptime = "-"

            out.append(f"   {name:15} ✅ up {uptime:5} load {loadavg:5} containers {ccount}")

    # UPS (auto-discover via NUT)
    out.append("\n⚡ UPS")
    ups_found = False
    for name, h in HOSTS.items():
        nok, ups_list = _quick_ssh(h['ip'], h['user'], "upsc -l")
        if not nok or not ups_list.strip() or "Error" in ups_list:
            continue

        for ups_name in ups_list.strip().split('\n'):
            ups_name = ups_name.strip()
            if not ups_name or ups_name.startswith("Init"):
                continue
            ups_found = True

            qok, ups_data = _quick_ssh(h['ip'], h['user'], f"upsc {ups_name}@localhost", timeout=8)
            if not qok:
                out.append(f"   {ups_name:15} ({name}) ❌ query failed")
                continue

            vals = {}
            for line in ups_data.split('\n'):
                if ':' in line and not line.startswith("Init"):
                    k, v = line.split(':', 1)
                    vals[k.strip()] = v.strip()

            status = vals.get('ups.status', '?')
            charge = vals.get('battery.charge', '?')
            load = vals.get('ups.load', '?')
            runtime = vals.get('battery.runtime', '?')

            try:
                runtime = f"{int(runtime) // 60}min"
            except:
                pass

            status_icon = "✅" if "OL" in status else "⚠️" if "OB" in status else "❓"
            out.append(f"   {ups_name:15} ({name:10}) {status_icon} {status:8} {charge:>3}% {runtime:>6} {load:>2}% load")

    if not ups_found:
        out.append("   (no UPS discovered via NUT)")

    # APIs
    out.append("\n🔌 APIS")
    if not APIS:
        out.append("   (no APIs configured)")
    else:
        api_status = []
        for name, api in APIS.items():
            try:
                resp = _http_get(api["url"], timeout=3, verify=api.get("verify_ssl", True))
                icon = "✅" if resp.status_code < 500 else "⚠️"
            except:
                icon = "❌"
            api_status.append(f"{name} {icon}")

        line = "   "
        for item in api_status:
            if len(line) + len(item) > 70:
                out.append(line)
                line = "   "
            line += item + "  "
        if line.strip():
            out.append(line)

    return "\n".join(out)


# =============================================================================
# CONTAINER TOOLS
# =============================================================================

@mcp.tool()
def container_logs(host: str, container: str, lines: int = 50) -> str:
    """
    Get recent logs from a container.

    Use when investigating a specific container's behaviour - errors, startup
    issues, or recent activity. For searching a pattern across ALL containers
    on a host, use search_logs() instead.

    Chains with: container_status() to check state first,
    containers_recent_restarts() to find which containers to investigate.

    Args:
        host: Target host (check health() for available hosts)
        container: Container name or ID
        lines: Number of lines to retrieve (default 50, max 500)
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        return f"Unknown host: {host}. Available: {', '.join(HOSTS.keys())}"

    if not _sanitize_container_name(container):
        return "Error: Invalid container name"

    lines = max(1, min(500, lines))

    h = HOSTS[host]
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             f"sudo docker logs --tail {lines} {container}"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout + result.stderr
        return output if output.strip() else "(no logs)"
    except subprocess.TimeoutExpired:
        return format_error(host, "Timeout", h['ip'], "Log retrieval timed out")
    except Exception as e:
        return format_error(host, "Error", h['ip'], str(e))


@mcp.tool()
def search_logs(host: str, pattern: str, lines: int = 100) -> str:
    """
    Search recent logs across all containers on a host.

    Use when you know WHAT to look for but not WHERE - searches every
    running container's recent logs for the pattern. For logs from a
    specific known container, use container_logs() instead (faster).

    Chains with: container_logs() to get full context once you find
    which container has the issue.

    Args:
        host: Target host (check health() for available hosts)
        pattern: Grep pattern to search for (case-insensitive)
        lines: Number of recent lines to search per container (default 100, max 500)
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        return f"Unknown host: {host}. Available: {', '.join(HOSTS.keys())}"

    if any(c in pattern for c in DANGEROUS_PATTERNS):
        return "Error: Invalid characters in pattern"

    lines = max(1, min(500, lines))
    h = HOSTS[host]

    # Get list of running containers
    result = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
         "sudo docker ps --format '{{.Names}}'"],
        capture_output=True, text=True, timeout=30
    )

    if result.returncode != 0:
        return format_error(host, "Failed to list containers", h['ip'], result.stderr)

    containers = [c.strip() for c in result.stdout.strip().split('\n') if c.strip()]

    if not containers:
        return "No running containers found"

    matches = []
    for container in containers:
        try:
            log_result = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
                 f"sudo docker logs --tail {lines} {container} 2>&1 | grep -i '{pattern}'"],
                capture_output=True, text=True, timeout=30
            )
            if log_result.stdout.strip():
                for line in log_result.stdout.strip().split('\n'):
                    matches.append(f"[{container}] {line}")
        except:
            continue

    if not matches:
        return f"No matches for '{pattern}' across {len(containers)} containers"

    return '\n'.join(matches[:200])


@mcp.tool()
def container_mounts(host: str, container: str) -> str:
    """
    Get volume/bind mounts for a container in clean format.

    Use when investigating WHERE a container stores data - shows bind mounts
    and named volumes with source, destination, and read/write mode.
    Not for host-level disk usage (use disk_usage() for that) or
    NAS storage capacity (use nas_storage() for that).

    Args:
        host: Target host (check health() for available hosts)
        container: Container name
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        return f"Unknown host: {host}. Available: {', '.join(HOSTS.keys())}"

    if not _sanitize_container_name(container):
        return "Error: Invalid container name"

    h = HOSTS[host]
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             f"sudo docker inspect {container} --format '{{{{json .Mounts}}}}'"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            return format_error(host, "Container not found", h['ip'], result.stderr.strip())

        mounts = json.loads(result.stdout.strip())

        if not mounts:
            return f"📁 {container}: No mounts configured"

        out = [f"📁 {container} mounts:\n"]
        for m in mounts:
            mount_type = m.get("Type", "unknown")
            src = m.get("Source", "?")
            dst = m.get("Destination", "?")
            mode = "ro" if not m.get("RW", True) else "rw"

            if mount_type == "volume":
                out.append(f"   [volume] {m.get('Name', src)}")
                out.append(f"            → {dst} ({mode})")
            else:
                out.append(f"   [bind]   {src}")
                out.append(f"            → {dst} ({mode})")

        return "\n".join(out)

    except json.JSONDecodeError:
        return format_error(host, "Parse Error", h['ip'], "Failed to parse mount info")
    except subprocess.TimeoutExpired:
        return format_error(host, "Timeout", h['ip'], "Inspect timed out")
    except Exception as e:
        return format_error(host, "Error", h['ip'], str(e))


@mcp.tool()
def container_status(host: str, container: str) -> str:
    """
    Get single container health status: running state, uptime, restart count.

    Use as the first check when investigating a specific container.
    Shows whether it's running, how long it's been up, and restart count
    (high restart count = crash loop).

    Chains with: container_logs() for details on why it's failing,
    container_mounts() for volume config.

    Args:
        host: Target host (check health() for available hosts)
        container: Container name
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        return f"Unknown host: {host}. Available: {', '.join(HOSTS.keys())}"

    if not _sanitize_container_name(container):
        return "Error: Invalid container name"

    h = HOSTS[host]
    try:
        # Get container state JSON
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             f"sudo docker inspect {container} --format '{{{{json .State}}}}'"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            return format_error(host, "Container not found", h['ip'], result.stderr.strip())

        state = json.loads(result.stdout.strip())

        status = state.get("Status", "unknown")
        running = state.get("Running", False)
        restarts = state.get("RestartCount", 0)
        started_at = state.get("StartedAt", "")

        # Calculate uptime
        uptime_str = "-"
        if started_at and running:
            try:
                # Parse ISO format, handle both Z and +00:00
                started_at = started_at.replace("Z", "+00:00")
                started = datetime.fromisoformat(started_at)
                now = datetime.now(started.tzinfo)
                delta = now - started
                days = delta.days
                hours = delta.seconds // 3600
                if days > 0:
                    uptime_str = f"{days}d {hours}h"
                else:
                    minutes = (delta.seconds % 3600) // 60
                    uptime_str = f"{hours}h {minutes}m"
            except:
                uptime_str = "-"

        icon = "✅" if running else "❌"
        out = [
            f"{icon} {container} on {host}",
            f"   Status:   {status}",
            f"   Uptime:   {uptime_str}",
            f"   Restarts: {restarts}",
        ]

        # Health check if available
        health = state.get("Health", {})
        if health:
            health_status = health.get("Status", "none")
            out.append(f"   Health:   {health_status}")

        return "\n".join(out)

    except json.JSONDecodeError:
        return format_error(host, "Parse Error", h['ip'], "Failed to parse container state")
    except subprocess.TimeoutExpired:
        return format_error(host, "Timeout", h['ip'], "Inspect timed out")
    except Exception as e:
        return format_error(host, "Error", h['ip'], str(e))


@mcp.tool()
def containers_recent_restarts(host: str, hours: int = 24) -> str:
    """
    Show containers that restarted within the specified time window.

    Use for instability checks - finds containers that crashed and restarted
    recently. Good starting point for "anything broken?" investigations.

    Chains with: container_status() then container_logs() on flagged
    containers to diagnose the root cause.

    Args:
        host: Target host (check health() for available hosts)
        hours: Look back window in hours (default 24)
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        return f"Unknown host: {host}. Available: {', '.join(HOSTS.keys())}"

    hours = max(1, min(168, hours))  # Cap at 1 week
    h = HOSTS[host]

    try:
        # Get all containers with their state
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             "sudo docker ps -a --format '{{.Names}}'"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            return format_error(host, "Failed to list containers", h['ip'], result.stderr)

        containers = [c.strip() for c in result.stdout.strip().split('\n') if c.strip()]

        if not containers:
            return "No containers found"

        # Check each container for restart count and start time
        threshold = datetime.now().astimezone() - timedelta(hours=hours)
        recent_restarts = []

        for container in containers:
            try:
                inspect_result = subprocess.run(
                    ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
                     f"sudo docker inspect {container} --format '{{{{json .State}}}}'"],
                    capture_output=True, text=True, timeout=10
                )

                if inspect_result.returncode != 0:
                    continue

                state = json.loads(inspect_result.stdout.strip())
                restarts = state.get("RestartCount", 0)
                started_at = state.get("StartedAt", "")

                if restarts > 0 and started_at:
                    started_at = started_at.replace("Z", "+00:00")
                    started = datetime.fromisoformat(started_at)
                    if started > threshold:
                        recent_restarts.append({
                            "name": container,
                            "restarts": restarts,
                            "started": started,
                            "running": state.get("Running", False)
                        })
            except:
                continue

        if not recent_restarts:
            return f"✅ No containers restarted in the last {hours} hours on {host}"

        # Sort by most recent restart
        recent_restarts.sort(key=lambda x: x["started"], reverse=True)

        out = [f"⚠️ Containers restarted in last {hours}h on {host}:\n"]
        for c in recent_restarts:
            icon = "🟢" if c["running"] else "🔴"
            time_str = c["started"].strftime("%Y-%m-%d %H:%M")
            out.append(f"   {icon} {c['name']:25} {c['restarts']:>3} restarts  (last: {time_str})")

        return "\n".join(out)

    except subprocess.TimeoutExpired:
        return format_error(host, "Timeout", h['ip'], "Operation timed out")
    except Exception as e:
        return format_error(host, "Error", h['ip'], str(e))


# =============================================================================
# MONITORING TOOLS (Type-based discovery)
# =============================================================================

@mcp.tool()
def prom_query(query: str) -> str:
    """
    Execute PromQL instant query against Prometheus.
    Requires an API with type: prometheus in inventory.

    Use for metric queries, threshold checks, and time-series data.
    For a quick "what's alerting?" check, use homelab_alerts() instead.
    For system resource overview, use system_stats(host) instead.

    Common queries:
    - up -> which scrape targets are reachable
    - node_memory_MemAvailable_bytes -> free memory
    - rate(node_cpu_seconds_total{mode="idle"}[5m]) -> CPU usage

    Args:
        query: PromQL expression (e.g., up, node_memory_MemFree_bytes)
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    prometheus_apis = _get_apis_by_type("prometheus")

    if not prometheus_apis:
        return "No Prometheus configured. Add an API with 'type: prometheus' to inventory.yml"

    # Use first prometheus instance (typically only one)
    api_name, api = next(iter(prometheus_apis.items()))

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{api['url']}/api/v1/query", params={"query": query})
        return resp.text[:10000]
    except Exception as e:
        return format_error("Prometheus", "Query Error", api['url'], str(e))


@mcp.tool()
def homelab_alerts() -> str:
    """
    Pull firing alerts from Prometheus and Uptime Kuma.
    Auto-discovers services by type in inventory.

    Use this for "is anything broken right now?" - returns only active alerts.
    For raw metric queries, use prom_query() instead.
    For a broader status overview including hosts and UPS, use homelab_status().
    """
    out = ["🚨 ALERTS\n"]
    alert_count = 0

    # Prometheus alerts
    prometheus_apis = _get_apis_by_type("prometheus")
    if prometheus_apis:
        api_name, api = next(iter(prometheus_apis.items()))
        try:
            resp = _http_get(f"{api['url']}/api/v1/alerts", timeout=5)
            data = resp.json()
            alerts = data.get("data", {}).get("alerts", [])
            firing = [a for a in alerts if a.get("state") == "firing"]
            pending = [a for a in alerts if a.get("state") == "pending"]

            if firing:
                out.append("⚠️  Prometheus FIRING:")
                for a in firing:
                    labels = a.get("labels", {})
                    name = labels.get("alertname", "unknown")
                    instance = labels.get("instance", "")
                    out.append(f"   • {name} ({instance})")
                    alert_count += 1

            if pending:
                out.append("⏳ Prometheus PENDING:")
                for a in pending:
                    labels = a.get("labels", {})
                    name = labels.get("alertname", "unknown")
                    out.append(f"   • {name}")
        except Exception as e:
            out.append(f"⚠️  Prometheus error: {e}")
    else:
        out.append("ℹ️  Prometheus not configured (add type: prometheus to enable)")

    # Uptime Kuma alerts
    kuma_apis = _get_apis_by_type("uptime-kuma")
    if kuma_apis:
        api_name, api = next(iter(kuma_apis.items()))
        try:
            # Build auth headers for Basic auth
            headers, auth_error = _build_auth_headers(api)
            if auth_error:
                out.append(f"⚠️  Uptime Kuma auth error: {auth_error}")
            else:
                resp = _http_get(f"{api['url']}/metrics", headers=headers, timeout=5)
                
                # Parse Prometheus format for monitor_status lines
                down_monitors = []
                maintenance_monitors = []
                for line in resp.text.split('\n'):
                    if line.startswith('monitor_status{'):
                        # Extract monitor name and status
                        try:
                            name_start = line.find('monitor_name="') + 14
                            name_end = line.find('"', name_start)
                            name = line[name_start:name_end]
                            status = int(line.split()[-1])
                            if status == 0:  # DOWN
                                down_monitors.append(name)
                            elif status == 3:  # MAINTENANCE
                                maintenance_monitors.append(name)
                        except:
                            continue
                
                if down_monitors:
                    out.append("\n🔴 Uptime Kuma DOWN:")
                    for name in down_monitors:
                        out.append(f"   • {name}")
                        alert_count += 1
                
                if maintenance_monitors:
                    out.append("\n🔧 Uptime Kuma MAINTENANCE:")
                    for name in maintenance_monitors:
                        out.append(f"   • {name}")        
        except Exception as e:
            out.append(f"⚠️  Uptime Kuma error: {e}")
    else:
        out.append("ℹ️  Uptime Kuma not configured (add type: uptime-kuma to enable)")

    if alert_count == 0:
        out.append("\n✅ All clear — no firing alerts")
    else:
        out.append(f"\n📊 Total: {alert_count} alert(s)")

    return "\n".join(out)


@mcp.tool()
def ollama_models(host: str = None) -> str:
    """
    List Ollama models: installed models + what's currently loaded in VRAM.
    Auto-discovers Ollama instances by type in inventory.

    Use when checking what models are available or what's consuming VRAM.
    Do not use api_get() against Ollama endpoints - this tool handles
    discovery, formatting, and VRAM status in one call.

    Args:
        host: Target host (e.g., 'beast', 'ai-lab'). Omit to list available hosts.
    """
    ollama_apis = _get_apis_by_type("ollama")

    if not ollama_apis:
        return "No Ollama instances configured. Add APIs with 'type: ollama' to inventory.yml"

    # Extract available hosts from api names (ollama-beast -> beast)
    available_hosts = {_extract_host_from_api_name(name, "ollama"): name for name in ollama_apis}

    if not host:
        return f"Available Ollama hosts: {', '.join(available_hosts.keys())}\n\nUsage: ollama_models(host='beast')"

    if host not in available_hosts:
        return f"Unknown host: {host}. Available: {', '.join(available_hosts.keys())}"

    api_name = available_hosts[host]
    api = ollama_apis[api_name]
    base_url = api["url"]

    out = [f"🤖 OLLAMA — {host}\n"]

    # Get installed models
    try:
        resp = _http_get(f"{base_url}/api/tags", timeout=10)
        data = resp.json()
        models = data.get("models", [])

        if models:
            out.append("📦 Installed:")
            total_size = 0
            for m in sorted(models, key=lambda x: x.get("size", 0), reverse=True):
                name = m.get("name", "unknown")
                size_gb = m.get("size", 0) / (1024 ** 3)
                total_size += m.get("size", 0)
                out.append(f"   {name:40} {size_gb:>6.1f} GB")
            out.append(f"\n   Total: {len(models)} models ({total_size / (1024 ** 3):.1f} GB)")
        else:
            out.append("📦 No models installed")
    except httpx.ConnectError:
        return format_error(f"ollama-{host}", "Connection Failed", base_url, "Is Ollama running?")
    except Exception as e:
        out.append(f"📦 Error fetching models: {e}")

    # Get currently loaded (in VRAM)
    try:
        resp = _http_get(f"{base_url}/api/ps", timeout=10)
        data = resp.json()
        loaded = data.get("models", [])

        out.append("")
        if loaded:
            out.append("🔥 Loaded in VRAM:")
            for m in loaded:
                name = m.get("name", "unknown")
                size_vram = m.get("size_vram", 0) / (1024 ** 3)
                out.append(f"   {name:40} {size_vram:>6.1f} GB VRAM")
        else:
            out.append("🔥 No models loaded (VRAM empty)")
    except Exception as e:
        out.append(f"🔥 Error fetching loaded models: {e}")

    return "\n".join(out)


@mcp.tool()
def system_stats(host: str = None) -> str:
    """
    Get system stats (CPU, memory, disk) from Glances.
    Auto-discovers Glances instances by type in inventory.

    Use for a quick resource overview of a host. Shows CPU, memory, swap,
    and disk usage from Glances API.

    For deeper investigation:
    - High CPU -> top_processes(host) to find what's consuming it
    - Disk full -> disk_usage(host) for per-filesystem breakdown
    - NAS storage -> nas_storage() for Synology volume capacity
    Do not use api_get() against Glances endpoints - this tool handles
    discovery and formatting automatically.

    Args:
        host: Target host (e.g., 'beast', 'docker-box'). Omit to list available hosts.
    """
    glances_apis = _get_apis_by_type("glances")

    if not glances_apis:
        return "No Glances instances configured. Add APIs with 'type: glances' to inventory.yml"

    # Extract available hosts from api names
    available_hosts = {_extract_host_from_api_name(name, "glances"): name for name in glances_apis}

    if not host:
        return f"Available Glances hosts: {', '.join(available_hosts.keys())}\n\nUsage: system_stats(host='beast')"

    if host not in available_hosts:
        return f"Unknown host: {host}. Available: {', '.join(available_hosts.keys())}"

    api_name = available_hosts[host]
    api = glances_apis[api_name]
    base_url = api["url"]

    out = [f"📊 SYSTEM STATS — {host}\n"]

    try:
        # CPU
        try:
            resp = _http_get(f"{base_url}/api/4/cpu", timeout=5)
            cpu = resp.json()
            total = cpu.get("total", 0)
            user = cpu.get("user", 0)
            system = cpu.get("system", 0)
            out.append(f"🔲 CPU:    {total:>5.1f}% total  ({user:.1f}% user, {system:.1f}% sys)")
        except Exception as e:
            out.append(f"🔲 CPU:    error - {e}")

        # Memory
        try:
            resp = _http_get(f"{base_url}/api/4/mem", timeout=5)
            mem = resp.json()
            used_gb = mem.get("used", 0) / (1024 ** 3)
            total_gb = mem.get("total", 0) / (1024 ** 3)
            percent = mem.get("percent", 0)
            out.append(f"🧠 Memory: {percent:>5.1f}%       ({used_gb:.1f} / {total_gb:.1f} GB)")
        except Exception as e:
            out.append(f"🧠 Memory: error - {e}")

        # Disk
        try:
            resp = _http_get(f"{base_url}/api/4/fs", timeout=5)
            disks = resp.json()
            out.append("💾 Disks:")
            for d in disks:
                mount = d.get("mnt_point", "?")
                used_gb = d.get("used", 0) / (1024 ** 3)
                total_gb = d.get("size", 0) / (1024 ** 3)
                percent = d.get("percent", 0)
                # Skip tiny filesystems
                if total_gb < 1:
                    continue
                out.append(f"   {mount:20} {percent:>5.1f}%  ({used_gb:.1f} / {total_gb:.1f} GB)")
        except Exception as e:
            out.append(f"💾 Disks:  error - {e}")

        # GPU (if available)
        try:
            resp = _http_get(f"{base_url}/api/4/gpu", timeout=5)
            gpus = resp.json()
            if gpus:
                out.append("🎮 GPU:")
                for g in gpus:
                    name = g.get("name", "Unknown GPU")
                    mem_percent = g.get("mem", 0)
                    proc_percent = g.get("proc", 0)
                    temp = g.get("temperature", 0)
                    out.append(f"   {name}")
                    out.append(f"      Load: {proc_percent:.0f}%  VRAM: {mem_percent:.0f}%  Temp: {temp}°C")
        except:
            pass  # GPU info is optional

    except httpx.ConnectError:
        return format_error(f"glances-{host}", "Connection Failed", base_url, "Is Glances running?")

    return "\n".join(out)


# =============================================================================
# DIAGNOSTICS
# =============================================================================

@mcp.tool()
def trigger_diagnostic(name: str) -> str:
    """
    Trigger a predefined diagnostic via n8n webhook.
    Each diagnostic runs a workflow that collects and returns system info.

    Use for complex multi-step diagnostics that are pre-built as n8n workflows.
    For simple single-command checks, use ssh_exec() or dedicated tools instead.

    Args:
        name: Diagnostic to run (e.g., 'docker-logs', 'fstab')
    """
    if not DIAGNOSTICS:
        return "No diagnostics configured in inventory.yml"

    if name not in DIAGNOSTICS:
        available = "\n".join(f"  {k}: {v.get('description', '(no description)')}" for k, v in DIAGNOSTICS.items())
        return f"Unknown diagnostic: {name}\n\nAvailable:\n{available}"

    diag = DIAGNOSTICS[name]
    url = diag["url"]

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(url)
        if resp.status_code >= 400:
            return format_error(f"diagnostic:{name}", f"HTTP {resp.status_code}", url, resp.text[:500])
        return resp.text[:50000]
    except httpx.ConnectError:
        return format_error(f"diagnostic:{name}", "Connection Failed", url, "Is n8n running?")
    except httpx.TimeoutException:
        return format_error(f"diagnostic:{name}", "Timeout", url, "Webhook did not respond within 30s")
    except Exception as e:
        return format_error(f"diagnostic:{name}", "Error", url, str(e))


# =============================================================================
# NAS TOOLS (Type-based discovery: synology)
# =============================================================================

@mcp.tool()
def nas_info(host: str = None) -> str:
    """
    Get Synology NAS system info: model, firmware, uptime, temperature.
    Auto-discovers Synology instances by type in inventory.

    Use for hardware/firmware info and basic health. For storage capacity
    use nas_storage(). For disk health use nas_disks(). For resource
    usage use nas_utilisation().

    Args:
        host: Target NAS host (e.g., 'nas'). Omit to list available hosts.
    """
    synology_apis = _get_apis_by_type("synology")

    if not synology_apis:
        return "No Synology instances configured. Add an API with 'type: synology' to inventory.yml"

    available_hosts = {_extract_host_from_api_name(name, "synology"): name for name in synology_apis}

    if not host:
        return f"Available NAS hosts: {', '.join(available_hosts.keys())}\n\nUsage: nas_info(host='nas')"

    if host not in available_hosts:
        return f"Unknown NAS: {host}. Available: {', '.join(available_hosts.keys())}"

    api_name = available_hosts[host]
    api = synology_apis[api_name]

    data, error = _synology_request(api_name, api, "SYNO.DSM.Info", "getinfo", version=2)
    if error:
        return format_error(f"synology-{host}", "API Error", api["url"], error)

    model = data.get("model", "Unknown")
    serial = data.get("serial", "Unknown")
    version = data.get("version_string", data.get("version", "Unknown"))
    ram = data.get("ram", 0)
    uptime_min = data.get("uptime", 0) // 60
    temp = data.get("temperature", "?")

    days = uptime_min // 1440
    hours = (uptime_min % 1440) // 60
    uptime_str = f"{days}d {hours}h" if days > 0 else f"{hours}h"

    out = [
        f"📦 NAS INFO — {host}\n",
        f"   Model:       {model}",
        f"   Serial:      {serial}",
        f"   DSM Version: {version}",
        f"   RAM:         {ram} MB",
        f"   Uptime:      {uptime_str}",
        f"   Temperature: {temp}°C",
    ]

    return "\n".join(out)


@mcp.tool()
def nas_storage(host: str = None) -> str:
    """
    Get Synology NAS volume status and usage.
    Auto-discovers Synology instances by type in inventory.

    Use for "how full is the NAS?" - shows volume health, total/used
    capacity, and percentage. This is Synology volume data, not host
    filesystem data (use disk_usage() for host mounts that connect TO
    the NAS).

    Args:
        host: Target NAS host (e.g., 'nas'). Omit to list available hosts.
    """
    synology_apis = _get_apis_by_type("synology")

    if not synology_apis:
        return "No Synology instances configured. Add an API with 'type: synology' to inventory.yml"

    available_hosts = {_extract_host_from_api_name(name, "synology"): name for name in synology_apis}

    if not host:
        return f"Available NAS hosts: {', '.join(available_hosts.keys())}\n\nUsage: nas_storage(host='nas')"

    if host not in available_hosts:
        return f"Unknown NAS: {host}. Available: {', '.join(available_hosts.keys())}"

    api_name = available_hosts[host]
    api = synology_apis[api_name]

    data, error = _synology_request(api_name, api, "SYNO.Storage.CGI.Storage", "load_info", version=1)
    if error:
        return format_error(f"synology-{host}", "API Error", api["url"], error)

    volumes = data.get("volumes", [])

    if not volumes:
        return f"📦 {host}: No volumes found"

    out = [f"💾 NAS STORAGE — {host}\n"]

    for vol in volumes:
        vol_id = vol.get("id", "?")
        status = vol.get("status", "unknown")
        total = vol.get("size", {}).get("total", "0")
        used = vol.get("size", {}).get("used", "0")

        try:
            total_tb = int(total) / (1024 ** 4)
            used_tb = int(used) / (1024 ** 4)
            percent = (int(used) / int(total) * 100) if int(total) > 0 else 0
        except (ValueError, ZeroDivisionError):
            total_tb = used_tb = percent = 0

        status_icon = "✅" if status == "normal" else "⚠️"
        out.append(f"   {status_icon} {vol_id:12} {status:10} {used_tb:>6.2f} / {total_tb:.2f} TB ({percent:.1f}%)")

    return "\n".join(out)


@mcp.tool()
def nas_disks(host: str = None) -> str:
    """
    Get Synology NAS disk health and SMART status.
    Auto-discovers Synology instances by type in inventory.

    Use when checking physical disk health - model, temperature, SMART
    status. For volume capacity, use nas_storage() instead.

    Args:
        host: Target NAS host (e.g., 'nas'). Omit to list available hosts.
    """
    synology_apis = _get_apis_by_type("synology")

    if not synology_apis:
        return "No Synology instances configured. Add an API with 'type: synology' to inventory.yml"

    available_hosts = {_extract_host_from_api_name(name, "synology"): name for name in synology_apis}

    if not host:
        return f"Available NAS hosts: {', '.join(available_hosts.keys())}\n\nUsage: nas_disks(host='nas')"

    if host not in available_hosts:
        return f"Unknown NAS: {host}. Available: {', '.join(available_hosts.keys())}"

    api_name = available_hosts[host]
    api = synology_apis[api_name]

    data, error = _synology_request(api_name, api, "SYNO.Storage.CGI.Storage", "load_info", version=1)
    if error:
        return format_error(f"synology-{host}", "API Error", api["url"], error)

    disks = data.get("disks", [])

    if not disks:
        return f"📦 {host}: No disks found"

    out = [f"🔧 NAS DISKS — {host}\n"]

    for disk in disks:
        name = disk.get("name", "?")
        model = disk.get("model", "Unknown").strip()
        vendor = disk.get("vendor", "").strip()
        status = disk.get("status", "unknown")
        temp = disk.get("temp", "?")
        smart = disk.get("smart_status", "unknown")
        size_total = disk.get("size_total", "0")

        try:
            size_gb = int(size_total) / (1024 ** 3)
        except (ValueError, TypeError):
            size_gb = 0

        status_icon = "✅" if status == "normal" else "⚠️"
        smart_icon = "✅" if smart == "normal" else "⚠️"

        label = f"{vendor} {model}".strip() if vendor else model
        out.append(f"   {status_icon} {name:8} {label:30} {size_gb:>8.1f} GB  {temp:>3}°C  SMART: {smart_icon} {smart}")

    return "\n".join(out)


@mcp.tool()
def nas_utilisation(host: str = None) -> str:
    """
    Get Synology NAS CPU, memory, and network utilisation.
    Auto-discovers Synology instances by type in inventory.

    Use for NAS performance - CPU load, memory pressure, network throughput.
    For NAS storage capacity, use nas_storage(). For host-level stats on
    machines that MOUNT the NAS, use system_stats(host) instead.

    Args:
        host: Target NAS host (e.g., 'nas'). Omit to list available hosts.
    """
    synology_apis = _get_apis_by_type("synology")

    if not synology_apis:
        return "No Synology instances configured. Add an API with 'type: synology' to inventory.yml"

    available_hosts = {_extract_host_from_api_name(name, "synology"): name for name in synology_apis}

    if not host:
        return f"Available NAS hosts: {', '.join(available_hosts.keys())}\n\nUsage: nas_utilisation(host='nas')"

    if host not in available_hosts:
        return f"Unknown NAS: {host}. Available: {', '.join(available_hosts.keys())}"

    api_name = available_hosts[host]
    api = synology_apis[api_name]

    data, error = _synology_request(api_name, api, "SYNO.Core.System.Utilization", "get", version=1)
    if error:
        return format_error(f"synology-{host}", "API Error", api["url"], error)

    out = [f"📊 NAS UTILISATION — {host}\n"]

    # CPU
    cpu = data.get("cpu", {})
    user_load = cpu.get("user_load", 0)
    system_load = cpu.get("system_load", 0)
    total_cpu = user_load + system_load
    out.append(f"   🔲 CPU:    {total_cpu:>5.1f}% total  ({user_load:.1f}% user, {system_load:.1f}% sys)")

    # Memory
    mem = data.get("memory", {})
    total_real = mem.get("total_real", 0)
    avail_real = mem.get("avail_real", 0)
    try:
        total_mb = int(total_real) / 1024
        avail_mb = int(avail_real) / 1024
        used_mb = total_mb - avail_mb
        percent = (used_mb / total_mb * 100) if total_mb > 0 else 0
        out.append(f"   🧠 Memory: {percent:>5.1f}%       ({used_mb:.0f} / {total_mb:.0f} MB)")
    except (ValueError, ZeroDivisionError):
        out.append(f"   🧠 Memory: unavailable")

    # Network
    network = data.get("network", [])
    if network:
        out.append("   🌐 Network:")
        for iface in network:
            device = iface.get("device", "?")
            rx = iface.get("rx", 0)
            tx = iface.get("tx", 0)
            # Convert bytes/sec to human-readable
            rx_mbit = rx * 8 / (1024 * 1024) if rx else 0
            tx_mbit = tx * 8 / (1024 * 1024) if tx else 0
            out.append(f"      {device:10} ↓ {rx_mbit:>6.1f} Mbit/s  ↑ {tx_mbit:>6.1f} Mbit/s")

    return "\n".join(out)


# =============================================================================
# SYSTEM TOOLS
# =============================================================================

@mcp.tool()
def get_paths() -> str:
    """
    Show configured filesystem paths from inventory.
    Returns key directories like repos, vault, compose locations.

    These are reference paths - use with ssh_exec() to explore contents.
    Example: After seeing vault path, use ssh_exec(host, 'ls /home/docker/bren-vault/vault')
    """
    if not PATHS:
        return (
            "No paths configured.\n\n"
            "Add a paths: section to inventory.yml:\n"
            "  paths:\n"
            "    labops-repo: /home/docker/labops-mcp\n"
            "    compose-dir: /home/docker/compose\n"
            "    backups: /mnt/backups"
        )

    out = ["CONFIGURED PATHS\n"]
    for name, path in PATHS.items():
        out.append(f"   {name:20} {path}")
    return "\n".join(out)


@mcp.tool()
def disk_usage(host: str) -> str:
    """
    Get disk usage for a host. Shows all mounted filesystems with size, used, available, and usage percentage.
    Flags any filesystem over 85% usage with a warning.

    Args:
        host: Target host (check health() for available hosts)
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        available = list(HOSTS.keys()) if HOSTS else ["(no hosts configured)"]
        return f"Unknown host: {host}. Available: {', '.join(available)}"

    h = HOSTS[host]
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             "df -h --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=squashfs"],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode != 0:
            return format_error(host, "df failed", h['ip'], result.stderr.strip())

        lines = result.stdout.strip().split('\n')
        if not lines:
            return format_error(host, "No output", h['ip'], "df returned empty output")

        out = [f"DISK USAGE - {host}\n"]
        out.append(f"   {'Filesystem':<30} {'Size':>6} {'Used':>6} {'Avail':>6} {'Use%':>5}  Mount")
        out.append(f"   {'-' * 80}")

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 6:
                continue
            filesystem = parts[0]
            size = parts[1]
            used = parts[2]
            avail = parts[3]
            use_pct = parts[4]
            mount = ' '.join(parts[5:])

            # Flag high usage
            try:
                pct_val = int(use_pct.rstrip('%'))
                flag = " !! WARNING" if pct_val > 85 else ""
            except ValueError:
                flag = ""

            out.append(f"   {filesystem:<30} {size:>6} {used:>6} {avail:>6} {use_pct:>5}  {mount}{flag}")

        return "\n".join(out)

    except subprocess.TimeoutExpired:
        return format_error(host, "Timeout", h['ip'], "df command timed out")
    except Exception as e:
        return format_error(host, "Error", h['ip'], str(e))


@mcp.tool()
def top_processes(host: str, n: int = 10) -> str:
    """
    Show top CPU and memory consuming processes on a host.
    Returns two sorted views: by CPU usage and by memory usage.

    Args:
        host: Target host (check health() for available hosts)
        n: Number of processes to show per sort (default 10, max 25)
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        available = list(HOSTS.keys()) if HOSTS else ["(no hosts configured)"]
        return f"Unknown host: {host}. Available: {', '.join(available)}"

    n = max(1, min(25, n))
    h = HOSTS[host]

    out = [f"TOP PROCESSES - {host}\n"]

    # Top by CPU
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             "ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu"],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            out.append("By CPU:")
            out.append(f"   {'PID':>7} {'USER':<12} {'%CPU':>6} {'%MEM':>6}  COMMAND")
            out.append(f"   {'-' * 50}")
            for line in lines[1:n + 1]:  # Skip header, take top n
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    out.append(f"   {parts[0]:>7} {parts[1]:<12} {parts[2]:>6} {parts[3]:>6}  {parts[4]}")
        else:
            out.append("By CPU: failed to retrieve")

    except subprocess.TimeoutExpired:
        out.append("By CPU: timed out")
    except Exception as e:
        out.append(f"By CPU: error - {e}")

    out.append("")

    # Top by Memory
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             "ps -eo pid,user,%cpu,%mem,comm --sort=-%mem"],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            out.append("By Memory:")
            out.append(f"   {'PID':>7} {'USER':<12} {'%CPU':>6} {'%MEM':>6}  COMMAND")
            out.append(f"   {'-' * 50}")
            for line in lines[1:n + 1]:  # Skip header, take top n
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    out.append(f"   {parts[0]:>7} {parts[1]:<12} {parts[2]:>6} {parts[3]:>6}  {parts[4]}")
        else:
            out.append("By Memory: failed to retrieve")

    except subprocess.TimeoutExpired:
        out.append("By Memory: timed out")
    except Exception as e:
        out.append(f"By Memory: error - {e}")

    return "\n".join(out)


@mcp.tool()
def service_status(host: str, service: str) -> str:
    """
    Get systemd service status for non-containerised services.
    Shows active state, uptime, and recent journal entries.

    Args:
        host: Target host (check health() for available hosts)
        service: Systemd service name (e.g., 'sshd', 'tailscaled', 'nut-server')
    """
    allowed, error = _check_rate_limit()
    if not allowed:
        return error

    if host not in HOSTS:
        available = list(HOSTS.keys()) if HOSTS else ["(no hosts configured)"]
        return f"Unknown host: {host}. Available: {', '.join(available)}"

    # Input validation - must happen before any SSH call
    if not re.match(r'^[a-zA-Z0-9._@-]+$', service):
        return "Error: Invalid service name. Must contain only alphanumeric characters, dots, underscores, @ signs, and hyphens."

    h = HOSTS[host]
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", f"{h['user']}@{h['ip']}",
             f"sudo systemctl status {service} --no-pager --lines=10"],
            capture_output=True, text=True, timeout=15
        )

        output = result.stdout + result.stderr
        return output.strip() if output.strip() else "(no output)"

    except subprocess.TimeoutExpired:
        return format_error(host, "Timeout", h['ip'], "systemctl status timed out")
    except Exception as e:
        return format_error(host, "Error", h['ip'], str(e))


# =============================================================================
# AUDIT TOOL (Optional)
# =============================================================================

try:
    from audit import register_audit_tool
    register_audit_tool(mcp, HOSTS, APIS, APIS_BY_TYPE)
except ImportError:
    pass


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8100)
