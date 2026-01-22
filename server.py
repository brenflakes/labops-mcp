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

  Monitoring (auto-discovered by type):
    - prom_query(query)           PromQL queries (requires type: prometheus)
    - homelab_alerts()            Firing alerts from Prometheus + Uptime Kuma
    - ollama_models(host)         List Ollama models (requires type: ollama)
    - system_stats(host)          CPU/mem/disk from Glances (requires type: glances)
"""

import os
import subprocess
import json
from pathlib import Path
from collections import deque
from time import time
from datetime import datetime, timedelta
import httpx
import yaml
import jq
from fastmcp import FastMCP

mcp = FastMCP("labops")

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "config/inventory.yml"))
with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

HOSTS = {name: h for name, h in config.get("hosts", {}).items() if h.get("ssh", False)}
APIS = config.get("apis", {})

# Build type indexes for service discovery
APIS_BY_TYPE = {}
for name, api in APIS.items():
    api_type = api.get("type")
    if api_type:
        if api_type not in APIS_BY_TYPE:
            APIS_BY_TYPE[api_type] = {}
        APIS_BY_TYPE[api_type][name] = api

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


# =============================================================================
# CORE TOOLS
# =============================================================================

@mcp.tool()
def ssh_exec(host: str, command: str) -> str:
    """
    Execute read-only command on a host via restricted SSH user.
    Security enforced at OS level via rbash + limited PATH + sudoers.

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
            resp = _http_get(api["url"], timeout=3, verify=api.get("verify_ssl", True))
            status["checks"][f"api_{name}"] = resp.status_code < 500
        except:
            status["checks"][f"api_{name}"] = False

    return json.dumps(status, indent=2)


@mcp.tool()
def homelab_status() -> str:
    """
    Quick status overview of all hosts, UPS units, and APIs.
    Discovers UPS automatically via NUT on each host.
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
