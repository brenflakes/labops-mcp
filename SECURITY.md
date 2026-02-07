# Security

## Overview

homelab-mcp provides **read-only** access to your infrastructure. It cannot execute code, modify files, or change state. However, it CAN expose sensitive information.

## Threat Model

**Attacker profile:** Someone with access to your MCP client (Claude Desktop) or the MCP server endpoint.

**What they can do:**
- View container status, logs, stats, and environment variables
- Query your APIs (Prometheus, Home Assistant, etc.)
- Map your network topology
- Read world-readable files on configured hosts

**What they cannot do:**
- Run containers or execute code
- Modify or delete files
- Start/stop/restart services
- Access hosts not in inventory

## Known Risks

### 🔴 docker inspect Exposes Secrets

`docker inspect` reveals environment variables from containers, including:
- Database passwords
- API keys and tokens
- VPN credentials (WireGuard keys, etc.)

**Mitigations:**
1. Accept the risk (single-operator homelabs)
2. Remove `docker inspect` from sudoers whitelist
3. Use Docker secrets instead of env vars
4. Restrict to specific "safe" containers in sudoers

### 🔴 Prometheus Exposes Network Topology

Unauthenticated Prometheus reveals:
- All host IPs and hostnames
- MAC addresses
- Kernel versions
- Full network topology

**Mitigation:** Add basic auth to Prometheus.

### 🟡 Container Logs May Contain Secrets

Apps that log credentials, tokens, or PII will expose them via `docker logs`, `container_logs`, and `search_logs`.

**Mitigation:** Audit what your apps log.

## Security Controls

### Authentication Layer

Bearer token middleware validates `Authorization: Bearer <token>` on every MCP request (`on_request` hook — catches tool calls, list operations, everything).

- **Optional by design** — disabled if `MCP_AUTH_TOKEN` env var is not set
- **Simple string comparison** (not JWT) — appropriate for single-operator, internal network
- **FastMCP native middleware** — runs before any tool execution
- **Designed to be replaceable** with Authentik reverse proxy when expanding to multiple MCP servers

### Restricted User (claude-ro)

Each host has a `claude-ro` user with:
- Restricted shell (rbash) - no cd, no PATH changes
- Limited PATH - only whitelisted binaries
- Sudoers whitelist - specific read-only commands only
- **NOT in docker group** (critical)

### Critical Check

```bash
groups claude-ro  # Must NOT include 'docker'
```

If in docker group, full root access is possible via:
```bash
docker run -v /:/host alpine chroot /host
```

### File Permissions

`.env` files containing API tokens and credentials must be `600` (owner read/write only):

```bash
chmod 600 /home/docker/labops-mcp/.env
chmod 600 /home/docker/*/.env   # All compose stacks
```

Without this, `claude-ro` can read `.env` files via SSH and expose every credential on the host.

### Input Validation

Commands are blocked if they contain:
- Command chaining: `;`, `&&`, `||`
- Subshells: `` ` ``, `$(`, `${`
- Redirects: `>`, `<`
- Variable expansion: `$`
- Newlines

Pipes (`|`) are allowed for output filtering.

### Rate Limiting

60 calls per minute across all tools. Prevents runaway loops.

### Sudoers Whitelist

Default allowed commands:
```
docker ps, docker logs, docker stats, docker inspect
journalctl --no-pager
systemctl status
```

Blocked:
```
docker run, docker exec, docker start, docker stop
```

### Verification

```bash
# Should work
ssh claude-ro@host 'sudo docker ps -a'

# Should fail
ssh claude-ro@host 'sudo docker run hello-world'

# .env files must not be readable by claude-ro
ssh claude-ro@host 'cat /home/docker/labops-mcp/.env'  # Should fail: Permission denied
```

## Post-Setup Audit

Run `security_audit()` after setup to check:
- Docker group membership
- Containers with env vars (potential secrets)
- Unauthenticated APIs
- Risk ratings per host

## SSH Escape Sequences

Not a risk. Escape sequences (`~.`, `~C`) only work in interactive mode. This MCP runs commands non-interactively.
