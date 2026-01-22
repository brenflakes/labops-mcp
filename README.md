# labops-mcp

A personal project inspired by watching NetworkChuck demo MCP integrations with Claude. I was already using Claude with Obsidian and other tools to document my homelab - his video made me realise I could build my own MCP to give Claude direct access to my homelab infrastructure.

Turns out you can. This MCP server gives Claude (or any MCP-compatible client) read-only access to your homelab - live container status, Prometheus metrics, logs, API queries - all without leaving the conversation.

The workflow before: ask a question → get told to run a command → copy output → paste it back → wait for analysis.

The workflow now: ask a question → Claude goes and gets the answer itself.

Built with security in mind: restricted shell users, SSH key auth, read-only by design. Modular config means adding new hosts or APIs is just a few lines of YAML.

## Features

- **Config-driven**: All hosts, APIs, and authentication in one YAML file
- **Auto-discovery**: Convenience tools find services by type (Prometheus, Ollama, Glances)
- **Secure by design**: OS-level restrictions via rbash + sudoers, not code logic
- **Graceful failures**: Missing services return helpful messages, not crashes

## Supported Services

These services have native support with dedicated auth handling or convenience tools:

| Service | Auth Type | Convenience Tools |
|---------|-----------|-------------------|
| Prometheus | - | `prom_query()`, `homelab_alerts()` |
| Uptime Kuma | `basic` | `homelab_alerts()` |
| Ollama | - | `ollama_models()` |
| Glances | - | `system_stats()` |
| NUT (UPS) | - | Auto-discovery in `homelab_status()` |
| Sonarr / Radarr / Prowlarr | `api_key` | - |
| Jellyfin / Emby | `emby` | - |
| Immich | `immich` | - |
| Proxmox | `pve` | - |
| Home Assistant | `bearer` | - |
| Grafana | `bearer` | - |
| Portainer | `api_key` | - |

Any other REST API can be added with `auth_type: bearer`, `api_key`, or `custom`.

## Tools

### Core

| Tool | Purpose |
|------|---------|
| `ssh_exec(host, command)` | Run read-only commands on Linux hosts |
| `api_get(service, endpoint, filter?)` | Query REST APIs with optional jq filtering |
| `health()` | Check connectivity to all configured hosts/services |
| `homelab_status()` | Quick dashboard: hosts, UPS, APIs at a glance |

### Containers

| Tool | Purpose |
|------|---------|
| `container_logs(host, container, lines?)` | Get recent logs from a container |
| `search_logs(host, pattern, lines?)` | Search logs across all containers on a host |
| `container_mounts(host, container)` | Show volume/bind mounts for a container |
| `container_status(host, container)` | Health check: running state, uptime, restarts |
| `containers_recent_restarts(host, hours?)` | List containers that restarted recently |

### Monitoring (auto-discovered by type)

| Tool | Purpose | Requires |
|------|---------|----------|
| `prom_query(query)` | Execute PromQL queries | `type: prometheus` |
| `homelab_alerts()` | Firing alerts from Prometheus + Uptime Kuma | `type: prometheus` and/or `type: uptime-kuma` |
| `ollama_models(host?)` | List models + VRAM usage | `type: ollama` |
| `system_stats(host?)` | CPU/memory/disk/GPU from Glances | `type: glances` |

### Security

| Tool | Purpose |
|------|---------|
| `security_audit(host?)` | Audit security posture and exposure |

## Quick Start

### 1. Clone and generate SSH key

```bash
git clone https://github.com/brenflakes/labops-mcp
cd labops-mcp
./setup/setup-mcp.sh
```

### 2. Set up each Linux host

```bash
./setup/setup-host.sh 'ssh-ed25519 AAAA... your-public-key'
```

### 3. Configure

```bash
cp config/inventory.example.yml config/inventory.yml
cp .env.example .env
# Edit both files with your hosts and API tokens
```

### 4. Deploy

```bash
docker-compose up -d
```

### 5. Add to Claude Desktop

Edit your Claude Desktop config:

```json
{
  "mcpServers": {
    "labops": {
      "command": "npx",
      "args": ["mcp-remote", "http://YOUR-MCP-IP:8100/sse", "--allow-http"]
    }
  }
}
```

Restart Claude Desktop.

## Configuration

### Auth Types

The `auth_type` field determines how tokens are sent:

| auth_type | Header Format | Services |
|-----------|---------------|----------|
| `bearer` | `Authorization: Bearer {token}` | Home Assistant, Grafana |
| `api_key` | `X-Api-Key: {token}` | Sonarr, Radarr, Prowlarr, Portainer |
| `emby` | `X-Emby-Token: {token}` | Jellyfin, Emby |
| `pve` | `Authorization: PVEAPIToken={token}` | Proxmox |
| `immich` | `x-api-key: {token}` | Immich |
| `basic` | `Authorization: Basic base64({token})` | Uptime Kuma |
| `custom` | `{auth_header}: {token}` | Anything else |

### Service Types

The `type` field enables auto-discovery for convenience tools:

| Type | Enables | Naming Convention |
|------|---------|-------------------|
| `prometheus` | `prom_query()`, `homelab_alerts()` | Any name |
| `uptime-kuma` | `homelab_alerts()` | Any name |
| `ollama` | `ollama_models(host)` | `ollama-{hostname}` |
| `glances` | `system_stats(host)` | `glances-{hostname}` |

Example:
```yaml
ollama-host1:
  url: http://192.168.1.100:11434
  auth: false
  type: ollama

glances-host2:
  url: http://192.168.1.100:61208
  auth: false
  type: glances

uptime-kuma:
  url: http://192.168.1.100:3002
  auth: true
  auth_type: basic
  token_env: KUMA_TOKEN    # Format in .env: username:password
  type: uptime-kuma
```

Then call: `ollama_models(host="beast")` or `system_stats(host="beast")`

## ⚠️ Security Notice

This tool exposes read-only access to your infrastructure. `docker inspect` will reveal container environment variables (passwords, API keys, etc.).

**Read [docs/SECURITY.md](SECURITY.md) before deploying.**

## Documentation

- [SECURITY.md](SECURITY.md) - Threat model, risks, hardening
- [TOOLS.md](TOOLS.md) - Tool reference and examples
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and fixes

## License

MIT
