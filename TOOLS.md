# Tools Reference

## Core Tools

### ssh_exec

Run read-only commands on Linux hosts.

```python
ssh_exec(host, command)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| host | string | Host name from inventory.yml |
| command | string | Command to execute |

**Example:**
```python
ssh_exec("my-server", "sudo docker ps -a")
ssh_exec("my-server", "df -h")
ssh_exec("my-server", "sudo docker stats --no-stream")
```

---

### api_get

Query REST APIs with optional jq filtering.

```python
api_get(service, endpoint, filter?)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| service | string | Service name from inventory.yml |
| endpoint | string | API path (e.g., `/api/v1/query`) |
| filter | string | Optional jq expression to filter response |

**Examples:**
```python
# Full response
api_get("prometheus", "/api/v1/targets")

# With jq filter - extract specific fields
api_get("sonarr", "/api/v3/series", filter=".[].title")
api_get("ha", "/api/states", filter=".[].entity_id")
api_get("prometheus", "/api/v1/label/__name__/values", filter=".data")
```

---

### health

Check connectivity to all configured hosts and APIs.

```python
health()
```

Returns JSON with:
- Status of each host (SSH connectivity)
- Status of each API (HTTP reachability)
- List of available hosts, APIs, and service types

---

### homelab_status

Quick dashboard showing hosts, UPS units, and API status.

```python
homelab_status()
```

**Example output:**
```
🖥️  HOSTS
   my-server      ✅ up 15d   load 0.42  containers 26
   other-host          ✅ up 3d    load 0.15  containers 4

⚡ UPS
   myups           (my-server) ✅ OL       100%  45min  12% load

🔌 APIS
   prometheus ✅  grafana ✅  sonarr ✅  radarr ✅
```

---

## Container Tools

### container_logs

Get recent logs from a specific container.

```python
container_logs(host, container, lines?)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| host | string | - | Host name from inventory.yml |
| container | string | - | Container name |
| lines | int | 50 | Number of lines (max 500) |

**Examples:**
```python
container_logs("my-server", "prometheus")
container_logs("my-server", "nginx", lines=200)
```

---

### search_logs

Search logs across all containers on a host.

```python
search_logs(host, pattern, lines?)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| host | string | - | Host name from inventory.yml |
| pattern | string | - | Grep pattern (case-insensitive) |
| lines | int | 100 | Lines to search per container (max 500) |

**Examples:**
```python
search_logs("my-server", "error")
search_logs("my-server", "connection refused", lines=200)
```

**Example output:**
```
[prometheus] level=error msg=...
[nginx] 2024/01/15 connection refused
```

---

### container_mounts

Show volume and bind mounts for a container.

```python
container_mounts(host, container)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| host | string | Host name from inventory.yml |
| container | string | Container name |

**Example:**
```python
container_mounts("my-server", "prometheus")
```

**Example output:**
```
📁 prometheus mounts:

   [volume] prometheus_prometheus-data
            → /prometheus (rw)
   [bind]   /home/user/prometheus/prometheus.yml
            → /etc/prometheus/prometheus.yml (ro)
```

---

### container_status

Get health status for a single container.

```python
container_status(host, container)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| host | string | Host name from inventory.yml |
| container | string | Container name |

**Example:**
```python
container_status("my-server", "jellyfin")
```

**Example output:**
```
✅ jellyfin on my-server
   Status:   running
   Uptime:   4d 7h
   Restarts: 0
   Health:   healthy
```

---

### containers_recent_restarts

Show containers that restarted within a time window.

```python
containers_recent_restarts(host, hours?)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| host | string | - | Host name from inventory.yml |
| hours | int | 24 | Look back window (max 168 / 1 week) |

**Example:**
```python
containers_recent_restarts("my-server")
containers_recent_restarts("my-server", hours=48)
```

**Example output:**
```
⚠️ Containers restarted in last 24h on my-server:

   🟢 some-container             2 restarts  (last: 2024-01-22 14:30)
   🟢 nginx                     1 restarts  (last: 2024-01-22 09:15)
```

Or if none:
```
✅ No containers restarted in the last 24 hours on my-server
```

---

## Monitoring Tools

These tools auto-discover services by `type` in inventory.yml.

### prom_query

Execute PromQL queries against Prometheus.

**Requires:** An API with `type: prometheus` in inventory.

```python
prom_query(query)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| query | string | PromQL expression |

**Examples:**
```python
prom_query("up")
prom_query("node_memory_MemFree_bytes")
prom_query("rate(node_cpu_seconds_total[5m])")
```

---

### homelab_alerts

Pull firing alerts from Prometheus and Uptime Kuma.

**Requires:** `type: prometheus` and/or `type: uptime-kuma` in inventory.

```python
homelab_alerts()
```

**Example output:**
```
🚨 ALERTS

⚠️  Prometheus FIRING:
   • HighMemoryUsage (my-server:9100)
   • TargetDown (other-host:9100)

🔴 Uptime Kuma DOWN:
   • Jellyfin
   • Immich

📊 Total: 4 alert(s)
```

Or if all clear:
```
🚨 ALERTS

✅ All clear — no firing alerts
```

---

### ollama_models

List Ollama models and VRAM usage.

**Requires:** APIs with `type: ollama` in inventory (naming: `ollama-{hostname}`).

```python
ollama_models(host?)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| host | string | Optional. Host name (e.g., "gpu-host"). Omit to list available hosts. |

**Examples:**
```python
ollama_models()                    # List available hosts
ollama_models(host="gpu-host")        # Show models on gpu-host
```

**Example output:**
```
🤖 OLLAMA — gpu-host

📦 Installed:
   llama3.1:70b                                39.0 GB
   mistral:7b                                  4.1 GB
   nomic-embed-text:latest                     0.3 GB

   Total: 3 models (43.4 GB)

🔥 Loaded in VRAM:
   llama3.1:70b                                39.0 GB VRAM
```

---

### system_stats

Get CPU, memory, disk, and GPU stats from Glances.

**Requires:** APIs with `type: glances` in inventory (naming: `glances-{hostname}`).

```python
system_stats(host?)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| host | string | Optional. Host name. Omit to list available hosts. |

**Examples:**
```python
system_stats()                     # List available hosts
system_stats(host="gpu-host")         # Show stats for gpu-host
```

**Example output:**
```
📊 SYSTEM STATS — gpu-host

🔲 CPU:      6.2% total  (2.4% user, 3.3% sys)
🧠 Memory:  45.6%       (14.6 / 32.0 GB)
💾 Disks:
   /                     30.0%  (142.5 / 475.0 GB)
   /data                 41.7%  (396.1 / 950.0 GB)
🎮 GPU:
   NVIDIA GeForce RTX 3090
      Load: 4%  VRAM: 9%  Temp: 44°C
```

---

## Security Tools

### security_audit

Audit security posture and show what data is exposed.

```python
security_audit(host?)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| host | string | Optional: audit specific host, or all if omitted |

**Checks:**
- Docker group membership (critical)
- Containers with environment variables (potential secrets)
- Unauthenticated APIs
- Risk ratings per host
