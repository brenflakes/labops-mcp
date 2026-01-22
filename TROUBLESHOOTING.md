# Troubleshooting

## SSH Connection Fails

**Test from MCP container:**
```bash
docker exec -it labops-mcp ssh claude-ro@192.168.1.100 "echo ok"
```

**Check SSH key is mounted:**
```bash
docker exec -it labops-mcp ls -la /root/.ssh/
```

**Check host is reachable:**
```bash
ping 192.168.1.100
```

---

## "sudo: command not found"

The setup script needs to symlink sudo into the restricted PATH:

```bash
sudo ln -s /usr/bin/sudo /home/claude-ro/bin/
```

---

## "sudo: a password is required"

Sudoers file isn't being read correctly.

**Check file exists and has correct permissions:**
```bash
sudo ls -la /etc/sudoers.d/claude-ro  # Must be -r--r----- (440)
sudo cat /etc/sudoers.d/claude-ro     # Should show NOPASSWD rules
```

**Fix permissions:**
```bash
sudo chmod 440 /etc/sudoers.d/claude-ro
```

---

## Claude Desktop Shows "Server disconnected"

1. **Check MCP container is running:**
   ```bash
   docker ps | grep labops-mcp
   ```

2. **Check container logs:**
   ```bash
   docker logs labops-mcp --tail 50
   ```

3. **Test SSE endpoint:**
   ```bash
   curl -N http://YOUR-IP:8100/sse
   ```
   Should show an event stream. Ctrl+C to exit.

4. **Verify Claude Desktop config has `--allow-http`:**
   ```json
   "args": ["mcp-remote", "http://...", "--allow-http"]
   ```

5. **Restart Claude Desktop** after config changes.

---

## API Returns Auth Error

**Check token is loaded:**
```bash
docker exec -it labops-mcp env | grep TOKEN
```

**Test API directly:**
```bash
curl -H "Authorization: Bearer $HA_TOKEN" http://192.168.1.101:8123/api/
```

**Common causes:**
- Token not in `.env` file
- Container not restarted after adding token
- Wrong `auth_type` in inventory.yml (check [README.md](../README.md#auth-types))

---

## "Command chaining/redirection not allowed"

The command contains blocked characters: `;`, `&&`, `||`, `` ` ``, `$()`, `${}`, `>`, `<`, `$`

This is intentional security. Run commands separately or use pipes (`|`) for filtering.

---

## Rate Limit Exceeded

Wait 60 seconds. The limit is 60 calls per minute across all tools.

---

## Host Shows Offline but Is Running

**Check SSH key permissions:**
```bash
docker exec -it labops-mcp ls -la /root/.ssh/id_ed25519
# Should be -rw------- (600)
```

**Check inventory.yml has correct IP:**
```yaml
hosts:
  my-server:
    ip: 192.168.1.100  # Verify this
    ssh: true
    user: claude-ro
```

**Test SSH manually:**
```bash
docker exec -it labops-mcp ssh -v claude-ro@192.168.1.100 "echo ok"
```

---

## Container Logs Return "(no logs)"

Container might be new or logs were cleared. Check directly:

```bash
docker logs CONTAINER_NAME --tail 10
```

If that works but `container_logs` doesn't, check the container name matches exactly (case-sensitive).

---

## search_logs Returns No Matches

- Pattern is case-insensitive but must match something in recent logs
- Default searches last 100 lines per container - try increasing `lines`
- Some containers log to files instead of stdout - won't be found

---

## jq Filter Error

**Common mistakes:**

```python
# Wrong - missing dot
api_get("sonarr", "/api/v3/series", filter="[].title")

# Right
api_get("sonarr", "/api/v3/series", filter=".[].title")
```

**Test jq expressions locally:**
```bash
curl -s http://localhost:8989/api/v3/series | jq '.[].title'
```

---

## ollama_models / system_stats Returns "No instances configured"

These tools auto-discover services by `type` in inventory.yml.

**For Ollama:**
```yaml
ollama-beast:                    # Must be named ollama-{hostname}
  url: http://192.168.1.100:11434
  auth: false
  type: ollama                   # This enables the tool
```

**For Glances:**
```yaml
glances-beast:                   # Must be named glances-{hostname}
  url: http://192.168.1.100:61208
  auth: false
  type: glances                  # This enables the tool
```

After adding, restart the MCP container:
```bash
docker-compose restart
```

---

## ollama_models Shows "Connection Failed"

Ollama might not be running or not accessible from the MCP container.

**Test from MCP container:**
```bash
docker exec -it labops-mcp curl http://192.168.1.100:11434/api/tags
```

**Common causes:**
- Ollama not running on target host
- Firewall blocking port 11434
- Ollama bound to localhost only (needs `OLLAMA_HOST=0.0.0.0`)

---

## homelab_alerts Shows Timeout or Auth Errors

### Prometheus Issues

**Check Prometheus is accessible:**
```bash
curl http://YOUR-IP:9090/api/v1/alerts
```

### Uptime Kuma Issues

`homelab_alerts()` uses Uptime Kuma's `/metrics` endpoint with basic auth.

**Check your inventory.yml config:**
```yaml
uptime-kuma:
  url: http://192.168.1.100:3002
  auth: true
  auth_type: basic
  token_env: KUMA_TOKEN
  type: uptime-kuma
```

**Check .env has credentials:**
```bash
# Format: username:password
KUMA_TOKEN=admin:yourpassword
```

**Test the endpoint directly:**
```bash
curl -u admin:yourpassword http://192.168.1.100:3002/metrics
```

**Common causes:**
- Missing `auth_type: basic` in inventory
- Wrong credentials in `.env`
- Uptime Kuma metrics endpoint not enabled (check Settings → General → Prometheus Metrics)
