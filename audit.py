#!/usr/bin/env python3
"""
Security audit tool for Homelab MCP Server.
Optional module - delete if not needed.
"""

import subprocess
import json


def _audit_ssh(host_ip: str, user: str, command: str, timeout: int = 10) -> tuple[bool, str]:
    """Run SSH command for audit purposes (bypasses dangerous pattern check)."""
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", 
             f"{user}@{host_ip}", command],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output.strip() if output.strip() else ""
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def register_audit_tool(mcp, hosts: dict, apis: dict, http_client):
    """Register the security_audit tool with the MCP server."""
    
    @mcp.tool()
    def security_audit(host: str = None) -> str:
        """
        Audit security posture and show what data is exposed.
        Run after setup to understand your attack surface.
        
        Args:
            host: Specific host to audit, or omit for all hosts
        """
        report = {"hosts": {}, "apis": {}, "issues": [], "summary": {}}
        
        hosts_to_check = {host: hosts[host]} if host and host in hosts else hosts
        
        for name, h in hosts_to_check.items():
            hr = {
                "ip": h["ip"], 
                "user": h["user"], 
                "reachable": False, 
                "shell": None, 
                "docker_group": False, 
                "containers": 0,
                "containers_with_env": [],
                "risk": "unknown"
            }
            
            # Reachability
            success, _ = _audit_ssh(h["ip"], h["user"], "echo ok", timeout=5)
            hr["reachable"] = success
            if not success:
                hr["risk"] = "⚪ unreachable"
                report["hosts"][name] = hr
                continue
            
            # Shell type
            success, output = _audit_ssh(h["ip"], h["user"], "echo $0", timeout=5)
            if success:
                hr["shell"] = output.split('\n')[0] if output else None
            
            # Docker group (CRITICAL CHECK)
            success, output = _audit_ssh(h["ip"], h["user"], "groups", timeout=5)
            if success:
                groups = output.lower().split()
                hr["docker_group"] = "docker" in groups
                if hr["docker_group"]:
                    report["issues"].append(
                        f"🔴 CRITICAL: {name} - user in docker group! "
                        f"Run: sudo gpasswd -d {h['user']} docker"
                    )
            
            # Container count
            success, output = _audit_ssh(h["ip"], h["user"], "sudo docker ps -q", timeout=10)
            if success:
                containers = [c for c in output.split('\n') if c.strip()]
                hr["containers"] = len(containers)
            
            # Check for containers with lots of env vars (potential secrets)
            success, output = _audit_ssh(h["ip"], h["user"], "sudo docker ps --format '{{.Names}}'", timeout=10)
            if success:
                container_names = [c.strip() for c in output.split('\n') if c.strip()]
                for cname in container_names[:15]:  # Limit to 15
                    env_success, env_output = _audit_ssh(
                        h["ip"], h["user"],
                        f"sudo docker inspect {cname} --format '{{{{len .Config.Env}}}}'",
                        timeout=5
                    )
                    if env_success and env_output:
                        try:
                            env_count = int(env_output.strip())
                            if env_count > 5:
                                hr["containers_with_env"].append({
                                    "name": cname,
                                    "env_vars": env_count
                                })
                        except ValueError:
                            pass
            
            # Check for world-readable .env files
            hr["readable_env_files"] = []
            env_success, env_output = _audit_ssh(
                h["ip"], h["user"],
                "find /home -name '.env' -readable -type f 2>/dev/null",
                timeout=10
            )
            if env_success and env_output.strip():
                readable = [f.strip() for f in env_output.strip().split('\n') if f.strip()]
                hr["readable_env_files"] = readable
                report["issues"].append(
                    f"🔴 CRITICAL: {name} - {len(readable)} .env file(s) readable by {h['user']}! "
                    f"Fix: chmod 600 on each file"
                )

            # Risk level
            if hr["docker_group"]:
                hr["risk"] = "🔴 CRITICAL"
            elif hr["readable_env_files"]:
                hr["risk"] = f"🔴 CRITICAL ({len(hr['readable_env_files'])} .env files exposed)"
            elif hr["containers_with_env"]:
                hr["risk"] = f"🟡 MEDIUM ({len(hr['containers_with_env'])} containers with env vars)"
            elif hr["shell"] and "rbash" in hr["shell"]:
                hr["risk"] = "🟢 LOW"
            else:
                hr["risk"] = "🟡 MEDIUM"
            
            report["hosts"][name] = hr
        
        # Check APIs
        for name, api in apis.items():
            ar = {"url": api["url"], "auth": api.get("auth", False), "reachable": False, "risk": "unknown"}
            try:
                resp = http_client.get(api["url"], timeout=3, verify=api.get("verify_ssl", True))
                ar["reachable"] = resp.status_code < 500
            except Exception:
                pass
            
            if ar["reachable"] and not ar["auth"]:
                ar["risk"] = "🟡 No auth"
                if "prometheus" in name.lower():
                    report["issues"].append(f"🟡 {name}: No auth - exposes host metrics, network topology")
            elif ar["reachable"]:
                ar["risk"] = "🟢 Auth configured"
            else:
                ar["risk"] = "⚪ Unreachable"
            
            report["apis"][name] = ar
        
        # Summary
        report["summary"] = {
            "hosts": len(report["hosts"]),
            "reachable": sum(1 for h in report["hosts"].values() if h["reachable"]),
            "critical": sum(1 for h in report["hosts"].values() if h.get("docker_group")),
            "containers_total": sum(h.get("containers", 0) for h in report["hosts"].values()),
            "containers_with_secrets": sum(len(h.get("containers_with_env", [])) for h in report["hosts"].values()),
            "readable_env_files": sum(len(h.get("readable_env_files", [])) for h in report["hosts"].values()),
            "unauth_apis": sum(1 for a in report["apis"].values() if "No auth" in a.get("risk", ""))
        }
        
        if not report["issues"]:
            report["issues"].append("✅ No critical issues found")
        
        return json.dumps(report, indent=2)