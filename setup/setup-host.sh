#!/bin/bash
# setup-host.sh — Run on each Linux host you want to manage
# Usage: ./setup-host.sh 'ssh-ed25519 AAAA... your-key-comment'

set -e

USER="claude-ro"
MCP_PUBKEY="$1"

if [ -z "$MCP_PUBKEY" ]; then
    echo "Usage: ./setup-host.sh 'ssh-ed25519 AAAA...'"
    echo ""
    echo "Pass your MCP server's public key as argument."
    echo "Generate one with: ssh-keygen -t ed25519 -f ~/.ssh/homelab-mcp"
    exit 1
fi

echo "=== Setting up restricted user: $USER ==="

# Create restricted user (rbash = restricted bash)
if id "$USER" &>/dev/null; then
    echo "User $USER already exists"
else
    sudo useradd -m -s /bin/rbash "$USER"
    echo "Created user $USER"
fi

# Setup restricted PATH with only safe commands
echo "Setting up restricted PATH..."
sudo mkdir -p /home/claude-ro/bin

# Core commands
for cmd in df mount ls free uptime cat grep head tail wc; do
    if [ -f "/usr/bin/$cmd" ]; then
        sudo ln -sf "/usr/bin/$cmd" "/home/claude-ro/bin/" 2>/dev/null || true
    elif [ -f "/bin/$cmd" ]; then
        sudo ln -sf "/bin/$cmd" "/home/claude-ro/bin/" 2>/dev/null || true
    fi
done

# Docker (needed for docker ps, logs, etc via sudo)
[ -f "/usr/bin/docker" ] && sudo ln -sf "/usr/bin/docker" "/home/claude-ro/bin/"

# Sudo (required for NOPASSWD commands)
[ -f "/usr/bin/sudo" ] && sudo ln -sf "/usr/bin/sudo" "/home/claude-ro/bin/"

# UPS monitoring
[ -f "/usr/bin/upsc" ] && sudo ln -sf "/usr/bin/upsc" "/home/claude-ro/bin/"

# Add nvidia-smi if present (for GPU hosts)
[ -f "/usr/bin/nvidia-smi" ] && sudo ln -sf "/usr/bin/nvidia-smi" "/home/claude-ro/bin/"

# Lock PATH in .bashrc (hardcoded path, not variable)
echo 'export PATH=/home/claude-ro/bin' | sudo tee /home/claude-ro/.bashrc > /dev/null
sudo chmod 644 /home/claude-ro/.bashrc

# Setup SSH key authentication
echo "Configuring SSH..."
sudo mkdir -p /home/claude-ro/.ssh
echo "$MCP_PUBKEY" | sudo tee /home/claude-ro/.ssh/authorized_keys > /dev/null
sudo chmod 700 /home/claude-ro/.ssh
sudo chmod 600 /home/claude-ro/.ssh/authorized_keys
sudo chown -R claude-ro:claude-ro /home/claude-ro

# Setup sudoers for read-only commands
echo "Configuring sudoers..."
sudo tee /etc/sudoers.d/claude-ro > /dev/null << 'EOF'
# Homelab MCP - Read-only commands for claude-ro
# NO docker exec, NO docker run, NO docker restart
# NO file writes, NO service management

# Docker read-only (wildcard requires at least one arg)
claude-ro ALL=(ALL) NOPASSWD: /usr/bin/docker ps *
claude-ro ALL=(ALL) NOPASSWD: /usr/bin/docker logs *
claude-ro ALL=(ALL) NOPASSWD: /usr/bin/docker stats *
claude-ro ALL=(ALL) NOPASSWD: /usr/bin/docker inspect *

# System read-only (--no-pager prevents shell escape via less)
claude-ro ALL=(ALL) NOPASSWD: /usr/bin/journalctl --no-pager *
claude-ro ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
claude-ro ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active *
EOF
sudo chmod 440 /etc/sudoers.d/claude-ro

# CRITICAL: Verify user is NOT in docker group
echo ""
echo "=== Security Verification ==="
if groups claude-ro 2>/dev/null | grep -q '\bdocker\b'; then
    echo ""
    echo "⚠️  CRITICAL: claude-ro is in the docker group!"
    echo "   This bypasses ALL security restrictions."
    echo ""
    echo "   Remove with: sudo gpasswd -d claude-ro docker"
    echo ""
    exit 1
else
    echo "✓ User is NOT in docker group (good)"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Test with:"
echo "  ssh -i ~/.ssh/homelab-mcp claude-ro@$(hostname -I | awk '{print $1}') 'echo ok'"
echo ""
echo "Verify sudoers:"
echo "  ssh -i ~/.ssh/homelab-mcp claude-ro@localhost 'sudo docker ps -a'    # Should work"
echo "  ssh -i ~/.ssh/homelab-mcp claude-ro@localhost 'sudo docker run hello-world'  # Should FAIL"
