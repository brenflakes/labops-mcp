#!/bin/bash
# setup-mcp.sh — Run on the host where MCP server will run
# Generates SSH keypair and prepares environment

set -e

SSH_DIR="$HOME/.ssh"
KEY_NAME="homelab-mcp"
KEY_PATH="$SSH_DIR/$KEY_NAME"

echo "=== Setting up MCP server environment ==="

# Create SSH directory if needed
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# Generate dedicated SSH keypair for MCP
if [ ! -f "$KEY_PATH" ]; then
    echo "Generating SSH keypair: $KEY_PATH"
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "homelab-mcp"
else
    echo "SSH keypair already exists: $KEY_PATH"
fi

# Create SSH socket directory for ControlMaster
mkdir -p "$SSH_DIR/sockets"
chmod 700 "$SSH_DIR/sockets"

# Create/update SSH config for ControlMaster
mkdir -p "$SSH_DIR/config.d"
cat > "$SSH_DIR/config.d/homelab-mcp" << 'EOF'
# Homelab MCP SSH config
# Connection multiplexing for faster sequential commands

Host *
    IdentityFile ~/.ssh/homelab-mcp
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
    StrictHostKeyChecking accept-new
    ConnectTimeout 5
EOF

# Ensure config.d is included in main config
if [ ! -f "$SSH_DIR/config" ] || ! grep -q "Include config.d" "$SSH_DIR/config" 2>/dev/null; then
    echo "Include config.d/*" >> "$SSH_DIR/config"
fi

# Create .env.example if it doesn't exist
if [ ! -f ".env.example" ]; then
    cat > .env.example << 'EOF'
# Copy to .env and fill in your values
# These are loaded by docker-compose

# Home Assistant long-lived access token
# Generate at: HA → Profile → Security → Long-lived access tokens
HA_TOKEN=

# Proxmox API token
# Format: user@realm!tokenid=secret
PROXMOX_TOKEN=

# Add other API tokens as needed
EOF
    echo "Created .env.example"
fi

# Create empty .env if it doesn't exist
if [ ! -f ".env" ]; then
    touch .env
    echo "Created empty .env (add tokens as needed)"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Your public key (use this with setup-host.sh on each target):"
echo ""
cat "$KEY_PATH.pub"
echo ""
echo "Next steps:"
echo "  1. Run setup-host.sh on each Linux host with the public key above"
echo "  2. Edit config/inventory.yml with your hosts/APIs"
echo "  3. Add tokens to .env if using authenticated APIs"
echo "  4. docker-compose up -d"
