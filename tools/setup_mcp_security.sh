#!/bin/bash
# ============================================================
# cyberm4fia-scanner — Security MCP Servers Setup
# Clones and builds cyproxio/mcp-for-security MCP servers
# ============================================================

set -e

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$TOOLS_DIR/mcp-for-security"
NPM_BIN="/home/erkanrzgc/.nvm/versions/node/v22.22.1/bin/npm"
NODE_BIN="/home/erkanrzgc/.nvm/versions/node/v22.22.1/bin/node"

# MCP servers we want to install
SERVERS=(
    "nuclei-mcp"
    "nmap-mcp"
    "sqlmap-mcp"
    "katana-mcp"
    "ffuf-mcp"
    "httpx-mcp"
    "waybackurls-mcp"
    "arjun-mcp"
    "sslscan-mcp"
    "smuggler-mcp"
)

echo "══════════════════════════════════════════════"
echo "  🛡️  cyberm4fia Security MCP Setup"
echo "══════════════════════════════════════════════"

# Step 1: Clone repo if not present
if [ ! -d "$REPO_DIR" ]; then
    echo "[*] Cloning cyproxio/mcp-for-security..."
    git clone https://github.com/cyproxio/mcp-for-security.git "$REPO_DIR"
else
    echo "[*] Repo already cloned, pulling latest..."
    cd "$REPO_DIR" && git pull origin main
fi

# Step 2: Install & build each MCP server
for server in "${SERVERS[@]}"; do
    SERVER_DIR="$REPO_DIR/$server"
    if [ -d "$SERVER_DIR" ]; then
        echo ""
        echo "[*] Setting up $server..."
        cd "$SERVER_DIR"
        
        if [ -f "package.json" ]; then
            echo "    Installing dependencies..."
            "$NPM_BIN" install --silent 2>/dev/null || "$NPM_BIN" install
            
            if grep -q '"build"' package.json; then
                echo "    Building..."
                "$NPM_BIN" run build 2>/dev/null || true
            fi
            
            if [ -f "build/index.js" ]; then
                echo "    ✅ $server ready!"
            else
                echo "    ⚠️  $server build/index.js not found, may need manual setup"
            fi
        else
            echo "    ⚠️  No package.json found for $server"
        fi
    else
        echo "    ❌ $server directory not found"
    fi
done

echo ""
echo "══════════════════════════════════════════════"
echo "  ✅ Setup complete!"
echo ""
echo "  Now update your mcp_config.json to add the"
echo "  security MCP servers. See README for details."
echo "══════════════════════════════════════════════"
