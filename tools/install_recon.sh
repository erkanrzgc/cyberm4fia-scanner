#!/usr/bin/env bash
# install_recon.sh — opt-in installer for the Go-based recon binaries
# wrapped by utils/recon_tools.py.
#
# The scanner runs unchanged without these. Installing them unlocks
# additional sources for modules/subdomain_enum.py:
#   * subfinder    — ProjectDiscovery passive enumerator (dozens of upstreams)
#   * amass        — OWASP, deeper passive coverage
#   * assetfinder  — tomnomnom, lightweight passive
#   * puredns      — d3mondev resolver brute (paired with wordlists/)
#
# Usage:
#   tools/install_recon.sh                # install all four
#   tools/install_recon.sh subfinder      # install only the named tools

set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
    echo "[!] go not found in PATH — install Go ≥1.21 first." >&2
    echo "    Debian/Ubuntu: sudo apt install golang-go" >&2
    echo "    macOS:         brew install go" >&2
    exit 2
fi

declare -A TOOLS=(
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [amass]="github.com/owasp-amass/amass/v4/...@master"
    [assetfinder]="github.com/tomnomnom/assetfinder@latest"
    [puredns]="github.com/d3mondev/puredns/v2@latest"
)

# Default: install everything.
if [[ $# -eq 0 ]]; then
    set -- subfinder amass assetfinder puredns
fi

for name in "$@"; do
    pkg="${TOOLS[$name]:-}"
    if [[ -z "$pkg" ]]; then
        echo "[!] unknown tool: $name (known: ${!TOOLS[@]})" >&2
        continue
    fi
    if command -v "$name" >/dev/null 2>&1; then
        echo "[=] $name already installed at $(command -v "$name")"
        continue
    fi
    echo "[+] go install $pkg"
    go install -v "$pkg"
done

echo
echo "[+] done. Ensure \$(go env GOPATH)/bin is on your PATH:"
echo "    export PATH=\"\$PATH:\$(go env GOPATH)/bin\""
