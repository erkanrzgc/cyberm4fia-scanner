#!/usr/bin/env bash
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
NC="\033[0m"

DATASET_REPO="https://github.com/pikpikcu/airecon-dataset.git"
CLONE_DIR="/tmp/airecon-dataset"

msg()  { echo -e "  ${CYAN}[*]${NC}  $*"; }
ok()   { echo -e "  ${GREEN}[OK]${NC}   $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC}  $*"; }
err()  { echo -e "  ${RED}[ERR]${NC} $*"; }

echo ""
echo -e "  ${BOLD}AIRecon Dataset Setup${NC}"
echo "  ========================"
echo ""

msg "Checking Python dependencies..."
python3 -c "import huggingface_hub" 2>/dev/null || {
    msg "Installing huggingface_hub..."
    pip install huggingface_hub
}
ok "huggingface_hub is available"

if python3 -c "import pyarrow" 2>/dev/null; then
    ok "pyarrow is available (parquet support)"
else
    warn "pyarrow not installed — parquet-based datasets will be skipped"
    warn "Install with: pip install pyarrow"
fi

echo ""

if [ -d "$CLONE_DIR" ]; then
    msg "airecon-dataset already cloned at $CLONE_DIR — pulling latest..."
    (cd "$CLONE_DIR" && git pull --ff-only) || warn "Pull failed — using existing clone"
else
    msg "Cloning airecon-dataset..."
    git clone --depth=1 "$DATASET_REPO" "$CLONE_DIR"
    ok "Cloned to $CLONE_DIR"
fi

echo ""

cd "$CLONE_DIR"

msg "Listing available datasets:"
python3 install.py --list

echo ""
msg "Installing all enabled datasets..."
echo ""
python3 install.py --all || {
    warn "Some datasets failed to install (run: python3 install.py installed to verify)"
}

echo ""
ok "AIRecon dataset installation complete."
msg "Databases stored in ~/.airecon/datasets/"
msg "Restart the scanner to activate dataset_search()."
echo ""
