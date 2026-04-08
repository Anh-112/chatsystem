#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  CryptoChat - install.sh
#  Cài đặt toàn bộ hệ thống: kernel module, C server, Python gateway
# ─────────────────────────────────────────────────────────────
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo -e "\n${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}   CryptoChat Installation Script       ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}\n"

# ── 1. System deps ──────────────────────────────────────────
info "Checking system dependencies..."
command -v gcc     >/dev/null || error "gcc not found. Run: sudo apt install gcc"
command -v make    >/dev/null || error "make not found. Run: sudo apt install make"
command -v python3 >/dev/null || error "python3 not found. Run: sudo apt install python3"
command -v pip3    >/dev/null || error "pip3 not found. Run: sudo apt install python3-pip"

# ── 2. Python packages ──────────────────────────────────────
info "Installing Python packages..."
pip3 install flask flask-socketio eventlet --break-system-packages -q \
  || pip3 install flask flask-socketio eventlet -q \
  || warn "pip install failed – try manually: pip3 install flask flask-socketio eventlet"

# ── 3. Build C server & client ──────────────────────────────
info "Building C chat server and client..."
cd "$ROOT/server"
make clean -s
make -s
info "  → Built: server/chat_server  server/chat_client"

# ── 4. Kernel module (optional) ─────────────────────────────
echo ""
warn "Kernel module build (optional, requires kernel headers):"
if dpkg -l linux-headers-$(uname -r) 2>/dev/null | grep -q '^ii'; then
    info "Kernel headers found, building module..."
    cd "$ROOT/kernel_module"
    make -s && info "  → Built: kernel_module/crypto_driver.ko" \
            || warn "  Kernel module build failed (non-fatal, fallback will be used)"
else
    warn "  linux-headers not installed."
    warn "  Install with: sudo apt install linux-headers-\$(uname -r)"
    warn "  Then run: cd kernel_module && make"
    warn "  Server will use pure-C fallback (same algorithms, no /dev/crypto_chat)"
fi

# ── 5. Summary ──────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}   Installation complete!                ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  To start the system:"
echo "    ./scripts/start.sh        (start everything)"
echo ""
echo "  To start manually:"
echo "    1. cd server && ./chat_server          # C server (port 9000)"
echo "    2. cd web   && python3 web_gateway.py  # Web bridge (port 5000)"
echo "    3. Open http://localhost:5000 in browser"
echo ""
echo "  Terminal client:"
echo "    cd server && ./chat_client             # connects to 127.0.0.1:9000"
echo ""
echo "  (Optional) Load kernel module:"
echo "    cd kernel_module"
echo "    sudo insmod crypto_driver.ko"
echo "    sudo chmod 666 /dev/crypto_chat"
echo ""
