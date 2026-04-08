#!/bin/bash
# start.sh – start C server + Python web gateway
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}[*] Starting CryptoChat...${NC}"

# ── Optional: load kernel module ────────────────────────────
if [ -f "$ROOT/kernel_module/crypto_driver.ko" ]; then
    if ! lsmod | grep -q crypto_driver; then
        echo -e "${YELLOW}[*] Loading kernel module...${NC}"
        sudo insmod "$ROOT/kernel_module/crypto_driver.ko" 2>/dev/null \
            && sudo chmod 666 /dev/crypto_chat 2>/dev/null \
            && echo -e "${GREEN}[✓] Kernel module loaded${NC}" \
            || echo -e "${YELLOW}[!] Kernel module load failed – using fallback${NC}"
    else
        echo -e "${GREEN}[✓] Kernel module already loaded${NC}"
    fi
fi

# ── Start C server ───────────────────────────────────────────
cd "$ROOT/server"
if pgrep -x chat_server > /dev/null; then
    echo -e "${YELLOW}[!] chat_server already running${NC}"
else
    ./chat_server > /tmp/chat_server.log 2>&1 &
    echo -e "${GREEN}[✓] C server started (port 9000, PID $!)${NC}"
    echo "    Log: /tmp/chat_server.log"
fi

sleep 0.5

# ── Start Python gateway ─────────────────────────────────────
cd "$ROOT/web"
if pgrep -f "web_gateway.py" > /dev/null; then
    echo -e "${YELLOW}[!] web_gateway already running${NC}"
else
    python3 web_gateway.py > /tmp/web_gateway.log 2>&1 &
    echo -e "${GREEN}[✓] Web gateway started (port 5000, PID $!)${NC}"
    echo "    Log: /tmp/web_gateway.log"
fi

sleep 1
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "  Web UI  : http://localhost:5000"
echo -e "  Terminal: cd server && ./chat_client"
echo -e "${GREEN}════════════════════════════════════════${NC}"
