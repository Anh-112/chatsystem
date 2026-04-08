#!/bin/bash
# stop.sh – stop all CryptoChat services
GREEN='\033[0;32m'; NC='\033[0m'

pkill -x chat_server   2>/dev/null && echo -e "${GREEN}[✓] chat_server stopped${NC}"   || echo "[i] chat_server not running"
pkill -f web_gateway.py 2>/dev/null && echo -e "${GREEN}[✓] web_gateway stopped${NC}" || echo "[i] web_gateway not running"

if lsmod | grep -q crypto_driver; then
    sudo rmmod crypto_driver 2>/dev/null && echo -e "${GREEN}[✓] kernel module unloaded${NC}"
fi
