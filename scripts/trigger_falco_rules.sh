#!/bin/bash
# =============================================================================
# Falco Rule Trigger Script
# Author: Mukesh Kumar
# Purpose: Deliberately trigger all 3 custom Falco detection rules
# Deployment: Docker-based Falco (falcosecurity/falco:0.43.0)
#
# PRE-REQUISITES before running this script:
#   Terminal 1: Falco Docker container must be running
#   Terminal 2: Run this script
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check vulnerable-nginx is running
CONTAINER_ID=$(docker ps --filter "name=vulnerable-nginx" --format "{{.ID}}" | head -1)

if [ -z "$CONTAINER_ID" ]; then
  echo -e "${RED}[!] Container 'vulnerable-nginx' not found. Start it first:${NC}"
  echo "    docker run -d --name vulnerable-nginx nginx:1.21.0"
  exit 1
fi

echo -e "${GREEN}[+] Found container: $CONTAINER_ID${NC}"
echo ""

# -----------------------------------------------------------------------
# TRIGGER 1: Shell Spawned in Container
# Rule: Shell Spawned in Container
# MITRE: T1059.004
# -----------------------------------------------------------------------
echo "======================================================="
echo " TRIGGER 1: Shell Spawned in Container"
echo " Rule: Shell Spawned in Container"
echo " MITRE: T1059.004"
echo "======================================================="
docker exec vulnerable-nginx bash -c "id && whoami"
sleep 3
echo -e "${GREEN}[+] Trigger 1 fired. Check Falco terminal for WARNING.${NC}"
echo ""

# -----------------------------------------------------------------------
# TRIGGER 2: Sensitive File Read
# Rule: Sensitive File Read in Container
# MITRE: T1552.001
# -----------------------------------------------------------------------
echo "======================================================="
echo " TRIGGER 2: Sensitive File Read in Container"
echo " Rule: Sensitive File Read in Container"
echo " MITRE: T1552.001"
echo "======================================================="
docker exec vulnerable-nginx cat /etc/shadow || true
sleep 3
echo -e "${GREEN}[+] Trigger 2 fired. Check Falco terminal for CRITICAL.${NC}"
echo ""

# -----------------------------------------------------------------------
# TRIGGER 3: Outbound Network Connection
# Rule: Unexpected Outbound Connection from Container
# MITRE: T1071.001 / T1048
# Using IP directly to avoid DNS masking the connection event
# -----------------------------------------------------------------------
echo "======================================================="
echo " TRIGGER 3: Outbound Connection from Container"
echo " Rule: Unexpected Outbound Connection from Container"
echo " MITRE: T1071.001 / T1048"
echo "======================================================="
docker exec vulnerable-nginx bash -c "curl -s --max-time 5 http://93.184.216.34 || true"
sleep 3
echo -e "${GREEN}[+] Trigger 3 fired. Check Falco terminal for WARNING.${NC}"
echo ""

echo "======================================================="
echo " All 3 triggers complete."
echo " Go to Terminal 1 to see Falco alerts."
echo " Then run: docker logs falco 2>&1 | grep -E 'WARNING|CRITICAL'"
echo "           > ~/trivy-falco-project/trivy-scans/falco_alerts.txt"
echo "======================================================="
