#!/bin/bash
#
# Quick Packet Duplication Diagnostic Script
# 
# This script helps identify why tcpdump shows higher trap volumes
# than TrapNinja reports. Run as root.
#
# Usage: sudo ./quick_packet_diagnostic.sh [destination_ip]
#

set -e

DEST_IP="${1:-}"
DURATION=10
TRAP_PORT=162

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Quick Packet Duplication Diagnostic${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Get server's IP addresses
echo -e "${YELLOW}[1/6] Detecting local IP addresses...${NC}"
LOCAL_IPS=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | tr '\n' '|' | sed 's/|$//')
echo "Local IPs: ${LOCAL_IPS//|/, }"
echo ""

# Check if Samplicator is running
echo -e "${YELLOW}[2/6] Checking for Samplicator...${NC}"
if pgrep -a samplicator > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Samplicator is RUNNING:${NC}"
    pgrep -a samplicator
    
    # Try to find and show config
    for conf in /etc/samplicator.conf /etc/samplicate.conf /usr/local/etc/samplicator.conf; do
        if [ -f "$conf" ]; then
            echo ""
            echo -e "${YELLOW}Samplicator config ($conf):${NC}"
            grep -v '^#' "$conf" | grep -v '^$' | head -20
            
            # Count destinations
            DEST_COUNT=$(grep -v '^#' "$conf" | grep -v '^$' | wc -l)
            echo ""
            echo -e "${BLUE}Number of destinations configured: $DEST_COUNT${NC}"
            echo -e "${BLUE}Expected amplification: ${DEST_COUNT}x${NC}"
            break
        fi
    done
else
    echo "Samplicator is NOT running"
fi
echo ""

# Check what's listening on port 162
echo -e "${YELLOW}[3/6] Checking listeners on port $TRAP_PORT...${NC}"
ss -tulnp | grep -E ":$TRAP_PORT |:161 " || echo "No listeners found (or need root)"
echo ""

# Quick traffic sample - INGRESS only
echo -e "${YELLOW}[4/6] Sampling INGRESS traffic (${DURATION}s)...${NC}"
echo "Filter: Packets where SOURCE is NOT this server (incoming traps)"
INGRESS_COUNT=0
if [ -n "$DEST_IP" ]; then
    INGRESS_COUNT=$(timeout $DURATION tcpdump -i any -nn -c 5000 \
        "udp port $TRAP_PORT and not (src ${LOCAL_IPS//|/ or src })" 2>/dev/null | wc -l || echo "0")
else
    INGRESS_COUNT=$(timeout $DURATION tcpdump -i any -nn -c 5000 \
        "udp port $TRAP_PORT and not (src ${LOCAL_IPS//|/ or src })" 2>/dev/null | wc -l || echo "0")
fi
echo -e "Ingress packets in ${DURATION}s: ${GREEN}$INGRESS_COUNT${NC}"
INGRESS_RATE=$((INGRESS_COUNT / DURATION))
echo -e "Ingress rate: ${GREEN}~$INGRESS_RATE packets/sec${NC}"
echo ""

# Quick traffic sample - EGRESS only
echo -e "${YELLOW}[5/6] Sampling EGRESS traffic (${DURATION}s)...${NC}"
echo "Filter: Packets where SOURCE IS this server (forwarded traps)"
EGRESS_COUNT=0
if [ -n "$DEST_IP" ]; then
    EGRESS_COUNT=$(timeout $DURATION tcpdump -i any -nn -c 10000 \
        "udp port $TRAP_PORT and (src ${LOCAL_IPS//|/ or src }) and dst $DEST_IP" 2>/dev/null | wc -l || echo "0")
else
    EGRESS_COUNT=$(timeout $DURATION tcpdump -i any -nn -c 10000 \
        "udp port $TRAP_PORT and (src ${LOCAL_IPS//|/ or src })" 2>/dev/null | wc -l || echo "0")
fi
echo -e "Egress packets in ${DURATION}s: ${GREEN}$EGRESS_COUNT${NC}"
EGRESS_RATE=$((EGRESS_COUNT / DURATION))
echo -e "Egress rate: ${GREEN}~$EGRESS_RATE packets/sec${NC}"
echo ""

# Calculate amplification
echo -e "${YELLOW}[6/6] Analysis...${NC}"
echo ""
if [ "$INGRESS_COUNT" -gt 0 ]; then
    AMP_FACTOR=$(echo "scale=2; $EGRESS_COUNT / $INGRESS_COUNT" | bc)
    echo -e "Amplification factor: ${BLUE}${AMP_FACTOR}x${NC}"
    echo ""
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  DIAGNOSIS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Provide diagnosis
if [ "$INGRESS_COUNT" -gt 0 ] && [ "$EGRESS_COUNT" -gt "$INGRESS_COUNT" ]; then
    echo -e "${YELLOW}Finding: Packet amplification detected.${NC}"
    echo ""
    echo "This is NORMAL if you have multiple destinations configured."
    echo ""
    echo "What's happening:"
    echo "  - You receive ~$INGRESS_RATE traps/sec from the network"
    echo "  - These are forwarded to multiple destinations"
    echo "  - Total egress: ~$EGRESS_RATE packets/sec"
    echo ""
    echo "When you run 'tcpdump dst host X', you see:"
    echo "  - BOTH the incoming trap destined for forwarding"
    echo "  - AND the outgoing forwarded copy to that destination"
    echo ""
    echo -e "${GREEN}TrapNinja's rate of ~65/s likely matches the INGRESS rate,${NC}"
    echo -e "${GREEN}which is the actual unique trap volume.${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  RECOMMENDED TCPDUMP COMMANDS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "To see ONLY INCOMING traps (real volume):"
echo "  tcpdump -i any 'udp port 162 and not src $(hostname -I | awk '{print $1}')'"
echo ""
echo "To see traps going TO specific destination:"
echo "  tcpdump -i any 'udp port 162 and src $(hostname -I | awk '{print $1}') and dst 1.2.3.4'"
echo ""
echo "To count unique source IPs (where traps originate):"
echo "  tcpdump -i any -nn 'udp port 162' -c 1000 | awk '{print \$3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn"
echo ""
