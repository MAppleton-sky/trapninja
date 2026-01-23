#!/bin/bash
#
# Spoofed Traffic Diagnostic Script
# 
# When source IP spoofing is enabled (Samplicator -S flag), you cannot
# distinguish ingress from egress by source IP alone. This script uses
# alternative methods to diagnose packet duplication.
#
# Usage: sudo ./spoofed_traffic_diagnostic.sh [interface]
#

set -e

INTERFACE="${1:-eth0}"
DURATION=10
TRAP_PORT=162

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Spoofed Traffic Diagnostic${NC}"
echo -e "${BLUE}  (For use when source IP spoofing is enabled)${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Detect spoofing configuration
echo -e "${YELLOW}[1/8] Detecting spoofing configuration...${NC}"

SPOOFING_DETECTED=false

# Check Samplicator for spoofing
if pgrep -a samplicator > /dev/null 2>&1; then
    SAMPLICATOR_CMD=$(pgrep -a samplicator)
    if echo "$SAMPLICATOR_CMD" | grep -q '\-S'; then
        echo -e "${RED}⚠ Samplicator running with -S flag (IP SPOOFING ENABLED)${NC}"
        SPOOFING_DETECTED=true
    fi
    
    # Check config file for spoof directive
    for conf in /etc/samplicator.conf /etc/samplicate.conf /usr/local/etc/samplicator.conf; do
        if [ -f "$conf" ]; then
            if grep -qi 'spoof' "$conf"; then
                echo -e "${RED}⚠ Samplicator config contains 'spoof' directive${NC}"
                SPOOFING_DETECTED=true
            fi
        fi
    done
fi

# Check TrapNinja for spoofing
for conf in /etc/trapninja/config.json /opt/trapninja/config.json ./config.json; do
    if [ -f "$conf" ]; then
        if grep -qi '"spoof".*true\|"preserve_source".*true' "$conf"; then
            echo -e "${RED}⚠ TrapNinja config has spoofing enabled${NC}"
            SPOOFING_DETECTED=true
        fi
    fi
done

if [ "$SPOOFING_DETECTED" = false ]; then
    echo -e "${GREEN}No spoofing detected in common configurations.${NC}"
    echo "If you're using custom spoofing, proceed anyway."
fi
echo ""

# List available interfaces
echo -e "${YELLOW}[2/8] Available interfaces...${NC}"
ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | tr -d ':'
echo ""
echo "Using interface: $INTERFACE"
echo "(Run with different interface if needed: $0 eth1)"
echo ""

# Method 1: Interface-specific capture (if multiple interfaces)
echo -e "${YELLOW}[3/8] Method 1: Interface-specific capture...${NC}"
echo ""
echo "With spoofed traffic, capture on SPECIFIC interfaces rather than -i any."
echo "This helps separate traffic if ingress and egress use different interfaces."
echo ""

# Get interface details
echo "Interface $INTERFACE details:"
ip addr show "$INTERFACE" 2>/dev/null | head -5 || echo "Interface not found"
echo ""

# Method 2: TTL-based analysis
echo -e "${YELLOW}[4/8] Method 2: TTL Analysis (${DURATION}s capture)...${NC}"
echo ""
echo "Capturing packets to analyze TTL values..."
echo "Forwarded packets typically have TTL decremented."
echo ""

# Capture with TTL info
TMPFILE=$(mktemp)
timeout $DURATION tcpdump -i "$INTERFACE" -nn -v "udp port $TRAP_PORT" 2>/dev/null > "$TMPFILE" || true

if [ -s "$TMPFILE" ]; then
    echo "TTL distribution in captured packets:"
    grep -oP 'ttl \K[0-9]+' "$TMPFILE" | sort | uniq -c | sort -rn | head -10
    echo ""
    
    TOTAL_PACKETS=$(wc -l < "$TMPFILE")
    echo "Total packets captured: $TOTAL_PACKETS"
    
    # Common TTL values:
    # 64 - Linux default
    # 128 - Windows default
    # 255 - Network equipment
    # If you see pairs like 64 and 63, the 63 is likely forwarded
    
    TTL_64=$(grep -c 'ttl 64' "$TMPFILE" 2>/dev/null || echo "0")
    TTL_63=$(grep -c 'ttl 63' "$TMPFILE" 2>/dev/null || echo "0")
    TTL_128=$(grep -c 'ttl 128' "$TMPFILE" 2>/dev/null || echo "0")
    TTL_127=$(grep -c 'ttl 127' "$TMPFILE" 2>/dev/null || echo "0")
    
    echo ""
    echo "Analysis:"
    if [ "$TTL_63" -gt 0 ] && [ "$TTL_64" -gt 0 ]; then
        echo -e "${CYAN}  TTL 64: $TTL_64 (likely original packets)${NC}"
        echo -e "${CYAN}  TTL 63: $TTL_63 (likely forwarded - TTL decremented)${NC}"
    fi
    if [ "$TTL_127" -gt 0 ] && [ "$TTL_128" -gt 0 ]; then
        echo -e "${CYAN}  TTL 128: $TTL_128 (likely original packets)${NC}"
        echo -e "${CYAN}  TTL 127: $TTL_127 (likely forwarded - TTL decremented)${NC}"
    fi
else
    echo "No packets captured on $INTERFACE"
fi
rm -f "$TMPFILE"
echo ""

# Method 3: Source port analysis
echo -e "${YELLOW}[5/8] Method 3: Source Port Analysis (${DURATION}s)...${NC}"
echo ""
echo "Analyzing source ports - forwarders often use different ports..."

TMPFILE2=$(mktemp)
timeout $DURATION tcpdump -i "$INTERFACE" -nn "udp port $TRAP_PORT" 2>/dev/null > "$TMPFILE2" || true

if [ -s "$TMPFILE2" ]; then
    echo "Top source ports:"
    awk '{print $3}' "$TMPFILE2" | grep -oP '\.\K[0-9]+$' | sort | uniq -c | sort -rn | head -10
    echo ""
    
    # Check for well-known trap source ports
    PORT_162=$(grep -c '\.162:' "$TMPFILE2" 2>/dev/null || echo "0")
    PORT_HIGH=$(grep -cE '\.[0-9]{4,5}:' "$TMPFILE2" 2>/dev/null || echo "0")
    
    echo "Source port 162 (device traps): $PORT_162"
    echo "High ports (forwarder/agent): $PORT_HIGH"
fi
rm -f "$TMPFILE2"
echo ""

# Method 4: Packet content hashing for duplicates
echo -e "${YELLOW}[6/8] Method 4: Duplicate Detection (${DURATION}s)...${NC}"
echo ""
echo "Capturing packets and checking for content duplicates..."
echo "(Duplicate content with different timestamps = forwarding)"

TMPFILE3=$(mktemp)
timeout $DURATION tcpdump -i "$INTERFACE" -xx -nn "udp port $TRAP_PORT" 2>/dev/null > "$TMPFILE3" || true

if [ -s "$TMPFILE3" ]; then
    # Extract packet hex data and count duplicates
    TOTAL=$(grep -c '^[0-9]' "$TMPFILE3" 2>/dev/null || echo "0")
    
    # This is a simplified check - in production you'd want proper packet parsing
    echo "Packets captured: $TOTAL"
    echo ""
    echo "Checking for near-duplicate packets (same content, different timestamps)..."
    
    # Count unique vs total based on payload similarity
    # Look for packets within milliseconds of each other with same size
    grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}' "$TMPFILE3" | \
        awk '{print $1, $(NF-1)}' | \
        sort | uniq -c | sort -rn | head -5
fi
rm -f "$TMPFILE3"
echo ""

# Method 5: iptables/nftables marking (requires setup)
echo -e "${YELLOW}[7/8] Method 5: Firewall-based tracking (info only)...${NC}"
echo ""
echo "For precise tracking with spoofed traffic, use iptables to mark packets"
echo "at different points in the network stack:"
echo ""
echo -e "${CYAN}# Mark incoming packets in PREROUTING (before local processing):${NC}"
echo "  iptables -t mangle -A PREROUTING -p udp --dport 162 -j MARK --set-mark 1"
echo ""
echo -e "${CYAN}# Mark outgoing packets in POSTROUTING (after forwarding):${NC}"
echo "  iptables -t mangle -A POSTROUTING -p udp --dport 162 -j MARK --set-mark 2"
echo ""
echo -e "${CYAN}# Then use nflog to capture marked packets separately:${NC}"
echo "  iptables -t mangle -A PREROUTING -p udp --dport 162 -j NFLOG --nflog-group 1"
echo "  iptables -t mangle -A POSTROUTING -p udp --dport 162 -j NFLOG --nflog-group 2"
echo ""
echo -e "${CYAN}# Capture with tcpdump on nflog interfaces:${NC}"
echo "  tcpdump -i nflog:1 -nn  # Ingress only"
echo "  tcpdump -i nflog:2 -nn  # Egress only"
echo ""

# Method 6: conntrack (if available)
echo -e "${YELLOW}[8/8] Method 6: Connection tracking...${NC}"
echo ""

if command -v conntrack &> /dev/null; then
    echo "Active UDP connections on port 162:"
    conntrack -L -p udp --dport 162 2>/dev/null | head -10 || echo "No connections or need root"
else
    echo "conntrack not installed. Install with: yum install conntrack-tools"
fi
echo ""

# Summary
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  SUMMARY: Diagnosing Spoofed Traffic${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo "When source IP spoofing is enabled, use these methods to distinguish"
echo "ingress from egress traffic:"
echo ""
echo -e "${GREEN}1. TTL Analysis${NC} - Forwarded packets have TTL-1"
echo "   Look for pairs like 64/63 or 128/127"
echo ""
echo -e "${GREEN}2. Source Port${NC} - Original traps often from port 162"
echo "   Forwarded traps may use high ephemeral ports"
echo ""
echo -e "${GREEN}3. Interface Separation${NC} - Capture on specific interfaces"
echo "   If ingress/egress use different NICs"
echo ""
echo -e "${GREEN}4. iptables Marking${NC} - Most reliable method"
echo "   Mark packets in PREROUTING vs POSTROUTING"
echo ""
echo -e "${GREEN}5. Timestamp Analysis${NC} - Duplicate content within ms"
echo "   Same trap, slightly different timestamps = forwarding"
echo ""
echo ""
echo -e "${YELLOW}Quick Test Commands:${NC}"
echo ""
echo "# See TTL distribution:"
echo "tcpdump -i $INTERFACE -v 'udp port 162' 2>/dev/null | grep -oP 'ttl \\K[0-9]+' | sort | uniq -c"
echo ""
echo "# Check source ports:"
echo "tcpdump -i $INTERFACE -nn 'udp port 162' | awk '{print \$3}' | grep -oP '\\.[0-9]+\$' | sort | uniq -c"
echo ""
