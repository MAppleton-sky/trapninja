#!/bin/bash
#
# snmp_trap_tracker.sh
# Track and compare incoming vs forwarded SNMP traps
#
# Usage: ./snmp_trap_tracker.sh -l <listen_ip> -f <forward_ip> [-i <interface>] [-d <duration>]
#

set -uo pipefail

# Default values
INTERFACE="any"
DURATION=0  # 0 = run indefinitely
SNMP_TRAP_PORTS="162"  # Can be comma-separated: "162,6667"
REFRESH_INTERVAL=5
DEBUG=0
BUFFER_SIZE=8192  # tcpdump buffer in KB (8MB default)

# Temp files
PCAP_FILE=""
TCPDUMP_STATS_FILE=""
STATS_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

usage() {
    cat << EOF
Usage: $(basename "$0") -l <listen_ip> -f <forward_ip> [OPTIONS]

Track and compare incoming vs forwarded SNMP traps.

Required:
  -l, --listen-ip     IP address where traps are received (server's IP)
  -f, --forward-ip    IP address where traps are forwarded to

Options:
  -i, --interface     Network interface to capture on (default: any)
  -d, --duration      Duration in seconds to capture (default: 0 = indefinite)
  -r, --refresh       Refresh interval for stats display (default: 5 seconds)
  -p, --port          SNMP trap port(s), comma-separated (default: 162)
                      Example: -p "162,6667" for multiple ports
  -b, --buffer        tcpdump buffer size in KB (default: 8192 = 8MB)
  -D, --debug         Enable debug mode (show raw tcpdump output)
  -h, --help          Show this help message

Examples:
  $(basename "$0") -l 192.168.1.10 -f 10.0.0.50
  $(basename "$0") -l 192.168.1.10 -f 10.0.0.50 -i eth0 -d 300
  $(basename "$0") -l 192.168.1.10 -f 10.0.0.50 -p "162,6667"
  $(basename "$0") -l 192.168.1.10 -f 10.0.0.50 -D

EOF
    exit 1
}

cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    
    # Kill tcpdump if running
    if [[ -n "${TCPDUMP_PID:-}" ]]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    
    # Final stats
    print_final_summary
    
    # Clean up temp files
    [[ -n "$PCAP_FILE" && -f "$PCAP_FILE" ]] && rm -f "$PCAP_FILE"
    [[ -n "$TCPDUMP_STATS_FILE" && -f "$TCPDUMP_STATS_FILE" ]] && rm -f "$TCPDUMP_STATS_FILE"
    [[ -n "$STATS_DIR" && -d "$STATS_DIR" ]] && rm -rf "$STATS_DIR"
    
    exit 0
}

check_dependencies() {
    local missing=()
    
    for cmd in tcpdump bc; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing required commands: ${missing[*]}${NC}"
        exit 1
    fi
    
    # Check for root/sudo for tcpdump
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script requires root privileges for packet capture.${NC}"
        echo -e "${YELLOW}Please run with sudo: sudo $0 $*${NC}"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--listen-ip)
                LISTEN_IP="$2"
                shift 2
                ;;
            -f|--forward-ip)
                FORWARD_IP="$2"
                shift 2
                ;;
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -r|--refresh)
                REFRESH_INTERVAL="$2"
                shift 2
                ;;
            -p|--port)
                SNMP_TRAP_PORTS="$2"
                shift 2
                ;;
            -b|--buffer)
                BUFFER_SIZE="$2"
                shift 2
                ;;
            -D|--debug)
                DEBUG=1
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                usage
                ;;
        esac
    done
    
    # Validate required args
    if [[ -z "${LISTEN_IP:-}" ]]; then
        echo -e "${RED}Error: Listen IP (-l) is required${NC}"
        usage
    fi
    
    if [[ -z "${FORWARD_IP:-}" ]]; then
        echo -e "${RED}Error: Forward IP (-f) is required${NC}"
        usage
    fi
}

print_header() {
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║           SNMP Trap Traffic Monitor                          ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo -e "  Listen IP (Incoming):   ${GREEN}$LISTEN_IP${NC}"
    echo -e "  Forward IP (Outgoing):  ${GREEN}$FORWARD_IP${NC}"
    echo -e "  Interface:              ${GREEN}$INTERFACE${NC}"
    echo -e "  SNMP Trap Port(s):      ${GREEN}$SNMP_TRAP_PORTS${NC}"
    echo -e "  Refresh Interval:       ${GREEN}${REFRESH_INTERVAL}s${NC}"
    echo -e "  Capture Buffer:         ${GREEN}${BUFFER_SIZE}KB${NC}"
    [[ $DURATION -gt 0 ]] && echo -e "  Duration:               ${GREEN}${DURATION}s${NC}"
    [[ $DEBUG -eq 1 ]] && echo -e "  Debug Mode:             ${YELLOW}ENABLED${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop and view final summary${NC}"
    echo ""
}

# Build port filter for BPF (e.g., "port 162 or port 6667")
build_bpf_port_filter() {
    local ports="$1"
    local filter=""
    
    # Split on comma and build filter
    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        port=$(echo "$port" | tr -d ' ')  # Trim whitespace
        if [[ -z "$filter" ]]; then
            filter="port $port"
        else
            filter="$filter or port $port"
        fi
    done
    
    echo "$filter"
}

# Build port regex for grep (e.g., "(162|6667|snmptrap)")
build_port_regex() {
    local ports="$1"
    local regex=""
    
    # Split on comma and build regex
    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        port=$(echo "$port" | tr -d ' ')  # Trim whitespace
        if [[ -z "$regex" ]]; then
            regex="$port"
        else
            regex="$regex|$port"
        fi
    done
    
    # Add snmptrap service name
    regex="$regex|snmptrap"
    
    echo "($regex)"
}

get_counts() {
    # Read the capture file and count packets
    # Using tcpdump to read the pcap and grep for destinations
    
    if [[ ! -f "$PCAP_FILE" ]] || [[ ! -s "$PCAP_FILE" ]]; then
        INCOMING_COUNT=0
        FORWARDED_COUNT=0
        return
    fi
    
    # Build port regex for matching (e.g., "(162|6667|snmptrap)")
    local port_regex
    port_regex=$(build_port_regex "$SNMP_TRAP_PORTS")
    
    # Count packets destined to listen IP (incoming traps)
    # tcpdump output format: "IP src.srcport > dst.dstport: UDP"
    # We look for "> LISTEN_IP.PORT:" pattern
    local in_count
    local fwd_count
    
    # Pattern matches configured ports or service name (snmptrap)
    in_count=$(tcpdump -n -r "$PCAP_FILE" 2>/dev/null | \
        grep -cE "> ${LISTEN_IP}\.${port_regex}:" 2>/dev/null) || in_count=0
    
    # Count packets destined to forward IP (forwarded traps)
    fwd_count=$(tcpdump -n -r "$PCAP_FILE" 2>/dev/null | \
        grep -cE "> ${FORWARD_IP}\.${port_regex}:" 2>/dev/null) || fwd_count=0
    
    # Sanitize - remove any whitespace/newlines and ensure numeric
    INCOMING_COUNT=${in_count//[^0-9]/}
    FORWARDED_COUNT=${fwd_count//[^0-9]/}
    
    # Default to 0 if empty
    INCOMING_COUNT=${INCOMING_COUNT:-0}
    FORWARDED_COUNT=${FORWARDED_COUNT:-0}
}

print_stats() {
    local elapsed=$(($(date +%s) - START_TIME))
    local hours=$((elapsed / 3600))
    local minutes=$(((elapsed % 3600) / 60))
    local seconds=$((elapsed % 60))
    
    # Calculate rates (per minute)
    local incoming_rate="0.00"
    local forwarded_rate="0.00"
    if [[ $elapsed -gt 0 ]]; then
        incoming_rate=$(echo "scale=2; $INCOMING_COUNT / ($elapsed / 60)" | bc 2>/dev/null || echo "0.00")
        forwarded_rate=$(echo "scale=2; $FORWARDED_COUNT / ($elapsed / 60)" | bc 2>/dev/null || echo "0.00")
    fi
    
    # Calculate difference
    local diff=$((INCOMING_COUNT - FORWARDED_COUNT))
    local diff_percent="0.0"
    if [[ $INCOMING_COUNT -gt 0 ]]; then
        diff_percent=$(echo "scale=1; ($diff * 100) / $INCOMING_COUNT" | bc 2>/dev/null || echo "0.0")
    fi
    
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    printf "${BOLD}%-30s %15s %15s${NC}\n" "Metric" "Incoming" "Forwarded"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    printf "%-30s ${GREEN}%15d${NC} ${BLUE}%15d${NC}\n" "Total Traps:" "$INCOMING_COUNT" "$FORWARDED_COUNT"
    printf "%-30s ${GREEN}%15s${NC} ${BLUE}%15s${NC}\n" "Rate (per min):" "$incoming_rate" "$forwarded_rate"
    echo -e "───────────────────────────────────────────────────────────────"
    
    if [[ $diff -gt 0 ]]; then
        printf "%-30s ${RED}%15d${NC} (${diff_percent}%% loss)\n" "Difference (In - Fwd):" "$diff"
    elif [[ $diff -lt 0 ]]; then
        printf "%-30s ${YELLOW}%15d${NC} (more forwarded?)\n" "Difference (In - Fwd):" "$diff"
    else
        printf "%-30s ${GREEN}%15d${NC} (no loss)\n" "Difference (In - Fwd):" "$diff"
    fi
    
    printf "%-30s %15s\n" "Elapsed Time:" "$(printf '%02d:%02d:%02d' $hours $minutes $seconds)"
    echo -e "═══════════════════════════════════════════════════════════════"
}

print_final_summary() {
    # Get final counts
    get_counts
    
    # Get tcpdump capture stats (packets dropped by kernel)
    local captured_count=0
    local received_count=0
    local dropped_count=0
    if [[ -n "$TCPDUMP_STATS_FILE" && -f "$TCPDUMP_STATS_FILE" ]]; then
        # Parse tcpdump stats output
        # Format: "X packets captured" "Y packets received by filter" "Z packets dropped by kernel"
        captured_count=$(grep -oP '\d+(?= packets captured)' "$TCPDUMP_STATS_FILE" 2>/dev/null || echo "0")
        received_count=$(grep -oP '\d+(?= packets received)' "$TCPDUMP_STATS_FILE" 2>/dev/null || echo "0")
        dropped_count=$(grep -oP '\d+(?= packets dropped)' "$TCPDUMP_STATS_FILE" 2>/dev/null || echo "0")
    fi
    
    local elapsed=$(($(date +%s) - START_TIME))
    local hours=$((elapsed / 3600))
    local minutes=$(((elapsed % 3600) / 60))
    local seconds=$((elapsed % 60))
    
    local incoming_rate="0.00"
    local forwarded_rate="0.00"
    if [[ $elapsed -gt 0 ]]; then
        incoming_rate=$(echo "scale=2; $INCOMING_COUNT / ($elapsed / 60)" | bc 2>/dev/null || echo "0.00")
        forwarded_rate=$(echo "scale=2; $FORWARDED_COUNT / ($elapsed / 60)" | bc 2>/dev/null || echo "0.00")
    fi
    
    local diff=$((INCOMING_COUNT - FORWARDED_COUNT))
    local diff_percent="0.00"
    local forward_percent="0.00"
    if [[ $INCOMING_COUNT -gt 0 ]]; then
        diff_percent=$(echo "scale=2; ($diff * 100) / $INCOMING_COUNT" | bc 2>/dev/null || echo "0.00")
        forward_percent=$(echo "scale=2; ($FORWARDED_COUNT * 100) / $INCOMING_COUNT" | bc 2>/dev/null || echo "0.00")
    fi
    
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║                    FINAL SUMMARY                             ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Duration:${NC} $(printf '%02d:%02d:%02d' $hours $minutes $seconds)"
    echo ""
    echo -e "${BOLD}Traffic Statistics:${NC}"
    echo -e "  Incoming Traps (to $LISTEN_IP):     ${GREEN}$INCOMING_COUNT${NC}"
    echo -e "  Forwarded Traps (to $FORWARD_IP):   ${BLUE}$FORWARDED_COUNT${NC}"
    echo ""
    echo -e "${BOLD}Rates (per minute):${NC}"
    echo -e "  Incoming:   ${GREEN}$incoming_rate${NC}"
    echo -e "  Forwarded:  ${BLUE}$forwarded_rate${NC}"
    echo ""
    echo -e "${BOLD}Comparison:${NC}"
    echo -e "  Difference:        $diff traps"
    echo -e "  Forward Rate:      ${forward_percent}%"
    
    if [[ $diff -gt 0 ]]; then
        echo -e "  ${RED}Loss Rate:          ${diff_percent}%${NC}"
    elif [[ $diff -eq 0 ]]; then
        echo -e "  ${GREEN}No trap loss detected${NC}"
    else
        echo -e "  ${YELLOW}Note: More forwarded than received (possible duplicates or other sources)${NC}"
    fi
    echo ""
    
    # Show capture health
    echo -e "${BOLD}Capture Health:${NC}"
    if [[ ${dropped_count:-0} -gt 0 ]]; then
        local drop_percent=$(echo "scale=2; ($dropped_count * 100) / ($captured_count + $dropped_count)" | bc 2>/dev/null || echo "?")
        echo -e "  ${RED}WARNING: tcpdump dropped $dropped_count packets (${drop_percent}%)${NC}"
        echo -e "  ${YELLOW}Consider increasing buffer size with -b option${NC}"
    else
        echo -e "  ${GREEN}No packets dropped by capture${NC}"
    fi
    echo ""
}

debug_output() {
    echo -e "\n${YELLOW}=== DEBUG: Recent tcpdump output ===${NC}"
    tcpdump -n -r "$PCAP_FILE" 2>/dev/null | tail -20
    echo -e "${YELLOW}=== END DEBUG ===${NC}\n"
}

start_capture() {
    # Create temp files
    PCAP_FILE=$(mktemp --suffix=.pcap)
    TCPDUMP_STATS_FILE=$(mktemp --suffix=.tcpdump_stats)
    
    # Build BPF port filter (e.g., "port 162 or port 6667")
    local port_filter
    port_filter=$(build_bpf_port_filter "$SNMP_TRAP_PORTS")
    
    # Build tcpdump filter - capture all UDP traffic to configured ports
    # going to either the listen IP or forward IP
    local FILTER="udp and ($port_filter) and (dst host $LISTEN_IP or dst host $FORWARD_IP)"
    
    echo -e "${BLUE}Starting packet capture...${NC}"
    echo -e "${BLUE}Filter: ${FILTER}${NC}"
    echo ""
    
    # Start tcpdump writing to pcap file
    # -U flag forces packet-buffered output so file is readable while capturing
    # -B sets buffer size in KB to prevent kernel drops during high-volume capture
    # stderr is captured to get drop statistics at the end
    tcpdump -n -U -B "$BUFFER_SIZE" -i "$INTERFACE" -w "$PCAP_FILE" "$FILTER" 2>"$TCPDUMP_STATS_FILE" &
    TCPDUMP_PID=$!
    
    # Give tcpdump a moment to start
    sleep 1
    
    # Check if tcpdump is still running
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        echo -e "${RED}Error: tcpdump failed to start. Check interface name and permissions.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Capture started (PID: $TCPDUMP_PID)${NC}"
    echo ""
    
    START_TIME=$(date +%s)
    
    # Stats update loop
    while true; do
        # Get current counts from pcap
        get_counts
        
        # Clear screen and show stats
        clear
        print_header
        print_stats
        
        if [[ $DEBUG -eq 1 ]]; then
            debug_output
        fi
        
        # Check if duration exceeded
        if [[ $DURATION -gt 0 ]]; then
            local elapsed=$(($(date +%s) - START_TIME))
            if [[ $elapsed -ge $DURATION ]]; then
                echo -e "\n${YELLOW}Duration reached. Stopping capture...${NC}"
                cleanup
            fi
        fi
        
        sleep "$REFRESH_INTERVAL"
    done
}

# Main execution
trap cleanup SIGINT SIGTERM

parse_args "$@"
check_dependencies
print_header

start_capture
