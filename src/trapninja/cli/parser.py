#!/usr/bin/env python3
"""
TrapNinja Argument Parser Module

Sets up comprehensive command-line argument parsing with validation.
UPDATED: Added new HA manual control commands (--promote, --demote, --ha-help)
"""

import argparse
from .validation import InputValidator


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser with all TrapNinja commands

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="TrapNinja - SNMP Trap Forwarder with HA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start the daemon
  python trapninja.py --start
  
  # Configure High Availability
  python trapninja.py --configure-ha --ha-mode primary --ha-peer-host 192.168.1.101
  
  # Manual HA control
  python trapninja.py --promote          # Promote to PRIMARY
  python trapninja.py --demote           # Demote to SECONDARY
  python trapninja.py --ha-help          # Show comprehensive HA help
  
  # Block an IP address
  python trapninja.py --block-ip 10.0.1.50
  
  # Run in foreground with debug logging
  python trapninja.py --foreground --debug
        """
    )

    # Validation type converters
    def validated_ip(value):
        result = InputValidator.validate_ip(value)
        if result is None:
            raise argparse.ArgumentTypeError(f"Invalid IP address: {value}")
        return result

    def validated_oid(value):
        result = InputValidator.validate_oid(value)
        if result is None:
            raise argparse.ArgumentTypeError(f"Invalid OID: {value}")
        return result

    def validated_tag(value):
        result = InputValidator.validate_tag(value)
        if result is None:
            raise argparse.ArgumentTypeError(f"Invalid tag: {value}")
        return result

    def validated_port(value):
        result = InputValidator.validate_port(value)
        if result is None:
            raise argparse.ArgumentTypeError(f"Invalid port: {value}")
        return result

    # Command group for daemon control and basic operations
    group = parser.add_mutually_exclusive_group(required=True)
    
    # Daemon control commands
    group.add_argument('--start', action='store_true', 
                      help='Start the daemon')
    group.add_argument('--stop', action='store_true', 
                      help='Stop the daemon')
    group.add_argument('--restart', action='store_true', 
                      help='Restart the daemon')
    group.add_argument('--status', action='store_true', 
                      help='Check daemon status')
    group.add_argument('--foreground', action='store_true', 
                      help='Run in foreground (not as daemon)')

    # HA configuration commands
    group.add_argument('--configure-ha', action='store_true', 
                      help='Configure High Availability')
    group.add_argument('--disable-ha', action='store_true', 
                      help='Disable High Availability')
    group.add_argument('--ha-status', action='store_true', 
                      help='Show HA status')
    
    # HA manual control commands (NEW)
    group.add_argument('--promote', action='store_true',
                      help='Manually promote this instance to PRIMARY')
    group.add_argument('--demote', action='store_true',
                      help='Manually demote this instance to SECONDARY')
    group.add_argument('--force-failover', action='store_true', 
                      help='Force failover (maintenance)')
    group.add_argument('--ha-help', action='store_true',
                      help='Show comprehensive HA help and usage examples')
    
    # HA config sync commands
    group.add_argument('--sync-status', action='store_true',
                      help='Show configuration synchronization status')
    group.add_argument('--sync-diff', action='store_true',
                      help='Show differences between local and peer configs')
    group.add_argument('--sync-push', action='store_true',
                      help='Push config(s) to peer (PRIMARY only)')
    group.add_argument('--sync-pull', action='store_true',
                      help='Pull config(s) from peer (SECONDARY)')
    group.add_argument('--enable-sync', action='store_true',
                      help='Enable configuration synchronization')
    group.add_argument('--disable-sync', action='store_true',
                      help='Disable configuration synchronization')
    group.add_argument('--configure-sync', action='store_true',
                      help='Configure sync settings')
    group.add_argument('--sync-help', action='store_true',
                      help='Show comprehensive config sync help')

    # HA configuration parameters
    parser.add_argument('--ha-mode', choices=['primary', 'secondary'],
                       help='HA mode: primary or secondary')
    parser.add_argument('--ha-peer-host', type=validated_ip,
                       help='IP address of HA peer')
    parser.add_argument('--ha-peer-port', type=validated_port, default=8162,
                       help='Port to connect to HA peer (default: 8162)')
    parser.add_argument('--ha-listen-port', type=validated_port, default=8162,
                       help='Port to listen for HA peer connections (default: 8162)')
    parser.add_argument('--ha-priority', type=int, default=100,
                       help='HA priority (1-1000, higher = preferred primary, default: 100)')
    
    # HA control parameter (NEW)
    parser.add_argument('--force', action='store_true',
                       help='Force promotion without peer coordination (use with --promote)')

    # IP filtering commands with validation
    group.add_argument('--block-ip', type=validated_ip, metavar='IP',
                      help='Add an IP address to the blocked list')
    group.add_argument('--unblock-ip', type=validated_ip, metavar='IP',
                      help='Remove an IP address from the blocked list')
    group.add_argument('--list-blocked-ips', action='store_true',
                      help='List all blocked IP addresses')

    # OID filtering commands with validation
    group.add_argument('--block-oid', type=validated_oid, metavar='OID',
                      help='Add an OID to the blocked traps list')
    group.add_argument('--unblock-oid', type=validated_oid, metavar='OID',
                      help='Remove an OID from the blocked traps list')
    group.add_argument('--list-blocked-oids', action='store_true',
                      help='List all blocked trap OIDs')

    # SNMPv3 commands
    group.add_argument('--snmpv3-add-user', action='store_true',
                      help='Add SNMPv3 user credentials')
    group.add_argument('--snmpv3-remove-user', action='store_true',
                      help='Remove SNMPv3 user credentials')
    group.add_argument('--snmpv3-list-users', action='store_true',
                      help='List SNMPv3 users')
    group.add_argument('--snmpv3-show-user', action='store_true',
                      help='Show detailed SNMPv3 user information')
    group.add_argument('--snmpv3-status', action='store_true',
                      help='Show SNMPv3 subsystem status')
    group.add_argument('--snmpv3-test-decrypt', action='store_true',
                      help='Test SNMPv3 decryption with a sample trap')

    # Cache commands
    group.add_argument('--cache-status', action='store_true',
                      help='Show cache status and statistics')
    group.add_argument('--cache-query', action='store_true',
                      help='Query cached traps for a time window')
    group.add_argument('--cache-replay', action='store_true',
                      help='Replay cached traps for a time window')
    group.add_argument('--cache-clear', action='store_true',
                      help='Clear cached entries')
    group.add_argument('--cache-trim', action='store_true',
                      help='Manually trigger retention trim')
    group.add_argument('--cache-help', action='store_true',
                      help='Show comprehensive cache help')

    # Granular statistics commands
    group.add_argument('--stats-summary', action='store_true',
                      help='Show granular statistics summary')
    group.add_argument('--stats-top-ips', action='store_true',
                      help='Show top source IPs by volume/rate')
    group.add_argument('--stats-top-oids', action='store_true',
                      help='Show top OIDs by volume/rate')
    group.add_argument('--stats-ip', action='store_true',
                      help='Show details for specific IP (use --ip)')
    group.add_argument('--stats-oid', action='store_true',
                      help='Show details for specific OID (use --oid)')
    group.add_argument('--stats-destinations', action='store_true',
                      help='Show destination statistics')
    group.add_argument('--stats-dashboard', action='store_true',
                      help='Export full dashboard data as JSON')
    group.add_argument('--stats-export', action='store_true',
                      help='Export statistics to file')
    group.add_argument('--stats-reset', action='store_true',
                      help='Reset all granular statistics')
    group.add_argument('--stats-help', action='store_true',
                      help='Show granular statistics help')

    # Shadow/Mirror mode for parallel testing
    parser.add_argument('--shadow-mode', action='store_true',
                       help='Run in shadow mode (observe only, no forwarding) - for testing alongside existing receivers')
    parser.add_argument('--mirror-mode', action='store_true',
                       help='Run in mirror mode (parallel capture and forward) - for comparison testing')
    parser.add_argument('--parallel', action='store_true',
                       help='Enable parallel operation (use sniff capture, no port binding)')
    parser.add_argument('--log-traps', type=str, metavar='FILE',
                       help='Log all observed traps to file (shadow mode)')
    parser.add_argument('--capture-mode', type=str, choices=['auto', 'sniff', 'socket'],
                       help='Packet capture mode: auto, sniff (parallel-safe), or socket (exclusive)')
    
    # Shadow mode status
    group.add_argument('--shadow-status', action='store_true',
                      help='Show shadow mode statistics')
    group.add_argument('--shadow-export', action='store_true',
                      help='Export shadow mode statistics to JSON')

    # Hidden option for internal daemon use
    parser.add_argument('--foreground-daemon', action='store_true',
                       help=argparse.SUPPRESS)

    # Runtime configuration parameters
    parser.add_argument('--interface', type=str, 
                       help='Network interface to listen on')
    parser.add_argument('--ports', type=str,
                       help='Comma-separated list of UDP ports to listen on (e.g., "162,1162,4789")')
    parser.add_argument('--config-dir', type=str, 
                       help='Configuration directory path')
    parser.add_argument('--log-file', type=str, 
                       help='Log file path')
    parser.add_argument('--pid-file', type=str, 
                       help='PID file path')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug mode with verbose logging')

    # Log rotation parameters
    parser.add_argument('--log-level', type=str, 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Set logging level')
    parser.add_argument('--log-max-size', type=str, metavar='SIZE',
                       help='Maximum log file size before rotation (e.g., "10M", "1G")')
    parser.add_argument('--log-backup-count', type=int, metavar='COUNT',
                       help='Number of backup log files to keep after rotation')
    parser.add_argument('--log-compress', action='store_true',
                       help='Enable compression of rotated log files')

    # Parameters for redirection operations
    parser.add_argument('--tag', type=validated_tag,
                       help='Destination group tag for redirection operations')
    parser.add_argument('--ip', type=validated_ip,
                       help='IP address for destination group operations')
    parser.add_argument('--port', type=validated_port,
                       help='Port for destination group operations')

    # SNMPv3 parameters
    parser.add_argument('--username', type=str,
                       help='SNMPv3 username')
    parser.add_argument('--engine-id', type=str,
                       help='SNMPv3 Engine ID (hex string)')
    parser.add_argument('--auth-protocol', type=str, 
                       choices=['NONE', 'MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
                       default='SHA',
                       help='SNMPv3 authentication protocol (default: SHA)')
    parser.add_argument('--auth-passphrase', type=str,
                       help='SNMPv3 authentication passphrase (prompted if not provided)')
    parser.add_argument('--priv-protocol', type=str,
                       choices=['NONE', 'DES', '3DES', 'AES128', 'AES192', 'AES256'],
                       default='AES128',
                       help='SNMPv3 privacy protocol (default: AES128)')
    parser.add_argument('--priv-passphrase', type=str,
                       help='SNMPv3 privacy passphrase (prompted if not provided)')
    parser.add_argument('--trap-file', type=str,
                       help='Path to SNMPv3 trap file for testing')
    parser.add_argument('--community', type=str, default='public',
                       help='SNMPv2c community string for converted traps (default: public)')
    parser.add_argument('--convert', action='store_true',
                       help='Convert decrypted trap to SNMPv2c (for testing)')
    parser.add_argument('--output', type=str,
                       help='Output file for converted trap')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output (show details)')
    parser.add_argument('--yes', '-y', action='store_true',
                       help='Skip confirmation prompts')

    # Stats parameters
    parser.add_argument('--oid', type=str,
                       help='OID for stats queries (use with --stats-oid)')
    parser.add_argument('--count', '-n', type=int, default=10,
                       help='Number of items to show in stats lists (default: 10)')
    parser.add_argument('--sort', '-s', type=str, default='total',
                       choices=['total', 'rate', 'peak', 'blocked', 'recent'],
                       help='Sort order for stats lists (default: total)')
    parser.add_argument('--format', '-f', type=str, default='json',
                       choices=['json', 'prometheus'],
                       help='Export format for stats (default: json)')
    parser.add_argument('--json', action='store_true',
                       help='Output stats as JSON')
    parser.add_argument('--pretty', action='store_true',
                       help='Pretty print JSON output')

    # Cache parameters
    parser.add_argument('--destination', type=str,
                       help='Destination for cache operations')
    parser.add_argument('--from', dest='from_time', type=str,
                       help='Start time for cache query/replay (e.g., "14:30", "-2h")')
    parser.add_argument('--to', dest='to_time', type=str,
                       help='End time for cache query/replay')
    parser.add_argument('--replay-to', type=str, metavar='HOST:PORT',
                       help='Custom replay destination (e.g., 10.1.2.3:162)')
    parser.add_argument('--rate-limit', type=int, default=500,
                       help='Max traps/sec for replay (default: 500)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview cache replay without sending')
    parser.add_argument('--oid-filter', type=str,
                       help='OID prefix filter for cache operations')
    parser.add_argument('--source-filter', type=str,
                       help='Source IP prefix filter for cache operations')
    parser.add_argument('--exclude-oid', type=str,
                       help='OID to exclude from cache replay')
    parser.add_argument('--limit', type=int, default=20,
                       help='Maximum entries to show in cache query (default: 20)')

    # Config sync parameters
    parser.add_argument('--config', type=str,
                       choices=['destinations', 'blocked_ips', 'blocked_traps',
                                'redirected_ips', 'redirected_oids', 'redirected_destinations'],
                       help='Specific config to sync (for --sync-push/--sync-pull)')
    parser.add_argument('--sync-on-startup', action='store_true', default=None,
                       help='Sync configs when service starts (for --configure-sync)')
    parser.add_argument('--push-on-file-change', action='store_true', default=None,
                       help='Auto-push when local configs change (for --configure-sync)')
    parser.add_argument('--version-check-interval', type=int, default=None,
                       help='Seconds between version checks (for --configure-sync)')

    return parser
