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

    return parser
