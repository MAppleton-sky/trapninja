#!/usr/bin/env python3
"""
TrapNinja Argument Parser Module

Provides a clean, well-organized command-line interface with:
- Subcommand-based structure (e.g., `trapninja daemon start`)
- Backward compatibility with flat-style arguments (e.g., `trapninja --start`)
- Clear, actionable error messages
- Category-organized help output

Usage:
    trapninja daemon start              # Subcommand style
    trapninja --start                   # Legacy flat style (still supported)
    trapninja --help                    # Show command categories
    trapninja daemon --help             # Show daemon commands
"""

import argparse
import sys
import textwrap
from typing import Optional, List, Tuple

from .validation import InputValidator


# =============================================================================
# Custom Help Formatter
# =============================================================================

class TrapNinjaHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter that provides cleaner, more organized help output."""
    
    def __init__(self, prog, indent_increment=2, max_help_position=30, width=100):
        super().__init__(prog, indent_increment, max_help_position, width)
    
    def _format_action_invocation(self, action):
        """Format action invocation more cleanly."""
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = action.option_strings
            if action.nargs == 0:
                return ', '.join(parts)
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)
                return ', '.join(parts) + ' ' + args_string


class TrapNinjaRootHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Formatter for the root parser that shows command categories."""
    
    def __init__(self, prog, indent_increment=2, max_help_position=40, width=100):
        super().__init__(prog, indent_increment, max_help_position, width)


# =============================================================================
# Validation Type Converters
# =============================================================================

def validated_ip(value: str) -> str:
    """Validate and return IP address or raise ArgumentTypeError."""
    result = InputValidator.validate_ip(value)
    if result is None:
        raise argparse.ArgumentTypeError(f"Invalid IP address: '{value}'")
    return result


def validated_oid(value: str) -> str:
    """Validate and return OID or raise ArgumentTypeError."""
    result = InputValidator.validate_oid(value)
    if result is None:
        raise argparse.ArgumentTypeError(f"Invalid OID format: '{value}'")
    return result


def validated_tag(value: str) -> str:
    """Validate and return tag or raise ArgumentTypeError."""
    result = InputValidator.validate_tag(value)
    if result is None:
        raise argparse.ArgumentTypeError(f"Invalid tag: '{value}' (use alphanumeric and underscores only)")
    return result


def validated_port(value: str) -> int:
    """Validate and return port number or raise ArgumentTypeError."""
    result = InputValidator.validate_port(value)
    if result is None:
        raise argparse.ArgumentTypeError(f"Invalid port: '{value}' (must be 1-65535)")
    return result


# =============================================================================
# Custom Error Handling
# =============================================================================

class TrapNinjaArgumentParser(argparse.ArgumentParser):
    """
    Custom ArgumentParser with improved error messages.
    
    Provides:
    - Clear, actionable error messages
    - Suggestions for correct usage
    - Category-aware help hints
    """
    
    def __init__(self, *args, command_category: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.command_category = command_category
    
    def error(self, message: str):
        """Override error handling to provide clearer messages."""
        sys.stderr.write('\n')
        sys.stderr.write(f'\033[91mError:\033[0m {message}\n')
        sys.stderr.write('\n')
        
        # Provide helpful hints based on the error
        if 'required' in message.lower() and 'argument' in message.lower():
            if self.command_category:
                sys.stderr.write(f'  Run \033[93mtrapninja {self.command_category} --help\033[0m for available commands.\n')
            else:
                sys.stderr.write('  Run \033[93mtrapninja --help\033[0m to see available command categories.\n')
        elif 'invalid choice' in message.lower():
            sys.stderr.write('  Run \033[93mtrapninja --help\033[0m to see valid commands.\n')
        elif 'unrecognized arguments' in message.lower():
            sys.stderr.write('  Check the command syntax and required parameters.\n')
            if self.command_category:
                sys.stderr.write(f'  Run \033[93mtrapninja {self.command_category} --help\033[0m for details.\n')
        
        sys.stderr.write('\n')
        sys.exit(2)
    
    def format_help(self):
        """Format help with additional context."""
        return super().format_help()


# =============================================================================
# Main Parser Factory
# =============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser with all TrapNinja commands.
    
    Supports both:
    - Subcommand style: trapninja daemon start
    - Legacy flat style: trapninja --start
    
    Returns:
        Configured ArgumentParser instance
    """
    # Root parser with category overview
    parser = TrapNinjaArgumentParser(
        prog='trapninja',
        description=textwrap.dedent('''
            \033[1mTrapNinja - High-Performance SNMP Trap Forwarder\033[0m
            
            A telecommunications-grade trap processing system with HA support,
            SNMPv3 decryption, and intelligent filtering.
        '''),
        formatter_class=TrapNinjaRootHelpFormatter,
        epilog=textwrap.dedent('''
            \033[1mCommand Categories:\033[0m
            
              \033[93mdaemon\033[0m      Service control (start, stop, restart, status)
              \033[93mfilter\033[0m      IP and OID blocking/redirection
              \033[93mha\033[0m          High Availability configuration
              \033[93msnmpv3\033[0m      SNMPv3 credential management
              \033[93mcache\033[0m       Trap caching and replay
              \033[93mstats\033[0m       Granular statistics and monitoring
              \033[93mmetrics\033[0m     Prometheus metrics configuration
              \033[93mshadow\033[0m      Shadow/mirror mode for testing
            
            \033[1mQuick Start:\033[0m
            
              trapninja daemon start            Start the service
              trapninja daemon status           Check service status
              trapninja filter block-ip 10.0.0.1    Block an IP
              trapninja ha status               Check HA status
            
            \033[1mLegacy Commands:\033[0m
            
              Flat-style arguments (--start, --block-ip, etc.) are still supported
              for backward compatibility.
            
            Use \033[93mtrapninja <category> --help\033[0m for detailed command help.
        ''')
    )
    
    # Add global options
    _add_global_options(parser)
    
    # Create subparsers for command categories
    subparsers = parser.add_subparsers(
        title='Command Categories',
        dest='category',
        metavar='<category>'
    )
    
    # Add each command category
    _add_daemon_subcommands(subparsers)
    _add_filter_subcommands(subparsers)
    _add_ha_subcommands(subparsers)
    _add_snmpv3_subcommands(subparsers)
    _add_cache_subcommands(subparsers)
    _add_stats_subcommands(subparsers)
    _add_metrics_subcommands(subparsers)
    _add_shadow_subcommands(subparsers)
    _add_failover_subcommands(subparsers)
    _add_sync_subcommands(subparsers)
    
    # Add legacy flat-style arguments for backward compatibility
    _add_legacy_arguments(parser)
    
    return parser


# =============================================================================
# Global Options
# =============================================================================

def _add_global_options(parser: argparse.ArgumentParser):
    """Add global options available to all commands."""
    global_group = parser.add_argument_group('Global Options')
    
    global_group.add_argument('--config-dir', type=str, metavar='PATH',
                              help='Configuration directory path')
    global_group.add_argument('--log-file', type=str, metavar='PATH',
                              help='Log file path')
    global_group.add_argument('--pid-file', type=str, metavar='PATH',
                              help='PID file path')
    global_group.add_argument('--debug', action='store_true',
                              help='Enable debug mode with verbose logging')
    global_group.add_argument('--json', action='store_true',
                              help='Output in JSON format')
    global_group.add_argument('--yes', '-y', action='store_true',
                              help='Skip confirmation prompts')
    global_group.add_argument('--verbose', action='store_true',
                              help='Verbose output')


# =============================================================================
# Daemon Commands
# =============================================================================

def _add_daemon_subcommands(subparsers):
    """Add daemon control subcommands."""
    daemon_parser = subparsers.add_parser(
        'daemon',
        help='Service control commands',
        description='Control the TrapNinja daemon service.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja daemon start              Start as background daemon
              trapninja daemon start --debug      Start with debug logging
              trapninja daemon foreground         Run in foreground
              trapninja daemon status             Check if running
              trapninja daemon config             Show configuration
        ''')
    )
    daemon_parser.set_defaults(command_category='daemon')
    
    daemon_cmds = daemon_parser.add_subparsers(dest='command', metavar='<command>')
    
    # start
    start_cmd = daemon_cmds.add_parser('start', help='Start the daemon')
    start_cmd.add_argument('--interface', type=str, help='Network interface')
    start_cmd.add_argument('--ports', type=str, help='Comma-separated UDP ports')
    _add_logging_options(start_cmd)
    
    # stop
    daemon_cmds.add_parser('stop', help='Stop the daemon')
    
    # restart
    restart_cmd = daemon_cmds.add_parser('restart', help='Restart the daemon')
    restart_cmd.add_argument('--interface', type=str, help='Network interface')
    restart_cmd.add_argument('--ports', type=str, help='Comma-separated UDP ports')
    _add_logging_options(restart_cmd)
    
    # status
    daemon_cmds.add_parser('status', help='Check daemon status')
    
    # foreground
    fg_cmd = daemon_cmds.add_parser('foreground', help='Run in foreground (not as daemon)')
    fg_cmd.add_argument('--interface', type=str, help='Network interface')
    fg_cmd.add_argument('--ports', type=str, help='Comma-separated UDP ports')
    fg_cmd.add_argument('--shadow-mode', action='store_true',
                        help='Run in shadow mode (observe only)')
    fg_cmd.add_argument('--mirror-mode', action='store_true',
                        help='Run in mirror mode (parallel capture)')
    fg_cmd.add_argument('--parallel', action='store_true',
                        help='Enable parallel operation')
    fg_cmd.add_argument('--capture-mode', choices=['auto', 'sniff', 'socket'],
                        help='Packet capture mode')
    fg_cmd.add_argument('--log-traps', type=str, metavar='FILE',
                        help='Log observed traps to file')
    _add_logging_options(fg_cmd)
    
    # config
    config_cmd = daemon_cmds.add_parser('config', help='Show current configuration')
    config_cmd.add_argument('--validate', action='store_true',
                            help='Validate configuration without starting')
    
    # queue-stats
    daemon_cmds.add_parser('queue-stats', help='Show packet queue statistics')
    
    # help
    daemon_cmds.add_parser('help', help='Show daemon command help')


def _add_logging_options(parser: argparse.ArgumentParser):
    """Add logging configuration options to a parser."""
    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                           help='Set logging level')
    log_group.add_argument('--log-max-size', type=str, metavar='SIZE',
                           help='Max log file size (e.g., "10M", "1G")')
    log_group.add_argument('--log-backup-count', type=int, metavar='COUNT',
                           help='Number of backup log files')
    log_group.add_argument('--log-compress', action='store_true',
                           help='Compress rotated log files')


# =============================================================================
# Filter Commands
# =============================================================================

def _add_filter_subcommands(subparsers):
    """Add filtering subcommands."""
    filter_parser = subparsers.add_parser(
        'filter',
        help='IP and OID filtering/redirection',
        description='Manage trap filtering and redirection rules.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja filter block-ip 10.0.0.1        Block an IP
              trapninja filter unblock-ip 10.0.0.1      Remove IP block
              trapninja filter list-blocked-ips         Show blocked IPs
              trapninja filter block-oid 1.3.6.1.4.1.9  Block OID prefix
              trapninja filter redirect-ip 10.0.0.1 --tag security
        ''')
    )
    filter_parser.set_defaults(command_category='filter')
    
    filter_cmds = filter_parser.add_subparsers(dest='command', metavar='<command>')
    
    # IP blocking
    block_ip = filter_cmds.add_parser('block-ip', help='Block an IP address')
    block_ip.add_argument('ip', type=validated_ip, help='IP address to block')
    
    unblock_ip = filter_cmds.add_parser('unblock-ip', help='Unblock an IP address')
    unblock_ip.add_argument('ip', type=validated_ip, help='IP address to unblock')
    
    filter_cmds.add_parser('list-blocked-ips', help='List all blocked IPs')
    
    # OID blocking
    block_oid = filter_cmds.add_parser('block-oid', help='Block an OID')
    block_oid.add_argument('oid', type=validated_oid, help='OID to block')
    
    unblock_oid = filter_cmds.add_parser('unblock-oid', help='Unblock an OID')
    unblock_oid.add_argument('oid', type=validated_oid, help='OID to unblock')
    
    filter_cmds.add_parser('list-blocked-oids', help='List all blocked OIDs')
    
    # IP redirection
    redirect_ip = filter_cmds.add_parser('redirect-ip', help='Redirect traps from IP')
    redirect_ip.add_argument('ip', type=validated_ip, help='IP address to redirect')
    redirect_ip.add_argument('--tag', type=validated_tag, required=True,
                             help='Destination group tag')
    
    unredirect_ip = filter_cmds.add_parser('unredirect-ip', help='Remove IP redirection')
    unredirect_ip.add_argument('ip', type=validated_ip, help='IP to remove redirection')
    
    filter_cmds.add_parser('list-redirected-ips', help='List IP redirections')
    
    # OID redirection
    redirect_oid = filter_cmds.add_parser('redirect-oid', help='Redirect traps with OID')
    redirect_oid.add_argument('oid', type=validated_oid, help='OID to redirect')
    redirect_oid.add_argument('--tag', type=validated_tag, required=True,
                              help='Destination group tag')
    
    unredirect_oid = filter_cmds.add_parser('unredirect-oid', help='Remove OID redirection')
    unredirect_oid.add_argument('oid', type=validated_oid, help='OID to remove redirection')
    
    filter_cmds.add_parser('list-redirected-oids', help='List OID redirections')
    
    # Redirect destinations
    add_dest = filter_cmds.add_parser('add-redirect-dest', help='Add redirect destination')
    add_dest.add_argument('--tag', type=validated_tag, required=True, help='Destination group tag')
    add_dest.add_argument('--ip', type=validated_ip, required=True, help='Destination IP')
    add_dest.add_argument('--port', type=validated_port, required=True, help='Destination port')
    
    remove_dest = filter_cmds.add_parser('remove-redirect-dest', help='Remove redirect destination')
    remove_dest.add_argument('--tag', type=validated_tag, required=True, help='Destination group tag')
    remove_dest.add_argument('--ip', type=validated_ip, required=True, help='Destination IP')
    remove_dest.add_argument('--port', type=validated_port, required=True, help='Destination port')
    
    filter_cmds.add_parser('list-redirect-dests', help='List redirect destinations')
    filter_cmds.add_parser('help', help='Show comprehensive redirection help')


# =============================================================================
# HA Commands
# =============================================================================

def _add_ha_subcommands(subparsers):
    """Add High Availability subcommands."""
    ha_parser = subparsers.add_parser(
        'ha',
        help='High Availability configuration',
        description='Configure and manage High Availability clustering.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja ha configure --mode primary --peer 192.168.1.102
              trapninja ha status              Check HA status
              trapninja ha promote             Promote to PRIMARY
              trapninja ha demote              Demote to SECONDARY
              trapninja ha disable             Disable HA
        ''')
    )
    ha_parser.set_defaults(command_category='ha')
    
    ha_cmds = ha_parser.add_subparsers(dest='command', metavar='<command>')
    
    # configure
    configure_cmd = ha_cmds.add_parser('configure', help='Configure HA')
    configure_cmd.add_argument('--mode', choices=['primary', 'secondary'], required=True,
                               help='HA mode')
    configure_cmd.add_argument('--peer', '--peer-host', type=validated_ip, required=True,
                               dest='ha_peer_host', help='Peer IP address')
    configure_cmd.add_argument('--peer-port', type=validated_port, default=8162,
                               help='Peer port (default: 8162)')
    configure_cmd.add_argument('--listen-port', type=validated_port, default=8162,
                               help='Listen port (default: 8162)')
    configure_cmd.add_argument('--priority', type=int, default=100,
                               help='Priority 1-1000 (default: 100)')
    
    # status
    ha_cmds.add_parser('status', help='Show HA status')
    
    # promote
    promote_cmd = ha_cmds.add_parser('promote', help='Promote to PRIMARY')
    promote_cmd.add_argument('--force', action='store_true',
                             help='Force without peer coordination')
    
    # demote
    ha_cmds.add_parser('demote', help='Demote to SECONDARY')
    
    # force-failover
    ha_cmds.add_parser('force-failover', help='Force failover (maintenance)')
    
    # disable
    ha_cmds.add_parser('disable', help='Disable HA')
    
    # help
    ha_cmds.add_parser('help', help='Show comprehensive HA help')


# =============================================================================
# SNMPv3 Commands
# =============================================================================

def _add_snmpv3_subcommands(subparsers):
    """Add SNMPv3 credential management subcommands."""
    snmpv3_parser = subparsers.add_parser(
        'snmpv3',
        help='SNMPv3 credential management',
        description='Manage SNMPv3 user credentials for trap decryption.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja snmpv3 add-user --username myuser --engine-id 80001f88...
              trapninja snmpv3 list-users           List configured users
              trapninja snmpv3 status               Show SNMPv3 status
              trapninja snmpv3 test-decrypt --trap-file /tmp/trap.bin
        ''')
    )
    snmpv3_parser.set_defaults(command_category='snmpv3')
    
    snmpv3_cmds = snmpv3_parser.add_subparsers(dest='command', metavar='<command>')
    
    # add-user
    add_user = snmpv3_cmds.add_parser('add-user', help='Add SNMPv3 user')
    add_user.add_argument('--username', required=True, help='Username')
    add_user.add_argument('--engine-id', required=True, help='Engine ID (hex)')
    add_user.add_argument('--auth-protocol', 
                          choices=['NONE', 'MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
                          default='SHA', help='Auth protocol (default: SHA)')
    add_user.add_argument('--auth-passphrase', help='Auth passphrase')
    add_user.add_argument('--priv-protocol',
                          choices=['NONE', 'DES', '3DES', 'AES128', 'AES192', 'AES256'],
                          default='AES128', help='Privacy protocol (default: AES128)')
    add_user.add_argument('--priv-passphrase', help='Privacy passphrase')
    
    # remove-user
    remove_user = snmpv3_cmds.add_parser('remove-user', help='Remove SNMPv3 user')
    remove_user.add_argument('--username', required=True, help='Username')
    remove_user.add_argument('--engine-id', required=True, help='Engine ID')
    
    # list-users
    snmpv3_cmds.add_parser('list-users', help='List SNMPv3 users')
    
    # show-user
    show_user = snmpv3_cmds.add_parser('show-user', help='Show user details')
    show_user.add_argument('--username', required=True, help='Username')
    show_user.add_argument('--engine-id', required=True, help='Engine ID')
    
    # status
    snmpv3_cmds.add_parser('status', help='Show SNMPv3 status')
    
    # test-decrypt
    test_decrypt = snmpv3_cmds.add_parser('test-decrypt', help='Test decryption')
    test_decrypt.add_argument('--trap-file', required=True, help='Trap file path')
    test_decrypt.add_argument('--community', default='public',
                              help='Community for converted trap')
    test_decrypt.add_argument('--convert', action='store_true',
                              help='Convert to SNMPv2c')
    test_decrypt.add_argument('--output', help='Output file path')
    
    # help
    snmpv3_cmds.add_parser('help', help='Show SNMPv3 command help')


# =============================================================================
# Cache Commands
# =============================================================================

def _add_cache_subcommands(subparsers):
    """Add cache management subcommands."""
    cache_parser = subparsers.add_parser(
        'cache',
        help='Trap caching and replay',
        description='Manage the Redis-based trap cache for backfill operations.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja cache status                     Show cache status
              trapninja cache query --destination default --from "-2h" --to now
              trapninja cache replay --destination voice_noc --from "14:30" --to "15:45"
              trapninja cache clear --destination default
        ''')
    )
    cache_parser.set_defaults(command_category='cache')
    
    cache_cmds = cache_parser.add_subparsers(dest='command', metavar='<command>')
    
    # status
    cache_cmds.add_parser('status', help='Show cache status')
    
    # query
    query_cmd = cache_cmds.add_parser('query', help='Query cached traps')
    query_cmd.add_argument('--destination', required=True, help='Destination name')
    query_cmd.add_argument('--from', dest='from_time', required=True, help='Start time')
    query_cmd.add_argument('--to', dest='to_time', required=True, help='End time')
    query_cmd.add_argument('--limit', type=int, default=20, help='Max entries (default: 20)')
    
    # replay
    replay_cmd = cache_cmds.add_parser('replay', help='Replay cached traps')
    replay_cmd.add_argument('--destination', required=True, help='Destination name')
    replay_cmd.add_argument('--from', dest='from_time', required=True, help='Start time')
    replay_cmd.add_argument('--to', dest='to_time', required=True, help='End time')
    replay_cmd.add_argument('--replay-to', metavar='HOST:PORT', help='Custom replay target')
    replay_cmd.add_argument('--rate-limit', type=int, default=500, help='Max traps/sec')
    replay_cmd.add_argument('--dry-run', action='store_true', help='Preview without sending')
    replay_cmd.add_argument('--oid-filter', help='OID prefix filter')
    replay_cmd.add_argument('--source-filter', help='Source IP filter')
    replay_cmd.add_argument('--exclude-oid', help='OID to exclude')
    
    # clear
    clear_cmd = cache_cmds.add_parser('clear', help='Clear cached entries')
    clear_cmd.add_argument('--destination', help='Destination to clear')
    
    # trim
    cache_cmds.add_parser('trim', help='Trigger retention trim')
    
    # help
    cache_cmds.add_parser('help', help='Show comprehensive cache help')


# =============================================================================
# Stats Commands
# =============================================================================

def _add_stats_subcommands(subparsers):
    """Add statistics subcommands."""
    stats_parser = subparsers.add_parser(
        'stats',
        help='Granular statistics and monitoring',
        description='View and export detailed trap statistics.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja stats summary               Overview of all statistics
              trapninja stats top-ips -n 20         Top 20 source IPs
              trapninja stats top-oids -s rate      Top OIDs by rate
              trapninja stats ip --ip 10.0.0.1      Details for specific IP
              trapninja stats export -f prometheus  Export for Prometheus
        ''')
    )
    stats_parser.set_defaults(command_category='stats')
    
    stats_cmds = stats_parser.add_subparsers(dest='command', metavar='<command>')
    
    # summary
    stats_cmds.add_parser('summary', help='Show statistics summary')
    
    # top-ips
    top_ips = stats_cmds.add_parser('top-ips', help='Show top source IPs')
    _add_stats_display_options(top_ips)
    
    # top-oids
    top_oids = stats_cmds.add_parser('top-oids', help='Show top OIDs')
    _add_stats_display_options(top_oids)
    
    # ip
    ip_detail = stats_cmds.add_parser('ip', help='Show details for IP')
    ip_detail.add_argument('--ip', type=validated_ip, required=True, help='IP address')
    ip_detail.add_argument('--oids', type=int, default=10, help='Top OIDs to show')
    
    # oid
    oid_detail = stats_cmds.add_parser('oid', help='Show details for OID')
    oid_detail.add_argument('--oid', required=True, help='OID')
    oid_detail.add_argument('--sources', type=int, default=10, help='Top sources to show')
    
    # destinations
    stats_cmds.add_parser('destinations', help='Show destination statistics')
    
    # dashboard
    stats_cmds.add_parser('dashboard', help='Export dashboard data as JSON')
    
    # export
    export_cmd = stats_cmds.add_parser('export', help='Export statistics')
    export_cmd.add_argument('-f', '--format', choices=['json', 'prometheus'],
                            default='json', help='Export format')
    export_cmd.add_argument('-o', '--output', help='Output file')
    
    # reset
    stats_cmds.add_parser('reset', help='Reset all statistics')
    
    # debug
    stats_cmds.add_parser('debug', help='Show diagnostic info')
    
    # help
    stats_cmds.add_parser('help', help='Show statistics help')


def _add_stats_display_options(parser: argparse.ArgumentParser):
    """Add common stats display options."""
    parser.add_argument('-n', '--count', type=int, default=10, help='Number of items')
    parser.add_argument('-s', '--sort', choices=['total', 'rate', 'peak', 'blocked', 'recent'],
                        default='total', help='Sort order')


# =============================================================================
# Metrics Commands
# =============================================================================

def _add_metrics_subcommands(subparsers):
    """Add Prometheus metrics configuration subcommands."""
    metrics_parser = subparsers.add_parser(
        'metrics',
        help='Prometheus metrics configuration',
        description='Configure Prometheus metrics export.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja metrics config            Show current configuration
              trapninja metrics set-dir /opt/metrics
              trapninja metrics add-label --name region --value us-west
              trapninja metrics set-interval 30
        ''')
    )
    metrics_parser.set_defaults(command_category='metrics')
    
    metrics_cmds = metrics_parser.add_subparsers(dest='command', metavar='<command>')
    
    # config
    metrics_cmds.add_parser('config', help='Show metrics configuration')
    
    # set-dir
    set_dir = metrics_cmds.add_parser('set-dir', help='Set output directory')
    set_dir.add_argument('directory', help='Directory path')
    
    # add-label
    add_label = metrics_cmds.add_parser('add-label', help='Add global label')
    add_label.add_argument('--name', required=True, help='Label name')
    add_label.add_argument('--value', required=True, help='Label value')
    
    # remove-label
    remove_label = metrics_cmds.add_parser('remove-label', help='Remove global label')
    remove_label.add_argument('name', help='Label name to remove')
    
    # set-interval
    set_interval = metrics_cmds.add_parser('set-interval', help='Set export interval')
    set_interval.add_argument('seconds', type=int, help='Interval in seconds')
    
    # help
    metrics_cmds.add_parser('help', help='Show metrics configuration help')


# =============================================================================
# Shadow Mode Commands
# =============================================================================

def _add_shadow_subcommands(subparsers):
    """Add shadow/mirror mode subcommands."""
    shadow_parser = subparsers.add_parser(
        'shadow',
        help='Shadow/mirror mode for testing',
        description='Run in observation or parallel testing modes.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja shadow status            Show shadow mode statistics
              trapninja shadow export            Export statistics to JSON
              
              To run in shadow mode:
              trapninja daemon foreground --shadow-mode
        ''')
    )
    shadow_parser.set_defaults(command_category='shadow')
    
    shadow_cmds = shadow_parser.add_subparsers(dest='command', metavar='<command>')
    
    # status
    shadow_cmds.add_parser('status', help='Show shadow mode statistics')
    
    # export
    shadow_cmds.add_parser('export', help='Export statistics to JSON')
    
    # help
    shadow_cmds.add_parser('help', help='Show shadow mode help')


# =============================================================================
# Failover Commands
# =============================================================================

def _add_failover_subcommands(subparsers):
    """Add failover replay subcommands."""
    failover_parser = subparsers.add_parser(
        'failover',
        help='Failover replay for zero trap loss',
        description='Manage failover gap detection and replay.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja failover status          Show failover tracking info
              trapninja failover detect          Detect forwarding gaps
              trapninja failover replay          Trigger gap replay
        ''')
    )
    failover_parser.set_defaults(command_category='failover')
    
    failover_cmds = failover_parser.add_subparsers(dest='command', metavar='<command>')
    
    # status
    failover_cmds.add_parser('status', help='Show failover status')
    
    # detect
    failover_cmds.add_parser('detect', help='Detect forwarding gaps')
    
    # replay
    replay_cmd = failover_cmds.add_parser('replay', help='Trigger gap replay')
    replay_cmd.add_argument('--destination', help='Destination (or "detect")')
    replay_cmd.add_argument('--from', dest='from_time', help='Start time')
    replay_cmd.add_argument('--to', dest='to_time', help='End time')
    replay_cmd.add_argument('--rate-limit', type=int, help='Max traps/sec')
    replay_cmd.add_argument('--dry-run', action='store_true', help='Preview only')
    
    # help
    failover_cmds.add_parser('help', help='Show failover replay help')


# =============================================================================
# Config Sync Commands
# =============================================================================

def _add_sync_subcommands(subparsers):
    """Add config sync subcommands."""
    sync_parser = subparsers.add_parser(
        'sync',
        help='Configuration synchronization (HA)',
        description='Manage configuration sync between HA nodes.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              trapninja sync now                 Sync with peer
              trapninja sync status              Show sync status
        ''')
    )
    sync_parser.set_defaults(command_category='sync')
    
    sync_cmds = sync_parser.add_subparsers(dest='command', metavar='<command>')
    
    # now (sync)
    sync_now = sync_cmds.add_parser('now', help='Sync configs with peer')
    sync_now.add_argument('--force', action='store_true', help='Force sync')
    
    # status
    sync_cmds.add_parser('status', help='Show sync status')
    
    # help
    sync_cmds.add_parser('help', help='Show sync help')


# =============================================================================
# Legacy Arguments (Backward Compatibility)
# =============================================================================

def _add_legacy_arguments(parser: argparse.ArgumentParser):
    """
    Add legacy flat-style arguments for backward compatibility.
    
    These arguments (--start, --stop, --block-ip, etc.) are deprecated
    but still supported for scripts that depend on them.
    """
    # Create a mutually exclusive group for legacy commands
    legacy_group = parser.add_argument_group(
        'Legacy Commands (Deprecated)',
        'These flat-style arguments are still supported but deprecated. '
        'Use subcommands instead (e.g., "trapninja daemon start").'
    )
    
    # We use a different approach for legacy commands:
    # They're optional and we detect them in the executor
    
    # Daemon control (legacy)
    legacy_group.add_argument('--start', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stop', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--restart', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--status', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--foreground', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--foreground-daemon', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--show-config', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--validate-config', action='store_true',
                              help=argparse.SUPPRESS)
    
    # HA commands (legacy)
    legacy_group.add_argument('--configure-ha', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--disable-ha', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--ha-status', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--promote', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--demote', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--force-failover', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--ha-help', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--ha-sync', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--sync-status', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--sync-help', action='store_true',
                              help=argparse.SUPPRESS)
    
    # HA parameters (legacy)
    parser.add_argument('--ha-mode', choices=['primary', 'secondary'],
                        help=argparse.SUPPRESS)
    parser.add_argument('--ha-peer-host', type=validated_ip,
                        help=argparse.SUPPRESS)
    parser.add_argument('--ha-peer-port', type=validated_port, default=8162,
                        help=argparse.SUPPRESS)
    parser.add_argument('--ha-listen-port', type=validated_port, default=8162,
                        help=argparse.SUPPRESS)
    parser.add_argument('--ha-priority', type=int, default=100,
                        help=argparse.SUPPRESS)
    parser.add_argument('--force', action='store_true',
                        help=argparse.SUPPRESS)
    
    # Filtering commands (legacy)
    legacy_group.add_argument('--block-ip', type=validated_ip, metavar='IP',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--unblock-ip', type=validated_ip, metavar='IP',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--list-blocked-ips', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--block-oid', type=validated_oid, metavar='OID',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--unblock-oid', type=validated_oid, metavar='OID',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--list-blocked-oids', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Redirection commands (legacy)
    legacy_group.add_argument('--redirect-ip', type=validated_ip, metavar='IP',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--unredirect-ip', type=validated_ip, metavar='IP',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--list-redirected-ips', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--redirect-oid', type=validated_oid, metavar='OID',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--unredirect-oid', type=validated_oid, metavar='OID',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--list-redirected-oids', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--add-redirect-dest', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--remove-redirect-dest', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--list-redirect-dests', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--redirection-help', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Redirection parameters (legacy)
    parser.add_argument('--tag', type=validated_tag, help=argparse.SUPPRESS)
    parser.add_argument('--ip', type=validated_ip, help=argparse.SUPPRESS)
    parser.add_argument('--port', type=validated_port, help=argparse.SUPPRESS)
    
    # SNMPv3 commands (legacy)
    legacy_group.add_argument('--snmpv3-add-user', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--snmpv3-remove-user', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--snmpv3-list-users', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--snmpv3-show-user', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--snmpv3-status', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--snmpv3-test-decrypt', action='store_true',
                              help=argparse.SUPPRESS)
    
    # SNMPv3 parameters (legacy)
    parser.add_argument('--username', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--engine-id', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--auth-protocol', type=str,
                        choices=['NONE', 'MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
                        default='SHA', help=argparse.SUPPRESS)
    parser.add_argument('--auth-passphrase', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--priv-protocol', type=str,
                        choices=['NONE', 'DES', '3DES', 'AES128', 'AES192', 'AES256'],
                        default='AES128', help=argparse.SUPPRESS)
    parser.add_argument('--priv-passphrase', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--trap-file', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--community', type=str, default='public', help=argparse.SUPPRESS)
    parser.add_argument('--convert', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output', type=str, help=argparse.SUPPRESS)
    
    # Cache commands (legacy)
    legacy_group.add_argument('--cache-status', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--cache-query', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--cache-replay', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--cache-clear', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--cache-trim', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--cache-help', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Cache parameters (legacy)
    parser.add_argument('--destination', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--from', dest='from_time', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--to', dest='to_time', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--replay-to', type=str, metavar='HOST:PORT', help=argparse.SUPPRESS)
    parser.add_argument('--rate-limit', type=int, default=500, help=argparse.SUPPRESS)
    parser.add_argument('--dry-run', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--oid-filter', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--source-filter', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--exclude-oid', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--limit', type=int, default=20, help=argparse.SUPPRESS)
    
    # Failover commands (legacy)
    legacy_group.add_argument('--failover-status', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--failover-detect', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--failover-replay', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--failover-help', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Queue stats (legacy)
    legacy_group.add_argument('--queue-stats', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Stats commands (legacy)
    legacy_group.add_argument('--stats-summary', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-top-ips', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-top-oids', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-ip', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-oid', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-destinations', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-dashboard', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-export', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-reset', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-debug', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--stats-help', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Stats parameters (legacy)
    parser.add_argument('--oid', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--count', '-n', type=int, default=10, help=argparse.SUPPRESS)
    parser.add_argument('--sort', '-s', type=str, default='total',
                        choices=['total', 'rate', 'peak', 'blocked', 'recent'],
                        help=argparse.SUPPRESS)
    parser.add_argument('--sources', type=int, default=10, help=argparse.SUPPRESS)
    parser.add_argument('--oids', type=int, default=10, help=argparse.SUPPRESS)
    parser.add_argument('--format', '-f', type=str, default='json',
                        choices=['json', 'prometheus'], help=argparse.SUPPRESS)
    parser.add_argument('--pretty', action='store_true', help=argparse.SUPPRESS)
    
    # Shadow mode commands (legacy)
    legacy_group.add_argument('--shadow-status', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--shadow-export', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Shadow mode parameters (legacy)
    parser.add_argument('--shadow-mode', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--mirror-mode', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parallel', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--log-traps', type=str, metavar='FILE', help=argparse.SUPPRESS)
    parser.add_argument('--capture-mode', type=str, choices=['auto', 'sniff', 'socket'],
                        help=argparse.SUPPRESS)
    
    # Metrics commands (legacy)
    legacy_group.add_argument('--metrics-config', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--metrics-set-dir', type=str, metavar='DIRECTORY',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--metrics-add-label', action='store_true',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--metrics-remove-label', type=str, metavar='NAME',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--metrics-set-interval', type=int, metavar='SECONDS',
                              help=argparse.SUPPRESS)
    legacy_group.add_argument('--metrics-help', action='store_true',
                              help=argparse.SUPPRESS)
    
    # Metrics parameters (legacy)
    parser.add_argument('--label-name', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--label-value', type=str, help=argparse.SUPPRESS)
    
    # Other legacy parameters
    parser.add_argument('--interface', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--ports', type=str, help=argparse.SUPPRESS)
    parser.add_argument('--log-level', type=str,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help=argparse.SUPPRESS)
    parser.add_argument('--log-max-size', type=str, metavar='SIZE',
                        help=argparse.SUPPRESS)
    parser.add_argument('--log-backup-count', type=int, metavar='COUNT',
                        help=argparse.SUPPRESS)
    parser.add_argument('--log-compress', action='store_true',
                        help=argparse.SUPPRESS)
    
    # Sync parameters (legacy)
    parser.add_argument('--config', type=str, choices=[
        'destinations', 'blocked_ips', 'blocked_traps',
        'redirected_ips', 'redirected_oids', 'redirected_destinations'
    ], help=argparse.SUPPRESS)
    parser.add_argument('--sync-on-startup', action='store_true', default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument('--push-on-file-change', action='store_true', default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument('--version-check-interval', type=int, default=None,
                        help=argparse.SUPPRESS)
