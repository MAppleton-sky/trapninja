#!/usr/bin/env python3
"""
TrapNinja Legacy Parser - Backward-compatible flat-style arguments.

These arguments (--start, --stop, --block-ip, etc.) are deprecated
but still supported for existing scripts and automation that depend on them.

All arguments are suppressed from help output to encourage migration
to the new subcommand-based interface.

Migration guide:
    --start                  →  trapninja daemon start
    --block-ip 10.0.0.1     →  trapninja filter block-ip 10.0.0.1
    --ha-status              →  trapninja ha status
    --cache-replay           →  trapninja cache replay
    --stats-summary          →  trapninja stats summary
"""

import argparse

from .base import validated_ip, validated_oid, validated_tag, validated_port


def add_legacy_arguments(parser: argparse.ArgumentParser):
    """
    Add legacy flat-style arguments for backward compatibility.

    All arguments are suppressed from help output.
    """
    _S = argparse.SUPPRESS

    # -----------------------------------------------------------------
    # Daemon control (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--start', action='store_true', help=_S)
    parser.add_argument('--stop', action='store_true', help=_S)
    parser.add_argument('--restart', action='store_true', help=_S)
    parser.add_argument('--status', action='store_true', help=_S)
    parser.add_argument('--foreground', action='store_true', help=_S)
    parser.add_argument('--foreground-daemon', action='store_true', help=_S)
    parser.add_argument('--show-config', action='store_true', help=_S)
    parser.add_argument('--validate-config', action='store_true', help=_S)

    # -----------------------------------------------------------------
    # HA commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--configure-ha', action='store_true', help=_S)
    parser.add_argument('--disable-ha', action='store_true', help=_S)
    parser.add_argument('--ha-status', action='store_true', help=_S)
    parser.add_argument('--promote', action='store_true', help=_S)
    parser.add_argument('--demote', action='store_true', help=_S)
    parser.add_argument('--force-failover', action='store_true', help=_S)
    parser.add_argument('--ha-help', action='store_true', help=_S)
    parser.add_argument('--ha-sync', action='store_true', help=_S)
    parser.add_argument('--sync-status', action='store_true', help=_S)
    parser.add_argument('--sync-help', action='store_true', help=_S)

    # HA parameters (legacy)
    parser.add_argument('--ha-mode', choices=['primary', 'secondary'], help=_S)
    parser.add_argument('--ha-peer-host', type=validated_ip, help=_S)
    parser.add_argument('--ha-peer-port', type=validated_port, default=8162,
                        help=_S)
    parser.add_argument('--ha-listen-port', type=validated_port, default=8162,
                        help=_S)
    parser.add_argument('--ha-priority', type=int, default=100, help=_S)
    parser.add_argument('--force', action='store_true', help=_S)

    # -----------------------------------------------------------------
    # Filtering commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--block-ip', type=validated_ip, metavar='IP', help=_S)
    parser.add_argument('--unblock-ip', type=validated_ip, metavar='IP', help=_S)
    parser.add_argument('--list-blocked-ips', action='store_true', help=_S)
    parser.add_argument('--block-oid', type=validated_oid, metavar='OID', help=_S)
    parser.add_argument('--unblock-oid', type=validated_oid, metavar='OID',
                        help=_S)
    parser.add_argument('--list-blocked-oids', action='store_true', help=_S)

    # Redirection commands (legacy)
    parser.add_argument('--redirect-ip', type=validated_ip, metavar='IP', help=_S)
    parser.add_argument('--unredirect-ip', type=validated_ip, metavar='IP',
                        help=_S)
    parser.add_argument('--list-redirected-ips', action='store_true', help=_S)
    parser.add_argument('--redirect-oid', type=validated_oid, metavar='OID',
                        help=_S)
    parser.add_argument('--unredirect-oid', type=validated_oid, metavar='OID',
                        help=_S)
    parser.add_argument('--list-redirected-oids', action='store_true', help=_S)
    parser.add_argument('--add-redirect-dest', action='store_true', help=_S)
    parser.add_argument('--remove-redirect-dest', action='store_true', help=_S)
    parser.add_argument('--list-redirect-dests', action='store_true', help=_S)
    parser.add_argument('--redirection-help', action='store_true', help=_S)

    # Redirection parameters (legacy)
    parser.add_argument('--tag', type=validated_tag, help=_S)
    parser.add_argument('--ip', type=validated_ip, help=_S)
    parser.add_argument('--port', type=validated_port, help=_S)

    # -----------------------------------------------------------------
    # SNMPv3 commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--snmpv3-add-user', action='store_true', help=_S)
    parser.add_argument('--snmpv3-remove-user', action='store_true', help=_S)
    parser.add_argument('--snmpv3-list-users', action='store_true', help=_S)
    parser.add_argument('--snmpv3-show-user', action='store_true', help=_S)
    parser.add_argument('--snmpv3-status', action='store_true', help=_S)
    parser.add_argument('--snmpv3-test-decrypt', action='store_true', help=_S)

    # SNMPv3 parameters (legacy)
    parser.add_argument('--username', type=str, help=_S)
    parser.add_argument('--engine-id', type=str, help=_S)
    parser.add_argument('--auth-protocol', type=str,
                        choices=['NONE', 'MD5', 'SHA', 'SHA224', 'SHA256',
                                 'SHA384', 'SHA512'],
                        default='SHA', help=_S)
    parser.add_argument('--auth-passphrase', type=str, help=_S)
    parser.add_argument('--priv-protocol', type=str,
                        choices=['NONE', 'DES', '3DES', 'AES128', 'AES192',
                                 'AES256'],
                        default='AES128', help=_S)
    parser.add_argument('--priv-passphrase', type=str, help=_S)
    parser.add_argument('--trap-file', type=str, help=_S)
    parser.add_argument('--community', type=str, default='public', help=_S)
    parser.add_argument('--convert', action='store_true', help=_S)
    parser.add_argument('--output', type=str, help=_S)

    # -----------------------------------------------------------------
    # Cache commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--cache-status', action='store_true', help=_S)
    parser.add_argument('--cache-query', action='store_true', help=_S)
    parser.add_argument('--cache-replay', action='store_true', help=_S)
    parser.add_argument('--cache-clear', action='store_true', help=_S)
    parser.add_argument('--cache-trim', action='store_true', help=_S)
    parser.add_argument('--cache-help', action='store_true', help=_S)

    # Cache parameters (legacy)
    parser.add_argument('--destination', type=str, help=_S)
    parser.add_argument('--from', dest='from_time', type=str, help=_S)
    parser.add_argument('--to', dest='to_time', type=str, help=_S)
    parser.add_argument('--replay-to', type=str, metavar='HOST:PORT', help=_S)
    parser.add_argument('--rate-limit', type=int, default=500, help=_S)
    parser.add_argument('--dry-run', action='store_true', help=_S)
    parser.add_argument('--oid-filter', type=str, help=_S)
    parser.add_argument('--source-filter', type=str, help=_S)
    parser.add_argument('--exclude-oid', type=str, help=_S)
    parser.add_argument('--limit', type=int, default=20, help=_S)

    # -----------------------------------------------------------------
    # Failover commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--failover-status', action='store_true', help=_S)
    parser.add_argument('--failover-detect', action='store_true', help=_S)
    parser.add_argument('--failover-replay', action='store_true', help=_S)
    parser.add_argument('--failover-help', action='store_true', help=_S)

    # Queue stats (legacy)
    parser.add_argument('--queue-stats', action='store_true', help=_S)

    # -----------------------------------------------------------------
    # Stats commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--stats-summary', action='store_true', help=_S)
    parser.add_argument('--stats-top-ips', action='store_true', help=_S)
    parser.add_argument('--stats-top-oids', action='store_true', help=_S)
    parser.add_argument('--stats-ip', action='store_true', help=_S)
    parser.add_argument('--stats-oid', action='store_true', help=_S)
    parser.add_argument('--stats-destinations', action='store_true', help=_S)
    parser.add_argument('--stats-dashboard', action='store_true', help=_S)
    parser.add_argument('--stats-export', action='store_true', help=_S)
    parser.add_argument('--stats-reset', action='store_true', help=_S)
    parser.add_argument('--stats-debug', action='store_true', help=_S)
    parser.add_argument('--stats-help', action='store_true', help=_S)

    # Stats parameters (legacy)
    parser.add_argument('--oid', type=str, help=_S)
    parser.add_argument('--count', '-n', type=int, default=10, help=_S)
    parser.add_argument('--sort', '-s', type=str, default='total',
                        choices=['total', 'rate', 'peak', 'blocked', 'recent'],
                        help=_S)
    parser.add_argument('--sources', type=int, default=10, help=_S)
    parser.add_argument('--oids', type=int, default=10, help=_S)
    parser.add_argument('--format', '-f', type=str, default='json',
                        choices=['json', 'prometheus'], help=_S)
    parser.add_argument('--pretty', action='store_true', help=_S)

    # -----------------------------------------------------------------
    # Shadow mode commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--shadow-status', action='store_true', help=_S)
    parser.add_argument('--shadow-export', action='store_true', help=_S)

    # Shadow mode parameters (legacy)
    parser.add_argument('--shadow-mode', action='store_true', help=_S)
    parser.add_argument('--mirror-mode', action='store_true', help=_S)
    parser.add_argument('--parallel', action='store_true', help=_S)
    parser.add_argument('--log-traps', type=str, metavar='FILE', help=_S)
    parser.add_argument('--capture-mode', type=str,
                        choices=['auto', 'sniff', 'socket'], help=_S)

    # -----------------------------------------------------------------
    # Metrics commands (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--metrics-config', action='store_true', help=_S)
    parser.add_argument('--metrics-set-dir', type=str, metavar='DIRECTORY',
                        help=_S)
    parser.add_argument('--metrics-add-label', action='store_true', help=_S)
    parser.add_argument('--metrics-remove-label', type=str, metavar='NAME',
                        help=_S)
    parser.add_argument('--metrics-set-interval', type=int, metavar='SECONDS',
                        help=_S)
    parser.add_argument('--metrics-help', action='store_true', help=_S)

    # Metrics parameters (legacy)
    parser.add_argument('--label-name', type=str, help=_S)
    parser.add_argument('--label-value', type=str, help=_S)

    # -----------------------------------------------------------------
    # Other legacy parameters
    # -----------------------------------------------------------------
    parser.add_argument('--interface', type=str, help=_S)
    parser.add_argument('--ports', type=str, help=_S)
    parser.add_argument('--log-level', type=str,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help=_S)
    parser.add_argument('--log-max-size', type=str, metavar='SIZE', help=_S)
    parser.add_argument('--log-backup-count', type=int, metavar='COUNT', help=_S)
    parser.add_argument('--log-compress', action='store_true', help=_S)

    # -----------------------------------------------------------------
    # Sync parameters (legacy)
    # -----------------------------------------------------------------
    parser.add_argument('--config', type=str, choices=[
        'destinations', 'blocked_ips', 'blocked_traps',
        'redirected_ips', 'redirected_oids', 'redirected_destinations'
    ], help=_S)
    parser.add_argument('--sync-on-startup', action='store_true', default=None,
                        help=_S)
    parser.add_argument('--push-on-file-change', action='store_true',
                        default=None, help=_S)
    parser.add_argument('--version-check-interval', type=int, default=None,
                        help=_S)
