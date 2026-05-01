#!/usr/bin/env python3
"""
TrapNinja CLI Command Registry

Data-driven command dispatch replacing the if/elif chains in executor.py.
Each command is registered once and supports both subcommand and legacy
routing through the same definition.

Refactoring: Category A4/A5 from CODE-REVIEW-REFACTORING-ANALYSIS.md
Previously ~700 lines of if/elif routing, now declarative tables.

Architecture:
    CommandDef   - Describes one CLI command (handler, args, legacy mapping)
    SUBCOMMANDS  - Dict mapping (category, command) → CommandDef
    LEGACY_MAP   - Dict mapping legacy_attr_name → (category, command)

    Dispatch:
        1. Subcommand style: look up (category, command) in SUBCOMMANDS
        2. Legacy style: scan LEGACY_MAP for matching getattr → normalize
           to (category, command) → look up in SUBCOMMANDS

Author: TrapNinja Team
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from argparse import Namespace


# =============================================================================
# COMMAND DEFINITION
# =============================================================================

@dataclass
class CommandDef:
    """
    Definition for a single CLI command.

    Attributes:
        handler:       Callable(args: Namespace) -> int
        returns_bool:  If True, handler returns bool; convert to 0/1 exit code
        legacy_attr:   Legacy --flag attribute name on args (for backward compat)
        required_args: Args that must be present (legacy validation only)
        required_msg:  Error message when required args missing (legacy only)
    """
    handler: Callable[[Namespace], Any]
    returns_bool: bool = False
    legacy_attr: Optional[str] = None
    required_args: List[str] = field(default_factory=list)
    required_msg: str = ""


# =============================================================================
# HANDLER WRAPPERS
# =============================================================================
#
# Each wrapper takes (args: Namespace) -> int, normalizing the interface
# between the registry and the underlying command module functions.
# Wrappers that call bool-returning functions set returns_bool=True in
# their CommandDef so the dispatcher can convert to exit codes.
#
# Grouping mirrors the command categories: daemon, filter, ha, snmpv3,
# cache, stats, metrics, shadow, failover, sync.
# =============================================================================


# -----------------------------------------------------------------------------
# Daemon
# -----------------------------------------------------------------------------

def _daemon_start(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.start(
        shadow_mode=getattr(args, 'shadow_mode', False),
        mirror_mode=getattr(args, 'mirror_mode', False),
        parallel=getattr(args, 'parallel', False),
        capture_mode=getattr(args, 'capture_mode', None),
        log_traps=getattr(args, 'log_traps', None),
    )


def _daemon_stop(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.stop()


def _daemon_restart(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.restart(
        shadow_mode=getattr(args, 'shadow_mode', False),
        mirror_mode=getattr(args, 'mirror_mode', False),
        parallel=getattr(args, 'parallel', False),
        capture_mode=getattr(args, 'capture_mode', None),
        log_traps=getattr(args, 'log_traps', None),
    )


def _daemon_status(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.status()


def _daemon_foreground(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.run_foreground(
        debug=getattr(args, 'debug', False),
        shadow_mode=getattr(args, 'shadow_mode', False),
        mirror_mode=getattr(args, 'mirror_mode', False),
        parallel=getattr(args, 'parallel', False),
        capture_mode=getattr(args, 'capture_mode', None),
        log_traps=getattr(args, 'log_traps', None),
    )


def _daemon_config(args: Namespace) -> int:
    from . import daemon_commands
    if getattr(args, 'validate', False):
        return daemon_commands.validate_config()
    return daemon_commands.show_config(json_output=getattr(args, 'json', False))


def _daemon_show_config(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.show_config(json_output=getattr(args, 'json', False))


def _daemon_validate_config(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.validate_config()


def _daemon_queue_stats(args: Namespace) -> int:
    from . import daemon_commands
    return daemon_commands.queue_stats(json_output=getattr(args, 'json', False))


# -----------------------------------------------------------------------------
# Config — all return int directly
# -----------------------------------------------------------------------------

def _config_show(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_config(
        json_output=getattr(args, 'json', False),
        brief=getattr(args, 'brief', False),
    )


def _config_destinations(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_destinations(json_output=getattr(args, 'json', False))


def _config_blocked_ips(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_blocked_ips(json_output=getattr(args, 'json', False))


def _config_blocked_oids(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_blocked_oids(json_output=getattr(args, 'json', False))


def _config_redirected_ips(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_redirected_ips(json_output=getattr(args, 'json', False))


def _config_redirected_oids(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_redirected_oids(json_output=getattr(args, 'json', False))


def _config_redirect_dests(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_redirect_dests(json_output=getattr(args, 'json', False))


def _config_listen_ports(args: Namespace) -> int:
    from . import config_commands
    return config_commands.show_listen_ports(json_output=getattr(args, 'json', False))


def _config_validate(args: Namespace) -> int:
    from . import config_commands
    return config_commands.validate_config()


# -----------------------------------------------------------------------------
# Filter — all return bool, converted to exit code
# -----------------------------------------------------------------------------

def _filter_block_ip(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.block_ip(getattr(args, 'ip', None) or getattr(args, 'block_ip', None))


def _filter_unblock_ip(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.unblock_ip(getattr(args, 'ip', None) or getattr(args, 'unblock_ip', None))


def _filter_list_blocked_ips(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.list_blocked_ips()


def _filter_block_oid(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.block_oid(getattr(args, 'oid', None) or getattr(args, 'block_oid', None))


def _filter_unblock_oid(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.unblock_oid(getattr(args, 'oid', None) or getattr(args, 'unblock_oid', None))


def _filter_list_blocked_oids(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.list_blocked_oids()


def _filter_redirect_ip(args: Namespace) -> bool:
    from . import filtering_commands
    ip = getattr(args, 'ip', None) or getattr(args, 'redirect_ip', None)
    tag = getattr(args, 'tag', None)
    return filtering_commands.redirect_ip(ip, tag)


def _filter_unredirect_ip(args: Namespace) -> bool:
    from . import filtering_commands
    ip = getattr(args, 'ip', None) or getattr(args, 'unredirect_ip', None)
    return filtering_commands.unredirect_ip(ip)


def _filter_list_redirected_ips(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.list_redirected_ips()


def _filter_redirect_oid(args: Namespace) -> bool:
    from . import filtering_commands
    oid = getattr(args, 'oid', None) or getattr(args, 'redirect_oid', None)
    tag = getattr(args, 'tag', None)
    return filtering_commands.redirect_oid(oid, tag)


def _filter_unredirect_oid(args: Namespace) -> bool:
    from . import filtering_commands
    oid = getattr(args, 'oid', None) or getattr(args, 'unredirect_oid', None)
    return filtering_commands.unredirect_oid(oid)


def _filter_list_redirected_oids(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.list_redirected_oids()


def _filter_add_redirect_dest(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.add_redirect_destination(args.tag, args.ip, args.port)


def _filter_remove_redirect_dest(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.remove_redirect_destination(args.tag, args.ip, args.port)


def _filter_list_redirect_dests(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.list_redirect_destinations()


def _filter_redirection_help(args: Namespace) -> bool:
    from . import filtering_commands
    return filtering_commands.show_redirection_help()


# -----------------------------------------------------------------------------
# HA — most return bool
# -----------------------------------------------------------------------------

def _ha_configure(args: Namespace) -> bool:
    from . import ha_commands
    mode = getattr(args, 'mode', None) or getattr(args, 'ha_mode', None)
    peer = getattr(args, 'ha_peer_host', None)
    return ha_commands.configure_ha(
        mode, peer,
        getattr(args, 'priority', None) or getattr(args, 'ha_priority', 100),
        getattr(args, 'peer_port', None) or getattr(args, 'ha_peer_port', 8162),
        getattr(args, 'listen_port', None) or getattr(args, 'ha_listen_port', 8162),
    )


def _ha_status(args: Namespace) -> bool:
    from . import ha_commands
    return ha_commands.show_ha_status()


def _ha_promote(args: Namespace) -> bool:
    from . import ha_commands
    return ha_commands.promote_to_primary(force=getattr(args, 'force', False))


def _ha_demote(args: Namespace) -> bool:
    from . import ha_commands
    return ha_commands.demote_to_secondary()


def _ha_force_failover(args: Namespace) -> bool:
    from . import ha_commands
    return ha_commands.force_failover()


def _ha_disable(args: Namespace) -> bool:
    from . import ha_commands
    return ha_commands.disable_ha()


def _ha_help(args: Namespace) -> bool:
    from . import ha_commands
    return ha_commands.show_ha_help()


# -----------------------------------------------------------------------------
# SNMPv3 — return int directly
# -----------------------------------------------------------------------------

def _snmpv3_add_user(args: Namespace) -> int:
    from . import snmpv3_commands
    return snmpv3_commands.handle_snmpv3_add_user(args)


def _snmpv3_remove_user(args: Namespace) -> int:
    from . import snmpv3_commands
    return snmpv3_commands.handle_snmpv3_remove_user(args)


def _snmpv3_list_users(args: Namespace) -> int:
    from . import snmpv3_commands
    return snmpv3_commands.handle_snmpv3_list_users(args)


def _snmpv3_show_user(args: Namespace) -> int:
    from . import snmpv3_commands
    return snmpv3_commands.handle_snmpv3_show_user(args)


def _snmpv3_status(args: Namespace) -> int:
    from . import snmpv3_commands
    return snmpv3_commands.handle_snmpv3_status(args)


def _snmpv3_test_decrypt(args: Namespace) -> int:
    from . import snmpv3_commands
    return snmpv3_commands.handle_snmpv3_test_decrypt(args)


# -----------------------------------------------------------------------------
# Cache — most return bool
# -----------------------------------------------------------------------------

def _cache_status(args: Namespace) -> bool:
    from . import cache_commands
    return cache_commands.show_cache_status(verbose=getattr(args, 'verbose', False))


def _cache_query(args: Namespace) -> bool:
    from . import cache_commands
    return cache_commands.query_cache(
        destination=args.destination,
        start_time=args.from_time,
        end_time=args.to_time,
        limit=getattr(args, 'limit', 20),
        show_oids=True,
    )


def _cache_replay(args: Namespace) -> bool:
    from . import cache_commands
    return cache_commands.replay_cache(
        destination=args.destination,
        start_time=args.from_time,
        end_time=args.to_time,
        rate_limit=getattr(args, 'rate_limit', 500),
        dry_run=getattr(args, 'dry_run', False),
        oid_filter=getattr(args, 'oid_filter', None),
        source_filter=getattr(args, 'source_filter', None),
        exclude_oid=getattr(args, 'exclude_oid', None),
        yes=getattr(args, 'yes', False),
        replay_to=getattr(args, 'replay_to', None),
    )


def _cache_clear(args: Namespace) -> bool:
    from . import cache_commands
    return cache_commands.clear_cache(
        destination=getattr(args, 'destination', None),
        yes=getattr(args, 'yes', False),
    )


def _cache_trim(args: Namespace) -> bool:
    from . import cache_commands
    return cache_commands.trim_cache(yes=getattr(args, 'yes', False))


def _cache_help(args: Namespace) -> bool:
    from . import cache_commands
    return cache_commands.show_cache_help()


# -----------------------------------------------------------------------------
# Stats — return int directly
# -----------------------------------------------------------------------------

def _stats_summary(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_summary(args)


def _stats_top_ips(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_top_ips(args)


def _stats_top_oids(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_top_oids(args)


def _stats_ip(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_ip_detail(args)


def _stats_oid(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_oid_detail(args)


def _stats_destinations(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_destinations(args)


def _stats_dashboard(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_dashboard(args)


def _stats_export(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_export(args)


def _stats_reset(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_reset(args)


def _stats_debug(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_debug(args)


def _stats_help(args: Namespace) -> int:
    from . import stats_commands
    return stats_commands.handle_stats_help(args)


# -----------------------------------------------------------------------------
# Metrics — return int directly
# -----------------------------------------------------------------------------

def _metrics_config(args: Namespace) -> int:
    from . import metrics_commands
    return metrics_commands.show_metrics_config(json_output=getattr(args, 'json', False))


def _metrics_set_dir(args: Namespace) -> int:
    from . import metrics_commands
    directory = getattr(args, 'directory', None) or getattr(args, 'metrics_set_dir', None)
    return metrics_commands.set_metrics_directory(directory)


def _metrics_add_label(args: Namespace) -> int:
    from . import metrics_commands
    name = getattr(args, 'name', None) or getattr(args, 'label_name', None)
    value = getattr(args, 'value', None) or getattr(args, 'label_value', None)
    if not name or value is None:
        print("Error: --label-name and --label-value are required for --metrics-add-label")
        print("Example: --metrics-add-label --label-name on_prem --label-value 1")
        return 1
    return metrics_commands.add_metrics_label(name, value)


def _metrics_remove_label(args: Namespace) -> int:
    from . import metrics_commands
    name = getattr(args, 'name', None) or getattr(args, 'metrics_remove_label', None)
    return metrics_commands.remove_metrics_label(name)


def _metrics_set_interval(args: Namespace) -> int:
    from . import metrics_commands
    seconds = getattr(args, 'seconds', None) or getattr(args, 'metrics_set_interval', None)
    return metrics_commands.set_export_interval(seconds)


def _metrics_help(args: Namespace) -> int:
    from . import metrics_commands
    return metrics_commands.show_metrics_help()


# -----------------------------------------------------------------------------
# Shadow — return int directly
# -----------------------------------------------------------------------------

def _shadow_status(args: Namespace) -> int:
    from . import shadow_commands
    return shadow_commands.handle_shadow_status(args)


def _shadow_export(args: Namespace) -> int:
    from . import shadow_commands
    return shadow_commands.handle_shadow_export(args)


# -----------------------------------------------------------------------------
# Failover — most return bool
# -----------------------------------------------------------------------------

def _failover_status(args: Namespace) -> bool:
    from . import failover_commands
    return failover_commands.show_failover_status(verbose=getattr(args, 'verbose', False))


def _failover_detect(args: Namespace) -> bool:
    from . import failover_commands
    return failover_commands.detect_gaps(verbose=getattr(args, 'verbose', False))


def _failover_replay(args: Namespace) -> bool:
    from . import failover_commands
    destination = getattr(args, 'destination', None) or 'detect'
    from_time = getattr(args, 'from_time', None) or '-5m'
    to_time = getattr(args, 'to_time', None) or 'now'
    rate_limit = getattr(args, 'rate_limit', None)
    # Normalize: legacy uses 500 as default, but we want None for "not set"
    if rate_limit == 500:
        rate_limit = None
    return failover_commands.trigger_manual_replay(
        destination=destination,
        start_time=from_time,
        end_time=to_time,
        rate_limit=rate_limit,
        dry_run=getattr(args, 'dry_run', False),
        yes=getattr(args, 'yes', False),
    )


def _failover_help(args: Namespace) -> bool:
    from . import failover_commands
    return failover_commands.show_failover_help()


# -----------------------------------------------------------------------------
# Sync — return bool
# -----------------------------------------------------------------------------

def _sync_now(args: Namespace) -> bool:
    from . import sync_commands
    return sync_commands.sync_now(force=getattr(args, 'force', False))


def _sync_status(args: Namespace) -> bool:
    from . import sync_commands
    return sync_commands.show_sync_status()


def _sync_help(args: Namespace) -> bool:
    from . import sync_commands
    return sync_commands.show_sync_help()


# =============================================================================
# SUBCOMMAND REGISTRY
# =============================================================================
#
# Maps (category, command) → CommandDef
# This is the single source of truth for all command routing.
# =============================================================================

SUBCOMMANDS: Dict[Tuple[str, str], CommandDef] = {
    # ----- daemon -----
    ('daemon', 'start'):         CommandDef(_daemon_start),
    ('daemon', 'stop'):          CommandDef(_daemon_stop),
    ('daemon', 'restart'):       CommandDef(_daemon_restart),
    ('daemon', 'status'):        CommandDef(_daemon_status),
    ('daemon', 'foreground'):    CommandDef(_daemon_foreground),
    ('daemon', 'config'):        CommandDef(_daemon_config),
    ('daemon', 'queue-stats'):   CommandDef(_daemon_queue_stats),

    # ----- config -----
    ('config', 'show'):             CommandDef(_config_show),
    ('config', 'destinations'):     CommandDef(_config_destinations),
    ('config', 'blocked-ips'):      CommandDef(_config_blocked_ips),
    ('config', 'blocked-oids'):     CommandDef(_config_blocked_oids),
    ('config', 'redirected-ips'):   CommandDef(_config_redirected_ips),
    ('config', 'redirected-oids'):  CommandDef(_config_redirected_oids),
    ('config', 'redirect-dests'):   CommandDef(_config_redirect_dests),
    ('config', 'listen-ports'):     CommandDef(_config_listen_ports),
    ('config', 'validate'):         CommandDef(_config_validate),

    # ----- filter -----
    ('filter', 'block-ip'):           CommandDef(_filter_block_ip, returns_bool=True),
    ('filter', 'unblock-ip'):         CommandDef(_filter_unblock_ip, returns_bool=True),
    ('filter', 'list-blocked-ips'):   CommandDef(_filter_list_blocked_ips, returns_bool=True),
    ('filter', 'block-oid'):          CommandDef(_filter_block_oid, returns_bool=True),
    ('filter', 'unblock-oid'):        CommandDef(_filter_unblock_oid, returns_bool=True),
    ('filter', 'list-blocked-oids'):  CommandDef(_filter_list_blocked_oids, returns_bool=True),
    ('filter', 'redirect-ip'):        CommandDef(_filter_redirect_ip, returns_bool=True),
    ('filter', 'unredirect-ip'):      CommandDef(_filter_unredirect_ip, returns_bool=True),
    ('filter', 'list-redirected-ips'):  CommandDef(_filter_list_redirected_ips, returns_bool=True),
    ('filter', 'redirect-oid'):       CommandDef(_filter_redirect_oid, returns_bool=True),
    ('filter', 'unredirect-oid'):     CommandDef(_filter_unredirect_oid, returns_bool=True),
    ('filter', 'list-redirected-oids'): CommandDef(_filter_list_redirected_oids, returns_bool=True),
    ('filter', 'add-redirect-dest'):  CommandDef(_filter_add_redirect_dest, returns_bool=True),
    ('filter', 'remove-redirect-dest'): CommandDef(_filter_remove_redirect_dest, returns_bool=True),
    ('filter', 'list-redirect-dests'):  CommandDef(_filter_list_redirect_dests, returns_bool=True),

    # ----- ha -----
    ('ha', 'configure'):      CommandDef(_ha_configure, returns_bool=True),
    ('ha', 'status'):         CommandDef(_ha_status, returns_bool=True),
    ('ha', 'promote'):        CommandDef(_ha_promote, returns_bool=True),
    ('ha', 'demote'):         CommandDef(_ha_demote, returns_bool=True),
    ('ha', 'force-failover'): CommandDef(_ha_force_failover, returns_bool=True),
    ('ha', 'disable'):        CommandDef(_ha_disable, returns_bool=True),

    # ----- snmpv3 -----
    ('snmpv3', 'add-user'):     CommandDef(_snmpv3_add_user),
    ('snmpv3', 'remove-user'):  CommandDef(_snmpv3_remove_user),
    ('snmpv3', 'list-users'):   CommandDef(_snmpv3_list_users),
    ('snmpv3', 'show-user'):    CommandDef(_snmpv3_show_user),
    ('snmpv3', 'status'):       CommandDef(_snmpv3_status),
    ('snmpv3', 'test-decrypt'): CommandDef(_snmpv3_test_decrypt),

    # ----- cache -----
    ('cache', 'status'):  CommandDef(_cache_status, returns_bool=True),
    ('cache', 'query'):   CommandDef(_cache_query, returns_bool=True),
    ('cache', 'replay'):  CommandDef(_cache_replay, returns_bool=True),
    ('cache', 'clear'):   CommandDef(_cache_clear, returns_bool=True),
    ('cache', 'trim'):    CommandDef(_cache_trim, returns_bool=True),

    # ----- stats -----
    ('stats', 'summary'):      CommandDef(_stats_summary),
    ('stats', 'top-ips'):      CommandDef(_stats_top_ips),
    ('stats', 'top-oids'):     CommandDef(_stats_top_oids),
    ('stats', 'ip'):           CommandDef(_stats_ip),
    ('stats', 'oid'):          CommandDef(_stats_oid),
    ('stats', 'destinations'): CommandDef(_stats_destinations),
    ('stats', 'dashboard'):    CommandDef(_stats_dashboard),
    ('stats', 'export'):       CommandDef(_stats_export),
    ('stats', 'reset'):        CommandDef(_stats_reset),
    ('stats', 'debug'):        CommandDef(_stats_debug),

    # ----- metrics -----
    ('metrics', 'config'):       CommandDef(_metrics_config),
    ('metrics', 'set-dir'):      CommandDef(_metrics_set_dir),
    ('metrics', 'add-label'):    CommandDef(_metrics_add_label),
    ('metrics', 'remove-label'): CommandDef(_metrics_remove_label),
    ('metrics', 'set-interval'): CommandDef(_metrics_set_interval),

    # ----- shadow -----
    ('shadow', 'status'):  CommandDef(_shadow_status),
    ('shadow', 'export'):  CommandDef(_shadow_export),

    # ----- failover -----
    ('failover', 'status'):  CommandDef(_failover_status, returns_bool=True),
    ('failover', 'detect'):  CommandDef(_failover_detect, returns_bool=True),
    ('failover', 'replay'):  CommandDef(_failover_replay, returns_bool=True),

    # ----- sync -----
    ('sync', 'now'):    CommandDef(_sync_now, returns_bool=True),
    ('sync', 'status'): CommandDef(_sync_status, returns_bool=True),
}


# =============================================================================
# LEGACY ARGUMENT MAPPING
# =============================================================================
#
# Maps legacy --flag attribute names to (category, command) pairs.
# When a legacy arg is found on the Namespace, the dispatch normalises
# it to the equivalent subcommand and routes through SUBCOMMANDS.
#
# The required_args and required_msg fields are used for legacy-only
# validation that was previously inline in _execute_legacy_command.
# =============================================================================

@dataclass
class LegacyMapping:
    """Maps a legacy --flag attribute to a subcommand."""
    category: str
    command: str
    required_args: List[str] = field(default_factory=list)
    required_msg: str = ""


# Ordered list — checked top-to-bottom, first match wins.
# Order matches the original executor.py for identical behaviour.
LEGACY_COMMANDS: List[Tuple[str, LegacyMapping]] = [
    # HA commands (checked first in original)
    ('configure_ha',    LegacyMapping('ha', 'configure',
        required_args=['ha_mode', 'ha_peer_host'],
        required_msg="Error: --ha-mode and --ha-peer-host are required for HA configuration\n"
                     "Example: --configure-ha --ha-mode primary --ha-peer-host 192.168.1.101")),
    ('disable_ha',      LegacyMapping('ha', 'disable')),
    ('ha_status',       LegacyMapping('ha', 'status')),
    ('promote',         LegacyMapping('ha', 'promote')),
    ('demote',          LegacyMapping('ha', 'demote')),
    ('force_failover',  LegacyMapping('ha', 'force-failover')),
    ('ha_help',         LegacyMapping('ha', 'help')),

    # Sync commands
    ('ha_sync',         LegacyMapping('sync', 'now')),
    ('sync_status',     LegacyMapping('sync', 'status')),
    ('sync_help',       LegacyMapping('sync', 'help')),

    # Filter commands
    ('block_ip',              LegacyMapping('filter', 'block-ip')),
    ('unblock_ip',            LegacyMapping('filter', 'unblock-ip')),
    ('list_blocked_ips',      LegacyMapping('filter', 'list-blocked-ips')),
    ('block_oid',             LegacyMapping('filter', 'block-oid')),
    ('unblock_oid',           LegacyMapping('filter', 'unblock-oid')),
    ('list_blocked_oids',     LegacyMapping('filter', 'list-blocked-oids')),
    ('redirect_ip',           LegacyMapping('filter', 'redirect-ip',
        required_args=['tag'],
        required_msg="Error: --tag is required for --redirect-ip\n"
                     "Example: --redirect-ip 10.0.0.1 --tag security")),
    ('unredirect_ip',         LegacyMapping('filter', 'unredirect-ip')),
    ('list_redirected_ips',   LegacyMapping('filter', 'list-redirected-ips')),
    ('redirect_oid',          LegacyMapping('filter', 'redirect-oid',
        required_args=['tag'],
        required_msg="Error: --tag is required for --redirect-oid\n"
                     "Example: --redirect-oid 1.3.6.1.4.1.9.9.41.2.0.1 --tag security")),
    ('unredirect_oid',        LegacyMapping('filter', 'unredirect-oid')),
    ('list_redirected_oids',  LegacyMapping('filter', 'list-redirected-oids')),
    ('add_redirect_dest',     LegacyMapping('filter', 'add-redirect-dest',
        required_args=['tag', 'ip', 'port'],
        required_msg="Error: --tag, --ip, and --port are required for --add-redirect-dest\n"
                     "Example: --add-redirect-dest --tag security --ip 10.1.1.100 --port 162")),
    ('remove_redirect_dest',  LegacyMapping('filter', 'remove-redirect-dest',
        required_args=['tag', 'ip', 'port'],
        required_msg="Error: --tag, --ip, and --port are required for --remove-redirect-dest\n"
                     "Example: --remove-redirect-dest --tag security --ip 10.1.1.100 --port 162")),
    ('list_redirect_dests',   LegacyMapping('filter', 'list-redirect-dests')),
    ('redirection_help',      LegacyMapping('filter', 'help')),

    # SNMPv3 commands
    ('snmpv3_add_user',     LegacyMapping('snmpv3', 'add-user',
        required_args=['username', 'engine_id'],
        required_msg="Error: --username and --engine-id are required\n"
                     "Example: --snmpv3-add-user --username myuser --engine-id 80001f888056565656565656 "
                     "--auth-protocol SHA --priv-protocol AES128")),
    ('snmpv3_remove_user',  LegacyMapping('snmpv3', 'remove-user',
        required_args=['username', 'engine_id'],
        required_msg="Error: --username and --engine-id are required")),
    ('snmpv3_list_users',   LegacyMapping('snmpv3', 'list-users')),
    ('snmpv3_show_user',    LegacyMapping('snmpv3', 'show-user',
        required_args=['username', 'engine_id'],
        required_msg="Error: --username and --engine-id are required")),
    ('snmpv3_status',       LegacyMapping('snmpv3', 'status')),
    ('snmpv3_test_decrypt', LegacyMapping('snmpv3', 'test-decrypt')),

    # Cache commands
    ('cache_status',  LegacyMapping('cache', 'status')),
    ('cache_query',   LegacyMapping('cache', 'query',
        required_args=['destination', 'from_time', 'to_time'],
        required_msg='Error: --destination, --from, and --to are required for cache query\n'
                     'Example: --cache-query --destination voice_noc --from "14:30" --to "15:45"')),
    ('cache_replay',  LegacyMapping('cache', 'replay',
        required_args=['destination', 'from_time', 'to_time'],
        required_msg='Error: --destination, --from, and --to are required for cache replay\n'
                     'Example: --cache-replay --destination voice_noc --from "14:30" --to "15:45"\n'
                     'Use --dry-run to preview without sending\n'
                     'Use --replay-to HOST:PORT to send to a custom destination')),
    ('cache_clear',   LegacyMapping('cache', 'clear')),
    ('cache_trim',    LegacyMapping('cache', 'trim')),
    ('cache_help',    LegacyMapping('cache', 'help')),

    # Failover commands
    ('failover_status',  LegacyMapping('failover', 'status')),
    ('failover_detect',  LegacyMapping('failover', 'detect')),
    ('failover_replay',  LegacyMapping('failover', 'replay')),
    ('failover_help',    LegacyMapping('failover', 'help')),

    # Queue stats
    ('queue_stats',  LegacyMapping('daemon', 'queue-stats')),

    # Granular stats
    ('stats_summary',      LegacyMapping('stats', 'summary')),
    ('stats_top_ips',      LegacyMapping('stats', 'top-ips')),
    ('stats_top_oids',     LegacyMapping('stats', 'top-oids')),
    ('stats_ip',           LegacyMapping('stats', 'ip',
        required_args=['ip'],
        required_msg="Error: --ip is required for --stats-ip\n"
                     "Example: --stats-ip --ip 10.0.0.1")),
    ('stats_oid',          LegacyMapping('stats', 'oid',
        required_args=['oid'],
        required_msg="Error: --oid is required for --stats-oid\n"
                     "Example: --stats-oid --oid 1.3.6.1.4.1.9.9.41.2.0.1")),
    ('stats_destinations', LegacyMapping('stats', 'destinations')),
    ('stats_dashboard',    LegacyMapping('stats', 'dashboard')),
    ('stats_export',       LegacyMapping('stats', 'export')),
    ('stats_reset',        LegacyMapping('stats', 'reset')),
    ('stats_help',         LegacyMapping('stats', 'help')),
    ('stats_debug',        LegacyMapping('stats', 'debug')),

    # Shadow commands
    ('shadow_status',  LegacyMapping('shadow', 'status')),
    ('shadow_export',  LegacyMapping('shadow', 'export')),

    # Metrics commands
    ('metrics_config',       LegacyMapping('metrics', 'config')),
    ('metrics_set_dir',      LegacyMapping('metrics', 'set-dir')),
    ('metrics_add_label',    LegacyMapping('metrics', 'add-label')),
    ('metrics_remove_label', LegacyMapping('metrics', 'remove-label')),
    ('metrics_set_interval', LegacyMapping('metrics', 'set-interval')),
    ('metrics_help',         LegacyMapping('metrics', 'help')),

    # Config commands
    ('show_config',      LegacyMapping('daemon', 'show-config')),
    ('validate_config',  LegacyMapping('daemon', 'validate-config')),

    # Daemon control (checked last in original)
    ('start',       LegacyMapping('daemon', 'start')),
    ('stop',        LegacyMapping('daemon', 'stop')),
    ('restart',     LegacyMapping('daemon', 'restart')),
    ('status',      LegacyMapping('daemon', 'status')),
    ('foreground',  LegacyMapping('daemon', 'foreground')),
]

# Also register the legacy-only show-config/validate-config in SUBCOMMANDS
SUBCOMMANDS[('daemon', 'show-config')] = CommandDef(_daemon_show_config)
SUBCOMMANDS[('daemon', 'validate-config')] = CommandDef(_daemon_validate_config)

# Register help-only commands that map to category help
# These are handled in the "help" special case but we add registry
# entries for completeness for categories that have dedicated help handlers
SUBCOMMANDS[('config', 'help')]    = CommandDef(_config_show)  # default to show
SUBCOMMANDS[('ha', 'help')]       = CommandDef(_ha_help, returns_bool=True)
SUBCOMMANDS[('filter', 'help')]   = CommandDef(_filter_redirection_help, returns_bool=True)
SUBCOMMANDS[('cache', 'help')]    = CommandDef(_cache_help, returns_bool=True)
SUBCOMMANDS[('stats', 'help')]    = CommandDef(_stats_help)
SUBCOMMANDS[('metrics', 'help')]  = CommandDef(_metrics_help)
SUBCOMMANDS[('sync', 'help')]     = CommandDef(_sync_help, returns_bool=True)
SUBCOMMANDS[('failover', 'help')] = CommandDef(_failover_help, returns_bool=True)


# =============================================================================
# DISPATCH FUNCTIONS
# =============================================================================

def dispatch_subcommand(args: Namespace, category: str, command: str) -> int:
    """
    Dispatch a subcommand-style invocation.

    Args:
        args: Parsed arguments
        category: Command category (daemon, filter, ha, etc.)
        command: Specific command within category

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    key = (category, command)
    cmd_def = SUBCOMMANDS.get(key)

    if cmd_def is None:
        print(f"Unknown {category} command: {command}")
        print(f"Run 'trapninja {category} --help' to see available commands.")
        return 1

    result = cmd_def.handler(args)

    if cmd_def.returns_bool:
        return 0 if result else 1
    return result


def dispatch_legacy(args: Namespace) -> Optional[int]:
    """
    Dispatch a legacy flat-style invocation.

    Scans the args Namespace for matching legacy attributes and routes
    through the same SUBCOMMANDS registry.

    Args:
        args: Parsed arguments with legacy --flag attributes

    Returns:
        Exit code if a command matched, None if no legacy command found
    """
    for attr_name, mapping in LEGACY_COMMANDS:
        value = getattr(args, attr_name, None)
        if not value:
            continue

        # Validate required args (legacy only — subcommand parsers handle this)
        if mapping.required_args:
            missing = [a for a in mapping.required_args if not getattr(args, a, None)]
            if missing:
                print(mapping.required_msg)
                return 1

        # Look up in SUBCOMMANDS and dispatch
        key = (mapping.category, mapping.command)
        cmd_def = SUBCOMMANDS.get(key)

        if cmd_def is None:
            # Shouldn't happen if tables are consistent, but fail gracefully
            print(f"Internal error: no handler for {mapping.category} {mapping.command}")
            return 1

        result = cmd_def.handler(args)

        if cmd_def.returns_bool:
            return 0 if result else 1
        return result

    # No legacy command matched
    return None


def get_categories() -> List[str]:
    """Return sorted list of all command categories."""
    return sorted(set(cat for cat, _ in SUBCOMMANDS.keys()))


def get_commands_for_category(category: str) -> List[str]:
    """Return sorted list of commands for a category."""
    return sorted(cmd for cat, cmd in SUBCOMMANDS.keys() if cat == category)
