#!/usr/bin/env python3
"""
TrapNinja Filtering Commands Module

Handles IP and OID blocking/unblocking and redirection operations
via command-line interface.

All commands delegate to ConfigListManager, ConfigPairListManager,
or ConfigGroupManager from command_base.py, eliminating the
duplicate load-validate-modify-save pattern that was previously
repeated across every function.

Refactoring: Category A2 from CODE-REVIEW-REFACTORING-ANALYSIS.md

Author: TrapNinja Team
"""

from .command_base import (
    ConfigListManager,
    ConfigPairListManager,
    ConfigGroupManager,
    config_io,
)
from .validation import InputValidator


# =============================================================================
# BACKWARD COMPATIBILITY — re-export ConfigManager-like interface
# =============================================================================
# Some modules may import ConfigManager or config_manager from here.
# ConfigFileIO is the replacement; this alias maintains compatibility.

class ConfigManager:
    """
    Backward-compatible wrapper around ConfigFileIO.

    Deprecated: Import config_io from command_base instead.
    """

    def __init__(self):
        self._io = config_io

    def load_json(self, file_path, default_value=None):
        return self._io.load(file_path, default_value)

    def save_json(self, file_path, data):
        return self._io.save(file_path, data)

    def invalidate_cache(self, file_path=None):
        self._io.invalidate(file_path)


# Global instance preserved for any external consumers
config_manager = ConfigManager()


# =============================================================================
# MANAGER INSTANCES
# =============================================================================

# --- Blocking (simple list operations) ---

ip_blocker = ConfigListManager(
    file_path_getter=lambda: _get_config_path('BLOCKED_IPS_FILE'),
    validator=InputValidator.validate_ip_or_cidr,
    item_name="IP address or CIDR range",
)

oid_blocker = ConfigListManager(
    file_path_getter=lambda: _get_config_path('BLOCKED_TRAPS_FILE'),
    validator=InputValidator.validate_oid,
    item_name="OID",
)

# --- Redirection (pair list operations) ---

ip_redirector = ConfigPairListManager(
    file_path_getter=lambda: _get_config_path('REDIRECTED_IPS_FILE'),
    dest_file_path_getter=lambda: _get_config_path('REDIRECTED_DESTINATIONS_FILE'),
    key_validator=InputValidator.validate_ip_or_cidr,
    tag_validator=InputValidator.validate_tag,
    key_name="IP or CIDR range",
)

oid_redirector = ConfigPairListManager(
    file_path_getter=lambda: _get_config_path('REDIRECTED_OIDS_FILE'),
    dest_file_path_getter=lambda: _get_config_path('REDIRECTED_DESTINATIONS_FILE'),
    key_validator=InputValidator.validate_oid,
    tag_validator=InputValidator.validate_tag,
    key_name="OID",
)

# --- Redirect destination groups ---

dest_group_manager = ConfigGroupManager(
    file_path_getter=lambda: _get_config_path('REDIRECTED_DESTINATIONS_FILE'),
    ip_validator=InputValidator.validate_ip,
    port_validator=InputValidator.validate_port,
    tag_validator=InputValidator.validate_tag,
)


def _get_config_path(attr_name: str) -> str:
    """
    Deferred config path lookup.

    Avoids importing config constants at module load time, which would
    trigger config initialisation before the CLI has parsed arguments.
    """
    from ..config import (
        BLOCKED_IPS_FILE,
        BLOCKED_TRAPS_FILE,
        REDIRECTED_IPS_FILE,
        REDIRECTED_OIDS_FILE,
        REDIRECTED_DESTINATIONS_FILE,
    )
    paths = {
        'BLOCKED_IPS_FILE': BLOCKED_IPS_FILE,
        'BLOCKED_TRAPS_FILE': BLOCKED_TRAPS_FILE,
        'REDIRECTED_IPS_FILE': REDIRECTED_IPS_FILE,
        'REDIRECTED_OIDS_FILE': REDIRECTED_OIDS_FILE,
        'REDIRECTED_DESTINATIONS_FILE': REDIRECTED_DESTINATIONS_FILE,
    }
    return paths[attr_name]


# =============================================================================
# IP BLOCKING COMMANDS
# =============================================================================

def block_ip(ip_address: str) -> bool:
    """
    Add an IP address to the blocked IPs list.

    Args:
        ip_address: IP address to block

    Returns:
        True if successful, False otherwise
    """
    return ip_blocker.add(ip_address)


def unblock_ip(ip_address: str) -> bool:
    """
    Remove an IP address from the blocked IPs list.

    Args:
        ip_address: IP address to unblock

    Returns:
        True if successful, False otherwise
    """
    return ip_blocker.remove(ip_address)


def list_blocked_ips() -> bool:
    """
    List all blocked IP addresses.

    Returns:
        True if successful, False otherwise
    """
    return ip_blocker.list_all()


# =============================================================================
# OID BLOCKING COMMANDS
# =============================================================================

def block_oid(oid: str) -> bool:
    """
    Add an OID to the blocked traps list.

    Args:
        oid: OID to block

    Returns:
        True if successful, False otherwise
    """
    return oid_blocker.add(oid)


def unblock_oid(oid: str) -> bool:
    """
    Remove an OID from the blocked traps list.

    Args:
        oid: OID to unblock

    Returns:
        True if successful, False otherwise
    """
    return oid_blocker.remove(oid)


def list_blocked_oids() -> bool:
    """
    List all blocked OIDs.

    Returns:
        True if successful, False otherwise
    """
    return oid_blocker.list_all()


# =============================================================================
# IP REDIRECTION COMMANDS
# =============================================================================

def redirect_ip(ip_address: str, tag: str) -> bool:
    """
    Add an IP address to the redirected IPs list with a destination tag.

    Args:
        ip_address: IP address to redirect
        tag: Destination group tag (must exist in redirect_destinations.json)

    Returns:
        True if successful, False otherwise
    """
    return ip_redirector.add(ip_address, tag)


def unredirect_ip(ip_address: str) -> bool:
    """
    Remove an IP address from the redirected IPs list.

    Args:
        ip_address: IP address to remove from redirection

    Returns:
        True if successful, False otherwise
    """
    return ip_redirector.remove(ip_address)


def list_redirected_ips() -> bool:
    """
    List all redirected IP addresses with their destination tags.

    Returns:
        True if successful, False otherwise
    """
    return ip_redirector.list_all()


# =============================================================================
# OID REDIRECTION COMMANDS
# =============================================================================

def redirect_oid(oid: str, tag: str) -> bool:
    """
    Add an OID to the redirected OIDs list with a destination tag.

    Args:
        oid: OID to redirect
        tag: Destination group tag (must exist in redirect_destinations.json)

    Returns:
        True if successful, False otherwise
    """
    return oid_redirector.add(oid, tag)


def unredirect_oid(oid: str) -> bool:
    """
    Remove an OID from the redirected OIDs list.

    Args:
        oid: OID to remove from redirection

    Returns:
        True if successful, False otherwise
    """
    return oid_redirector.remove(oid)


def list_redirected_oids() -> bool:
    """
    List all redirected OIDs with their destination tags.

    Returns:
        True if successful, False otherwise
    """
    return oid_redirector.list_all()


# =============================================================================
# REDIRECT DESTINATION GROUP COMMANDS
# =============================================================================

def add_redirect_destination(tag: str, ip_address: str, port: int) -> bool:
    """
    Add a destination to a redirect group.

    Args:
        tag: Destination group tag
        ip_address: Destination IP address
        port: Destination port

    Returns:
        True if successful, False otherwise
    """
    return dest_group_manager.add(tag, ip_address, port)


def remove_redirect_destination(tag: str, ip_address: str, port: int) -> bool:
    """
    Remove a destination from a redirect group.

    Args:
        tag: Destination group tag
        ip_address: Destination IP address
        port: Destination port

    Returns:
        True if successful, False otherwise
    """
    return dest_group_manager.remove(tag, ip_address, port)


def list_redirect_destinations() -> bool:
    """
    List all redirect destination groups and their destinations.

    Returns:
        True if successful, False otherwise
    """
    return dest_group_manager.list_all()


# =============================================================================
# HELP
# =============================================================================

def show_redirection_help() -> bool:
    """
    Display comprehensive help for redirection commands.

    Returns:
        True always
    """
    help_text = """
================================================================================
                    TrapNinja Redirection Help
================================================================================

OVERVIEW
--------
Redirection allows you to route traps from specific sources (IPs or OIDs) to
different destination groups instead of the default forwarding destinations.

This is useful for:
  - Sending security-related traps to a security NOC
  - Routing configuration change traps to a config management system
  - Separating trap streams by device type or vendor
  - Routing all traps from a management subnet to a dedicated handler
  - Blocking or redirecting traffic from entire address ranges (e.g. vendor
    subnets, remote sites) without listing individual IPs

CONCEPTS
--------

1. DESTINATION GROUPS (trapninja filter list-redirect-dests)
   Named groups of IP:port destinations. Create these first.
   Example: "security" group with destinations 10.1.1.100:162, 10.1.1.101:162

2. IP REDIRECTIONS (trapninja filter list-redirected-ips)
   Map source IPs to destination groups.
   Example: Traps from 192.168.10.50 -> "security" group

3. OID REDIRECTIONS (trapninja filter list-redirected-oids)
   Map trap OIDs to destination groups.
   Example: OID 1.3.6.1.4.1.9.9.41.2.0.1 -> "config" group

WORKFLOW
--------

Step 1: Create destination group
  trapninja filter add-redirect-dest --tag security --ip 10.1.1.100 --port 162
  trapninja filter add-redirect-dest --tag security --ip 10.1.1.101 --port 162

Step 2: Add redirection rules
  # Redirect by source IP
  trapninja filter redirect-ip 192.168.10.50 --tag security

  # Redirect by OID
  trapninja filter redirect-oid 1.3.6.1.4.1.9.9.41.2.0.1 --tag security

Step 3: Verify configuration
  trapninja filter list-redirect-dests
  trapninja filter list-redirected-ips
  trapninja filter list-redirected-oids

  # Or view all config at once:
  trapninja config show

COMMANDS REFERENCE
------------------

Destination Groups:
  trapninja filter add-redirect-dest --tag TAG --ip IP --port PORT
      Add a destination to a redirect group

  trapninja filter remove-redirect-dest --tag TAG --ip IP --port PORT
      Remove a destination from a redirect group

  trapninja filter list-redirect-dests
      List all redirect destination groups

IP Redirection:
  trapninja filter redirect-ip IP_OR_CIDR --tag TAG
      Redirect traps from IP or CIDR range to destination group
      Examples: 10.0.0.1  or  192.168.50.0/24

  trapninja filter unredirect-ip IP_OR_CIDR
      Remove IP or CIDR range redirection rule

  trapninja filter list-redirected-ips
      List all IP and CIDR range redirection rules

OID Redirection:
  trapninja filter redirect-oid OID --tag TAG
      Redirect traps with OID to destination group

  trapninja filter unredirect-oid OID
      Remove OID redirection rule

  trapninja filter list-redirected-oids
      List all OID redirection rules

Blocking:
  trapninja filter block-ip IP_OR_CIDR
      Block traps from IP or CIDR range
      Examples: 10.0.0.1  or  10.50.0.0/16

Viewing Configuration:
  trapninja config show               Full configuration overview
  trapninja config blocked-ips        Show blocked IPs
  trapninja config blocked-oids       Show blocked OIDs
  trapninja config redirected-ips     Show IP redirection rules
  trapninja config redirected-oids    Show OID redirection rules
  trapninja config redirect-dests     Show redirect destination groups
  trapninja config destinations       Show forwarding destinations

PRIORITY
--------
When a trap matches multiple rules:
  1. IP redirection is checked first
  2. OID redirection is checked second
  3. Default destinations are used if no redirections match

CONFIGURATION FILES
-------------------
  redirected_destinations.json - Destination groups
  redirected_ips.json          - IP -> tag mappings
  redirected_oids.json         - OID -> tag mappings

Changes take effect within 60 seconds (config reload interval).

================================================================================
"""
    print(help_text)
    return True
