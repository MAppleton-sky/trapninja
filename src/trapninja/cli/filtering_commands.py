#!/usr/bin/env python3
"""
TrapNinja Filtering Commands Module

Handles IP and OID blocking/unblocking operations via command-line interface.
"""

import os
import json
from typing import List, Optional
from .validation import InputValidator


class ConfigManager:
    """Centralized configuration file management with atomic operations and caching"""

    def __init__(self):
        self._cache = {}
        import threading
        self._cache_lock = threading.RLock()
        self._file_locks = {}

    def _file_lock(self, file_path: str):
        """Get a per-file lock for thread-safe operations"""
        import threading
        from contextlib import contextmanager

        if file_path not in self._file_locks:
            self._file_locks[file_path] = threading.RLock()

        @contextmanager
        def lock_context():
            with self._file_locks[file_path]:
                yield

        return lock_context()

    def load_json(self, file_path: str, default_value=None):
        """Load JSON with caching and validation"""
        with self._cache_lock:
            # Check cache first
            if file_path in self._cache:
                return self._cache[file_path]

            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        self._cache[file_path] = data
                        return data
                else:
                    return default_value or []
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading {file_path}: {e}")
                return default_value or []

    def save_json(self, file_path: str, data) -> bool:
        """Atomic JSON save with cache invalidation"""
        with self._file_lock(file_path):
            try:
                # Write to temporary file first
                temp_path = f"{file_path}.tmp"
                with open(temp_path, 'w') as f:
                    json.dump(data, f, indent=2)

                # Atomic rename
                os.rename(temp_path, file_path)

                # Update cache
                with self._cache_lock:
                    self._cache[file_path] = data

                return True
            except Exception as e:
                print(f"Error saving {file_path}: {e}")
                # Clean up temp file
                try:
                    if os.path.exists(f"{file_path}.tmp"):
                        os.remove(f"{file_path}.tmp")
                except:
                    pass
                return False

    def invalidate_cache(self, file_path: str = None):
        """Invalidate cache for specific file or all files"""
        with self._cache_lock:
            if file_path:
                self._cache.pop(file_path, None)
            else:
                self._cache.clear()


# Global configuration manager instance
config_manager = ConfigManager()


def block_ip(ip_address: str) -> bool:
    """
    Add an IP address to the blocked IPs list

    Args:
        ip_address: IP address to block

    Returns:
        True if successful, False otherwise
    """
    from ..config import BLOCKED_IPS_FILE

    valid_ip = InputValidator.validate_ip(ip_address)
    if not valid_ip:
        return False

    try:
        blocked_ips = config_manager.load_json(BLOCKED_IPS_FILE, [])
        if not isinstance(blocked_ips, list):
            blocked_ips = []

        if valid_ip not in blocked_ips:
            blocked_ips.append(valid_ip)
            if config_manager.save_json(BLOCKED_IPS_FILE, blocked_ips):
                print(f"IP address {valid_ip} added to blocked list")
                return True
        else:
            print(f"IP address {valid_ip} is already in blocked list")
            return True
    except Exception as e:
        print(f"Error updating blocked IPs file: {e}")
        return False


def unblock_ip(ip_address: str) -> bool:
    """
    Remove an IP address from the blocked IPs list

    Args:
        ip_address: IP address to unblock

    Returns:
        True if successful, False otherwise
    """
    from ..config import BLOCKED_IPS_FILE

    valid_ip = InputValidator.validate_ip(ip_address)
    if not valid_ip:
        return False

    try:
        blocked_ips = config_manager.load_json(BLOCKED_IPS_FILE, [])
        if not isinstance(blocked_ips, list):
            print("Blocked IPs file contains invalid data")
            return False

        if valid_ip in blocked_ips:
            blocked_ips.remove(valid_ip)
            if config_manager.save_json(BLOCKED_IPS_FILE, blocked_ips):
                print(f"IP address {valid_ip} removed from blocked list")
                return True
        else:
            print(f"IP address {valid_ip} is not in blocked list")
            return True
    except Exception as e:
        print(f"Error updating blocked IPs file: {e}")
        return False


def list_blocked_ips() -> bool:
    """
    List all blocked IP addresses

    Returns:
        True if successful, False otherwise
    """
    from ..config import BLOCKED_IPS_FILE

    try:
        blocked_ips = config_manager.load_json(BLOCKED_IPS_FILE, [])
        if blocked_ips:
            print("Blocked IP addresses:")
            for ip in sorted(blocked_ips):
                print(f"  - {ip}")
        else:
            print("No IP addresses are currently blocked")
        return True
    except Exception as e:
        print(f"Error reading blocked IPs file: {e}")
        return False


def block_oid(oid: str) -> bool:
    """
    Add an OID to the blocked traps list

    Args:
        oid: OID to block

    Returns:
        True if successful, False otherwise
    """
    from ..config import BLOCKED_TRAPS_FILE

    valid_oid = InputValidator.validate_oid(oid)
    if not valid_oid:
        return False

    try:
        blocked_oids = config_manager.load_json(BLOCKED_TRAPS_FILE, [])
        if not isinstance(blocked_oids, list):
            blocked_oids = []

        if valid_oid not in blocked_oids:
            blocked_oids.append(valid_oid)
            if config_manager.save_json(BLOCKED_TRAPS_FILE, blocked_oids):
                print(f"OID {valid_oid} added to blocked list")
                return True
        else:
            print(f"OID {valid_oid} is already in blocked list")
            return True
    except Exception as e:
        print(f"Error updating blocked OIDs file: {e}")
        return False


def unblock_oid(oid: str) -> bool:
    """
    Remove an OID from the blocked traps list

    Args:
        oid: OID to unblock

    Returns:
        True if successful, False otherwise
    """
    from ..config import BLOCKED_TRAPS_FILE

    valid_oid = InputValidator.validate_oid(oid)
    if not valid_oid:
        return False

    try:
        blocked_oids = config_manager.load_json(BLOCKED_TRAPS_FILE, [])
        if not isinstance(blocked_oids, list):
            print("Blocked OIDs file contains invalid data")
            return False

        if valid_oid in blocked_oids:
            blocked_oids.remove(valid_oid)
            if config_manager.save_json(BLOCKED_TRAPS_FILE, blocked_oids):
                print(f"OID {valid_oid} removed from blocked list")
                return True
        else:
            print(f"OID {valid_oid} is not in blocked list")
            return True
    except Exception as e:
        print(f"Error updating blocked OIDs file: {e}")
        return False


def list_blocked_oids() -> bool:
    """
    List all blocked OIDs

    Returns:
        True if successful, False otherwise
    """
    from ..config import BLOCKED_TRAPS_FILE

    try:
        blocked_oids = config_manager.load_json(BLOCKED_TRAPS_FILE, [])
        if blocked_oids:
            print("Blocked trap OIDs:")
            for oid in sorted(blocked_oids):
                print(f"  - {oid}")
        else:
            print("No trap OIDs are currently blocked")
        return True
    except Exception as e:
        print(f"Error reading blocked traps file: {e}")
        return False


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
    from ..config import REDIRECTED_IPS_FILE, REDIRECTED_DESTINATIONS_FILE

    valid_ip = InputValidator.validate_ip(ip_address)
    if not valid_ip:
        print(f"Invalid IP address: {ip_address}")
        return False

    valid_tag = InputValidator.validate_tag(tag)
    if not valid_tag:
        print(f"Invalid tag: {tag}")
        return False

    try:
        # Verify the tag exists in redirect destinations
        redirect_dests = config_manager.load_json(REDIRECTED_DESTINATIONS_FILE, {})
        if valid_tag not in redirect_dests:
            print(f"Warning: Tag '{valid_tag}' not found in redirect destinations.")
            print(f"Available tags: {', '.join(redirect_dests.keys()) if redirect_dests else 'none'}")
            print(f"Use --add-redirect-dest to create the destination group first.")
            return False

        # Load current redirected IPs (list of [ip, tag] pairs)
        redirected_ips = config_manager.load_json(REDIRECTED_IPS_FILE, [])
        if not isinstance(redirected_ips, list):
            redirected_ips = []

        # Check if IP already has a redirection
        for i, entry in enumerate(redirected_ips):
            if len(entry) >= 2 and entry[0] == valid_ip:
                old_tag = entry[1]
                if old_tag == valid_tag:
                    print(f"IP {valid_ip} is already redirected to '{valid_tag}'")
                    return True
                else:
                    # Update existing entry
                    redirected_ips[i] = [valid_ip, valid_tag]
                    if config_manager.save_json(REDIRECTED_IPS_FILE, redirected_ips):
                        print(f"Updated IP {valid_ip} redirection: '{old_tag}' -> '{valid_tag}'")
                        return True
                    return False

        # Add new entry
        redirected_ips.append([valid_ip, valid_tag])
        if config_manager.save_json(REDIRECTED_IPS_FILE, redirected_ips):
            print(f"IP {valid_ip} will be redirected to '{valid_tag}'")
            return True
        return False

    except Exception as e:
        print(f"Error updating redirected IPs file: {e}")
        return False


def unredirect_ip(ip_address: str) -> bool:
    """
    Remove an IP address from the redirected IPs list.

    Args:
        ip_address: IP address to remove from redirection

    Returns:
        True if successful, False otherwise
    """
    from ..config import REDIRECTED_IPS_FILE

    valid_ip = InputValidator.validate_ip(ip_address)
    if not valid_ip:
        print(f"Invalid IP address: {ip_address}")
        return False

    try:
        redirected_ips = config_manager.load_json(REDIRECTED_IPS_FILE, [])
        if not isinstance(redirected_ips, list):
            print("Redirected IPs file contains invalid data")
            return False

        # Find and remove the entry
        original_len = len(redirected_ips)
        redirected_ips = [entry for entry in redirected_ips 
                         if not (len(entry) >= 2 and entry[0] == valid_ip)]

        if len(redirected_ips) < original_len:
            if config_manager.save_json(REDIRECTED_IPS_FILE, redirected_ips):
                print(f"IP {valid_ip} removed from redirection list")
                return True
            return False
        else:
            print(f"IP {valid_ip} is not in redirection list")
            return True

    except Exception as e:
        print(f"Error updating redirected IPs file: {e}")
        return False


def list_redirected_ips() -> bool:
    """
    List all redirected IP addresses with their destination tags.

    Returns:
        True if successful, False otherwise
    """
    from ..config import REDIRECTED_IPS_FILE

    try:
        redirected_ips = config_manager.load_json(REDIRECTED_IPS_FILE, [])
        if redirected_ips:
            print("Redirected IP addresses:")
            print(f"  {'IP Address':<20} {'Destination Tag'}")
            print(f"  {'-'*20} {'-'*20}")
            for entry in sorted(redirected_ips, key=lambda x: x[0] if len(x) >= 1 else ''):
                if len(entry) >= 2:
                    print(f"  {entry[0]:<20} {entry[1]}")
        else:
            print("No IP addresses are currently redirected")
        return True
    except Exception as e:
        print(f"Error reading redirected IPs file: {e}")
        return False


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
    from ..config import REDIRECTED_OIDS_FILE, REDIRECTED_DESTINATIONS_FILE

    valid_oid = InputValidator.validate_oid(oid)
    if not valid_oid:
        print(f"Invalid OID: {oid}")
        return False

    valid_tag = InputValidator.validate_tag(tag)
    if not valid_tag:
        print(f"Invalid tag: {tag}")
        return False

    try:
        # Verify the tag exists in redirect destinations
        redirect_dests = config_manager.load_json(REDIRECTED_DESTINATIONS_FILE, {})
        if valid_tag not in redirect_dests:
            print(f"Warning: Tag '{valid_tag}' not found in redirect destinations.")
            print(f"Available tags: {', '.join(redirect_dests.keys()) if redirect_dests else 'none'}")
            print(f"Use --add-redirect-dest to create the destination group first.")
            return False

        # Load current redirected OIDs (list of [oid, tag] pairs)
        redirected_oids = config_manager.load_json(REDIRECTED_OIDS_FILE, [])
        if not isinstance(redirected_oids, list):
            redirected_oids = []

        # Check if OID already has a redirection
        for i, entry in enumerate(redirected_oids):
            if len(entry) >= 2 and entry[0] == valid_oid:
                old_tag = entry[1]
                if old_tag == valid_tag:
                    print(f"OID {valid_oid} is already redirected to '{valid_tag}'")
                    return True
                else:
                    # Update existing entry
                    redirected_oids[i] = [valid_oid, valid_tag]
                    if config_manager.save_json(REDIRECTED_OIDS_FILE, redirected_oids):
                        print(f"Updated OID {valid_oid} redirection: '{old_tag}' -> '{valid_tag}'")
                        return True
                    return False

        # Add new entry
        redirected_oids.append([valid_oid, valid_tag])
        if config_manager.save_json(REDIRECTED_OIDS_FILE, redirected_oids):
            print(f"OID {valid_oid} will be redirected to '{valid_tag}'")
            return True
        return False

    except Exception as e:
        print(f"Error updating redirected OIDs file: {e}")
        return False


def unredirect_oid(oid: str) -> bool:
    """
    Remove an OID from the redirected OIDs list.

    Args:
        oid: OID to remove from redirection

    Returns:
        True if successful, False otherwise
    """
    from ..config import REDIRECTED_OIDS_FILE

    valid_oid = InputValidator.validate_oid(oid)
    if not valid_oid:
        print(f"Invalid OID: {oid}")
        return False

    try:
        redirected_oids = config_manager.load_json(REDIRECTED_OIDS_FILE, [])
        if not isinstance(redirected_oids, list):
            print("Redirected OIDs file contains invalid data")
            return False

        # Find and remove the entry
        original_len = len(redirected_oids)
        redirected_oids = [entry for entry in redirected_oids 
                          if not (len(entry) >= 2 and entry[0] == valid_oid)]

        if len(redirected_oids) < original_len:
            if config_manager.save_json(REDIRECTED_OIDS_FILE, redirected_oids):
                print(f"OID {valid_oid} removed from redirection list")
                return True
            return False
        else:
            print(f"OID {valid_oid} is not in redirection list")
            return True

    except Exception as e:
        print(f"Error updating redirected OIDs file: {e}")
        return False


def list_redirected_oids() -> bool:
    """
    List all redirected OIDs with their destination tags.

    Returns:
        True if successful, False otherwise
    """
    from ..config import REDIRECTED_OIDS_FILE

    try:
        redirected_oids = config_manager.load_json(REDIRECTED_OIDS_FILE, [])
        if redirected_oids:
            print("Redirected OIDs:")
            print(f"  {'OID':<45} {'Destination Tag'}")
            print(f"  {'-'*45} {'-'*20}")
            for entry in sorted(redirected_oids, key=lambda x: x[0] if len(x) >= 1 else ''):
                if len(entry) >= 2:
                    oid_display = entry[0] if len(entry[0]) <= 45 else entry[0][:42] + '...'
                    print(f"  {oid_display:<45} {entry[1]}")
        else:
            print("No OIDs are currently redirected")
        return True
    except Exception as e:
        print(f"Error reading redirected OIDs file: {e}")
        return False


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
    from ..config import REDIRECTED_DESTINATIONS_FILE

    valid_tag = InputValidator.validate_tag(tag)
    if not valid_tag:
        print(f"Invalid tag: {tag}")
        return False

    valid_ip = InputValidator.validate_ip(ip_address)
    if not valid_ip:
        print(f"Invalid IP address: {ip_address}")
        return False

    valid_port = InputValidator.validate_port(port)
    if not valid_port:
        print(f"Invalid port: {port}")
        return False

    try:
        redirect_dests = config_manager.load_json(REDIRECTED_DESTINATIONS_FILE, {})
        if not isinstance(redirect_dests, dict):
            redirect_dests = {}

        # Get or create the tag's destination list
        if valid_tag not in redirect_dests:
            redirect_dests[valid_tag] = []

        # Check if destination already exists
        dest_entry = [valid_ip, valid_port]
        for existing in redirect_dests[valid_tag]:
            if existing[0] == valid_ip and existing[1] == valid_port:
                print(f"Destination {valid_ip}:{valid_port} already exists in group '{valid_tag}'")
                return True

        # Add the destination
        redirect_dests[valid_tag].append(dest_entry)
        if config_manager.save_json(REDIRECTED_DESTINATIONS_FILE, redirect_dests):
            print(f"Added {valid_ip}:{valid_port} to redirect group '{valid_tag}'")
            return True
        return False

    except Exception as e:
        print(f"Error updating redirect destinations file: {e}")
        return False


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
    from ..config import REDIRECTED_DESTINATIONS_FILE

    valid_tag = InputValidator.validate_tag(tag)
    if not valid_tag:
        print(f"Invalid tag: {tag}")
        return False

    valid_ip = InputValidator.validate_ip(ip_address)
    if not valid_ip:
        print(f"Invalid IP address: {ip_address}")
        return False

    valid_port = InputValidator.validate_port(port)
    if not valid_port:
        print(f"Invalid port: {port}")
        return False

    try:
        redirect_dests = config_manager.load_json(REDIRECTED_DESTINATIONS_FILE, {})
        if not isinstance(redirect_dests, dict):
            print("Redirect destinations file contains invalid data")
            return False

        if valid_tag not in redirect_dests:
            print(f"Tag '{valid_tag}' not found in redirect destinations")
            return False

        # Find and remove the destination
        original_len = len(redirect_dests[valid_tag])
        redirect_dests[valid_tag] = [
            dest for dest in redirect_dests[valid_tag]
            if not (dest[0] == valid_ip and dest[1] == valid_port)
        ]

        if len(redirect_dests[valid_tag]) < original_len:
            # Remove empty groups
            if not redirect_dests[valid_tag]:
                del redirect_dests[valid_tag]
                print(f"Removed {valid_ip}:{valid_port} from '{valid_tag}' (group now empty and removed)")
            else:
                print(f"Removed {valid_ip}:{valid_port} from redirect group '{valid_tag}'")
            
            if config_manager.save_json(REDIRECTED_DESTINATIONS_FILE, redirect_dests):
                return True
            return False
        else:
            print(f"Destination {valid_ip}:{valid_port} not found in group '{valid_tag}'")
            return True

    except Exception as e:
        print(f"Error updating redirect destinations file: {e}")
        return False


def list_redirect_destinations() -> bool:
    """
    List all redirect destination groups and their destinations.

    Returns:
        True if successful, False otherwise
    """
    from ..config import REDIRECTED_DESTINATIONS_FILE

    try:
        redirect_dests = config_manager.load_json(REDIRECTED_DESTINATIONS_FILE, {})
        if redirect_dests:
            print("Redirect destination groups:")
            print()
            for tag in sorted(redirect_dests.keys()):
                destinations = redirect_dests[tag]
                print(f"  [{tag}]")
                if destinations:
                    for dest in destinations:
                        if len(dest) >= 2:
                            print(f"    - {dest[0]}:{dest[1]}")
                else:
                    print(f"    (no destinations)")
                print()
        else:
            print("No redirect destination groups configured")
        return True
    except Exception as e:
        print(f"Error reading redirect destinations file: {e}")
        return False


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

CONCEPTS
--------

1. DESTINATION GROUPS (--list-redirect-dests)
   Named groups of IP:port destinations. Create these first.
   Example: "security" group with destinations 10.1.1.100:162, 10.1.1.101:162

2. IP REDIRECTIONS (--list-redirected-ips)
   Map source IPs to destination groups.
   Example: Traps from 192.168.10.50 -> "security" group

3. OID REDIRECTIONS (--list-redirected-oids)
   Map trap OIDs to destination groups.
   Example: OID 1.3.6.1.4.1.9.9.41.2.0.1 -> "config" group

WORKFLOW
--------

Step 1: Create destination group
  trapninja --add-redirect-dest --tag security --ip 10.1.1.100 --port 162
  trapninja --add-redirect-dest --tag security --ip 10.1.1.101 --port 162

Step 2: Add redirection rules
  # Redirect by source IP
  trapninja --redirect-ip 192.168.10.50 --tag security
  
  # Redirect by OID
  trapninja --redirect-oid 1.3.6.1.4.1.9.9.41.2.0.1 --tag security

Step 3: Verify configuration
  trapninja --list-redirect-dests
  trapninja --list-redirected-ips
  trapninja --list-redirected-oids

COMMANDS REFERENCE
------------------

Destination Groups:
  --add-redirect-dest --tag TAG --ip IP --port PORT
      Add a destination to a redirect group
  
  --remove-redirect-dest --tag TAG --ip IP --port PORT
      Remove a destination from a redirect group
  
  --list-redirect-dests
      List all redirect destination groups

IP Redirection:
  --redirect-ip IP --tag TAG
      Redirect traps from IP to destination group
  
  --unredirect-ip IP
      Remove IP redirection rule
  
  --list-redirected-ips
      List all IP redirection rules

OID Redirection:
  --redirect-oid OID --tag TAG
      Redirect traps with OID to destination group
  
  --unredirect-oid OID
      Remove OID redirection rule
  
  --list-redirected-oids
      List all OID redirection rules

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
