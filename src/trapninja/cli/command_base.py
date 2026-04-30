#!/usr/bin/env python3
"""
TrapNinja CLI Command Base Classes

Provides reusable patterns for configuration management commands,
eliminating duplication across block/unblock/redirect operations.

Three manager types handle the distinct config file structures:

  ConfigListManager    - Simple lists (blocked IPs, blocked OIDs)
  ConfigPairListManager - Lists of [key, tag] pairs (redirected IPs/OIDs)
  ConfigGroupManager   - Dict of tag -> [[ip, port], ...] (redirect destinations)

All managers share the same ConfigFileIO backend for thread-safe,
atomic JSON file operations with caching.

Refactoring: Category A2 from CODE-REVIEW-REFACTORING-ANALYSIS.md
Previously ~400 lines of near-identical code, now ~100 lines of configuration.

Author: TrapNinja Team
"""

import os
import json
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple


# =============================================================================
# CONFIG FILE I/O
# =============================================================================

class ConfigFileIO:
    """
    Thread-safe JSON configuration file I/O with atomic writes and caching.

    Centralises all JSON config file operations previously scattered across
    filtering_commands.ConfigManager, config.safe_load_json(), and inline
    file handling in various modules.

    Thread safety:
      - Per-file RLocks prevent concurrent writes to the same file
      - Cache lock protects the in-memory cache dict
      - Atomic rename prevents partial writes on crash

    Usage:
        config_io = ConfigFileIO()
        data = config_io.load("/etc/trapninja/blocked_ips.json", default=[])
        data.append("10.0.0.1")
        config_io.save("/etc/trapninja/blocked_ips.json", data)
    """

    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._cache_lock = threading.RLock()
        self._file_locks: Dict[str, threading.RLock] = {}
        self._file_locks_lock = threading.Lock()

    def _get_file_lock(self, file_path: str) -> threading.RLock:
        """Get or create a per-file lock for thread-safe operations."""
        if file_path not in self._file_locks:
            with self._file_locks_lock:
                # Double-check after acquiring lock
                if file_path not in self._file_locks:
                    self._file_locks[file_path] = threading.RLock()
        return self._file_locks[file_path]

    def load(self, file_path: str, default: Any = None) -> Any:
        """
        Load JSON data from file with caching.

        Args:
            file_path: Path to JSON file
            default: Default value if file missing or invalid

        Returns:
            Parsed JSON data or default value
        """
        if default is None:
            default = []

        with self._cache_lock:
            if file_path in self._cache:
                return self._cache[file_path]

        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                with self._cache_lock:
                    self._cache[file_path] = data
                return data
            return default
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading {file_path}: {e}")
            return default

    def save(self, file_path: str, data: Any) -> bool:
        """
        Atomically save JSON data to file, invalidating cache on success.

        Uses write-to-temp + rename for crash safety.

        Args:
            file_path: Path to JSON file
            data: Data to serialise

        Returns:
            True on success, False on error
        """
        with self._get_file_lock(file_path):
            temp_path = f"{file_path}.tmp"
            try:
                with open(temp_path, 'w') as f:
                    json.dump(data, f, indent=2)
                os.rename(temp_path, file_path)
                with self._cache_lock:
                    self._cache[file_path] = data
                return True
            except Exception as e:
                print(f"Error saving {file_path}: {e}")
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except OSError:
                    pass
                return False

    def invalidate(self, file_path: Optional[str] = None) -> None:
        """
        Invalidate cached data.

        Args:
            file_path: Specific file to invalidate, or None for all
        """
        with self._cache_lock:
            if file_path:
                self._cache.pop(file_path, None)
            else:
                self._cache.clear()


# Global instance — shared across all command modules
config_io = ConfigFileIO()


# =============================================================================
# LIST MANAGER — for blocked IPs, blocked OIDs
# =============================================================================

class ConfigListManager:
    """
    Manages a JSON list-based configuration file.

    Handles the common add/remove/list pattern used by IP blocking
    and OID blocking commands.

    The file stores a simple JSON array: ["item1", "item2", ...]

    Args:
        file_path_getter: Callable returning the config file path
                          (deferred to avoid import-time config loading)
        validator: Callable that validates and normalises input,
                   returns valid string or None
        item_name: Human-readable name for messages (e.g., "IP address")

    Example:
        ip_blocker = ConfigListManager(
            file_path_getter=lambda: BLOCKED_IPS_FILE,
            validator=InputValidator.validate_ip,
            item_name="IP address",
        )
        ip_blocker.add("10.0.0.1")    # "IP address 10.0.0.1 added to blocked list"
        ip_blocker.remove("10.0.0.1") # "IP address 10.0.0.1 removed from blocked list"
        ip_blocker.list_all()          # "Blocked IP addresses: ..."
    """

    def __init__(
        self,
        file_path_getter: Callable[[], str],
        validator: Callable[[str], Optional[str]],
        item_name: str,
    ):
        self._get_file_path = file_path_getter
        self._validator = validator
        self._item_name = item_name

    @property
    def file_path(self) -> str:
        return self._get_file_path()

    def add(self, value: str) -> bool:
        """
        Add an item to the list.

        Args:
            value: Raw input value (will be validated)

        Returns:
            True if added or already present, False on error
        """
        validated = self._validator(value)
        if not validated:
            return False

        try:
            items = config_io.load(self.file_path, [])
            if not isinstance(items, list):
                items = []

            if validated in items:
                print(f"{self._item_name} {validated} is already in blocked list")
                return True

            items.append(validated)
            if config_io.save(self.file_path, items):
                print(f"{self._item_name} {validated} added to blocked list")
                return True
            return False
        except Exception as e:
            print(f"Error updating {self._item_name} file: {e}")
            return False

    def remove(self, value: str) -> bool:
        """
        Remove an item from the list.

        Args:
            value: Raw input value (will be validated)

        Returns:
            True if removed or not present, False on error
        """
        validated = self._validator(value)
        if not validated:
            return False

        try:
            items = config_io.load(self.file_path, [])
            if not isinstance(items, list):
                print(f"{self._item_name} file contains invalid data")
                return False

            if validated not in items:
                print(f"{self._item_name} {validated} is not in blocked list")
                return True

            items.remove(validated)
            if config_io.save(self.file_path, items):
                print(f"{self._item_name} {validated} removed from blocked list")
                return True
            return False
        except Exception as e:
            print(f"Error updating {self._item_name} file: {e}")
            return False

    def list_all(self) -> bool:
        """
        List all items in the configuration.

        Returns:
            True on success, False on error
        """
        try:
            items = config_io.load(self.file_path, [])
            if items:
                plain_ips = sorted(i for i in items if '/' not in i)
                cidr_ranges = sorted(i for i in items if '/' in i)
                print(f"Blocked {self._item_name}s:")
                if plain_ips:
                    print("  Individual IPs:")
                    for item in plain_ips:
                        print(f"    - {item}")
                if cidr_ranges:
                    print("  CIDR Ranges:")
                    for item in cidr_ranges:
                        print(f"    - {item}")
            else:
                print(f"No {self._item_name}s are currently blocked")
            return True
        except Exception as e:
            print(f"Error reading {self._item_name} file: {e}")
            return False


# =============================================================================
# PAIR LIST MANAGER — for redirected IPs, redirected OIDs
# =============================================================================

class ConfigPairListManager:
    """
    Manages a JSON list of [key, tag] pairs for redirection rules.

    The file stores: [["10.0.0.1", "security"], ["10.0.0.2", "voice"], ...]

    Supports add (with update if key exists), remove, and list operations.
    Tag validation includes checking that the tag exists in the redirect
    destinations file.

    Args:
        file_path_getter: Callable returning the config file path
        dest_file_path_getter: Callable returning the redirect destinations
                               file path (for tag validation)
        key_validator: Validates and normalises the key (IP or OID)
        tag_validator: Validates and normalises the tag
        key_name: Human-readable name for the key (e.g., "IP", "OID")

    Example:
        ip_redirector = ConfigPairListManager(
            file_path_getter=lambda: REDIRECTED_IPS_FILE,
            dest_file_path_getter=lambda: REDIRECTED_DESTINATIONS_FILE,
            key_validator=InputValidator.validate_ip,
            tag_validator=InputValidator.validate_tag,
            key_name="IP",
        )
        ip_redirector.add("10.0.0.1", "security")
        ip_redirector.remove("10.0.0.1")
        ip_redirector.list_all()
    """

    def __init__(
        self,
        file_path_getter: Callable[[], str],
        dest_file_path_getter: Callable[[], str],
        key_validator: Callable[[str], Optional[str]],
        tag_validator: Callable[[str], Optional[str]],
        key_name: str,
    ):
        self._get_file_path = file_path_getter
        self._get_dest_file_path = dest_file_path_getter
        self._key_validator = key_validator
        self._tag_validator = tag_validator
        self._key_name = key_name

    @property
    def file_path(self) -> str:
        return self._get_file_path()

    @property
    def dest_file_path(self) -> str:
        return self._get_dest_file_path()

    def _validate_tag_exists(self, tag: str) -> bool:
        """Check that the tag exists in redirect destinations."""
        redirect_dests = config_io.load(self.dest_file_path, {})
        if tag not in redirect_dests:
            print(f"Warning: Tag '{tag}' not found in redirect destinations.")
            available = ', '.join(redirect_dests.keys()) if redirect_dests else 'none'
            print(f"Available tags: {available}")
            print(f"Use --add-redirect-dest to create the destination group first.")
            return False
        return True

    def add(self, key: str, tag: str) -> bool:
        """
        Add or update a redirection rule.

        If the key already has a different tag, it is updated in-place.

        Args:
            key: Raw key value (IP or OID, will be validated)
            tag: Destination group tag (will be validated)

        Returns:
            True on success, False on error
        """
        valid_key = self._key_validator(key)
        if not valid_key:
            print(f"Invalid {self._key_name}: {key}")
            return False

        valid_tag = self._tag_validator(tag)
        if not valid_tag:
            print(f"Invalid tag: {tag}")
            return False

        try:
            if not self._validate_tag_exists(valid_tag):
                return False

            pairs = config_io.load(self.file_path, [])
            if not isinstance(pairs, list):
                pairs = []

            # Check for existing entry
            for i, entry in enumerate(pairs):
                if len(entry) >= 2 and entry[0] == valid_key:
                    old_tag = entry[1]
                    if old_tag == valid_tag:
                        print(f"{self._key_name} {valid_key} is already redirected to '{valid_tag}'")
                        return True
                    # Update existing entry
                    pairs[i] = [valid_key, valid_tag]
                    if config_io.save(self.file_path, pairs):
                        print(f"Updated {self._key_name} {valid_key} redirection: '{old_tag}' -> '{valid_tag}'")
                        return True
                    return False

            # Add new entry
            pairs.append([valid_key, valid_tag])
            if config_io.save(self.file_path, pairs):
                print(f"{self._key_name} {valid_key} will be redirected to '{valid_tag}'")
                return True
            return False
        except Exception as e:
            print(f"Error updating redirected {self._key_name}s file: {e}")
            return False

    def remove(self, key: str) -> bool:
        """
        Remove a redirection rule.

        Args:
            key: Raw key value (IP or OID, will be validated)

        Returns:
            True if removed or not present, False on error
        """
        valid_key = self._key_validator(key)
        if not valid_key:
            print(f"Invalid {self._key_name}: {key}")
            return False

        try:
            pairs = config_io.load(self.file_path, [])
            if not isinstance(pairs, list):
                print(f"Redirected {self._key_name}s file contains invalid data")
                return False

            original_len = len(pairs)
            pairs = [
                entry for entry in pairs
                if not (len(entry) >= 2 and entry[0] == valid_key)
            ]

            if len(pairs) < original_len:
                if config_io.save(self.file_path, pairs):
                    print(f"{self._key_name} {valid_key} removed from redirection list")
                    return True
                return False
            else:
                print(f"{self._key_name} {valid_key} is not in redirection list")
                return True
        except Exception as e:
            print(f"Error updating redirected {self._key_name}s file: {e}")
            return False

    def list_all(self) -> bool:
        """
        List all redirection rules with their destination tags.

        When CIDR ranges are present alongside plain IPs, entries are grouped
        into "Individual IPs" and "CIDR Ranges" subsections. OID entries and
        plain-IP-only lists use the original flat-table format.

        Returns:
            True on success, False on error
        """
        try:
            pairs = config_io.load(self.file_path, [])
            if pairs:
                valid_pairs = [e for e in pairs if len(e) >= 2]
                has_cidrs = any('/' in e[0] for e in valid_pairs)
                col_width = 45 if self._key_name.startswith("OID") else 24
                print(f"Redirected {self._key_name}s:")

                if has_cidrs:
                    plain_pairs = sorted(
                        (e for e in valid_pairs if '/' not in e[0]),
                        key=lambda x: x[0],
                    )
                    cidr_pairs = sorted(
                        (e for e in valid_pairs if '/' in e[0]),
                        key=lambda x: x[0],
                    )
                    if plain_pairs:
                        print("  Individual IPs:")
                        print(f"    {'Key':<{col_width}} {'Destination Tag'}")
                        print(f"    {'-' * col_width} {'-' * 20}")
                        for entry in plain_pairs:
                            display = entry[0]
                            if len(display) > col_width:
                                display = display[:col_width - 3] + '...'
                            print(f"    {display:<{col_width}} {entry[1]}")
                    if cidr_pairs:
                        print("  CIDR Ranges:")
                        print(f"    {'Range':<{col_width}} {'Destination Tag'}")
                        print(f"    {'-' * col_width} {'-' * 20}")
                        for entry in cidr_pairs:
                            display = entry[0]
                            if len(display) > col_width:
                                display = display[:col_width - 3] + '...'
                            print(f"    {display:<{col_width}} {entry[1]}")
                else:
                    # Flat table — OIDs, or plain-IP-only lists
                    print(f"  {self._key_name:<{col_width}} {'Destination Tag'}")
                    print(f"  {'-' * col_width} {'-' * 20}")
                    for entry in sorted(valid_pairs, key=lambda x: x[0]):
                        display = entry[0]
                        if len(display) > col_width:
                            display = display[:col_width - 3] + '...'
                        print(f"  {display:<{col_width}} {entry[1]}")
            else:
                print(f"No {self._key_name}s are currently redirected")
            return True
        except Exception as e:
            print(f"Error reading redirected {self._key_name}s file: {e}")
            return False


# =============================================================================
# GROUP MANAGER — for redirect destination groups
# =============================================================================

class ConfigGroupManager:
    """
    Manages a JSON dict of tag -> [[ip, port], ...] for redirect destinations.

    The file stores:
    {
        "security": [["10.1.1.100", 162], ["10.1.1.101", 162]],
        "voice":    [["10.2.2.200", 162]]
    }

    Args:
        file_path_getter: Callable returning the config file path
        ip_validator: Validates and normalises IP addresses
        port_validator: Validates and normalises port numbers
        tag_validator: Validates and normalises tag names

    Example:
        dest_manager = ConfigGroupManager(
            file_path_getter=lambda: REDIRECTED_DESTINATIONS_FILE,
            ip_validator=InputValidator.validate_ip,
            port_validator=InputValidator.validate_port,
            tag_validator=InputValidator.validate_tag,
        )
        dest_manager.add("security", "10.1.1.100", 162)
        dest_manager.remove("security", "10.1.1.100", 162)
        dest_manager.list_all()
    """

    def __init__(
        self,
        file_path_getter: Callable[[], str],
        ip_validator: Callable[[str], Optional[str]],
        port_validator: Callable[[Any], Optional[int]],
        tag_validator: Callable[[str], Optional[str]],
    ):
        self._get_file_path = file_path_getter
        self._ip_validator = ip_validator
        self._port_validator = port_validator
        self._tag_validator = tag_validator

    @property
    def file_path(self) -> str:
        return self._get_file_path()

    def add(self, tag: str, ip_address: str, port: Any) -> bool:
        """
        Add a destination to a redirect group.

        Creates the group if it doesn't exist.

        Args:
            tag: Destination group tag
            ip_address: Destination IP address
            port: Destination port number

        Returns:
            True on success or already exists, False on error
        """
        valid_tag = self._tag_validator(tag)
        if not valid_tag:
            print(f"Invalid tag: {tag}")
            return False

        valid_ip = self._ip_validator(ip_address)
        if not valid_ip:
            print(f"Invalid IP address: {ip_address}")
            return False

        valid_port = self._port_validator(port)
        if not valid_port:
            print(f"Invalid port: {port}")
            return False

        try:
            groups = config_io.load(self.file_path, {})
            if not isinstance(groups, dict):
                groups = {}

            if valid_tag not in groups:
                groups[valid_tag] = []

            # Check for duplicate
            dest_entry = [valid_ip, valid_port]
            for existing in groups[valid_tag]:
                if existing[0] == valid_ip and existing[1] == valid_port:
                    print(f"Destination {valid_ip}:{valid_port} already exists in group '{valid_tag}'")
                    return True

            groups[valid_tag].append(dest_entry)
            if config_io.save(self.file_path, groups):
                print(f"Added {valid_ip}:{valid_port} to redirect group '{valid_tag}'")
                return True
            return False
        except Exception as e:
            print(f"Error updating redirect destinations file: {e}")
            return False

    def remove(self, tag: str, ip_address: str, port: Any) -> bool:
        """
        Remove a destination from a redirect group.

        Removes the group entirely if it becomes empty.

        Args:
            tag: Destination group tag
            ip_address: Destination IP address
            port: Destination port number

        Returns:
            True if removed or not found, False on error
        """
        valid_tag = self._tag_validator(tag)
        if not valid_tag:
            print(f"Invalid tag: {tag}")
            return False

        valid_ip = self._ip_validator(ip_address)
        if not valid_ip:
            print(f"Invalid IP address: {ip_address}")
            return False

        valid_port = self._port_validator(port)
        if not valid_port:
            print(f"Invalid port: {port}")
            return False

        try:
            groups = config_io.load(self.file_path, {})
            if not isinstance(groups, dict):
                print("Redirect destinations file contains invalid data")
                return False

            if valid_tag not in groups:
                print(f"Tag '{valid_tag}' not found in redirect destinations")
                return False

            original_len = len(groups[valid_tag])
            groups[valid_tag] = [
                dest for dest in groups[valid_tag]
                if not (dest[0] == valid_ip and dest[1] == valid_port)
            ]

            if len(groups[valid_tag]) < original_len:
                if not groups[valid_tag]:
                    del groups[valid_tag]
                    msg = f"Removed {valid_ip}:{valid_port} from '{valid_tag}' (group now empty and removed)"
                else:
                    msg = f"Removed {valid_ip}:{valid_port} from redirect group '{valid_tag}'"

                if config_io.save(self.file_path, groups):
                    print(msg)
                    return True
                return False
            else:
                print(f"Destination {valid_ip}:{valid_port} not found in group '{valid_tag}'")
                return True
        except Exception as e:
            print(f"Error updating redirect destinations file: {e}")
            return False

    def list_all(self) -> bool:
        """
        List all redirect destination groups and their destinations.

        Returns:
            True on success, False on error
        """
        try:
            groups = config_io.load(self.file_path, {})
            if groups:
                print("Redirect destination groups:")
                print()
                for tag in sorted(groups.keys()):
                    destinations = groups[tag]
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
