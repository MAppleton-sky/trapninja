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
