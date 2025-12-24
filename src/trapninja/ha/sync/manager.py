#!/usr/bin/env python3
"""
TrapNinja HA Config Synchronization Manager

Simplified implementation for synchronizing shared configurations between
HA cluster nodes. Integrates with HACluster for seamless config sync.

Design Principles:
    - Primary pushes config changes to Secondary
    - Secondary pulls configs from Primary on startup
    - Checksums in heartbeats detect config drift
    - Configs are written to local files on sync

Shared Configurations (synced between nodes):
    - destinations.json: Forward destinations
    - blocked_ips.json: Blocked source IPs
    - blocked_traps.json: Blocked trap OIDs
    - redirected_ips.json: IP-based redirection rules
    - redirected_oids.json: OID-based redirection rules
    - redirected_destinations.json: Redirection target destinations

Local Configurations (NOT synced):
    - ha_config.json: Node-specific HA settings
    - cache_config.json: Node-specific cache settings
    - listen_ports.json: Node-specific listening ports
    - capture_config.json, shadow_config.json, stats_config.json, sync_config.json

Author: TrapNinja Team
Version: 2.0.0
"""

import hashlib
import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("trapninja")


# Shared config files that get synchronized
SHARED_CONFIG_FILES = [
    "destinations.json",
    "blocked_ips.json",
    "blocked_traps.json",
    "redirected_ips.json",
    "redirected_oids.json",
    "redirected_destinations.json",
]

# Local-only configs that should NEVER be synced
LOCAL_ONLY_CONFIGS = frozenset({
    "ha_config.json",
    "cache_config.json",
    "listen_ports.json",
    "capture_config.json",
    "shadow_config.json",
    "stats_config.json",
    "sync_config.json",
})


@dataclass
class ConfigBundle:
    """Bundle of shared configuration files for sync."""
    configs: Dict[str, Any] = field(default_factory=dict)
    checksum: str = ""
    timestamp: float = 0.0
    source_instance: str = ""
    
    def __post_init__(self):
        if not self.checksum and self.configs:
            self.checksum = self._calculate_checksum()
        if not self.timestamp:
            self.timestamp = time.time()
    
    def _calculate_checksum(self) -> str:
        """Calculate overall checksum of all configs."""
        combined = json.dumps(self.configs, sort_keys=True)
        return hashlib.md5(combined.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'configs': self.configs,
            'checksum': self.checksum,
            'timestamp': self.timestamp,
            'source_instance': self.source_instance,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigBundle':
        return cls(
            configs=data.get('configs', {}),
            checksum=data.get('checksum', ''),
            timestamp=data.get('timestamp', 0.0),
            source_instance=data.get('source_instance', ''),
        )
    
    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ConfigBundle':
        return cls.from_dict(json.loads(data.decode('utf-8')))


class ConfigSyncManager:
    """
    Manages configuration synchronization between HA cluster nodes.
    
    Simplified interface that integrates directly with HACluster.
    """
    
    def __init__(
        self,
        config_dir: str,
        instance_id: str,
        peer_host: str,
        peer_port: int,
        on_config_changed: Optional[Callable[[], None]] = None
    ):
        """
        Initialize the config sync manager.
        
        Args:
            config_dir: Path to local configuration directory
            instance_id: Unique identifier for this node
            peer_host: Peer's hostname or IP
            peer_port: Peer's HA port
            on_config_changed: Callback when configs are updated from sync
        """
        self.config_dir = config_dir
        self.instance_id = instance_id
        self.peer_host = peer_host
        self.peer_port = peer_port
        self.on_config_changed = on_config_changed
        
        self._lock = threading.RLock()
        self._is_primary = False
        self._local_checksum: Optional[str] = None
        self._remote_checksum: Optional[str] = None
        self._checksum_mismatch_count = 0
        
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        
        # Stats
        self._stats = {
            'pulls_completed': 0,
            'pushes_completed': 0,
            'pull_failures': 0,
            'push_failures': 0,
            'last_sync_time': None,
            'last_error': None,
        }
        
        # Calculate initial checksum
        self._local_checksum = self._calculate_local_checksum()
        
        logger.info(f"ConfigSyncManager initialized for {instance_id[:8]}...")
        logger.info(f"Config dir: {config_dir}, Peer: {peer_host}:{peer_port}")
    
    def _calculate_local_checksum(self) -> str:
        """Calculate checksum of all local shared configs."""
        checksums = []
        for filename in sorted(SHARED_CONFIG_FILES):
            filepath = os.path.join(self.config_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        content = json.load(f)
                    file_checksum = hashlib.md5(
                        json.dumps(content, sort_keys=True).encode()
                    ).hexdigest()
                    checksums.append(f"{filename}:{file_checksum}")
                except Exception as e:
                    logger.debug(f"Error reading {filename}: {e}")
                    checksums.append(f"{filename}:error")
            else:
                checksums.append(f"{filename}:missing")
        
        combined = "|".join(checksums)
        return hashlib.md5(combined.encode()).hexdigest()
    
    def get_local_checksum(self) -> str:
        """Get the current local config checksum."""
        with self._lock:
            if self._local_checksum is None:
                self._local_checksum = self._calculate_local_checksum()
            return self._local_checksum
    
    def update_remote_checksum(self, checksum: str):
        """Update the remote peer's config checksum (from heartbeat)."""
        with self._lock:
            old_checksum = self._remote_checksum
            self._remote_checksum = checksum
            
            # Check for mismatch
            if self._local_checksum and checksum != self._local_checksum:
                self._checksum_mismatch_count += 1
                if self._checksum_mismatch_count >= 3:
                    logger.info(
                        f"Config checksum mismatch detected "
                        f"(local={self._local_checksum[:8]}..., "
                        f"remote={checksum[:8]}...) - will sync"
                    )
                    # If we're secondary, pull from primary
                    if not self._is_primary:
                        threading.Thread(
                            target=self._pull_configs_async,
                            daemon=True
                        ).start()
                    self._checksum_mismatch_count = 0
            else:
                self._checksum_mismatch_count = 0
    
    def set_primary(self, is_primary: bool):
        """Set whether this node is primary (called on state change)."""
        with self._lock:
            was_primary = self._is_primary
            self._is_primary = is_primary
            
            if is_primary and not was_primary:
                logger.info("Became PRIMARY - will push configs to peer on changes")
            elif not is_primary and was_primary:
                logger.info("Became SECONDARY - pulling configs from PRIMARY")
                # Pull configs when becoming secondary
                threading.Thread(
                    target=self._pull_configs_async,
                    daemon=True
                ).start()
    
    def start(self, is_primary: bool = False):
        """
        Start the config sync system.
        
        Args:
            is_primary: Whether this node is starting as primary
        """
        logger.info(f"Starting config sync (is_primary={is_primary})...")
        
        self._is_primary = is_primary
        self._stop_event.clear()
        
        # Start file monitor thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="ConfigSyncMonitor"
        )
        self._monitor_thread.start()
        
        # If starting as secondary, pull configs from primary
        if not is_primary:
            logger.info("Starting as SECONDARY - pulling configs from PRIMARY...")
            # Give the primary a moment to be ready
            time.sleep(2.0)
            success = self.pull_configs()
            if success:
                logger.info("Initial config sync from PRIMARY completed")
            else:
                logger.warning("Initial config sync from PRIMARY failed - will retry")
        
        logger.info("Config sync system started")
    
    def stop(self):
        """Stop the config sync system."""
        logger.info("Stopping config sync system...")
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3.0)
        
        logger.info("Config sync system stopped")
    
    def _monitor_loop(self):
        """Background loop for monitoring file changes (PRIMARY only)."""
        logger.debug("Config sync monitor started")
        
        last_checksum = self._local_checksum
        
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(timeout=10.0):
                    break
                
                # Only monitor for changes if we're primary
                if self._is_primary:
                    current_checksum = self._calculate_local_checksum()
                    
                    if current_checksum != last_checksum:
                        logger.info("Local config changed - pushing to peer")
                        with self._lock:
                            self._local_checksum = current_checksum
                        self.push_configs()
                        last_checksum = current_checksum
                else:
                    # Update local checksum periodically
                    with self._lock:
                        self._local_checksum = self._calculate_local_checksum()
                        
            except Exception as e:
                logger.warning(f"Config sync monitor error: {e}")
        
        logger.debug("Config sync monitor stopped")
    
    def _pull_configs_async(self):
        """Pull configs in background thread."""
        try:
            time.sleep(1.0)  # Brief delay to avoid overwhelming peer
            self.pull_configs()
        except Exception as e:
            logger.error(f"Async config pull failed: {e}")
    
    def pull_configs(self) -> bool:
        """
        Pull all shared configs from PRIMARY.
        
        Returns:
            True if successful
        """
        logger.info(f"Pulling configs from {self.peer_host}:{self.peer_port}...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            
            try:
                sock.connect((self.peer_host, self.peer_port))
                
                # Send config request
                request = {
                    'type': 'config_request',
                    'sender': self.instance_id,
                    'timestamp': time.time(),
                }
                sock.send(json.dumps(request).encode('utf-8'))
                
                # Receive response
                response_data = sock.recv(65536)
                if not response_data:
                    logger.warning("Empty response from peer")
                    self._stats['pull_failures'] += 1
                    return False
                
                response = json.loads(response_data.decode('utf-8'))
                
                if response.get('type') == 'config_response':
                    bundle = ConfigBundle.from_dict(response.get('bundle', {}))
                    return self._apply_bundle(bundle)
                else:
                    logger.warning(f"Unexpected response type: {response.get('type')}")
                    self._stats['pull_failures'] += 1
                    return False
                    
            finally:
                sock.close()
                
        except socket.timeout:
            logger.warning("Config pull timeout")
            self._stats['pull_failures'] += 1
            self._stats['last_error'] = "Pull timeout"
            return False
        except ConnectionRefusedError:
            logger.warning("Peer not available for config pull")
            self._stats['pull_failures'] += 1
            self._stats['last_error'] = "Connection refused"
            return False
        except Exception as e:
            logger.error(f"Config pull failed: {e}")
            self._stats['pull_failures'] += 1
            self._stats['last_error'] = str(e)
            return False
    
    def push_configs(self) -> bool:
        """
        Push all shared configs to SECONDARY.
        
        Returns:
            True if successful
        """
        if not self._is_primary:
            logger.warning("Cannot push configs - not PRIMARY")
            return False
        
        logger.info(f"Pushing configs to {self.peer_host}:{self.peer_port}...")
        
        try:
            bundle = self._create_bundle()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            
            try:
                sock.connect((self.peer_host, self.peer_port))
                
                # Send config push
                message = {
                    'type': 'config_push',
                    'sender': self.instance_id,
                    'timestamp': time.time(),
                    'bundle': bundle.to_dict(),
                }
                sock.send(json.dumps(message).encode('utf-8'))
                
                # Wait for ack
                response_data = sock.recv(4096)
                if response_data:
                    response = json.loads(response_data.decode('utf-8'))
                    if response.get('success'):
                        logger.info("Config push acknowledged by peer")
                        self._stats['pushes_completed'] += 1
                        self._stats['last_sync_time'] = time.time()
                        return True
                    else:
                        logger.warning(f"Config push rejected: {response.get('error')}")
                        self._stats['push_failures'] += 1
                        return False
                
                # No response but no error - assume success
                self._stats['pushes_completed'] += 1
                self._stats['last_sync_time'] = time.time()
                return True
                
            finally:
                sock.close()
                
        except socket.timeout:
            logger.warning("Config push timeout")
            self._stats['push_failures'] += 1
            return False
        except ConnectionRefusedError:
            logger.debug("Peer not available for config push")
            self._stats['push_failures'] += 1
            return False
        except Exception as e:
            logger.error(f"Config push failed: {e}")
            self._stats['push_failures'] += 1
            self._stats['last_error'] = str(e)
            return False
    
    def _create_bundle(self) -> ConfigBundle:
        """Create a bundle from local config files."""
        configs = {}
        
        for filename in SHARED_CONFIG_FILES:
            filepath = os.path.join(self.config_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        configs[filename] = json.load(f)
                except Exception as e:
                    logger.warning(f"Error reading {filename}: {e}")
                    # Use empty default
                    if 'destination' in filename.lower():
                        configs[filename] = {}
                    else:
                        configs[filename] = []
            else:
                # File doesn't exist - use empty default
                if 'destination' in filename.lower():
                    configs[filename] = {}
                else:
                    configs[filename] = []
        
        return ConfigBundle(
            configs=configs,
            source_instance=self.instance_id,
        )
    
    def _apply_bundle(self, bundle: ConfigBundle) -> bool:
        """
        Apply a received config bundle to local files.
        
        Args:
            bundle: ConfigBundle to apply
            
        Returns:
            True if successful
        """
        logger.info(f"Applying config bundle from {bundle.source_instance[:8]}...")
        
        success_count = 0
        total_count = len(bundle.configs)
        
        for filename, content in bundle.configs.items():
            # Safety check - never overwrite local-only configs
            if filename in LOCAL_ONLY_CONFIGS:
                logger.warning(f"Refusing to sync local-only config: {filename}")
                continue
            
            filepath = os.path.join(self.config_dir, filename)
            
            try:
                # Create backup
                if os.path.exists(filepath):
                    backup_path = filepath + '.bak'
                    try:
                        with open(filepath, 'r') as src:
                            with open(backup_path, 'w') as dst:
                                dst.write(src.read())
                    except Exception as e:
                        logger.debug(f"Backup failed for {filename}: {e}")
                
                # Write new config atomically
                temp_path = filepath + '.tmp'
                with open(temp_path, 'w') as f:
                    json.dump(content, f, indent=2)
                os.rename(temp_path, filepath)
                
                logger.debug(f"Applied synced config: {filename}")
                success_count += 1
                
            except Exception as e:
                logger.error(f"Failed to apply config {filename}: {e}")
        
        # Update local checksum
        with self._lock:
            self._local_checksum = self._calculate_local_checksum()
        
        # Notify callback
        if self.on_config_changed and success_count > 0:
            try:
                self.on_config_changed()
            except Exception as e:
                logger.warning(f"Config changed callback error: {e}")
        
        if success_count == total_count:
            logger.info(f"Applied {success_count} config files from PRIMARY")
            self._stats['pulls_completed'] += 1
            self._stats['last_sync_time'] = time.time()
            return True
        else:
            logger.warning(f"Applied {success_count}/{total_count} config files")
            self._stats['pull_failures'] += 1
            return False
    
    def handle_config_push(self, bundle_bytes: bytes) -> Tuple[bool, str]:
        """
        Handle incoming config push from PRIMARY.
        
        Args:
            bundle_bytes: Serialized ConfigBundle
            
        Returns:
            Tuple of (success, message)
        """
        if self._is_primary:
            return False, "Cannot accept push - we are PRIMARY"
        
        try:
            bundle = ConfigBundle.from_bytes(bundle_bytes)
            success = self._apply_bundle(bundle)
            if success:
                return True, f"Applied {len(bundle.configs)} configs"
            else:
                return False, "Failed to apply some configs"
        except Exception as e:
            logger.error(f"Error handling config push: {e}")
            return False, str(e)
    
    def handle_config_request(self) -> Optional[ConfigBundle]:
        """
        Handle incoming config request from SECONDARY.
        
        Returns:
            ConfigBundle if we're PRIMARY, None otherwise
        """
        if not self._is_primary:
            logger.debug("Ignoring config request - we are not PRIMARY")
            return None
        
        logger.info("Responding to config request from peer")
        return self._create_bundle()
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive sync status."""
        with self._lock:
            return {
                'is_primary': self._is_primary,
                'local_checksum': self._local_checksum[:8] + '...' if self._local_checksum else None,
                'remote_checksum': self._remote_checksum[:8] + '...' if self._remote_checksum else None,
                'checksums_match': self._local_checksum == self._remote_checksum if self._local_checksum and self._remote_checksum else None,
                'config_dir': self.config_dir,
                'peer': f"{self.peer_host}:{self.peer_port}",
                'shared_configs': SHARED_CONFIG_FILES,
                'stats': self._stats.copy(),
            }


# Re-export for backward compatibility
SyncedConfigType = type('SyncedConfigType', (), {
    'DESTINATIONS': 'destinations',
    'BLOCKED_IPS': 'blocked_ips',
    'BLOCKED_TRAPS': 'blocked_traps',
    'REDIRECTED_IPS': 'redirected_ips',
    'REDIRECTED_OIDS': 'redirected_oids',
    'REDIRECTED_DESTINATIONS': 'redirected_destinations',
})
