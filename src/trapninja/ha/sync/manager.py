#!/usr/bin/env python3
"""
TrapNinja HA Config Synchronization Manager

Core implementation for synchronizing shared configurations between
HA cluster nodes using the existing HA TCP socket mechanism.

Design Principles:
    - Uses existing HA communication (no Redis dependency for sync)
    - Non-blocking: Sync failures don't affect trap processing
    - Eventually consistent: All nodes converge to same config
    - Primary authority: Only PRIMARY pushes changes
    - Version tracking: Checksums detect drift between nodes

Shared Configurations (synced between nodes):
    - destinations.json: Forward destinations
    - blocked_ips.json: Blocked source IPs
    - blocked_traps.json: Blocked trap OIDs
    - redirected_ips.json: IP-based redirection rules
    - redirected_oids.json: OID-based redirection rules
    - redirected_destinations.json: Redirection target destinations

Local Configurations (NOT synced):
    - ha_config.json: Node-specific HA settings (mode, priority, peer)
    - cache_config.json: Node-specific cache settings
    - listen_ports.json: Node-specific listening ports
    - capture_config.json: Node-specific capture settings
    - shadow_config.json: Node-specific shadow mode settings
    - stats_config.json: Node-specific stats settings
    - sync_config.json: Node-specific sync settings

Author: TrapNinja Team
Version: 1.0.0
"""

import hashlib
import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("trapninja")


class SyncedConfigType(Enum):
    """
    Configuration types that can be synchronized.
    
    Each type maps to a specific configuration file.
    """
    DESTINATIONS = "destinations"
    BLOCKED_IPS = "blocked_ips"
    BLOCKED_TRAPS = "blocked_traps"
    REDIRECTED_IPS = "redirected_ips"
    REDIRECTED_OIDS = "redirected_oids"
    REDIRECTED_DESTINATIONS = "redirected_destinations"
    
    @property
    def filename(self) -> str:
        """Get the configuration filename for this type."""
        return f"{self.value}.json"
    
    @classmethod
    def all_types(cls) -> List['SyncedConfigType']:
        """Get all syncable config types."""
        return list(cls)


class ConfigSyncMessageType(Enum):
    """
    Message types for config synchronization.
    
    These extend the HA protocol for config sync operations.
    """
    CONFIG_REQUEST = "config_request"
    CONFIG_RESPONSE = "config_response"
    CONFIG_PUSH = "config_push"
    CONFIG_ACK = "config_ack"
    CONFIG_VERSION_REQUEST = "config_version_request"
    CONFIG_VERSION_RESPONSE = "config_version_response"


# Map of local-only configs that should NEVER be synced
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
class ConfigSyncConfig:
    """Configuration for the config sync system."""
    enabled: bool = False
    sync_on_startup: bool = True
    sync_on_promotion: bool = True
    push_on_file_change: bool = True
    version_check_interval: int = 30
    primary_authority: bool = True
    sync_timeout: float = 10.0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigSyncConfig':
        """Create config from dictionary."""
        return cls(
            enabled=data.get('enabled', False),
            sync_on_startup=data.get('sync_on_startup', True),
            sync_on_promotion=data.get('sync_on_promotion', True),
            push_on_file_change=data.get('push_on_file_change', True),
            version_check_interval=data.get('version_check_interval', 30),
            primary_authority=data.get('primary_authority', True),
            sync_timeout=data.get('sync_timeout', 10.0),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'enabled': self.enabled,
            'sync_on_startup': self.sync_on_startup,
            'sync_on_promotion': self.sync_on_promotion,
            'push_on_file_change': self.push_on_file_change,
            'version_check_interval': self.version_check_interval,
            'primary_authority': self.primary_authority,
            'sync_timeout': self.sync_timeout,
        }


@dataclass
class ConfigVersionInfo:
    """Version information for a configuration."""
    checksum: str
    mtime: float
    size: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'checksum': self.checksum,
            'mtime': self.mtime,
            'size': self.size,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigVersionInfo':
        return cls(
            checksum=data.get('checksum', ''),
            mtime=data.get('mtime', 0.0),
            size=data.get('size', 0),
        )


@dataclass
class SyncStats:
    """Statistics for config sync operations."""
    pushes_sent: int = 0
    pushes_received: int = 0
    sync_requests: int = 0
    sync_responses: int = 0
    conflicts_detected: int = 0
    errors: int = 0
    last_sync_time: Optional[float] = None
    last_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pushes_sent': self.pushes_sent,
            'pushes_received': self.pushes_received,
            'sync_requests': self.sync_requests,
            'sync_responses': self.sync_responses,
            'conflicts_detected': self.conflicts_detected,
            'errors': self.errors,
            'last_sync_time': self.last_sync_time,
            'last_error': self.last_error,
        }


class ConfigSyncManager:
    """
    Manages configuration synchronization between HA cluster nodes.
    
    Uses the existing HA TCP socket communication for sync operations.
    Integrates with HACluster to send/receive config sync messages.
    
    Thread-safe for concurrent access.
    """
    
    def __init__(
        self,
        config: ConfigSyncConfig,
        config_dir: str,
        instance_id: str,
        get_ha_state: Callable[[], str],
        get_peer_info: Callable[[], Tuple[str, int]],
        on_config_updated: Optional[Callable[[SyncedConfigType], None]] = None
    ):
        """
        Initialize the config sync manager.
        
        Args:
            config: Sync configuration
            config_dir: Path to local configuration directory
            instance_id: Unique identifier for this node
            get_ha_state: Callback to get current HA state
            get_peer_info: Callback to get peer host and port
            on_config_updated: Callback when a config is updated from sync
        """
        self.config = config
        self.config_dir = config_dir
        self.instance_id = instance_id
        self.get_ha_state = get_ha_state
        self.get_peer_info = get_peer_info
        self.on_config_updated = on_config_updated
        
        self._lock = threading.RLock()
        self._stats = SyncStats()
        
        self._local_versions: Dict[SyncedConfigType, ConfigVersionInfo] = {}
        self._peer_versions: Dict[SyncedConfigType, ConfigVersionInfo] = {}
        self._file_mtimes: Dict[str, float] = {}
        
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        
        logger.info(f"ConfigSyncManager initialized for instance {instance_id[:8]}...")
    
    def _compute_checksum(self, data: Any) -> str:
        """Compute MD5 checksum of configuration data."""
        content = json.dumps(data, sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_config_path(self, config_type: SyncedConfigType) -> str:
        """Get local file path for a config type."""
        return os.path.join(self.config_dir, config_type.filename)
    
    def _get_local_version(self, config_type: SyncedConfigType) -> Optional[ConfigVersionInfo]:
        """Get version info for a local config file."""
        path = self._get_config_path(config_type)
        try:
            if not os.path.exists(path):
                return None
            
            stat = os.stat(path)
            with open(path, 'r') as f:
                data = json.load(f)
            
            return ConfigVersionInfo(
                checksum=self._compute_checksum(data),
                mtime=stat.st_mtime,
                size=stat.st_size,
            )
        except Exception as e:
            logger.warning(f"Failed to get version for {config_type.value}: {e}")
            return None
    
    def get_all_local_versions(self) -> Dict[str, Dict[str, Any]]:
        """Get version info for all local synced configs."""
        versions = {}
        for config_type in SyncedConfigType.all_types():
            version = self._get_local_version(config_type)
            if version:
                versions[config_type.value] = version.to_dict()
                self._local_versions[config_type] = version
        return versions
    
    def _check_version_mismatch(
        self,
        config_type: SyncedConfigType,
        remote_version: ConfigVersionInfo
    ) -> bool:
        """Check if local and remote versions differ."""
        local_version = self._local_versions.get(config_type)
        if not local_version:
            local_version = self._get_local_version(config_type)
            if local_version:
                self._local_versions[config_type] = local_version
        
        if not local_version:
            return True
        
        return local_version.checksum != remote_version.checksum
    
    def _read_local_config(self, config_type: SyncedConfigType) -> Optional[Any]:
        """Read configuration from local file."""
        path = self._get_config_path(config_type)
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
            return None
        except Exception as e:
            logger.warning(f"Failed to read local config {config_type.value}: {e}")
            return None
    
    def _write_local_config(self, config_type: SyncedConfigType, data: Any) -> bool:
        """Write configuration to local file atomically."""
        path = self._get_config_path(config_type)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            temp_path = path + '.tmp'
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)
            os.rename(temp_path, path)
            
            self._local_versions[config_type] = ConfigVersionInfo(
                checksum=self._compute_checksum(data),
                mtime=os.path.getmtime(path),
                size=os.path.getsize(path),
            )
            
            logger.debug(f"Wrote local config: {config_type.value}")
            return True
        except Exception as e:
            logger.error(f"Failed to write local config {config_type.value}: {e}")
            return False
    
    def create_version_request_message(self) -> Dict[str, Any]:
        """Create a message requesting peer's config versions."""
        return {
            'type': ConfigSyncMessageType.CONFIG_VERSION_REQUEST.value,
            'sender': self.instance_id,
            'timestamp': time.time(),
        }
    
    def create_version_response_message(self) -> Dict[str, Any]:
        """Create a message with our config versions."""
        return {
            'type': ConfigSyncMessageType.CONFIG_VERSION_RESPONSE.value,
            'sender': self.instance_id,
            'timestamp': time.time(),
            'versions': self.get_all_local_versions(),
        }
    
    def create_config_request_message(
        self,
        config_types: Optional[List[SyncedConfigType]] = None
    ) -> Dict[str, Any]:
        """Create a message requesting full config data."""
        if config_types is None:
            config_types = SyncedConfigType.all_types()
        
        return {
            'type': ConfigSyncMessageType.CONFIG_REQUEST.value,
            'sender': self.instance_id,
            'timestamp': time.time(),
            'config_types': [ct.value for ct in config_types],
        }
    
    def create_config_response_message(
        self,
        config_types: Optional[List[SyncedConfigType]] = None
    ) -> Dict[str, Any]:
        """Create a message with full config data."""
        if config_types is None:
            config_types = SyncedConfigType.all_types()
        
        configs = {}
        versions = {}
        
        for config_type in config_types:
            data = self._read_local_config(config_type)
            if data is not None:
                configs[config_type.value] = data
                version = self._get_local_version(config_type)
                if version:
                    versions[config_type.value] = version.to_dict()
        
        return {
            'type': ConfigSyncMessageType.CONFIG_RESPONSE.value,
            'sender': self.instance_id,
            'timestamp': time.time(),
            'configs': configs,
            'versions': versions,
        }
    
    def create_config_push_message(
        self,
        config_type: SyncedConfigType,
        data: Any
    ) -> Dict[str, Any]:
        """Create a message pushing a single config update."""
        version = ConfigVersionInfo(
            checksum=self._compute_checksum(data),
            mtime=time.time(),
            size=len(json.dumps(data)),
        )
        
        return {
            'type': ConfigSyncMessageType.CONFIG_PUSH.value,
            'sender': self.instance_id,
            'timestamp': time.time(),
            'config_type': config_type.value,
            'config_data': data,
            'version': version.to_dict(),
        }
    
    def create_config_ack_message(
        self,
        config_type: SyncedConfigType,
        success: bool,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create acknowledgment for config received."""
        return {
            'type': ConfigSyncMessageType.CONFIG_ACK.value,
            'sender': self.instance_id,
            'timestamp': time.time(),
            'config_type': config_type.value,
            'success': success,
            'error': error,
        }
    
    def _send_sync_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a sync message to peer via TCP socket."""
        try:
            peer_host, peer_port = self.get_peer_info()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.sync_timeout)
            
            try:
                sock.connect((peer_host, peer_port))
                
                msg_bytes = json.dumps(message).encode('utf-8')
                sock.send(msg_bytes)
                
                msg_type = message.get('type', '')
                if msg_type in (
                    ConfigSyncMessageType.CONFIG_REQUEST.value,
                    ConfigSyncMessageType.CONFIG_VERSION_REQUEST.value,
                    ConfigSyncMessageType.CONFIG_PUSH.value,
                ):
                    response_data = sock.recv(65536)
                    if response_data:
                        return json.loads(response_data.decode('utf-8'))
                
                return None
                
            finally:
                sock.close()
                
        except socket.timeout:
            logger.warning("Config sync message timeout")
            return None
        except ConnectionRefusedError:
            logger.debug("Peer not available for config sync")
            return None
        except Exception as e:
            logger.warning(f"Failed to send config sync message: {e}")
            self._stats.errors += 1
            self._stats.last_error = str(e)
            return None
    
    def handle_sync_message(
        self,
        message: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Handle incoming config sync message.
        
        Called by HACluster when a config sync message is received.
        """
        msg_type = message.get('type', '')
        
        try:
            if msg_type == ConfigSyncMessageType.CONFIG_VERSION_REQUEST.value:
                return self._handle_version_request(message)
            elif msg_type == ConfigSyncMessageType.CONFIG_VERSION_RESPONSE.value:
                return self._handle_version_response(message)
            elif msg_type == ConfigSyncMessageType.CONFIG_REQUEST.value:
                return self._handle_config_request(message)
            elif msg_type == ConfigSyncMessageType.CONFIG_RESPONSE.value:
                return self._handle_config_response(message)
            elif msg_type == ConfigSyncMessageType.CONFIG_PUSH.value:
                return self._handle_config_push(message)
            elif msg_type == ConfigSyncMessageType.CONFIG_ACK.value:
                return self._handle_config_ack(message)
            else:
                logger.warning(f"Unknown config sync message type: {msg_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error handling config sync message: {e}")
            self._stats.errors += 1
            self._stats.last_error = str(e)
            return None
    
    def _handle_version_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle request for our config versions."""
        logger.debug(f"Received version request from {message.get('sender', 'unknown')[:8]}...")
        return self.create_version_response_message()
    
    def _handle_version_response(self, message: Dict[str, Any]) -> None:
        """Handle received config versions from peer."""
        sender = message.get('sender', 'unknown')[:8]
        versions = message.get('versions', {})
        
        logger.debug(f"Received version response from {sender}... with {len(versions)} configs")
        
        for config_type_str, version_data in versions.items():
            try:
                config_type = SyncedConfigType(config_type_str)
                self._peer_versions[config_type] = ConfigVersionInfo.from_dict(version_data)
            except ValueError:
                continue
        
        ha_state = self.get_ha_state()
        if ha_state == 'secondary':
            mismatched = self._find_version_mismatches()
            if mismatched:
                logger.info(f"Config version mismatch detected: {[ct.value for ct in mismatched]}")
                self.request_configs(mismatched)
        
        return None
    
    def _handle_config_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle request for full config data."""
        sender = message.get('sender', 'unknown')[:8]
        requested_types = message.get('config_types', [])
        
        logger.info(f"Received config request from {sender}... for {len(requested_types)} configs")
        self._stats.sync_requests += 1
        
        config_types = []
        for type_str in requested_types:
            try:
                config_types.append(SyncedConfigType(type_str))
            except ValueError:
                continue
        
        return self.create_config_response_message(config_types or None)
    
    def _handle_config_response(self, message: Dict[str, Any]) -> None:
        """Handle received full config data from peer."""
        sender = message.get('sender', 'unknown')[:8]
        configs = message.get('configs', {})
        versions = message.get('versions', {})
        
        logger.info(f"Received config response from {sender}... with {len(configs)} configs")
        self._stats.sync_responses += 1
        
        for config_type_str, config_data in configs.items():
            try:
                config_type = SyncedConfigType(config_type_str)
            except ValueError:
                continue
            
            if self._write_local_config(config_type, config_data):
                logger.info(f"Applied synced config: {config_type.value}")
                
                if config_type_str in versions:
                    self._peer_versions[config_type] = ConfigVersionInfo.from_dict(
                        versions[config_type_str]
                    )
                
                if self.on_config_updated:
                    try:
                        self.on_config_updated(config_type)
                    except Exception as e:
                        logger.warning(f"Config update callback error: {e}")
        
        self._stats.last_sync_time = time.time()
        return None
    
    def _handle_config_push(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle pushed config update from PRIMARY."""
        sender = message.get('sender', 'unknown')[:8]
        config_type_str = message.get('config_type', '')
        config_data = message.get('config_data')
        version_data = message.get('version', {})
        
        logger.info(f"Received config push from {sender}... for {config_type_str}")
        self._stats.pushes_received += 1
        
        try:
            config_type = SyncedConfigType(config_type_str)
        except ValueError:
            return self.create_config_ack_message(
                SyncedConfigType.DESTINATIONS,
                success=False,
                error=f"Unknown config type: {config_type_str}"
            )
        
        ha_state = self.get_ha_state()
        if ha_state == 'primary' and self.config.primary_authority:
            logger.warning("Rejecting config push - we are PRIMARY")
            self._stats.conflicts_detected += 1
            return self.create_config_ack_message(
                config_type,
                success=False,
                error="Cannot push to PRIMARY node"
            )
        
        if self._write_local_config(config_type, config_data):
            self._peer_versions[config_type] = ConfigVersionInfo.from_dict(version_data)
            
            if self.on_config_updated:
                try:
                    self.on_config_updated(config_type)
                except Exception as e:
                    logger.warning(f"Config update callback error: {e}")
            
            self._stats.last_sync_time = time.time()
            return self.create_config_ack_message(config_type, success=True)
        else:
            return self.create_config_ack_message(
                config_type,
                success=False,
                error="Failed to write config"
            )
    
    def _handle_config_ack(self, message: Dict[str, Any]) -> None:
        """Handle acknowledgment of pushed config."""
        sender = message.get('sender', 'unknown')[:8]
        config_type = message.get('config_type', '')
        success = message.get('success', False)
        error = message.get('error')
        
        if success:
            logger.debug(f"Config push acknowledged by {sender}... for {config_type}")
        else:
            logger.warning(f"Config push rejected by {sender}... for {config_type}: {error}")
            self._stats.conflicts_detected += 1
        
        return None
    
    def _find_version_mismatches(self) -> List[SyncedConfigType]:
        """Find configs where local and peer versions differ."""
        mismatched = []
        
        for config_type in SyncedConfigType.all_types():
            peer_version = self._peer_versions.get(config_type)
            if not peer_version:
                continue
            
            if self._check_version_mismatch(config_type, peer_version):
                mismatched.append(config_type)
        
        return mismatched
    
    def request_versions(self) -> bool:
        """Request config versions from peer."""
        message = self.create_version_request_message()
        response = self._send_sync_message(message)
        
        if response:
            self._handle_version_response(response)
            return True
        return False
    
    def request_configs(
        self,
        config_types: Optional[List[SyncedConfigType]] = None
    ) -> bool:
        """Request full config data from peer."""
        message = self.create_config_request_message(config_types)
        response = self._send_sync_message(message)
        
        if response:
            self._handle_config_response(response)
            return True
        return False
    
    def push_config(self, config_type: SyncedConfigType) -> bool:
        """Push a single config to peer."""
        ha_state = self.get_ha_state()
        if ha_state != 'primary' and self.config.primary_authority:
            logger.warning(f"Cannot push config as {ha_state} - only PRIMARY can push")
            return False
        
        data = self._read_local_config(config_type)
        if data is None:
            logger.warning(f"No local config to push: {config_type.value}")
            return False
        
        message = self.create_config_push_message(config_type, data)
        response = self._send_sync_message(message)
        
        self._stats.pushes_sent += 1
        
        if response:
            self._handle_config_ack(response)
            return response.get('success', False)
        
        return False
    
    def push_all_configs(self) -> Dict[str, bool]:
        """Push all local shared configs to peer."""
        results = {}
        
        for config_type in SyncedConfigType.all_types():
            if self._read_local_config(config_type) is not None:
                results[config_type.value] = self.push_config(config_type)
            else:
                results[config_type.value] = True
        
        return results
    
    def pull_all_configs(self) -> bool:
        """Pull all configs from peer (for SECONDARY)."""
        return self.request_configs(None)
    
    def sync_all(self) -> bool:
        """Synchronize all configs based on HA role."""
        ha_state = self.get_ha_state()
        
        if ha_state == 'primary':
            results = self.push_all_configs()
            return all(results.values())
        else:
            return self.pull_all_configs()
    
    def _check_file_changes(self) -> List[SyncedConfigType]:
        """Check which config files have changed since last check."""
        changed = []
        
        for config_type in SyncedConfigType.all_types():
            path = self._get_config_path(config_type)
            
            try:
                if not os.path.exists(path):
                    continue
                
                current_mtime = os.path.getmtime(path)
                last_mtime = self._file_mtimes.get(path, 0)
                
                if current_mtime > last_mtime:
                    changed.append(config_type)
                    self._file_mtimes[path] = current_mtime
                    
            except Exception as e:
                logger.debug(f"Error checking file {path}: {e}")
        
        return changed
    
    def _monitor_loop(self):
        """Background loop for monitoring file changes and syncing."""
        logger.info("Config sync monitor started")
        
        for config_type in SyncedConfigType.all_types():
            path = self._get_config_path(config_type)
            if os.path.exists(path):
                self._file_mtimes[path] = os.path.getmtime(path)
        
        last_version_check = 0
        
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(timeout=5.0):
                    break
                
                ha_state = self.get_ha_state()
                
                if ha_state == 'primary' and self.config.push_on_file_change:
                    changed = self._check_file_changes()
                    for config_type in changed:
                        logger.info(f"Local config changed: {config_type.value} - pushing to peer")
                        self.push_config(config_type)
                
                elif ha_state == 'secondary':
                    now = time.time()
                    if now - last_version_check >= self.config.version_check_interval:
                        last_version_check = now
                        logger.debug("Checking config versions with PRIMARY...")
                        self.request_versions()
                        
            except Exception as e:
                logger.warning(f"Config sync monitor error: {e}")
        
        logger.info("Config sync monitor stopped")
    
    def start(self) -> bool:
        """Start the config sync system."""
        if not self.config.enabled:
            logger.info("Config sync not enabled")
            return False
        
        logger.info("Starting config sync system...")
        
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="ConfigSyncMonitor"
        )
        self._monitor_thread.start()
        
        if self.config.sync_on_startup:
            logger.info("Performing initial config sync...")
            time.sleep(2.0)
            self.sync_all()
        
        logger.info("Config sync system started")
        return True
    
    def stop(self):
        """Stop the config sync system."""
        logger.info("Stopping config sync system...")
        
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3.0)
        
        logger.info("Config sync system stopped")
    
    def on_ha_state_change(self, old_state: str, new_state: str):
        """Handle HA state change."""
        logger.info(f"Config sync: HA state changed {old_state} -> {new_state}")
        
        if new_state == 'primary' and self.config.sync_on_promotion:
            logger.info("Became PRIMARY - pushing configs to peer")
            self.push_all_configs()
        
        elif new_state == 'secondary':
            logger.info("Became SECONDARY - pulling configs from PRIMARY")
            self.pull_all_configs()
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive sync status."""
        local_versions = {}
        for config_type, version in self._local_versions.items():
            local_versions[config_type.value] = version.to_dict()
        
        peer_versions = {}
        for config_type, version in self._peer_versions.items():
            peer_versions[config_type.value] = version.to_dict()
        
        return {
            'enabled': self.config.enabled,
            'ha_state': self.get_ha_state(),
            'instance_id': self.instance_id[:8] + '...',
            'stats': self._stats.to_dict(),
            'local_versions': local_versions,
            'peer_versions': peer_versions,
            'synced_config_types': [ct.value for ct in SyncedConfigType.all_types()],
            'local_only_configs': list(LOCAL_ONLY_CONFIGS),
        }


def load_sync_config(config_path: Optional[str] = None) -> ConfigSyncConfig:
    """Load sync configuration from file."""
    if not config_path:
        try:
            from ...config import CONFIG_DIR
            config_path = os.path.join(CONFIG_DIR, "sync_config.json")
        except ImportError:
            config_path = "/opt/trapninja/config/sync_config.json"
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                data = json.load(f)
            return ConfigSyncConfig.from_dict(data)
    except Exception as e:
        logger.warning(f"Failed to load sync config: {e}")
    
    return ConfigSyncConfig()


def save_sync_config(config: ConfigSyncConfig, config_path: Optional[str] = None) -> bool:
    """Save sync configuration to file."""
    if not config_path:
        try:
            from ...config import CONFIG_DIR
            config_path = os.path.join(CONFIG_DIR, "sync_config.json")
        except ImportError:
            config_path = "/opt/trapninja/config/sync_config.json"
    
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config.to_dict(), f, indent=2)
        logger.info(f"Saved sync config to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save sync config: {e}")
        return False
