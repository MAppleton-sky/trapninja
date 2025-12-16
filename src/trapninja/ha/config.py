#!/usr/bin/env python3
"""
TrapNinja HA Configuration

Handles HA configuration loading, saving, and validation.

Author: TrapNinja Team
Version: 2.0.0
"""

import os
import json
import logging
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any

logger = logging.getLogger("trapninja")


@dataclass
class HAConfig:
    """
    High Availability Configuration.
    
    Attributes:
        enabled: Whether HA is enabled
        mode: Initial mode ('primary' or 'secondary')
        peer_host: Hostname/IP of peer node
        peer_port: Port for peer HA communication
        listen_port: Port to listen for peer connections
        heartbeat_interval: Seconds between heartbeats
        heartbeat_timeout: Seconds before peer is considered dead
        failover_delay: Seconds to wait before completing failover
        priority: Priority for tie-breaking (higher wins)
        shared_secret: Shared secret for authentication (future)
        split_brain_detection: Enable split-brain detection
        max_retries: Maximum connection retry attempts
        retry_delay: Seconds between retries
        auto_failback: If True, original primary reclaims role on restart
        startup_peer_check: Check peer state before claiming initial state
    """
    enabled: bool = False
    mode: str = "primary"
    peer_host: str = "127.0.0.1"
    peer_port: int = 60006
    listen_port: int = 60006
    heartbeat_interval: float = 1.0
    heartbeat_timeout: float = 3.0
    failover_delay: float = 2.0
    priority: int = 100
    shared_secret: str = ""
    split_brain_detection: bool = True
    max_retries: int = 3
    retry_delay: float = 0.5
    auto_failback: bool = False
    startup_peer_check: bool = True
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()
    
    def _validate(self):
        """Validate configuration values."""
        # Validate mode
        if self.mode not in ('primary', 'secondary'):
            raise ValueError(f"Invalid mode '{self.mode}', must be 'primary' or 'secondary'")
        
        # Validate ports
        if not (1 <= self.peer_port <= 65535):
            raise ValueError(f"Invalid peer_port {self.peer_port}, must be 1-65535")
        if not (1 <= self.listen_port <= 65535):
            raise ValueError(f"Invalid listen_port {self.listen_port}, must be 1-65535")
        
        # Validate intervals
        if self.heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")
        if self.heartbeat_timeout <= 0:
            raise ValueError("heartbeat_timeout must be positive")
        if self.heartbeat_timeout <= self.heartbeat_interval:
            logger.warning(
                f"heartbeat_timeout ({self.heartbeat_timeout}s) should be > "
                f"heartbeat_interval ({self.heartbeat_interval}s)"
            )
        
        # Validate priority
        if not (0 <= self.priority <= 255):
            raise ValueError(f"Invalid priority {self.priority}, must be 0-255")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HAConfig':
        """Create from dictionary."""
        # Filter to only known fields
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)
    
    def __str__(self) -> str:
        return (
            f"HAConfig(enabled={self.enabled}, mode={self.mode}, "
            f"peer={self.peer_host}:{self.peer_port}, priority={self.priority})"
        )


def load_ha_config(config_path: Optional[str] = None) -> HAConfig:
    """
    Load HA configuration from file.
    
    Args:
        config_path: Path to configuration file.
                    If None, uses default path.
    
    Returns:
        HAConfig instance
    """
    if not config_path:
        # Try to get CONFIG_DIR from main config module
        try:
            from ..config import CONFIG_DIR
            config_path = os.path.join(CONFIG_DIR, "ha_config.json")
        except ImportError:
            config_path = "/opt/trapninja/config/ha_config.json"
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            config = HAConfig.from_dict(config_data)
            logger.info(f"HA configuration loaded from {config_path}")
            return config
        else:
            logger.info(f"HA config file not found at {config_path}, using defaults")
            return HAConfig()
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in HA configuration: {e}")
        return HAConfig()
    except ValueError as e:
        logger.error(f"Invalid HA configuration values: {e}")
        return HAConfig()
    except Exception as e:
        logger.error(f"Error loading HA configuration: {e}")
        return HAConfig()


def save_ha_config(config: HAConfig, config_path: Optional[str] = None) -> bool:
    """
    Save HA configuration to file.
    
    Args:
        config: HAConfig instance to save
        config_path: Path to save to. If None, uses default path.
    
    Returns:
        True if successful, False otherwise
    """
    if not config_path:
        try:
            from ..config import CONFIG_DIR
            config_path = os.path.join(CONFIG_DIR, "ha_config.json")
        except ImportError:
            config_path = "/opt/trapninja/config/ha_config.json"
    
    try:
        # Ensure directory exists
        config_dir = os.path.dirname(config_path)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir)
        
        config_data = config.to_dict()
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        logger.info(f"HA configuration saved to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving HA configuration: {e}")
        return False


def create_primary_config(
    peer_host: str,
    peer_port: int = 60006,
    priority: int = 150,
    **kwargs
) -> HAConfig:
    """
    Create a primary node configuration.
    
    Args:
        peer_host: Hostname/IP of secondary node
        peer_port: Port for HA communication
        priority: Priority value (higher than secondary)
        **kwargs: Additional configuration options
    
    Returns:
        HAConfig instance for primary node
    """
    return HAConfig(
        enabled=True,
        mode="primary",
        peer_host=peer_host,
        peer_port=peer_port,
        listen_port=peer_port,
        priority=priority,
        **kwargs
    )


def create_secondary_config(
    peer_host: str,
    peer_port: int = 60006,
    priority: int = 100,
    **kwargs
) -> HAConfig:
    """
    Create a secondary node configuration.
    
    Args:
        peer_host: Hostname/IP of primary node
        peer_port: Port for HA communication
        priority: Priority value (lower than primary)
        **kwargs: Additional configuration options
    
    Returns:
        HAConfig instance for secondary node
    """
    return HAConfig(
        enabled=True,
        mode="secondary",
        peer_host=peer_host,
        peer_port=peer_port,
        listen_port=peer_port,
        priority=priority,
        **kwargs
    )
