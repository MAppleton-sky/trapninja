#!/usr/bin/env python3
"""
TrapNinja Core Types

Type definitions and data structures used throughout TrapNinja.
Uses dataclasses for clean, immutable data structures with type hints.

Author: TrapNinja Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any, Union
from enum import Enum, auto


# =============================================================================
# TYPE ALIASES
# =============================================================================

# Destination is (ip, port) tuple
Destination = Tuple[str, int]

# List of destinations
DestinationList = List[Destination]

# OID string representation
OID = str

# IP address string
IPAddress = str


# =============================================================================
# PACKET DATA STRUCTURES
# =============================================================================

@dataclass(frozen=True)
class PacketData:
    """
    Immutable packet data structure for processing.
    
    Contains the essential information extracted from captured packets
    for efficient processing in the worker threads.
    """
    src_ip: str
    dst_port: int
    payload: bytes
    timestamp: float = field(default_factory=lambda: __import__('time').time())
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_port, self.timestamp))


@dataclass
class ParsedTrap:
    """
    Parsed SNMP trap information.
    
    Contains the extracted information from an SNMP trap after parsing.
    """
    version: str
    source_ip: str
    trap_oid: Optional[str]
    enterprise_oid: Optional[str]
    varbinds: Dict[str, Any]
    community: Optional[str] = None
    security_name: Optional[str] = None
    raw_payload: Optional[bytes] = None


@dataclass
class ForwardingResult:
    """
    Result of a packet forwarding operation.
    """
    success: bool
    destinations_reached: int
    destinations_failed: int
    error_message: Optional[str] = None
    forwarding_time_ms: float = 0.0


# =============================================================================
# REDIRECTION STRUCTURES
# =============================================================================

@dataclass
class RedirectionRule:
    """
    Redirection rule configuration.
    """
    rule_type: str  # 'ip' or 'oid'
    pattern: str    # IP address or OID pattern
    tag: str        # Destination tag
    enabled: bool = True


@dataclass
class RedirectionMatch:
    """
    Result of a redirection check.
    """
    is_redirected: bool
    destinations: DestinationList
    tag: Optional[str] = None
    matched_by: Optional[str] = None  # 'ip' or 'oid'


# =============================================================================
# FILTERING STRUCTURES
# =============================================================================

class FilterAction(Enum):
    """Actions that can be taken on filtered packets."""
    ALLOW = auto()
    BLOCK = auto()
    REDIRECT = auto()


@dataclass
class FilterResult:
    """
    Result of filtering a packet.
    """
    action: FilterAction
    reason: Optional[str] = None
    redirect_tag: Optional[str] = None


# =============================================================================
# STATISTICS STRUCTURES
# =============================================================================

@dataclass
class ProcessingStats:
    """
    Packet processing statistics.
    """
    packets_received: int = 0
    packets_forwarded: int = 0
    packets_blocked: int = 0
    packets_redirected: int = 0
    packets_dropped: int = 0
    packets_errors: int = 0
    
    # Fast path statistics
    fast_path_hits: int = 0
    slow_path_hits: int = 0
    
    # Queue statistics
    queue_full_events: int = 0
    max_queue_depth: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary for JSON serialization."""
        return {
            'packets_received': self.packets_received,
            'packets_forwarded': self.packets_forwarded,
            'packets_blocked': self.packets_blocked,
            'packets_redirected': self.packets_redirected,
            'packets_dropped': self.packets_dropped,
            'packets_errors': self.packets_errors,
            'fast_path_hits': self.fast_path_hits,
            'slow_path_hits': self.slow_path_hits,
            'queue_full_events': self.queue_full_events,
            'max_queue_depth': self.max_queue_depth,
        }
    
    @property
    def fast_path_ratio(self) -> float:
        """Calculate fast path ratio as percentage."""
        total = self.fast_path_hits + self.slow_path_hits
        if total == 0:
            return 0.0
        return (self.fast_path_hits / total) * 100


@dataclass
class QueueStats:
    """
    Queue statistics for monitoring.
    """
    current_depth: int = 0
    max_depth: int = 0
    capacity: int = 0
    total_queued: int = 0
    total_dropped: int = 0
    
    @property
    def utilization(self) -> float:
        """Calculate queue utilization as a ratio."""
        if self.capacity == 0:
            return 0.0
        return self.current_depth / self.capacity


# =============================================================================
# HA STRUCTURES
# =============================================================================

class HAStateEnum(Enum):
    """High Availability states."""
    INITIALIZING = "initializing"
    PRIMARY = "primary"
    SECONDARY = "secondary"
    STANDALONE = "standalone"
    FAILOVER = "failover"
    SPLIT_BRAIN = "split_brain"
    ERROR = "error"


@dataclass
class HAStatus:
    """
    High Availability status information.
    """
    instance_id: str
    state: HAStateEnum
    is_forwarding: bool
    uptime: float
    priority: int
    peer_connected: bool
    peer_state: Optional[HAStateEnum]
    peer_priority: int
    peer_uptime: float
    split_brain_detected: bool
    manual_override: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'instance_id': self.instance_id,
            'state': self.state.value,
            'is_forwarding': self.is_forwarding,
            'uptime': self.uptime,
            'priority': self.priority,
            'peer_connected': self.peer_connected,
            'peer_state': self.peer_state.value if self.peer_state else None,
            'peer_priority': self.peer_priority,
            'peer_uptime': self.peer_uptime,
            'split_brain_detected': self.split_brain_detected,
            'manual_override': self.manual_override,
        }


# =============================================================================
# CONFIGURATION STRUCTURES
# =============================================================================

@dataclass
class ServiceConfig:
    """
    Main service configuration.
    """
    interface: str = "ens192"
    listen_ports: List[int] = field(default_factory=lambda: [162])
    destinations: DestinationList = field(default_factory=list)
    capture_mode: str = "auto"
    debug: bool = False


@dataclass
class SNMPv3Credentials:
    """
    SNMPv3 credentials for a user.
    """
    username: str
    auth_protocol: str = "none"
    auth_key: Optional[str] = None
    priv_protocol: str = "none"
    priv_key: Optional[str] = None
    engine_id: Optional[str] = None
