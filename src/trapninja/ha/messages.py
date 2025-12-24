#!/usr/bin/env python3
"""
TrapNinja HA Messages

Defines message types and serialization for HA cluster communication.
Messages are used for heartbeats, state coordination, and commands.

Author: TrapNinja Team
Version: 2.0.0
"""

import json
import hashlib
from enum import Enum
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any

from .state import HAState


class HAMessageType(Enum):
    """
    HA Message types for cluster communication.
    
    Message Types:
        HEARTBEAT: Periodic health check
        HEARTBEAT_ACK: Response to heartbeat
        CLAIM_PRIMARY: Request to become primary
        YIELD_PRIMARY: Voluntarily give up primary role
        FORCE_SECONDARY: Force peer to become secondary
        STATUS_REQUEST: Request peer status
        STATUS_RESPONSE: Response with status
        SHUTDOWN: Notify peer of shutdown
        CONFIG_SYNC: Configuration synchronization
        CONFIG_REQUEST: Request full config bundle
        CONFIG_PUSH: Push config to peer
        CONFIG_ACK: Acknowledge config receipt
    """
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    CLAIM_PRIMARY = "claim_primary"
    YIELD_PRIMARY = "yield_primary"
    FORCE_SECONDARY = "force_secondary"
    STATUS_REQUEST = "status_request"
    STATUS_RESPONSE = "status_response"
    SHUTDOWN = "shutdown"
    # Config sync message types
    CONFIG_SYNC = "config_sync"
    CONFIG_REQUEST = "config_request"
    CONFIG_PUSH = "config_push"
    CONFIG_ACK = "config_ack"
    
    def __str__(self) -> str:
        return self.value
    
    @property
    def requires_response(self) -> bool:
        """Check if this message type requires a response."""
        return self in (
            HAMessageType.HEARTBEAT,
            HAMessageType.STATUS_REQUEST,
            HAMessageType.CONFIG_REQUEST,
            HAMessageType.CONFIG_PUSH
        )
    
    @property
    def is_command(self) -> bool:
        """Check if this is a command message."""
        return self in (
            HAMessageType.CLAIM_PRIMARY,
            HAMessageType.YIELD_PRIMARY,
            HAMessageType.FORCE_SECONDARY,
            HAMessageType.SHUTDOWN,
            HAMessageType.CONFIG_PUSH
        )
    
    @property
    def is_config_sync(self) -> bool:
        """Check if this is a config sync message."""
        return self in (
            HAMessageType.CONFIG_SYNC,
            HAMessageType.CONFIG_REQUEST,
            HAMessageType.CONFIG_PUSH,
            HAMessageType.CONFIG_ACK
        )


@dataclass
class HAMessage:
    """
    HA communication message.
    
    All messages between HA cluster nodes use this format.
    Includes checksum for message integrity verification.
    
    Attributes:
        msg_type: Type of message
        sender_id: UUID of sending instance
        timestamp: Unix timestamp when message was created
        sequence: Sequence number for ordering
        state: Current HA state of sender
        priority: Priority value of sender
        uptime: Uptime of sender in seconds
        last_trap_time: Timestamp of last processed trap
        checksum: MD5 checksum for integrity
        payload: Optional additional data
        config_checksum: Checksum of shared configuration (for sync detection)
    """
    msg_type: HAMessageType
    sender_id: str
    timestamp: float
    sequence: int
    state: HAState
    priority: int
    uptime: float
    last_trap_time: Optional[float] = None
    checksum: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    config_checksum: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert message to dictionary for JSON serialization.
        
        Returns:
            Dictionary representation of message
        """
        data = {
            'msg_type': self.msg_type.value,
            'sender_id': self.sender_id,
            'timestamp': self.timestamp,
            'sequence': self.sequence,
            'state': self.state.value,
            'priority': self.priority,
            'uptime': self.uptime,
            'last_trap_time': self.last_trap_time,
            'checksum': self.checksum,
            'config_checksum': self.config_checksum
        }
        if self.payload:
            data['payload'] = self.payload
        return data
    
    def to_json(self) -> str:
        """
        Convert message to JSON string.
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict())
    
    def to_bytes(self) -> bytes:
        """
        Convert message to bytes for network transmission.
        
        Returns:
            UTF-8 encoded JSON bytes
        """
        return self.to_json().encode('utf-8')
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HAMessage':
        """
        Create message from dictionary.
        
        Args:
            data: Dictionary representation of message
            
        Returns:
            HAMessage instance
        """
        return cls(
            msg_type=HAMessageType(data['msg_type']),
            sender_id=data['sender_id'],
            timestamp=data['timestamp'],
            sequence=data['sequence'],
            state=HAState(data['state']),
            priority=data['priority'],
            uptime=data['uptime'],
            last_trap_time=data.get('last_trap_time'),
            checksum=data.get('checksum'),
            payload=data.get('payload'),
            config_checksum=data.get('config_checksum')
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'HAMessage':
        """
        Create message from JSON string.
        
        Args:
            json_str: JSON string representation
            
        Returns:
            HAMessage instance
        """
        return cls.from_dict(json.loads(json_str))
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'HAMessage':
        """
        Create message from bytes.
        
        Args:
            data: UTF-8 encoded JSON bytes
            
        Returns:
            HAMessage instance
        """
        return cls.from_json(data.decode('utf-8'))
    
    def calculate_checksum(self) -> str:
        """
        Calculate MD5 checksum of message content.
        
        The checksum covers all fields except the checksum itself.
        
        Returns:
            Hex-encoded MD5 checksum
        """
        data = self.to_dict()
        data.pop('checksum', None)
        content = json.dumps(data, sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()
    
    def sign(self) -> 'HAMessage':
        """
        Sign message by calculating and setting checksum.
        
        Returns:
            Self for chaining
        """
        self.checksum = self.calculate_checksum()
        return self
    
    def verify(self) -> bool:
        """
        Verify message checksum.
        
        Returns:
            True if checksum is valid
        """
        if not self.checksum:
            return False
        return self.calculate_checksum() == self.checksum
    
    def __str__(self) -> str:
        return (
            f"HAMessage({self.msg_type.value}, "
            f"from={self.sender_id[:8]}..., "
            f"state={self.state.value}, "
            f"seq={self.sequence})"
        )


class MessageFactory:
    """
    Factory for creating HA messages.
    
    Provides convenient methods for creating common message types
    with automatic sequence numbering and checksum calculation.
    """
    
    def __init__(self, instance_id: str, priority: int):
        self.instance_id = instance_id
        self.priority = priority
        self._sequence = 0
        self._start_time = __import__('time').time()
        self._config_checksum: Optional[str] = None
    
    def set_config_checksum(self, checksum: str):
        """Set the config checksum to include in messages."""
        self._config_checksum = checksum
    
    def _next_sequence(self) -> int:
        """Get next sequence number."""
        self._sequence += 1
        return self._sequence
    
    def _uptime(self) -> float:
        """Get current uptime."""
        return __import__('time').time() - self._start_time
    
    def create(
        self,
        msg_type: HAMessageType,
        state: HAState,
        last_trap_time: Optional[float] = None,
        payload: Optional[Dict[str, Any]] = None,
        config_checksum: Optional[str] = None
    ) -> HAMessage:
        """
        Create a new HA message.
        
        Args:
            msg_type: Type of message
            state: Current HA state
            last_trap_time: Timestamp of last processed trap
            payload: Optional additional data
            config_checksum: Optional config checksum override
            
        Returns:
            Signed HAMessage instance
        """
        message = HAMessage(
            msg_type=msg_type,
            sender_id=self.instance_id,
            timestamp=__import__('time').time(),
            sequence=self._next_sequence(),
            state=state,
            priority=self.priority,
            uptime=self._uptime(),
            last_trap_time=last_trap_time,
            payload=payload,
            config_checksum=config_checksum or self._config_checksum
        )
        return message.sign()
    
    def heartbeat(self, state: HAState, last_trap_time: Optional[float] = None) -> HAMessage:
        """Create a heartbeat message."""
        return self.create(HAMessageType.HEARTBEAT, state, last_trap_time)
    
    def heartbeat_ack(self, state: HAState) -> HAMessage:
        """Create a heartbeat acknowledgment message."""
        return self.create(HAMessageType.HEARTBEAT_ACK, state)
    
    def claim_primary(self, state: HAState) -> HAMessage:
        """Create a claim primary message."""
        return self.create(HAMessageType.CLAIM_PRIMARY, state)
    
    def yield_primary(self, state: HAState) -> HAMessage:
        """Create a yield primary message."""
        return self.create(HAMessageType.YIELD_PRIMARY, state)
    
    def force_secondary(self, state: HAState) -> HAMessage:
        """Create a force secondary message."""
        return self.create(HAMessageType.FORCE_SECONDARY, state)
    
    def status_request(self, state: HAState) -> HAMessage:
        """Create a status request message."""
        return self.create(HAMessageType.STATUS_REQUEST, state)
    
    def status_response(self, state: HAState, status: Dict[str, Any]) -> HAMessage:
        """Create a status response message."""
        return self.create(HAMessageType.STATUS_RESPONSE, state, payload=status)
    
    def shutdown(self, state: HAState) -> HAMessage:
        """Create a shutdown notification message."""
        return self.create(HAMessageType.SHUTDOWN, state)
    
    def config_request(self, state: HAState) -> HAMessage:
        """Create a config request message."""
        return self.create(HAMessageType.CONFIG_REQUEST, state)
    
    def config_push(self, state: HAState, bundle_data: Dict[str, Any]) -> HAMessage:
        """Create a config push message with bundle payload."""
        return self.create(HAMessageType.CONFIG_PUSH, state, payload={'bundle': bundle_data})
    
    def config_ack(self, state: HAState, success: bool, message: str = "") -> HAMessage:
        """Create a config acknowledgment message."""
        return self.create(
            HAMessageType.CONFIG_ACK,
            state,
            payload={'success': success, 'message': message}
        )
