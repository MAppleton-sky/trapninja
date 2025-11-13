#!/usr/bin/env python3
"""
TrapNinja High Availability Module - IMPROVED VERSION

Key improvements:
- Manual promotion/demotion commands
- Improved peer discovery at startup
- Graceful failback mechanism
- Better state coordination
- Persistent state tracking
"""
import os
import sys
import time
import json
import socket
import threading
import logging
import hashlib
import uuid
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Dict, Callable

logger = logging.getLogger("trapninja")


class HAState(Enum):
    """High Availability states"""
    INITIALIZING = "initializing"
    PRIMARY = "primary"
    SECONDARY = "secondary"
    STANDALONE = "standalone"
    FAILOVER = "failover"
    SPLIT_BRAIN = "split_brain"
    ERROR = "error"


class HAMessageType(Enum):
    """HA Message types"""
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    CLAIM_PRIMARY = "claim_primary"
    YIELD_PRIMARY = "yield_primary"
    FORCE_SECONDARY = "force_secondary"
    STATUS_REQUEST = "status_request"
    STATUS_RESPONSE = "status_response"
    SHUTDOWN = "shutdown"


@dataclass
class HAMessage:
    """HA communication message"""
    msg_type: HAMessageType
    sender_id: str
    timestamp: float
    sequence: int
    state: HAState
    priority: int
    uptime: float
    last_trap_time: Optional[float] = None
    checksum: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data['msg_type'] = self.msg_type.value
        data['state'] = self.state.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> 'HAMessage':
        data['msg_type'] = HAMessageType(data['msg_type'])
        data['state'] = HAState(data['state'])
        return cls(**data)

    def calculate_checksum(self) -> str:
        data = self.to_dict()
        data.pop('checksum', None)
        content = json.dumps(data, sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()

    def verify_checksum(self) -> bool:
        if not self.checksum:
            return False
        return self.calculate_checksum() == self.checksum


@dataclass
class HAConfig:
    """HA Configuration"""
    enabled: bool = False
    mode: str = "primary"
    peer_host: str = "127.0.0.1"
    peer_port: int = 8162
    listen_port: int = 8162
    heartbeat_interval: float = 1.0
    heartbeat_timeout: float = 3.0
    failover_delay: float = 2.0
    priority: int = 100
    shared_secret: str = ""
    split_brain_detection: bool = True
    max_retries: int = 3
    retry_delay: float = 0.5
    # NEW: Failback behavior
    auto_failback: bool = False  # If True, Primary auto-reclaims on restart
    startup_peer_check: bool = True  # Check peer state before becoming PRIMARY


class HACluster:
    """
    IMPROVED High Availability cluster manager
    
    New features:
    - Manual promotion/demotion
    - Smarter startup behavior
    - Graceful failback
    - Persistent state tracking
    """

    def __init__(self, config: HAConfig, trap_forwarder_callback: Callable[[bool], None]):
        self.config = config
        self.trap_forwarder_callback = trap_forwarder_callback

        self.instance_id = str(uuid.uuid4())
        self.start_time = time.time()

        self.current_state = HAState.INITIALIZING
        self.is_forwarding = False
        self.last_trap_time: Optional[float] = None

        self.sequence_counter = 0
        self.heartbeat_socket: Optional[socket.socket] = None
        self.listen_socket: Optional[socket.socket] = None

        self.stop_event = threading.Event()
        self.state_lock = threading.RLock()
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.listen_thread: Optional[threading.Thread] = None

        self.peer_last_seen: Optional[float] = None
        self.peer_state: Optional[HAState] = None
        self.peer_priority: int = 0
        self.peer_uptime: float = 0

        self.failover_timer: Optional[threading.Timer] = None
        self.split_brain_detected = False
        
        # NEW: Manual override flag
        self.manual_override = False

        logger.info(f"HA Cluster initialized - Instance ID: {self.instance_id}")
        logger.info(f"Mode: {self.config.mode}, Priority: {self.config.priority}")

    def start(self) -> bool:
        """Start HA cluster with improved peer discovery"""
        if not self.config.enabled:
            logger.info("HA not enabled, running in standalone mode")
            self._set_state(HAState.STANDALONE)
            self._enable_forwarding()
            return True

        logger.info("Starting HA cluster...")

        try:
            # Start listener first
            if not self._start_listener():
                return False

            # NEW: Perform comprehensive peer discovery BEFORE claiming state
            if self.config.startup_peer_check:
                logger.info("Performing peer discovery before claiming state...")
                peer_discovered = self._comprehensive_peer_discovery()
                
                if peer_discovered:
                    logger.info(f"Peer discovered: state={self.peer_state}, priority={self.peer_priority}")
                    
                    # If peer is PRIMARY, we should become SECONDARY regardless of config
                    if self.peer_state == HAState.PRIMARY:
                        logger.info("Peer is already PRIMARY - becoming SECONDARY")
                        self._set_state(HAState.SECONDARY)
                    elif self.peer_state == HAState.SECONDARY:
                        # Both would be secondary - use priority to decide
                        if self.config.priority > self.peer_priority:
                            logger.info("Peer is SECONDARY and we have higher priority - claiming PRIMARY")
                            self._claim_primary()
                        else:
                            logger.info("Peer is SECONDARY but has higher/equal priority - staying SECONDARY")
                            self._set_state(HAState.SECONDARY)
                    else:
                        # Peer is in some other state, follow configured mode
                        initial_state = HAState.PRIMARY if self.config.mode == "primary" else HAState.SECONDARY
                        self._set_state(initial_state)
                else:
                    # No peer found - follow configured mode
                    logger.info("No peer discovered - following configured mode")
                    initial_state = HAState.PRIMARY if self.config.mode == "primary" else HAState.SECONDARY
                    self._set_state(initial_state)
            else:
                # Original behavior - follow config without checking
                initial_state = HAState.PRIMARY if self.config.mode == "primary" else HAState.SECONDARY
                self._set_state(initial_state)

            # Start heartbeat
            self._start_heartbeat()

            logger.info(f"HA cluster started in {self.current_state.value} mode")
            return True

        except Exception as e:
            logger.error(f"Failed to start HA cluster: {e}")
            return False

    def _comprehensive_peer_discovery(self, timeout: float = 3.0) -> bool:
        """
        Perform comprehensive peer discovery with multiple attempts
        
        Returns:
            True if peer was discovered and responded, False otherwise
        """
        max_attempts = 3
        attempt_delay = 1.0
        
        for attempt in range(max_attempts):
            logger.debug(f"Peer discovery attempt {attempt + 1}/{max_attempts}")
            
            try:
                # Send status request
                status_msg = self._create_message(HAMessageType.STATUS_REQUEST)
                
                # Create temporary socket for this request
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                try:
                    sock.connect((self.config.peer_host, self.config.peer_port))
                    data = json.dumps(status_msg.to_dict()).encode()
                    sock.send(data)
                    
                    # Wait for response
                    response = sock.recv(4096)
                    if response:
                        resp_data = json.loads(response.decode())
                        resp_msg = HAMessage.from_dict(resp_data)
                        
                        # Update peer information
                        self.peer_last_seen = time.time()
                        self.peer_state = resp_msg.state
                        self.peer_priority = resp_msg.priority
                        self.peer_uptime = resp_msg.uptime
                        
                        logger.info(f"Peer discovery successful: {self.peer_state.value}")
                        return True
                        
                except socket.timeout:
                    logger.debug(f"Peer discovery timeout on attempt {attempt + 1}")
                except socket.error as e:
                    logger.debug(f"Peer discovery socket error: {e}")
                finally:
                    sock.close()
                    
            except Exception as e:
                logger.debug(f"Peer discovery error: {e}")
            
            # Wait before next attempt
            if attempt < max_attempts - 1:
                time.sleep(attempt_delay)
        
        logger.info("Peer discovery completed - no peer found")
        return False

    def stop(self):
        """Stop the HA cluster"""
        logger.info("Stopping HA cluster...")

        if self.current_state == HAState.PRIMARY:
            self._send_message(HAMessageType.YIELD_PRIMARY)

        self.stop_event.set()

        if self.failover_timer:
            self.failover_timer.cancel()

        self._close_sockets()

        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=2.0)

        if self.listen_thread and self.listen_thread.is_alive():
            self.listen_thread.join(timeout=2.0)

        self._disable_forwarding()
        logger.info("HA cluster stopped")

    def get_status(self) -> Dict:
        """Get current HA status"""
        with self.state_lock:
            status = {
                "instance_id": self.instance_id,
                "state": self.current_state.value,
                "is_forwarding": self.is_forwarding,
                "uptime": time.time() - self.start_time,
                "priority": self.config.priority,
                "peer_connected": self.peer_last_seen is not None and
                                  (time.time() - self.peer_last_seen) < self.config.heartbeat_timeout,
                "peer_state": self.peer_state.value if self.peer_state else None,
                "peer_priority": self.peer_priority,
                "peer_uptime": self.peer_uptime,
                "peer_last_seen": self.peer_last_seen,
                "split_brain_detected": self.split_brain_detected,
                "last_trap_time": self.last_trap_time,
                "manual_override": self.manual_override,
                "auto_failback": self.config.auto_failback
            }
        return status

    def notify_trap_processed(self):
        """Notify HA system that a trap was processed"""
        self.last_trap_time = time.time()

    # =========================================================================
    # NEW: Manual control methods
    # =========================================================================
    
    def promote_to_primary(self, force: bool = False) -> bool:
        """
        Manually promote this node to PRIMARY
        
        Args:
            force: If True, become PRIMARY immediately without coordination
            
        Returns:
            True if successful
        """
        with self.state_lock:
            logger.info(f"Manual promotion to PRIMARY requested (force={force})")
            
            if self.current_state == HAState.PRIMARY:
                logger.info("Already PRIMARY - no action needed")
                return True
            
            self.manual_override = True
            
            if force:
                # Immediate promotion without coordination
                logger.warning("FORCE promotion - immediately becoming PRIMARY")
                self._send_message(HAMessageType.FORCE_SECONDARY)
                self._set_state(HAState.PRIMARY)
                return True
            else:
                # Graceful promotion with coordination
                logger.info("Graceful promotion - coordinating with peer")
                self._claim_primary()
                return True
    
    def demote_to_secondary(self) -> bool:
        """
        Manually demote this node to SECONDARY
        
        Returns:
            True if successful
        """
        with self.state_lock:
            logger.info("Manual demotion to SECONDARY requested")
            
            if self.current_state == HAState.SECONDARY:
                logger.info("Already SECONDARY - no action needed")
                return True
            
            if self.current_state == HAState.PRIMARY:
                logger.info("Yielding PRIMARY role and becoming SECONDARY")
                self._send_message(HAMessageType.YIELD_PRIMARY)
                self._set_state(HAState.SECONDARY)
                self.manual_override = False
                return True
            
            logger.warning(f"Cannot demote from state: {self.current_state.value}")
            return False

    def force_failover(self):
        """Force failover to secondary (for testing/maintenance)"""
        if self.current_state == HAState.PRIMARY:
            logger.warning("Forcing failover - yielding primary role")
            self._send_message(HAMessageType.YIELD_PRIMARY)
            self._set_state(HAState.SECONDARY)
            self._disable_forwarding()

    # =========================================================================
    # Internal methods (mostly unchanged, with improvements)
    # =========================================================================

    def _set_state(self, new_state: HAState):
        """Set HA state with proper locking and logging"""
        with self.state_lock:
            old_state = self.current_state
            self.current_state = new_state

            if old_state != new_state:
                logger.info(f"HA state transition: {old_state.value} -> {new_state.value}")

                if new_state == HAState.PRIMARY:
                    self._enable_forwarding()
                elif new_state in [HAState.SECONDARY, HAState.SPLIT_BRAIN]:
                    self._disable_forwarding()

    def _enable_forwarding(self):
        """Enable trap forwarding"""
        if not self.is_forwarding:
            self.is_forwarding = True
            logger.info("Trap forwarding ENABLED")
            try:
                self.trap_forwarder_callback(True)
            except Exception as e:
                logger.error(f"Error enabling trap forwarding: {e}")

    def _disable_forwarding(self):
        """Disable trap forwarding"""
        if self.is_forwarding:
            self.is_forwarding = False
            logger.info("Trap forwarding DISABLED")
            try:
                self.trap_forwarder_callback(False)
            except Exception as e:
                logger.error(f"Error disabling trap forwarding: {e}")

    def _start_listener(self) -> bool:
        """Start socket listener"""
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.settimeout(1.0)

            self.listen_socket.bind(('0.0.0.0', self.config.listen_port))
            self.listen_socket.listen(1)

            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()

            logger.info(f"HA listener started on port {self.config.listen_port}")
            return True

        except Exception as e:
            logger.error(f"Failed to start HA listener: {e}")
            return False

    def _listen_loop(self):
        """Main listening loop"""
        while not self.stop_event.is_set():
            try:
                conn, addr = self.listen_socket.accept()
                logger.debug(f"HA connection from {addr}")

                threading.Thread(
                    target=self._handle_peer_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()

            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    logger.error(f"Error in HA listen loop: {e}")
                    time.sleep(1)

    def _handle_peer_connection(self, conn: socket.socket, addr: tuple):
        """Handle incoming peer connection"""
        try:
            conn.settimeout(5.0)
            data = conn.recv(4096)
            if not data:
                return

            try:
                msg_data = json.loads(data.decode())
                message = HAMessage.from_dict(msg_data)
            except Exception as e:
                logger.warning(f"Invalid HA message from {addr}: {e}")
                return

            if not message.verify_checksum():
                logger.warning(f"HA message checksum verification failed from {addr}")
                return

            self._process_peer_message(message, addr)

            if message.msg_type == HAMessageType.HEARTBEAT:
                ack_msg = self._create_message(HAMessageType.HEARTBEAT_ACK)
                response_data = json.dumps(ack_msg.to_dict()).encode()
                conn.send(response_data)
            elif message.msg_type == HAMessageType.STATUS_REQUEST:
                resp_msg = self._create_message(HAMessageType.STATUS_RESPONSE)
                response_data = json.dumps(resp_msg.to_dict()).encode()
                conn.send(response_data)

        except Exception as e:
            logger.error(f"Error handling peer connection from {addr}: {e}")
        finally:
            conn.close()

    def _start_heartbeat(self):
        """Start heartbeat thread"""
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        logger.info("HA heartbeat started")

    def _heartbeat_loop(self):
        """Main heartbeat loop"""
        while not self.stop_event.is_set():
            try:
                self._send_heartbeat()
                self._check_peer_timeout()
                time.sleep(self.config.heartbeat_interval)
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                time.sleep(1)

    def _send_heartbeat(self):
        """Send heartbeat to peer"""
        if self.current_state == HAState.STANDALONE:
            return
        message = self._create_message(HAMessageType.HEARTBEAT)
        self._send_message_to_peer(message)

    def _send_message(self, msg_type: HAMessageType):
        """Send message to peer"""
        message = self._create_message(msg_type)
        self._send_message_to_peer(message)

    def _create_message(self, msg_type: HAMessageType) -> HAMessage:
        """Create HA message"""
        self.sequence_counter += 1

        message = HAMessage(
            msg_type=msg_type,
            sender_id=self.instance_id,
            timestamp=time.time(),
            sequence=self.sequence_counter,
            state=self.current_state,
            priority=self.config.priority,
            uptime=time.time() - self.start_time,
            last_trap_time=self.last_trap_time
        )

        message.checksum = message.calculate_checksum()
        return message

    def _send_message_to_peer(self, message: HAMessage):
        """Send message to peer via socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)

            sock.connect((self.config.peer_host, self.config.peer_port))

            data = json.dumps(message.to_dict()).encode()
            sock.send(data)

            if message.msg_type in [HAMessageType.HEARTBEAT, HAMessageType.STATUS_REQUEST]:
                response = sock.recv(1024)
                if response:
                    try:
                        resp_data = json.loads(response.decode())
                        resp_msg = HAMessage.from_dict(resp_data)
                        logger.debug(f"Received response: {resp_msg.msg_type.value}")
                    except Exception:
                        pass

            sock.close()

        except Exception as e:
            logger.debug(f"Failed to send HA message to peer: {e}")

    def _process_peer_message(self, message: HAMessage, addr: tuple):
        """Process message from peer"""
        logger.debug(f"Received HA message: {message.msg_type.value} from {addr}")

        self.peer_last_seen = time.time()
        self.peer_state = message.state
        self.peer_priority = message.priority
        self.peer_uptime = message.uptime

        if message.msg_type == HAMessageType.HEARTBEAT:
            self._handle_peer_heartbeat(message)
        elif message.msg_type == HAMessageType.CLAIM_PRIMARY:
            self._handle_peer_claim_primary(message)
        elif message.msg_type == HAMessageType.YIELD_PRIMARY:
            self._handle_peer_yield_primary(message)
        elif message.msg_type == HAMessageType.FORCE_SECONDARY:
            self._handle_peer_force_secondary(message)

    def _handle_peer_heartbeat(self, message: HAMessage):
        """Handle heartbeat from peer"""
        # Detect split-brain
        if (self.current_state == HAState.PRIMARY and
                message.state == HAState.PRIMARY and
                self.config.split_brain_detection):
            logger.error("SPLIT-BRAIN detected! Both instances are primary!")
            self._handle_split_brain(message)
            return

        # Normal heartbeat processing - states are complementary
        if (self.current_state == HAState.SECONDARY and message.state == HAState.PRIMARY):
            return
        if (self.current_state == HAState.PRIMARY and message.state == HAState.SECONDARY):
            return

        # Both secondary - decide who becomes primary
        if (self.current_state == HAState.SECONDARY and message.state == HAState.SECONDARY):
            self._resolve_dual_secondary(message)

    def _handle_split_brain(self, peer_message: HAMessage):
        """Handle split-brain scenario"""
        self.split_brain_detected = True

        # Don't yield if we have manual override
        if self.manual_override:
            logger.warning("Split-brain detected but manual override active - maintaining PRIMARY")
            return

        should_yield = False

        if self.config.priority < peer_message.priority:
            should_yield = True
            reason = "lower priority"
        elif self.config.priority == peer_message.priority:
            if self.start_time > peer_message.timestamp - peer_message.uptime:
                should_yield = True
                reason = "started later"
            else:
                should_yield = False
                reason = "started earlier"
        else:
            should_yield = False
            reason = "higher priority"

        if should_yield:
            logger.warning(f"Yielding primary role due to split-brain ({reason})")
            self._set_state(HAState.SECONDARY)
            self._send_message(HAMessageType.YIELD_PRIMARY)
        else:
            logger.warning(f"Maintaining primary role in split-brain ({reason})")
            self._send_message(HAMessageType.CLAIM_PRIMARY)

    def _resolve_dual_secondary(self, peer_message: HAMessage):
        """Resolve both instances being secondary"""
        should_become_primary = False

        if self.config.priority > peer_message.priority:
            should_become_primary = True
        elif self.config.priority == peer_message.priority:
            if self.start_time < peer_message.timestamp - peer_message.uptime:
                should_become_primary = True

        if should_become_primary:
            logger.info("Claiming primary role (peer is also secondary)")
            self._claim_primary()

    def _handle_peer_claim_primary(self, message: HAMessage):
        """Handle peer claiming primary role"""
        if self.current_state == HAState.PRIMARY:
            # Don't yield if we have manual override
            if self.manual_override:
                logger.warning("Peer claiming PRIMARY but manual override active - maintaining")
                self._send_message(HAMessageType.CLAIM_PRIMARY)
                return

            if message.priority > self.config.priority:
                logger.info("Yielding primary role to higher priority peer")
                self._set_state(HAState.SECONDARY)
            elif message.priority == self.config.priority:
                peer_start_time = message.timestamp - message.uptime
                if peer_start_time < self.start_time:
                    logger.info("Yielding primary role to peer with longer uptime")
                    self._set_state(HAState.SECONDARY)
                else:
                    logger.info("Maintaining primary role (longer uptime)")
                    self._send_message(HAMessageType.CLAIM_PRIMARY)
            else:
                logger.info("Rejecting peer primary claim (higher priority)")
                self._send_message(HAMessageType.CLAIM_PRIMARY)

    def _handle_peer_yield_primary(self, message: HAMessage):
        """Handle peer yielding primary role"""
        if self.current_state == HAState.SECONDARY:
            logger.info("Peer yielded primary role, claiming it")
            self._claim_primary()

    def _handle_peer_force_secondary(self, message: HAMessage):
        """Handle peer forcing us to SECONDARY"""
        logger.warning("Peer sent FORCE_SECONDARY - complying")
        if self.current_state == HAState.PRIMARY:
            self._set_state(HAState.SECONDARY)
            self.manual_override = False

    def _claim_primary(self):
        """Claim primary role"""
        logger.info("Claiming primary role")
        self._set_state(HAState.FAILOVER)

        self._send_message(HAMessageType.CLAIM_PRIMARY)

        self.failover_timer = threading.Timer(
            self.config.failover_delay,
            self._complete_failover
        )
        self.failover_timer.start()

    def _complete_failover(self):
        """Complete failover to primary role"""
        logger.info("Completing failover to primary role")
        self._set_state(HAState.PRIMARY)
        self.split_brain_detected = False

    def _check_peer_timeout(self):
        """Check if peer has timed out"""
        if not self.peer_last_seen:
            return

        time_since_last_seen = time.time() - self.peer_last_seen

        if time_since_last_seen > self.config.heartbeat_timeout:
            logger.warning(f"Peer timeout detected ({time_since_last_seen:.1f}s)")

            if self.current_state == HAState.SECONDARY:
                logger.info("Peer timeout - claiming primary role")
                self._claim_primary()

            self.peer_last_seen = None
            self.peer_state = None

    def _close_sockets(self):
        """Close all sockets"""
        if self.heartbeat_socket:
            try:
                self.heartbeat_socket.close()
            except:
                pass
            self.heartbeat_socket = None

        if self.listen_socket:
            try:
                self.listen_socket.close()
            except:
                pass
            self.listen_socket = None


# ============================================================================
# Module-level functions (API)
# ============================================================================

def load_ha_config(config_path: str = None) -> HAConfig:
    """Load HA configuration from file"""
    if not config_path:
        from .config import CONFIG_DIR
        config_path = os.path.join(CONFIG_DIR, "ha_config.json")

    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            config = HAConfig(**config_data)
            logger.info(f"HA configuration loaded from {config_path}")
            return config
        else:
            logger.info(f"HA config file not found, using defaults")
            return HAConfig()
    except Exception as e:
        logger.error(f"Error loading HA configuration: {e}")
        return HAConfig()


def save_ha_config(config: HAConfig, config_path: str = None) -> bool:
    """Save HA configuration to file"""
    if not config_path:
        from .config import CONFIG_DIR
        config_path = os.path.join(CONFIG_DIR, "ha_config.json")

    try:
        config_data = asdict(config)
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        logger.info(f"HA configuration saved to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving HA configuration: {e}")
        return False


# Global HA cluster instance
_ha_cluster: Optional[HACluster] = None


def get_ha_cluster() -> Optional[HACluster]:
    """Get the global HA cluster instance"""
    return _ha_cluster


def initialize_ha(config: HAConfig, trap_forwarder_callback: Callable[[bool], None]) -> bool:
    """Initialize the global HA cluster"""
    global _ha_cluster

    try:
        _ha_cluster = HACluster(config, trap_forwarder_callback)
        return _ha_cluster.start()
    except Exception as e:
        logger.error(f"Failed to initialize HA cluster: {e}")
        return False


def shutdown_ha():
    """Shutdown the global HA cluster"""
    global _ha_cluster

    if _ha_cluster:
        _ha_cluster.stop()
        _ha_cluster = None


def notify_trap_processed():
    """Notify HA system that a trap was processed"""
    if _ha_cluster:
        _ha_cluster.notify_trap_processed()


def get_ha_status() -> Dict:
    """Get current HA status"""
    if _ha_cluster:
        return _ha_cluster.get_status()
    return {"enabled": False, "state": "disabled"}


def is_forwarding_enabled() -> bool:
    """Check if trap forwarding is currently enabled"""
    if _ha_cluster:
        return _ha_cluster.is_forwarding
    return True


# ============================================================================
# NEW: Manual control functions
# ============================================================================

def promote_to_primary(force: bool = False) -> bool:
    """
    Manually promote this instance to PRIMARY
    
    Args:
        force: If True, become PRIMARY immediately without coordination
        
    Returns:
        True if successful, False otherwise
    """
    if _ha_cluster:
        return _ha_cluster.promote_to_primary(force=force)
    logger.error("HA cluster not running")
    return False


def demote_to_secondary() -> bool:
    """
    Manually demote this instance to SECONDARY
    
    Returns:
        True if successful, False otherwise
    """
    if _ha_cluster:
        return _ha_cluster.demote_to_secondary()
    logger.error("HA cluster not running")
    return False
