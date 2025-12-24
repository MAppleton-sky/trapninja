#!/usr/bin/env python3
"""
TrapNinja HA Cluster

Main High Availability cluster implementation.
Handles peer communication, state coordination, and failover.

Author: TrapNinja Team
Version: 2.0.0
"""

import time
import json
import socket
import threading
import uuid
import logging
from typing import Optional, Dict, Any, Callable

from .state import HAState, HAStateManager
from .messages import HAMessage, HAMessageType, MessageFactory
from .config import HAConfig

# Try to import config sync (optional feature)
try:
    from .sync import ConfigSyncManager, ConfigBundle
    CONFIG_SYNC_AVAILABLE = True
except ImportError:
    CONFIG_SYNC_AVAILABLE = False

logger = logging.getLogger("trapninja")


class HACluster:
    """
    High Availability Cluster Manager.
    
    Manages HA clustering with:
    - Automatic failover on peer failure
    - Manual promotion/demotion commands
    - Split-brain detection and resolution
    - Peer discovery at startup
    - Graceful shutdown coordination
    
    Attributes:
        config: HA configuration
        instance_id: Unique identifier for this instance
        state_manager: State machine manager
        is_forwarding: Whether forwarding is currently enabled
    """
    
    def __init__(
        self,
        config: HAConfig,
        trap_forwarder_callback: Callable[[bool], None],
        config_dir: Optional[str] = None,
        on_config_changed: Optional[Callable[[], None]] = None
    ):
        """
        Initialize HA cluster.
        
        Args:
            config: HA configuration
            trap_forwarder_callback: Callback to enable/disable forwarding
            config_dir: Path to configuration directory (for config sync)
            on_config_changed: Callback when config is updated by sync
        """
        self.config = config
        self.trap_forwarder_callback = trap_forwarder_callback
        self.config_dir = config_dir
        self.on_config_changed = on_config_changed
        
        # Instance identification
        self.instance_id = str(uuid.uuid4())
        self.start_time = time.time()
        
        # State management
        self.state_manager = HAStateManager(HAState.INITIALIZING)
        self.is_forwarding = False
        self.last_trap_time: Optional[float] = None
        
        # Message factory
        self.msg_factory = MessageFactory(self.instance_id, config.priority)
        
        # Network
        self.listen_socket: Optional[socket.socket] = None
        
        # Threading
        self.stop_event = threading.Event()
        self.state_lock = threading.RLock()
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.listen_thread: Optional[threading.Thread] = None
        self.failover_timer: Optional[threading.Timer] = None
        
        # Peer tracking
        self.peer_last_seen: Optional[float] = None
        self.peer_state: Optional[HAState] = None
        self.peer_priority: int = 0
        self.peer_uptime: float = 0
        
        # Flags
        self.split_brain_detected = False
        self.manual_override = False
        
        # Config sync manager (optional)
        self.config_sync: Optional['ConfigSyncManager'] = None
        if CONFIG_SYNC_AVAILABLE and config_dir:
            self.config_sync = ConfigSyncManager(
                config_dir=config_dir,
                instance_id=self.instance_id,
                peer_host=config.peer_host,
                peer_port=config.peer_port,
                on_config_changed=on_config_changed
            )
        
        logger.info(f"HA Cluster initialized - Instance ID: {self.instance_id[:8]}...")
        logger.info(f"Mode: {config.mode}, Priority: {config.priority}")
        if self.config_sync:
            logger.info("Config sync enabled")
    
    @property
    def current_state(self) -> HAState:
        """Get current HA state."""
        return self.state_manager.state
    
    def start(self) -> bool:
        """
        Start HA cluster.
        
        Performs peer discovery and initializes to appropriate state.
        
        Returns:
            True if started successfully
        """
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
            
            # Perform peer discovery
            if self.config.startup_peer_check:
                logger.info("Performing peer discovery...")
                peer_found = self._discover_peer()
                
                if peer_found:
                    logger.info(
                        f"Peer discovered: state={self.peer_state}, "
                        f"priority={self.peer_priority}"
                    )
                    
                    # Determine initial state based on peer
                    if self.peer_state == HAState.PRIMARY:
                        logger.info("Peer is PRIMARY - becoming SECONDARY")
                        self._set_state(HAState.SECONDARY)
                        # Start config sync as secondary
                        if self.config_sync:
                            self.config_sync.start(is_primary=False)
                    elif self.peer_state == HAState.SECONDARY:
                        if self.config.priority > self.peer_priority:
                            logger.info("Higher priority - claiming PRIMARY")
                            self._claim_primary()
                        else:
                            logger.info("Lower/equal priority - staying SECONDARY")
                            self._set_state(HAState.SECONDARY)
                    else:
                        # Follow configured mode
                        self._set_initial_state()
                else:
                    logger.info("No peer discovered - following configured mode")
                    self._set_initial_state()
            else:
                self._set_initial_state()
            
            # Start heartbeat
            self._start_heartbeat()
            
            # Update config sync with initial state
            if self.config_sync and not self.config_sync._monitor_thread:
                is_primary = self.current_state == HAState.PRIMARY
                self.config_sync.start(is_primary=is_primary)
                # Update message factory with config checksum
                self.msg_factory.set_config_checksum(
                    self.config_sync.get_local_checksum()
                )
            
            logger.info(f"HA cluster started in {self.current_state.value} mode")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start HA cluster: {e}")
            return False
    
    def stop(self):
        """Stop HA cluster gracefully."""
        logger.info("Stopping HA cluster...")
        
        # Notify peer of shutdown
        if self.current_state == HAState.PRIMARY:
            self._send_message(HAMessageType.YIELD_PRIMARY)
        
        self.stop_event.set()
        
        # Stop config sync
        if self.config_sync:
            self.config_sync.stop()
        
        # Cancel failover timer
        if self.failover_timer:
            self.failover_timer.cancel()
        
        # Close sockets
        self._close_sockets()
        
        # Wait for threads
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=2.0)
        if self.listen_thread and self.listen_thread.is_alive():
            self.listen_thread.join(timeout=2.0)
        
        self._disable_forwarding()
        logger.info("HA cluster stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current HA status."""
        with self.state_lock:
            peer_connected = (
                self.peer_last_seen is not None and
                (time.time() - self.peer_last_seen) < self.config.heartbeat_timeout
            )
            
            status = {
                "instance_id": self.instance_id,
                "state": self.current_state.value,
                "is_forwarding": self.is_forwarding,
                "uptime": time.time() - self.start_time,
                "priority": self.config.priority,
                "peer_connected": peer_connected,
                "peer_state": self.peer_state.value if self.peer_state else None,
                "peer_priority": self.peer_priority,
                "peer_uptime": self.peer_uptime,
                "peer_last_seen": self.peer_last_seen,
                "split_brain_detected": self.split_brain_detected,
                "last_trap_time": self.last_trap_time,
                "manual_override": self.manual_override,
                "auto_failback": self.config.auto_failback,
                "enabled": self.config.enabled
            }
            
            # Add config sync status if available
            if self.config_sync:
                status["config_sync"] = self.config_sync.get_status()
            
            return status
    
    def notify_trap_processed(self):
        """Notify that a trap was processed."""
        self.last_trap_time = time.time()
    
    # =========================================================================
    # Manual Control Methods
    # =========================================================================
    
    def promote_to_primary(self, force: bool = False) -> bool:
        """
        Manually promote to PRIMARY.
        
        Args:
            force: If True, become PRIMARY immediately
            
        Returns:
            True if successful
        """
        with self.state_lock:
            logger.info(f"Manual promotion requested (force={force})")
            
            if self.current_state == HAState.PRIMARY:
                logger.info("Already PRIMARY")
                return True
            
            self.manual_override = True
            
            if force:
                logger.warning("FORCE promotion - immediately becoming PRIMARY")
                self._send_message(HAMessageType.FORCE_SECONDARY)
                self._set_state(HAState.PRIMARY)
            else:
                logger.info("Graceful promotion - coordinating with peer")
                self._claim_primary()
            
            return True
    
    def demote_to_secondary(self) -> bool:
        """
        Manually demote to SECONDARY.
        
        Returns:
            True if successful
        """
        with self.state_lock:
            logger.info("Manual demotion requested")
            
            if self.current_state == HAState.SECONDARY:
                logger.info("Already SECONDARY")
                return True
            
            if self.current_state == HAState.PRIMARY:
                logger.info("Yielding PRIMARY role")
                self._send_message(HAMessageType.YIELD_PRIMARY)
                self._set_state(HAState.SECONDARY)
                self.manual_override = False
                return True
            
            logger.warning(f"Cannot demote from state: {self.current_state.value}")
            return False
    
    # =========================================================================
    # Internal Methods
    # =========================================================================
    
    def _set_initial_state(self):
        """Set initial state based on configuration."""
        initial = HAState.PRIMARY if self.config.mode == "primary" else HAState.SECONDARY
        self._set_state(initial)
    
    def _set_state(self, new_state: HAState):
        """Set HA state with proper handling."""
        with self.state_lock:
            old_state = self.current_state
            
            if self.state_manager.transition_to(new_state):
                if old_state != new_state:
                    if new_state.is_active:
                        self._enable_forwarding()
                    else:
                        self._disable_forwarding()
                    
                    # Update config sync primary status
                    if self.config_sync:
                        is_primary = new_state == HAState.PRIMARY
                        self.config_sync.set_primary(is_primary)
    
    def _enable_forwarding(self):
        """Enable trap forwarding."""
        was_disabled = not self.is_forwarding
        self.is_forwarding = True  # Always set to True
        
        if was_disabled:
            logger.info("Trap forwarding ENABLED")
            try:
                self.trap_forwarder_callback(True)
            except Exception as e:
                logger.error(f"Error enabling forwarding: {e}")
        else:
            logger.debug("Trap forwarding already enabled")
    
    def _disable_forwarding(self):
        """
        Disable trap forwarding.
        
        CRITICAL: This method ALWAYS sets is_forwarding to False,
        regardless of current state. This ensures forwarding is
        disabled even if the state machine transitions directly
        to SECONDARY from INITIALIZING.
        """
        was_enabled = self.is_forwarding
        self.is_forwarding = False  # ALWAYS set to False
        
        if was_enabled:
            logger.info("Trap forwarding DISABLED")
            try:
                self.trap_forwarder_callback(False)
            except Exception as e:
                logger.error(f"Error disabling forwarding: {e}")
        else:
            # Still log at info level for state transitions to help debugging
            logger.info("Trap forwarding confirmed DISABLED (was already disabled)")
    
    def _discover_peer(self, timeout: float = 3.0) -> bool:
        """
        Discover peer with multiple attempts.
        
        Returns:
            True if peer was discovered
        """
        for attempt in range(self.config.max_retries):
            logger.debug(f"Peer discovery attempt {attempt + 1}/{self.config.max_retries}")
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                try:
                    sock.connect((self.config.peer_host, self.config.peer_port))
                    
                    # Send status request
                    msg = self.msg_factory.status_request(self.current_state)
                    sock.send(msg.to_bytes())
                    
                    # Wait for response
                    response = sock.recv(4096)
                    if response:
                        resp_msg = HAMessage.from_bytes(response)
                        self._update_peer_info(resp_msg)
                        logger.info(f"Peer discovery successful")
                        return True
                        
                except socket.timeout:
                    logger.debug(f"Peer discovery timeout")
                except socket.error as e:
                    logger.debug(f"Peer discovery socket error: {e}")
                finally:
                    sock.close()
                    
            except Exception as e:
                logger.debug(f"Peer discovery error: {e}")
            
            if attempt < self.config.max_retries - 1:
                time.sleep(self.config.retry_delay)
        
        return False
    
    def _start_listener(self) -> bool:
        """Start socket listener."""
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.settimeout(1.0)
            
            self.listen_socket.bind(('0.0.0.0', self.config.listen_port))
            self.listen_socket.listen(5)
            
            self.listen_thread = threading.Thread(
                target=self._listen_loop,
                daemon=True,
                name="HAListener"
            )
            self.listen_thread.start()
            
            logger.info(f"HA listener started on port {self.config.listen_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start HA listener: {e}")
            return False
    
    def _listen_loop(self):
        """Main listening loop."""
        while not self.stop_event.is_set():
            try:
                conn, addr = self.listen_socket.accept()
                logger.debug(f"HA connection from {addr}")
                
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    logger.error(f"HA listen error: {e}")
                    time.sleep(1)
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle incoming peer connection."""
        try:
            conn.settimeout(5.0)
            data = conn.recv(65536)  # Larger buffer for config sync
            if not data:
                return
            
            # Try to parse as JSON first (config sync messages)
            try:
                json_data = json.loads(data.decode('utf-8'))
                msg_type = json_data.get('type', '')
                
                # Handle config sync messages
                if msg_type == 'config_request':
                    self._handle_config_request_json(conn, json_data, addr)
                    return
                elif msg_type == 'config_push':
                    self._handle_config_push_json(conn, json_data, addr)
                    return
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Not a JSON message, try as HAMessage
                pass
            
            # Parse as HAMessage
            try:
                message = HAMessage.from_bytes(data)
            except Exception as e:
                logger.warning(f"Invalid HA message from {addr}: {e}")
                return
            
            if not message.verify():
                logger.warning(
                    f"HA message checksum failed from {addr} - "
                    f"possible version mismatch between HA nodes. "
                    f"Received: type={message.msg_type.value}, "
                    f"sender={message.sender_id[:8]}..."
                )
                logger.debug(
                    f"Checksum details - received: {message.checksum}, "
                    f"calculated: {message.calculate_checksum()}"
                )
                return
            
            self._process_message(message, addr)
            
            # Send response if needed
            if message.msg_type == HAMessageType.HEARTBEAT:
                ack = self.msg_factory.heartbeat_ack(self.current_state)
                conn.send(ack.to_bytes())
            elif message.msg_type == HAMessageType.STATUS_REQUEST:
                resp = self.msg_factory.status_response(
                    self.current_state,
                    self.get_status()
                )
                conn.send(resp.to_bytes())
                
        except Exception as e:
            logger.error(f"Error handling connection from {addr}: {e}")
        finally:
            conn.close()
    
    def _handle_config_request_json(self, conn: socket.socket, data: dict, addr: tuple):
        """Handle JSON config request from peer."""
        sender = data.get('sender', 'unknown')[:8]
        logger.info(f"Config request from {sender}... at {addr}")
        
        if not self.config_sync:
            logger.warning("Config request received but config sync not available")
            response = {'type': 'error', 'error': 'Config sync not available'}
            conn.send(json.dumps(response).encode('utf-8'))
            return
        
        if self.current_state != HAState.PRIMARY:
            logger.debug("Config request received but we are not PRIMARY")
            response = {'type': 'error', 'error': 'Not PRIMARY'}
            conn.send(json.dumps(response).encode('utf-8'))
            return
        
        # Get config bundle and send response
        bundle = self.config_sync.handle_config_request()
        if bundle:
            response = {
                'type': 'config_response',
                'bundle': bundle.to_dict(),
            }
            conn.send(json.dumps(response).encode('utf-8'))
            logger.info(f"Sent config bundle to {sender}...")
        else:
            response = {'type': 'error', 'error': 'Failed to create bundle'}
            conn.send(json.dumps(response).encode('utf-8'))
    
    def _handle_config_push_json(self, conn: socket.socket, data: dict, addr: tuple):
        """Handle JSON config push from peer."""
        sender = data.get('sender', 'unknown')[:8]
        logger.info(f"Config push from {sender}... at {addr}")
        
        if not self.config_sync:
            logger.warning("Config push received but config sync not available")
            response = {'success': False, 'error': 'Config sync not available'}
            conn.send(json.dumps(response).encode('utf-8'))
            return
        
        if self.current_state == HAState.PRIMARY:
            logger.warning("Config push received but we are PRIMARY - rejecting")
            response = {'success': False, 'error': 'Cannot push to PRIMARY'}
            conn.send(json.dumps(response).encode('utf-8'))
            return
        
        # Apply the bundle
        bundle_data = data.get('bundle', {})
        try:
            from .sync import ConfigBundle
            bundle = ConfigBundle.from_dict(bundle_data)
            success, msg = self.config_sync.handle_config_push(bundle.to_bytes())
            response = {'success': success, 'message': msg}
            conn.send(json.dumps(response).encode('utf-8'))
            logger.info(f"Config push result: success={success}, {msg}")
        except Exception as e:
            logger.error(f"Failed to handle config push: {e}")
            response = {'success': False, 'error': str(e)}
            conn.send(json.dumps(response).encode('utf-8'))
    
    def _start_heartbeat(self):
        """Start heartbeat thread."""
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="HAHeartbeat"
        )
        self.heartbeat_thread.start()
        logger.info("HA heartbeat started")
    
    def _heartbeat_loop(self):
        """Main heartbeat loop."""
        while not self.stop_event.is_set():
            try:
                self._send_heartbeat()
                self._check_peer_timeout()
                time.sleep(self.config.heartbeat_interval)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                time.sleep(1)
    
    def _send_heartbeat(self):
        """Send heartbeat to peer."""
        if self.current_state == HAState.STANDALONE:
            return
        
        # Update config checksum in message factory
        if self.config_sync:
            self.msg_factory.set_config_checksum(
                self.config_sync.get_local_checksum()
            )
        
        msg = self.msg_factory.heartbeat(self.current_state, self.last_trap_time)
        self._send_message_to_peer(msg)
    
    def _send_message(self, msg_type: HAMessageType):
        """Send message to peer."""
        msg = self.msg_factory.create(msg_type, self.current_state, self.last_trap_time)
        self._send_message_to_peer(msg)
    
    def _send_message_to_peer(self, message: HAMessage):
        """Send message to peer via socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            
            sock.connect((self.config.peer_host, self.config.peer_port))
            sock.send(message.to_bytes())
            
            if message.msg_type.requires_response:
                response = sock.recv(1024)
                if response:
                    try:
                        resp_msg = HAMessage.from_bytes(response)
                        logger.debug(f"Received response: {resp_msg.msg_type.value}")
                    except Exception:
                        pass
            
            sock.close()
            
        except Exception as e:
            logger.debug(f"Failed to send HA message: {e}")
    
    def _process_message(self, message: HAMessage, addr: tuple):
        """Process message from peer."""
        logger.debug(f"Received: {message}")
        
        self._update_peer_info(message)
        
        handlers = {
            HAMessageType.HEARTBEAT: self._handle_heartbeat,
            HAMessageType.CLAIM_PRIMARY: self._handle_claim_primary,
            HAMessageType.YIELD_PRIMARY: self._handle_yield_primary,
            HAMessageType.FORCE_SECONDARY: self._handle_force_secondary,
            HAMessageType.CONFIG_REQUEST: self._handle_config_request,
            HAMessageType.CONFIG_PUSH: self._handle_config_push,
        }
        
        handler = handlers.get(message.msg_type)
        if handler:
            handler(message)
    
    def _update_peer_info(self, message: HAMessage):
        """Update peer information from message."""
        self.peer_last_seen = time.time()
        self.peer_state = message.state
        self.peer_priority = message.priority
        self.peer_uptime = message.uptime
        
        # Update config sync with peer's config checksum
        if self.config_sync and message.config_checksum:
            self.config_sync.update_remote_checksum(message.config_checksum)
    
    def _handle_heartbeat(self, message: HAMessage):
        """Handle heartbeat from peer."""
        # Detect split-brain
        if (self.current_state == HAState.PRIMARY and
                message.state == HAState.PRIMARY and
                self.config.split_brain_detection):
            logger.error("SPLIT-BRAIN detected!")
            self._handle_split_brain(message)
            return
        
        # Both secondary - resolve
        if (self.current_state == HAState.SECONDARY and
                message.state == HAState.SECONDARY):
            self._resolve_dual_secondary(message)
    
    def _handle_split_brain(self, message: HAMessage):
        """Handle split-brain scenario."""
        self.split_brain_detected = True
        
        if self.manual_override:
            logger.warning("Split-brain but manual override active - maintaining PRIMARY")
            return
        
        # Determine who yields based on priority and uptime
        should_yield = False
        reason = ""
        
        if self.config.priority < message.priority:
            should_yield = True
            reason = "lower priority"
        elif self.config.priority == message.priority:
            peer_start = message.timestamp - message.uptime
            if self.start_time > peer_start:
                should_yield = True
                reason = "started later"
            else:
                reason = "started earlier"
        else:
            reason = "higher priority"
        
        if should_yield:
            logger.warning(f"Yielding in split-brain ({reason})")
            self._set_state(HAState.SECONDARY)
            self._send_message(HAMessageType.YIELD_PRIMARY)
        else:
            logger.warning(f"Maintaining PRIMARY in split-brain ({reason})")
            self._send_message(HAMessageType.CLAIM_PRIMARY)
    
    def _resolve_dual_secondary(self, message: HAMessage):
        """Resolve both instances being secondary."""
        should_become_primary = False
        
        if self.config.priority > message.priority:
            should_become_primary = True
        elif self.config.priority == message.priority:
            peer_start = message.timestamp - message.uptime
            if self.start_time < peer_start:
                should_become_primary = True
        
        if should_become_primary:
            logger.info("Claiming PRIMARY (peer also secondary)")
            self._claim_primary()
    
    def _handle_claim_primary(self, message: HAMessage):
        """Handle peer claiming primary."""
        if self.current_state != HAState.PRIMARY:
            return
        
        if self.manual_override:
            logger.warning("Peer claiming PRIMARY but manual override active")
            self._send_message(HAMessageType.CLAIM_PRIMARY)
            return
        
        # Compare priority and uptime
        if message.priority > self.config.priority:
            logger.info("Yielding to higher priority peer")
            self._set_state(HAState.SECONDARY)
        elif message.priority == self.config.priority:
            peer_start = message.timestamp - message.uptime
            if peer_start < self.start_time:
                logger.info("Yielding to peer with longer uptime")
                self._set_state(HAState.SECONDARY)
            else:
                logger.info("Maintaining PRIMARY (longer uptime)")
                self._send_message(HAMessageType.CLAIM_PRIMARY)
        else:
            logger.info("Rejecting claim (higher priority)")
            self._send_message(HAMessageType.CLAIM_PRIMARY)
    
    def _handle_yield_primary(self, message: HAMessage):
        """Handle peer yielding primary."""
        if self.current_state == HAState.SECONDARY:
            logger.info("Peer yielded - claiming PRIMARY")
            self._claim_primary()
    
    def _handle_force_secondary(self, message: HAMessage):
        """Handle force secondary command."""
        logger.warning("Received FORCE_SECONDARY - complying")
        if self.current_state == HAState.PRIMARY:
            self._set_state(HAState.SECONDARY)
            self.manual_override = False
    
    def _claim_primary(self):
        """Claim primary role."""
        logger.info("Claiming PRIMARY role")
        self._set_state(HAState.FAILOVER)
        self._send_message(HAMessageType.CLAIM_PRIMARY)
        
        self.failover_timer = threading.Timer(
            self.config.failover_delay,
            self._complete_failover
        )
        self.failover_timer.start()
    
    def _complete_failover(self):
        """Complete failover to primary."""
        logger.info("Completing failover to PRIMARY")
        self._set_state(HAState.PRIMARY)
        self.split_brain_detected = False
    
    def _check_peer_timeout(self):
        """Check if peer has timed out."""
        if not self.peer_last_seen:
            return
        
        elapsed = time.time() - self.peer_last_seen
        
        if elapsed > self.config.heartbeat_timeout:
            logger.warning(f"Peer timeout ({elapsed:.1f}s)")
            
            if self.current_state == HAState.SECONDARY:
                logger.info("Peer timeout - claiming PRIMARY")
                self._claim_primary()
            
            self.peer_last_seen = None
            self.peer_state = None
    
    def _handle_config_request(self, message: HAMessage):
        """Handle config request from peer."""
        if not self.config_sync:
            logger.warning("Config request received but config sync not available")
            return
        
        if not self.current_state == HAState.PRIMARY:
            logger.debug("Config request received but we are not primary")
            return
        
        # Response handled in connection handler
        logger.info(f"Config request from {message.sender_id[:8]}...")
    
    def _handle_config_push(self, message: HAMessage):
        """Handle config push from peer."""
        if not self.config_sync:
            logger.warning("Config push received but config sync not available")
            return
        
        if self.current_state == HAState.PRIMARY:
            logger.warning("Config push received but we are primary - rejecting")
            return
        
        if message.payload and 'bundle' in message.payload:
            bundle_data = message.payload['bundle']
            try:
                bundle = ConfigBundle.from_dict(bundle_data)
                success, msg = self.config_sync.handle_config_push(bundle.to_bytes())
                logger.info(f"Config push handled: success={success}, {msg}")
            except Exception as e:
                logger.error(f"Failed to handle config push: {e}")
    
    def sync_config(self, force: bool = False) -> Dict[str, Any]:
        """
        Manually trigger config synchronization.
        
        Args:
            force: If True, force sync regardless of checksums
            
        Returns:
            Dict with sync result details
        """
        if not self.config_sync:
            return {
                'success': False,
                'message': 'Config sync not available'
            }
        
        if self.current_state == HAState.PRIMARY:
            success = self.config_sync.push_configs()
            return {
                'success': success,
                'message': 'Pushed configs to peer' if success else 'Push failed',
                'direction': 'push'
            }
        else:
            success = self.config_sync.pull_configs()
            return {
                'success': success,
                'message': 'Pulled configs from PRIMARY' if success else 'Pull failed',
                'direction': 'pull'
            }
    
    def _close_sockets(self):
        """Close all sockets."""
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except Exception:
                pass
            self.listen_socket = None
