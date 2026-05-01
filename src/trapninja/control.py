#!/usr/bin/env python3
"""
TrapNinja Control Socket Module

Provides inter-process communication between CLI commands and the
running daemon via a Unix domain socket.

Architecture:
    - Daemon listens on control socket
    - CLI commands connect and send JSON requests
    - Daemon processes requests and returns JSON responses

Security Features:
    - Socket path validation (prevents path traversal)
    - Request size limits (prevents memory exhaustion)
    - Connection rate limiting (prevents DoS)
    - Owner-only permissions (0o600)

Supported commands:
    - ha_status: Get current HA status
    - ha_promote: Promote to PRIMARY role
    - ha_demote: Demote to SECONDARY role
    - ha_force_failover: Force failover to SECONDARY
    - config_sync: Trigger configuration synchronisation
    - service_status: Get service status
    - show_config: Show current configuration
    - stats: Statistics queries (with action sub-routing)

Command handler implementations live in control_handlers.py for
maintainability; this module handles socket infrastructure.
"""

import os
import json
import socket
import threading
import logging
import time
from collections import deque
from typing import Optional, Dict, Any, FrozenSet
from pathlib import Path

from .control_handlers import ControlHandlers

logger = logging.getLogger("trapninja")


class ControlSocketError(Exception):
    """Base exception for control socket errors."""
    pass


class SocketPathError(ControlSocketError):
    """Raised when socket path validation fails."""
    pass


class RateLimitError(ControlSocketError):
    """Raised when rate limit is exceeded."""
    pass


class ControlSocket(ControlHandlers):
    """Control socket for daemon communication with security hardening."""

    # Default socket path
    SOCKET_PATH = "/tmp/trapninja_control.sock"

    # Allowed directories for socket files (security)
    ALLOWED_SOCKET_DIRS: FrozenSet[str] = frozenset([
        '/tmp',
        '/var/run',
        '/run',
        '/var/run/trapninja',
        '/run/trapninja'
    ])

    # Request timeout
    REQUEST_TIMEOUT = 5.0

    # Maximum request size (64KB — prevents memory exhaustion)
    MAX_REQUEST_SIZE = 65536

    # Rate limiting settings
    MAX_CONNECTIONS_PER_SECOND = 20
    RATE_LIMIT_WINDOW = 1.0  # seconds

    # Response codes
    SUCCESS = 0
    ERROR = 1
    NOT_FOUND = 2
    INVALID_REQUEST = 3
    RATE_LIMITED = 4

    def __init__(self, socket_path: str = None):
        """
        Initialise control socket with security validation.

        Args:
            socket_path: Path to Unix domain socket

        Raises:
            SocketPathError: If socket path fails security validation
        """
        if socket_path:
            self.socket_path = self._validate_socket_path(socket_path)
        else:
            self.socket_path = self.SOCKET_PATH

        self.server_socket: Optional[socket.socket] = None
        self.stop_event = threading.Event()
        self.listen_thread: Optional[threading.Thread] = None

        # Rate limiting state
        self._connection_times: deque = deque(maxlen=200)
        self._rate_limit_lock = threading.Lock()

    @classmethod
    def _validate_socket_path(cls, socket_path: str) -> str:
        """
        Validate socket path for security.

        Checks:
        - No path traversal (..)
        - Path is in allowed directory
        - Filename is reasonable

        Args:
            socket_path: Proposed socket path

        Returns:
            Validated path string

        Raises:
            SocketPathError: If validation fails
        """
        # Resolve to absolute path and check for traversal
        path = Path(socket_path).resolve()
        path_str = str(path)

        # Check for path traversal attempts
        if '..' in socket_path:
            raise SocketPathError(
                f"Path traversal detected in socket path: {socket_path}"
            )

        # Check parent directory is allowed
        # Resolve allowed dirs too so symlinks (e.g. /tmp → /private/tmp on macOS)
        # are compared consistently.
        parent = str(path.parent)
        resolved_allowed = {str(Path(d).resolve()) for d in cls.ALLOWED_SOCKET_DIRS}
        if parent not in cls.ALLOWED_SOCKET_DIRS and parent not in resolved_allowed:
            raise SocketPathError(
                f"Socket path not in allowed directory: {parent}\n"
                f"Allowed: {', '.join(sorted(cls.ALLOWED_SOCKET_DIRS))}"
            )

        # Check filename length and characters
        filename = path.name
        if len(filename) > 108:  # Unix socket path limit
            raise SocketPathError(
                f"Socket filename too long: {len(filename)} chars"
            )

        # Only allow alphanumeric, underscore, dot, dash
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
            raise SocketPathError(
                f"Socket filename contains invalid characters: {filename}"
            )

        return path_str

    def _check_rate_limit(self, client_info: str = "") -> bool:
        """
        Check if a new connection should be rate limited.

        Args:
            client_info: Client identifier for logging

        Returns:
            True if connection is allowed, False if rate limited
        """
        now = time.time()

        with self._rate_limit_lock:
            # Remove old timestamps outside the window
            while (self._connection_times and
                   self._connection_times[0] < now - self.RATE_LIMIT_WINDOW):
                self._connection_times.popleft()

            # Check rate
            if len(self._connection_times) >= self.MAX_CONNECTIONS_PER_SECOND:
                logger.warning(
                    f"Control socket rate limit exceeded: "
                    f"{len(self._connection_times)} connections in "
                    f"{self.RATE_LIMIT_WINDOW}s"
                )
                return False

            self._connection_times.append(now)
            return True

    # -----------------------------------------------------------------
    # Server lifecycle
    # -----------------------------------------------------------------

    def start_server(self) -> bool:
        """
        Start the control socket server.

        Returns:
            True if server started successfully
        """
        try:
            # Clean up any stale socket
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)

            # Create socket with restricted permissions
            self.server_socket = socket.socket(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )
            self.server_socket.bind(self.socket_path)

            # Set owner-only permissions
            os.chmod(self.socket_path, 0o600)

            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            # Start listener thread
            self.stop_event.clear()
            self.listen_thread = threading.Thread(
                target=self._listen_loop,
                daemon=True,
                name="ControlSocket-Listener"
            )
            self.listen_thread.start()

            logger.info(f"Control socket listening on {self.socket_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to start control socket: {e}")
            return False

    def stop_server(self):
        """Stop the control socket server."""
        self.stop_event.set()

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        if self.listen_thread:
            self.listen_thread.join(timeout=3)

        # Clean up socket file
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except Exception:
            pass

        logger.info("Control socket stopped")

    # -----------------------------------------------------------------
    # Connection handling
    # -----------------------------------------------------------------

    def _listen_loop(self):
        """Main listener loop — accept and handle connections."""
        while not self.stop_event.is_set():
            try:
                conn, addr = self.server_socket.accept()

                # Rate limiting
                if not self._check_rate_limit():
                    try:
                        response = json.dumps({
                            'status': self.RATE_LIMITED,
                            'error': 'Rate limit exceeded'
                        }).encode('utf-8')
                        conn.send(response)
                    except Exception:
                        pass
                    finally:
                        conn.close()
                    continue

                # Handle connection in a thread
                handler_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                    name="ControlSocket-Handler"
                )
                handler_thread.start()

            except socket.timeout:
                continue
            except OSError as e:
                if not self.stop_event.is_set():
                    logger.error(f"Control socket accept error: {e}")
            except Exception as e:
                if not self.stop_event.is_set():
                    logger.error(f"Control socket listener error: {e}")

    def _receive_with_limit(self, conn: socket.socket) -> bytes:
        """
        Receive data from connection with size limit.

        Prevents memory exhaustion from oversized requests.

        Args:
            conn: Client socket connection

        Returns:
            Received data bytes

        Raises:
            ValueError: If request exceeds MAX_REQUEST_SIZE
        """
        data = b''
        conn.settimeout(self.REQUEST_TIMEOUT)

        while len(data) < self.MAX_REQUEST_SIZE:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk

                # Check if we have a complete JSON message
                try:
                    json.loads(data)
                    return data
                except json.JSONDecodeError:
                    continue

            except socket.timeout:
                if data:
                    return data
                raise

        if len(data) >= self.MAX_REQUEST_SIZE:
            raise ValueError(
                f"Request size exceeds limit: {len(data)} >= "
                f"{self.MAX_REQUEST_SIZE}"
            )

        return data

    def _handle_connection(self, conn: socket.socket):
        """Handle a single client connection."""
        try:
            # Receive request
            data = self._receive_with_limit(conn)

            if not data:
                return

            # Parse request
            try:
                request = json.loads(data.decode('utf-8'))
            except json.JSONDecodeError as e:
                response = {
                    'status': self.INVALID_REQUEST,
                    'error': f'Invalid JSON: {e}'
                }
                conn.send(json.dumps(response).encode('utf-8'))
                return

            # Validate request structure
            if not isinstance(request, dict):
                response = {
                    'status': self.INVALID_REQUEST,
                    'error': 'Request must be a JSON object'
                }
                conn.send(json.dumps(response).encode('utf-8'))
                return

            # Process request
            response = self._process_request(request)

            # Send response
            response_data = json.dumps(response).encode('utf-8')
            conn.send(response_data)

        except socket.timeout:
            logger.debug("Control socket connection timed out")
        except ValueError as e:
            logger.warning(f"Control socket request error: {e}")
            try:
                error_response = json.dumps({
                    'status': self.INVALID_REQUEST,
                    'error': str(e)
                }).encode('utf-8')
                conn.send(error_response)
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Control socket handler error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # -----------------------------------------------------------------
    # Request dispatch
    # -----------------------------------------------------------------

    def _process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process control socket request by routing to the appropriate handler.

        Args:
            request: Request dictionary with 'command' and optional parameters

        Returns:
            Response dictionary with 'status' and result data
        """
        command = request.get('command')

        if not command:
            return {
                'status': self.INVALID_REQUEST,
                'error': 'Missing command field'
            }

        if not isinstance(command, str):
            return {
                'status': self.INVALID_REQUEST,
                'error': 'Command must be a string'
            }

        if len(command) > 64:
            return {
                'status': self.INVALID_REQUEST,
                'error': 'Command name too long'
            }

        logger.debug(f"Processing control command: {command}")

        # Route to appropriate handler (defined in ControlHandlers mixin)
        handler = self._COMMAND_HANDLERS.get(command)
        if handler:
            return handler(self, request)
        elif command == 'ping':
            return {'status': self.SUCCESS, 'message': 'pong'}
        else:
            return {
                'status': self.INVALID_REQUEST,
                'error': f'Unknown command: {command}'
            }

    # Command dispatch table
    _COMMAND_HANDLERS = {
        'ha_status': ControlHandlers._handle_ha_status,
        'ha_promote': ControlHandlers._handle_ha_promote,
        'ha_demote': ControlHandlers._handle_ha_demote,
        'ha_force_failover': ControlHandlers._handle_ha_force_failover,
        'service_status': ControlHandlers._handle_service_status,
        'stats': ControlHandlers._handle_stats,
        'config_sync': ControlHandlers._handle_config_sync,
        'show_config': ControlHandlers._handle_show_config,
    }

    # -----------------------------------------------------------------
    # Client API
    # -----------------------------------------------------------------

    @staticmethod
    def send_command(command: str, params: Dict[str, Any] = None,
                     socket_path: str = None,
                     timeout: float = None) -> Dict[str, Any]:
        """
        Send a command to the daemon (client side).

        Args:
            command: Command name
            params: Optional command parameters
            socket_path: Path to control socket
            timeout: Request timeout in seconds

        Returns:
            Response dictionary

        Raises:
            ConnectionRefusedError: If daemon is not running
            TimeoutError: If request times out
        """
        socket_path = socket_path or ControlSocket.SOCKET_PATH
        timeout = timeout or ControlSocket.REQUEST_TIMEOUT

        if not os.path.exists(socket_path):
            raise ConnectionRefusedError(
                "Control socket not found - is the daemon running?"
            )

        request = {
            'command': command,
            'timestamp': time.time()
        }
        if params:
            request.update(params)

        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.settimeout(timeout)

        try:
            client_socket.connect(socket_path)

            request_data = json.dumps(request).encode('utf-8')
            client_socket.send(request_data)

            response_data = b''
            while len(response_data) < ControlSocket.MAX_REQUEST_SIZE:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if len(chunk) < 4096:
                    break

            response = json.loads(response_data.decode('utf-8'))
            return response

        finally:
            client_socket.close()


# =============================================================================
# MODULE-LEVEL API
# =============================================================================

_control_socket: Optional[ControlSocket] = None


def get_control_socket() -> Optional[ControlSocket]:
    """Get the global control socket instance."""
    return _control_socket


def initialize_control_socket(socket_path: str = None) -> bool:
    """
    Initialise the global control socket.

    Args:
        socket_path: Path to control socket

    Returns:
        True if successful, False otherwise
    """
    global _control_socket

    try:
        _control_socket = ControlSocket(socket_path)
        return _control_socket.start_server()
    except SocketPathError as e:
        logger.error(f"Socket path validation failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to initialize control socket: {e}")
        return False


def shutdown_control_socket():
    """Shutdown the global control socket."""
    global _control_socket

    if _control_socket:
        _control_socket.stop_server()
        _control_socket = None
