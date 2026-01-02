#!/usr/bin/env python3
"""
TrapNinja Control Socket Module

Provides inter-process communication between CLI commands and the running daemon.
Uses a Unix domain socket for secure, local communication.

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
- config_sync: Trigger configuration synchronization
- service_status: Get service status
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


class ControlSocket:
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

    # Maximum request size (64KB - prevents memory exhaustion)
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
        Initialize control socket with security validation.

        Args:
            socket_path: Path to Unix domain socket (default: /tmp/trapninja_control.sock)

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
            socket_path: Path to validate

        Returns:
            Validated absolute path

        Raises:
            SocketPathError: If validation fails
        """
        # Convert to absolute path
        abs_path = os.path.abspath(socket_path)

        # Check for path traversal attempts
        if '..' in socket_path:
            raise SocketPathError(
                f"Path traversal not allowed in socket path: {socket_path}"
            )

        # Get the directory containing the socket
        socket_dir = os.path.dirname(abs_path)

        # Check if directory is in allowed list
        is_allowed = False
        for allowed_dir in cls.ALLOWED_SOCKET_DIRS:
            # Check if socket_dir starts with allowed_dir
            if socket_dir == allowed_dir or socket_dir.startswith(allowed_dir + os.sep):
                is_allowed = True
                break

        if not is_allowed:
            raise SocketPathError(
                f"Socket path must be in one of: {sorted(cls.ALLOWED_SOCKET_DIRS)}. "
                f"Got: {socket_dir}"
            )

        # Validate filename
        filename = os.path.basename(abs_path)
        if not filename:
            raise SocketPathError("Socket path must include a filename")

        if not filename.endswith('.sock'):
            logger.warning(f"Socket filename '{filename}' doesn't end with .sock")

        # Check filename for suspicious characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.')
        if not all(c in allowed_chars for c in filename):
            raise SocketPathError(
                f"Socket filename contains invalid characters: {filename}"
            )

        logger.debug(f"Socket path validated: {abs_path}")
        return abs_path

    def _check_rate_limit(self, client_info: str = "") -> bool:
        """
        Check if connection rate limit has been exceeded.

        Args:
            client_info: Optional client identifier for logging

        Returns:
            True if connection is allowed, False if rate limited
        """
        with self._rate_limit_lock:
            now = time.time()
            cutoff = now - self.RATE_LIMIT_WINDOW

            # Remove old entries outside the time window
            while self._connection_times and self._connection_times[0] < cutoff:
                self._connection_times.popleft()

            # Check if limit exceeded
            if len(self._connection_times) >= self.MAX_CONNECTIONS_PER_SECOND:
                logger.warning(
                    f"Control socket rate limit exceeded: "
                    f"{len(self._connection_times)} connections in {self.RATE_LIMIT_WINDOW}s"
                    f"{' from ' + client_info if client_info else ''}"
                )
                return False

            # Record this connection
            self._connection_times.append(now)
            return True

    def start_server(self) -> bool:
        """
        Start the control socket server (daemon side).

        Returns:
            True if successful, False otherwise
        """
        try:
            # Remove existing socket file if it exists
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)

            # Ensure parent directory exists
            socket_dir = os.path.dirname(self.socket_path)
            if socket_dir and not os.path.exists(socket_dir):
                os.makedirs(socket_dir, mode=0o755)

            # Create Unix domain socket
            self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.server_socket.bind(self.socket_path)
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            # Set permissions so only owner can access
            os.chmod(self.socket_path, 0o600)

            # Start listener thread
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()

            logger.info(f"Control socket started: {self.socket_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to start control socket: {e}")
            return False

    def stop_server(self):
        """Stop the control socket server."""
        logger.info("Stopping control socket server...")

        self.stop_event.set()

        if self.listen_thread and self.listen_thread.is_alive():
            self.listen_thread.join(timeout=2.0)

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None

        # Remove socket file
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except:
                pass

        logger.info("Control socket stopped")

    def _listen_loop(self):
        """Main listening loop for control socket."""
        while not self.stop_event.is_set():
            try:
                conn, addr = self.server_socket.accept()

                # Rate limit check
                if not self._check_rate_limit():
                    # Send rate limit response and close
                    try:
                        response = {
                            'status': self.RATE_LIMITED,
                            'error': 'Rate limit exceeded. Please try again later.'
                        }
                        conn.send(json.dumps(response).encode('utf-8'))
                    except:
                        pass
                    finally:
                        conn.close()
                    continue

                # Handle connection in separate thread
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    logger.error(f"Error in control socket listen loop: {e}")
                    time.sleep(1)

    def _receive_with_limit(self, conn: socket.socket) -> bytes:
        """
        Receive data from socket with size limit.

        Prevents memory exhaustion from oversized requests.

        Args:
            conn: Socket connection

        Returns:
            Received data

        Raises:
            ValueError: If data exceeds size limit
        """
        data = b''
        conn.settimeout(self.REQUEST_TIMEOUT)

        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break

                data += chunk

                # Check size limit
                if len(data) > self.MAX_REQUEST_SIZE:
                    raise ValueError(
                        f"Request size ({len(data)} bytes) exceeds limit "
                        f"({self.MAX_REQUEST_SIZE} bytes)"
                    )

                # If we got less than buffer size, we're probably done
                if len(chunk) < 4096:
                    break

            except socket.timeout:
                break

        return data

    def _handle_connection(self, conn: socket.socket):
        """
        Handle incoming control socket connection with security checks.

        Args:
            conn: Client connection socket
        """
        try:
            # Receive request with size limit
            try:
                data = self._receive_with_limit(conn)
            except ValueError as e:
                logger.warning(f"Request size limit exceeded: {e}")
                response = {
                    'status': self.INVALID_REQUEST,
                    'error': str(e)
                }
                conn.send(json.dumps(response).encode('utf-8'))
                return

            if not data:
                return

            # Parse JSON
            try:
                request = json.loads(data.decode('utf-8'))
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON in control request: {e}")
                response = {
                    'status': self.INVALID_REQUEST,
                    'error': 'Invalid JSON format'
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
            conn.send(json.dumps(response).encode('utf-8'))

        except Exception as e:
            logger.error(f"Error handling control connection: {e}")
            try:
                error_response = {
                    'status': self.ERROR,
                    'error': str(e)
                }
                conn.send(json.dumps(error_response).encode('utf-8'))
            except:
                pass
        finally:
            conn.close()

    def _process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process control socket request.

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

        # Validate command is a string
        if not isinstance(command, str):
            return {
                'status': self.INVALID_REQUEST,
                'error': 'Command must be a string'
            }

        # Limit command length
        if len(command) > 64:
            return {
                'status': self.INVALID_REQUEST,
                'error': 'Command name too long'
            }

        logger.debug(f"Processing control command: {command}")

        # Route to appropriate handler
        if command == 'ha_status':
            return self._handle_ha_status(request)
        elif command == 'ha_promote':
            return self._handle_ha_promote(request)
        elif command == 'ha_demote':
            return self._handle_ha_demote(request)
        elif command == 'ha_force_failover':
            return self._handle_ha_force_failover(request)
        elif command == 'service_status':
            return self._handle_service_status(request)
        elif command == 'stats':
            return self._handle_stats(request)
        elif command == 'config_sync':
            return self._handle_config_sync(request)
        elif command == 'show_config':
            return self._handle_show_config(request)
        elif command == 'ping':
            return {'status': self.SUCCESS, 'message': 'pong'}
        else:
            return {
                'status': self.INVALID_REQUEST,
                'error': f'Unknown command: {command}'
            }

    def _handle_ha_status(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA status request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not initialized'
                }

            ha_status = ha_cluster.get_status()
            return {
                'status': self.SUCCESS,
                'data': ha_status
            }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error getting HA status: {e}'
            }

    def _handle_ha_promote(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA promote request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            force = request.get('force', False)
            success = ha_cluster.promote_to_primary(force=force)

            if success:
                return {
                    'status': self.SUCCESS,
                    'message': f'Promotion initiated (force={force})'
                }
            else:
                return {
                    'status': self.ERROR,
                    'error': 'Promotion failed'
                }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error promoting to PRIMARY: {e}'
            }

    def _handle_ha_demote(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA demote request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            success = ha_cluster.demote_to_secondary()

            if success:
                return {
                    'status': self.SUCCESS,
                    'message': 'Demotion successful'
                }
            else:
                return {
                    'status': self.ERROR,
                    'error': 'Demotion failed'
                }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error demoting to SECONDARY: {e}'
            }

    def _handle_ha_force_failover(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA force failover request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            ha_cluster.force_failover()

            return {
                'status': self.SUCCESS,
                'message': 'Force failover initiated'
            }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error forcing failover: {e}'
            }

    def _handle_service_status(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle service status request."""
        try:
            from .metrics import get_metrics_summary
            from .ha import get_ha_cluster

            # Get service metrics
            metrics = get_metrics_summary()

            # Get HA status
            ha_cluster = get_ha_cluster()
            ha_status = ha_cluster.get_status() if ha_cluster else None

            return {
                'status': self.SUCCESS,
                'data': {
                    'metrics': metrics,
                    'ha': ha_status
                }
            }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error getting service status: {e}'
            }

    def _handle_config_sync(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle configuration synchronization request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            # Check if config sync is available
            if not hasattr(ha_cluster, 'sync_config') or not ha_cluster.config_sync:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'Config sync not available'
                }

            force = request.get('force', False)
            result = ha_cluster.sync_config(force=force)

            return {
                'status': self.SUCCESS,
                'data': result
            }
        except Exception as e:
            logger.error(f"Error handling config sync: {e}")
            return {
                'status': self.ERROR,
                'error': f'Error during config sync: {e}'
            }

    def _handle_show_config(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle show configuration request."""
        try:
            # IMPORTANT: Import the module, not the variables directly!
            # Variables like destinations, blocked_ips are reassigned in load_config(),
            # so direct imports get stale references to the original empty containers.
            from . import config as cfg
            from .ha import load_ha_config

            # Build configuration summary - access via module reference
            config = {
                'config_directory': cfg.CONFIG_DIR,
                'interface': cfg.INTERFACE,
                'capture_mode': cfg.CAPTURE_MODE,
                'listen_ports': list(cfg.LISTEN_PORTS),
                'forwarding': {
                    'destinations': cfg.destinations,
                    'destination_count': len(cfg.destinations) if cfg.destinations else 0
                },
                'filtering': {
                    'blocked_ips_count': len(cfg.blocked_ips) if cfg.blocked_ips else 0,
                    'blocked_oids_count': len(cfg.blocked_traps) if cfg.blocked_traps else 0,
                    'ip_redirections_count': len(cfg.redirected_ips) if cfg.redirected_ips else 0,
                    'oid_redirections_count': len(cfg.redirected_oids) if cfg.redirected_oids else 0,
                    'redirect_destinations_count': len(cfg.redirected_destinations) if cfg.redirected_destinations else 0
                }
            }

            # Add HA configuration
            try:
                ha_config = load_ha_config()
                config['high_availability'] = {
                    'enabled': ha_config.enabled,
                    'mode': ha_config.mode,
                    'priority': ha_config.priority,
                    'peer_host': ha_config.peer_host if ha_config.enabled else None,
                    'peer_port': ha_config.peer_port if ha_config.enabled else None,
                    'heartbeat_interval': ha_config.heartbeat_interval,
                    'failover_delay': ha_config.failover_delay
                }
            except Exception:
                config['high_availability'] = {'enabled': False}

            # Add cache configuration
            try:
                from .config import load_cache_config
                cache_config = load_cache_config()
                if cache_config:
                    config['cache'] = {
                        'enabled': cache_config.enabled,
                        'host': cache_config.host if cache_config.enabled else None,
                        'port': cache_config.port if cache_config.enabled else None,
                        'retention_hours': cache_config.retention_hours
                    }
            except Exception:
                config['cache'] = {'enabled': False}

            return {
                'status': self.SUCCESS,
                'data': config
            }

        except Exception as e:
            logger.error(f"Error getting configuration: {e}")
            return {
                'status': self.ERROR,
                'error': f'Error getting configuration: {e}'
            }

    def _handle_stats(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle granular statistics requests."""
        try:
            from .stats import get_stats_collector

            collector = get_stats_collector()
            if not collector:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'Statistics collector not initialized'
                }

            action = request.get('action', 'summary')

            if action == 'summary':
                return {
                    'status': self.SUCCESS,
                    'data': collector.get_summary()
                }

            elif action == 'top_ips':
                count = min(request.get('count', 10), 100)  # Limit to 100
                sort_by = request.get('sort_by', 'total')
                data = collector.get_top_ips(n=count, sort_by=sort_by)
                return {
                    'status': self.SUCCESS,
                    'data': data
                }

            elif action == 'top_oids':
                count = min(request.get('count', 10), 100)  # Limit to 100
                sort_by = request.get('sort_by', 'total')
                data = collector.get_top_oids(n=count, sort_by=sort_by)
                return {
                    'status': self.SUCCESS,
                    'data': data
                }

            elif action == 'ip_detail':
                ip_address = request.get('ip_address')
                if not ip_address:
                    return {
                        'status': self.INVALID_REQUEST,
                        'error': 'ip_address required'
                    }
                # Allow configurable number of top OIDs (default 10, max 500)
                top_n_oids = min(request.get('top_n_oids', 10), 500)
                data = collector.get_ip_stats(ip_address, top_n_oids=top_n_oids)
                if data:
                    return {
                        'status': self.SUCCESS,
                        'data': data
                    }
                return {
                    'status': self.NOT_FOUND,
                    'error': f'IP {ip_address} not found'
                }

            elif action == 'oid_detail':
                oid = request.get('oid')
                if not oid:
                    return {
                        'status': self.INVALID_REQUEST,
                        'error': 'oid required'
                    }
                # Allow configurable number of top sources (default 10, max 500)
                top_n_sources = min(request.get('top_n_sources', 10), 500)
                data = collector.get_oid_stats(oid, top_n_sources=top_n_sources)
                if data:
                    return {
                        'status': self.SUCCESS,
                        'data': data
                    }
                return {
                    'status': self.NOT_FOUND,
                    'error': f'OID {oid} not found'
                }

            elif action == 'destinations':
                data = collector.get_all_destinations()
                return {
                    'status': self.SUCCESS,
                    'data': data
                }

            elif action == 'dashboard':
                snapshot = collector.get_snapshot(top_n=50)
                return {
                    'status': self.SUCCESS,
                    'data': snapshot.to_dict()
                }

            elif action == 'reset':
                collector.reset()
                return {
                    'status': self.SUCCESS,
                    'message': 'Statistics reset'
                }

            elif action == 'debug':
                # Debug info to diagnose stats collection issues
                from .processing.stats import get_global_stats
                processing_stats = get_global_stats()
                
                debug_info = {
                    'granular_collector': {
                        'initialized': collector is not None,
                        'running': collector._running if collector else False,
                        'total_traps': collector._total_traps if collector else 0,
                        'unique_ips': len(collector._ip_stats) if collector else 0,
                        'unique_oids': len(collector._oid_stats) if collector else 0,
                    },
                    'processing_stats': processing_stats.to_dict() if processing_stats else {},
                }
                return {
                    'status': self.SUCCESS,
                    'data': debug_info
                }

            else:
                return {
                    'status': self.INVALID_REQUEST,
                    'error': f'Unknown stats action: {action}'
                }

        except Exception as e:
            logger.error(f"Error handling stats request: {e}")
            return {
                'status': self.ERROR,
                'error': f'Error getting statistics: {e}'
            }

    @staticmethod
    def send_command(command: str, params: Dict[str, Any] = None,
                     socket_path: str = None, timeout: float = None) -> Dict[str, Any]:
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

        # Check if socket exists
        if not os.path.exists(socket_path):
            raise ConnectionRefusedError(
                "Control socket not found - is the daemon running?"
            )

        # Create request
        request = {
            'command': command,
            'timestamp': time.time()
        }
        if params:
            request.update(params)

        # Connect and send request
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.settimeout(timeout)

        try:
            client_socket.connect(socket_path)

            # Send request
            request_data = json.dumps(request).encode('utf-8')
            client_socket.send(request_data)

            # Receive response (with size limit for safety)
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


# Global control socket instance
_control_socket: Optional[ControlSocket] = None


def get_control_socket() -> Optional[ControlSocket]:
    """Get the global control socket instance."""
    return _control_socket


def initialize_control_socket(socket_path: str = None) -> bool:
    """
    Initialize the global control socket.

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
