#!/usr/bin/env python3
"""
TrapNinja Control Socket Module

Provides inter-process communication between CLI commands and the running daemon.
Uses a Unix domain socket for secure, local communication.

Architecture:
- Daemon listens on control socket
- CLI commands connect and send JSON requests
- Daemon processes requests and returns JSON responses

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
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger("trapninja")


class ControlSocket:
    """Control socket for daemon communication"""

    # Default socket path
    SOCKET_PATH = "/tmp/trapninja_control.sock"

    # Request timeout
    REQUEST_TIMEOUT = 5.0

    # Response codes
    SUCCESS = 0
    ERROR = 1
    NOT_FOUND = 2
    INVALID_REQUEST = 3

    def __init__(self, socket_path: str = None):
        """
        Initialize control socket

        Args:
            socket_path: Path to Unix domain socket (default: /tmp/trapninja_control.sock)
        """
        self.socket_path = socket_path or self.SOCKET_PATH
        self.server_socket: Optional[socket.socket] = None
        self.stop_event = threading.Event()
        self.listen_thread: Optional[threading.Thread] = None

    def start_server(self) -> bool:
        """
        Start the control socket server (daemon side)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Remove existing socket file if it exists
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)

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
        """Stop the control socket server"""
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
        """Main listening loop for control socket"""
        while not self.stop_event.is_set():
            try:
                conn, _ = self.server_socket.accept()
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

    def _handle_connection(self, conn: socket.socket):
        """
        Handle incoming control socket connection

        Args:
            conn: Client connection socket
        """
        try:
            conn.settimeout(self.REQUEST_TIMEOUT)

            # Receive request
            data = conn.recv(4096)
            if not data:
                return

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
        Process control socket request

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
        elif command == 'ping':
            return {'status': self.SUCCESS, 'message': 'pong'}
        else:
            return {
                'status': self.INVALID_REQUEST,
                'error': f'Unknown command: {command}'
            }

    def _handle_ha_status(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA status request"""
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
        """Handle HA promote request"""
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
        """Handle HA demote request"""
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
        """Handle HA force failover request"""
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
        """Handle service status request"""
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
        """Handle configuration synchronization request"""
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

    def _handle_stats(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle granular statistics requests"""
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
                count = request.get('count', 10)
                sort_by = request.get('sort_by', 'total')
                data = collector.get_top_ips(n=count, sort_by=sort_by)
                return {
                    'status': self.SUCCESS,
                    'data': data
                }
            
            elif action == 'top_oids':
                count = request.get('count', 10)
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
                data = collector.get_ip_stats(ip_address)
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
                data = collector.get_oid_stats(oid)
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
                     socket_path: str = None, timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
        """
        Send a command to the daemon (client side)

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

            # Receive response
            response_data = client_socket.recv(4096)
            response = json.loads(response_data.decode('utf-8'))

            return response

        finally:
            client_socket.close()


# Global control socket instance
_control_socket: Optional[ControlSocket] = None


def get_control_socket() -> Optional[ControlSocket]:
    """Get the global control socket instance"""
    return _control_socket


def initialize_control_socket(socket_path: str = None) -> bool:
    """
    Initialize the global control socket

    Args:
        socket_path: Path to control socket

    Returns:
        True if successful, False otherwise
    """
    global _control_socket

    try:
        _control_socket = ControlSocket(socket_path)
        return _control_socket.start_server()
    except Exception as e:
        logger.error(f"Failed to initialize control socket: {e}")
        return False


def shutdown_control_socket():
    """Shutdown the global control socket"""
    global _control_socket

    if _control_socket:
        _control_socket.stop_server()
        _control_socket = None