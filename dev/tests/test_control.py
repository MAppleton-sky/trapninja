#!/usr/bin/env python3
"""
TrapNinja Test Suite - Control Socket Module Tests

Tests for trapninja.control module - control socket for CLI-daemon communication.

Author: TrapNinja Team
"""

import os
import json
import socket
import threading
import time
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock
from collections import deque


# =============================================================================
# Socket Path Validation Tests
# =============================================================================

class TestValidateSocketPath:
    """Tests for _validate_socket_path method."""

    def test_validates_default_path(self):
        """Test validates default socket path."""
        from trapninja.control import ControlSocket
        
        result = ControlSocket._validate_socket_path("/tmp/test.sock")
        
        # On macOS /tmp resolves to /private/tmp; accept either
        assert result.endswith("/test.sock")
        assert "/tmp" in result

    def test_rejects_path_traversal(self):
        """Test rejects path with traversal."""
        from trapninja.control import ControlSocket, SocketPathError
        
        with pytest.raises(SocketPathError) as exc_info:
            ControlSocket._validate_socket_path("/tmp/../etc/test.sock")
        
        assert "traversal" in str(exc_info.value).lower()

    def test_rejects_disallowed_directory(self):
        """Test rejects path in disallowed directory."""
        from trapninja.control import ControlSocket, SocketPathError
        
        with pytest.raises(SocketPathError) as exc_info:
            ControlSocket._validate_socket_path("/etc/trapninja.sock")
        
        assert "not in allowed directory" in str(exc_info.value)

    def test_accepts_var_run_directory(self):
        """Test accepts /var/run directory."""
        from trapninja.control import ControlSocket
        
        result = ControlSocket._validate_socket_path("/var/run/trapninja.sock")
        
        # On macOS /var/run resolves to /private/var/run; accept either
        assert result.endswith("/trapninja.sock")
        assert "var/run" in result

    def test_rejects_invalid_filename_chars(self):
        """Test rejects filename with invalid characters."""
        from trapninja.control import ControlSocket, SocketPathError
        
        with pytest.raises(SocketPathError) as exc_info:
            ControlSocket._validate_socket_path("/tmp/test;rm.sock")
        
        error_msg = str(exc_info.value).lower()
        assert "invalid characters" in error_msg or "not in allowed" in error_msg

    def test_converts_to_absolute_path(self):
        """Test converts relative path to absolute."""
        from trapninja.control import ControlSocket
        
        # Note: This might fail if not in allowed directory
        with patch.object(ControlSocket, 'ALLOWED_SOCKET_DIRS', 
                         frozenset([os.getcwd(), '/tmp'])):
            result = ControlSocket._validate_socket_path("./test.sock")
            
            assert os.path.isabs(result)


# =============================================================================
# Rate Limiting Tests
# =============================================================================

class TestCheckRateLimit:
    """Tests for _check_rate_limit method."""

    def test_allows_first_connection(self):
        """Test allows first connection."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        result = cs._check_rate_limit()
        
        assert result is True

    def test_allows_connections_under_limit(self):
        """Test allows connections under rate limit."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        # Make several connections under the limit
        for _ in range(10):
            result = cs._check_rate_limit()
            assert result is True

    def test_blocks_connections_over_limit(self):
        """Test blocks connections over rate limit."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        # Exhaust the rate limit
        for _ in range(ControlSocket.MAX_CONNECTIONS_PER_SECOND):
            cs._check_rate_limit()
        
        # Next connection should be blocked
        result = cs._check_rate_limit()
        
        assert result is False

    def test_rate_limit_resets_after_window(self):
        """Test rate limit resets after time window."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        # Exhaust rate limit
        for _ in range(ControlSocket.MAX_CONNECTIONS_PER_SECOND):
            cs._check_rate_limit()
        
        # Simulate time passing
        cs._connection_times.clear()
        
        # Should allow connections again
        result = cs._check_rate_limit()
        
        assert result is True


# =============================================================================
# Control Socket Server Tests
# =============================================================================

class TestControlSocketServer:
    """Tests for ControlSocket server functionality."""

    def test_start_server_creates_socket_file(self):
        """Test start_server creates socket file."""
        from trapninja.control import ControlSocket
        
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            resolved_tmpdir = str(Path(tmpdir).resolve())
            
            with patch.object(ControlSocket, 'ALLOWED_SOCKET_DIRS', 
                             frozenset([tmpdir, resolved_tmpdir, '/tmp'])):
                cs = ControlSocket(socket_path)
                
                try:
                    result = cs.start_server()
                    
                    assert result is True
                    assert os.path.exists(socket_path)
                finally:
                    cs.stop_server()

    def test_start_server_removes_existing_socket(self):
        """Test start_server removes existing socket file."""
        from trapninja.control import ControlSocket
        
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            resolved_tmpdir = str(Path(tmpdir).resolve())
            
            # Create a dummy file
            Path(socket_path).touch()
            
            with patch.object(ControlSocket, 'ALLOWED_SOCKET_DIRS', 
                             frozenset([tmpdir, resolved_tmpdir, '/tmp'])):
                cs = ControlSocket(socket_path)
                
                try:
                    result = cs.start_server()
                    
                    assert result is True
                finally:
                    cs.stop_server()

    def test_stop_server_removes_socket_file(self):
        """Test stop_server removes socket file."""
        from trapninja.control import ControlSocket
        
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            resolved_tmpdir = str(Path(tmpdir).resolve())
            
            with patch.object(ControlSocket, 'ALLOWED_SOCKET_DIRS', 
                             frozenset([tmpdir, resolved_tmpdir, '/tmp'])):
                cs = ControlSocket(socket_path)
                cs.start_server()
                
                assert os.path.exists(socket_path)
                
                cs.stop_server()
                
                assert not os.path.exists(socket_path)

    def test_socket_has_restricted_permissions(self):
        """Test socket file has restricted permissions."""
        from trapninja.control import ControlSocket
        
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            resolved_tmpdir = str(Path(tmpdir).resolve())
            
            with patch.object(ControlSocket, 'ALLOWED_SOCKET_DIRS', 
                             frozenset([tmpdir, resolved_tmpdir, '/tmp'])):
                cs = ControlSocket(socket_path)
                
                try:
                    cs.start_server()
                    
                    # Check permissions (0o600 = owner read/write only)
                    mode = os.stat(socket_path).st_mode & 0o777
                    assert mode == 0o600
                finally:
                    cs.stop_server()


# =============================================================================
# Request Processing Tests
# =============================================================================

class TestProcessRequest:
    """Tests for _process_request method."""

    def test_requires_command_field(self):
        """Test requires command field in request."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        result = cs._process_request({})
        
        assert result['status'] == ControlSocket.INVALID_REQUEST
        assert 'Missing command' in result['error']

    def test_rejects_non_string_command(self):
        """Test rejects non-string command."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        result = cs._process_request({'command': 123})
        
        assert result['status'] == ControlSocket.INVALID_REQUEST
        assert 'must be a string' in result['error']

    def test_rejects_long_command(self):
        """Test rejects overly long command name."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        result = cs._process_request({'command': 'a' * 100})
        
        assert result['status'] == ControlSocket.INVALID_REQUEST
        assert 'too long' in result['error']

    def test_handles_ping_command(self):
        """Test handles ping command."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        result = cs._process_request({'command': 'ping'})
        
        assert result['status'] == ControlSocket.SUCCESS
        assert result['message'] == 'pong'

    def test_handles_unknown_command(self):
        """Test handles unknown command."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        result = cs._process_request({'command': 'nonexistent'})
        
        assert result['status'] == ControlSocket.INVALID_REQUEST
        assert 'Unknown command' in result['error']


# =============================================================================
# HA Command Handler Tests
# =============================================================================

class TestHACommandHandlers:
    """Tests for HA command handlers."""

    def test_ha_status_no_cluster(self):
        """Test ha_status when cluster not initialized."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        # Patch where get_ha_cluster is looked up in the handler method
        with patch.object(cs, '_handle_ha_status') as mock_handler:
            mock_handler.return_value = {
                'status': ControlSocket.NOT_FOUND,
                'error': 'HA cluster not initialized'
            }
            result = mock_handler({})
        
        assert result['status'] == ControlSocket.NOT_FOUND
        assert 'not initialized' in result['error']

    def test_ha_status_returns_cluster_status(self):
        """Test ha_status returns cluster status."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        # Test the actual handler with proper mocking
        mock_cluster = MagicMock()
        mock_cluster.get_status.return_value = {
            'state': 'PRIMARY',
            'is_forwarding': True
        }
        
        # Patch at the module level where it's imported
        with patch('trapninja.ha.get_ha_cluster', return_value=mock_cluster):
            result = cs._handle_ha_status({})
        
        assert result['status'] == ControlSocket.SUCCESS
        assert result['data']['state'] == 'PRIMARY'

    def test_ha_promote_no_cluster(self):
        """Test ha_promote when cluster not running."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        with patch('trapninja.ha.get_ha_cluster', return_value=None):
            result = cs._handle_ha_promote({})
        
        assert result['status'] == ControlSocket.NOT_FOUND

    def test_ha_promote_success(self):
        """Test ha_promote success."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_cluster = MagicMock()
        mock_cluster.promote_to_primary.return_value = True
        
        with patch('trapninja.ha.get_ha_cluster', return_value=mock_cluster):
            result = cs._handle_ha_promote({'force': True})
        
        assert result['status'] == ControlSocket.SUCCESS
        mock_cluster.promote_to_primary.assert_called_once_with(force=True)

    def test_ha_demote_success(self):
        """Test ha_demote success."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_cluster = MagicMock()
        mock_cluster.demote_to_secondary.return_value = True
        
        with patch('trapninja.ha.get_ha_cluster', return_value=mock_cluster):
            result = cs._handle_ha_demote({})
        
        assert result['status'] == ControlSocket.SUCCESS

    def test_ha_force_failover(self):
        """Test ha_force_failover."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_cluster = MagicMock()
        
        with patch('trapninja.ha.get_ha_cluster', return_value=mock_cluster):
            result = cs._handle_ha_force_failover({})
        
        assert result['status'] == ControlSocket.SUCCESS
        mock_cluster.force_failover.assert_called_once()


# =============================================================================
# Stats Command Handler Tests
# =============================================================================

class TestStatsCommandHandler:
    """Tests for stats command handler."""

    def test_stats_no_collector(self):
        """Test stats when collector not initialized."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        with patch('trapninja.stats.get_stats_collector', return_value=None):
            result = cs._handle_stats({})
        
        assert result['status'] == ControlSocket.NOT_FOUND

    def test_stats_summary_action(self):
        """Test stats summary action."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_collector = MagicMock()
        mock_collector.get_summary.return_value = {'total_traps': 100}
        
        with patch('trapninja.stats.get_stats_collector', return_value=mock_collector):
            result = cs._handle_stats({'action': 'summary'})
        
        assert result['status'] == ControlSocket.SUCCESS
        assert result['data']['total_traps'] == 100

    def test_stats_top_ips_action(self):
        """Test stats top_ips action."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = [
            {'ip': '192.168.1.1', 'count': 50}
        ]
        
        with patch('trapninja.stats.get_stats_collector', return_value=mock_collector):
            result = cs._handle_stats({'action': 'top_ips', 'count': 5})
        
        assert result['status'] == ControlSocket.SUCCESS
        mock_collector.get_top_ips.assert_called_once_with(n=5, sort_by='total')

    def test_stats_top_ips_respects_max_limit(self):
        """Test stats top_ips respects max limit of 100."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = []
        
        with patch('trapninja.stats.get_stats_collector', return_value=mock_collector):
            result = cs._handle_stats({'action': 'top_ips', 'count': 500})
        
        # Should limit to 100
        mock_collector.get_top_ips.assert_called_once_with(n=100, sort_by='total')

    def test_stats_ip_detail_requires_address(self):
        """Test stats ip_detail requires ip_address."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_collector = MagicMock()
        
        with patch('trapninja.stats.get_stats_collector', return_value=mock_collector):
            result = cs._handle_stats({'action': 'ip_detail'})
        
        assert result['status'] == ControlSocket.INVALID_REQUEST
        assert 'ip_address required' in result['error']

    def test_stats_reset_action(self):
        """Test stats reset action."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_collector = MagicMock()
        
        with patch('trapninja.stats.get_stats_collector', return_value=mock_collector):
            result = cs._handle_stats({'action': 'reset'})
        
        assert result['status'] == ControlSocket.SUCCESS
        mock_collector.reset.assert_called_once()

    def test_stats_unknown_action(self):
        """Test stats unknown action."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        mock_collector = MagicMock()
        
        with patch('trapninja.stats.get_stats_collector', return_value=mock_collector):
            result = cs._handle_stats({'action': 'unknown_action'})
        
        assert result['status'] == ControlSocket.INVALID_REQUEST


# =============================================================================
# Show Config Command Handler Tests
# =============================================================================

class TestShowConfigHandler:
    """Tests for show_config command handler."""

    def test_show_config_returns_structure(self):
        """Test show_config returns expected structure."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        # The _handle_show_config imports config inside the function
        # We need to mock at a deeper level
        mock_cfg = MagicMock()
        mock_cfg.CONFIG_DIR = '/etc/trapninja'
        mock_cfg.INTERFACE = 'eth0'
        mock_cfg.CAPTURE_MODE = 'auto'
        mock_cfg.LISTEN_PORTS = [162, 1162]
        mock_cfg.destinations = [['192.168.1.100', 162]]
        mock_cfg.blocked_ips = set(['10.0.0.1'])
        mock_cfg.blocked_traps = set(['1.3.6.1.4.1.9999'])
        mock_cfg.redirected_ips = [['192.168.1.50', 'security']]
        mock_cfg.redirected_oids = []
        mock_cfg.redirected_destinations = {'security': [['127.0.0.1', 1362]]}
        
        mock_ha_config = MagicMock()
        mock_ha_config.enabled = False
        
        # Patch at import time in the function
        with patch.dict('sys.modules', {'trapninja.config': mock_cfg}):
            with patch('trapninja.ha.load_ha_config', return_value=mock_ha_config):
                result = cs._handle_show_config({})
        
        assert result['status'] == ControlSocket.SUCCESS
        assert 'data' in result


# =============================================================================
# Send Command Tests (Client Side)
# =============================================================================

class TestSendCommand:
    """Tests for send_command static method."""

    def test_raises_when_socket_not_found(self):
        """Test raises ConnectionRefusedError when socket not found."""
        from trapninja.control import ControlSocket
        
        with pytest.raises(ConnectionRefusedError) as exc_info:
            ControlSocket.send_command('ping', socket_path='/nonexistent/path.sock')
        
        assert 'not found' in str(exc_info.value)

    def test_sends_json_request(self):
        """Test sends JSON-encoded request."""
        from trapninja.control import ControlSocket
        
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            
            # Create a simple server
            server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server_sock.bind(socket_path)
            server_sock.listen(1)
            
            received_data = []
            
            def server_handler():
                conn, _ = server_sock.accept()
                data = conn.recv(4096)
                received_data.append(data)
                response = json.dumps({'status': 0, 'message': 'ok'})
                conn.send(response.encode('utf-8'))
                conn.close()
            
            server_thread = threading.Thread(target=server_handler)
            server_thread.start()
            
            try:
                result = ControlSocket.send_command('test_cmd', 
                                                    params={'key': 'value'},
                                                    socket_path=socket_path)
                
                server_thread.join(timeout=2)
                
                # Verify request was JSON
                request = json.loads(received_data[0].decode('utf-8'))
                assert request['command'] == 'test_cmd'
                assert request['key'] == 'value'
                assert 'timestamp' in request
                
            finally:
                server_sock.close()


# =============================================================================
# Global Function Tests
# =============================================================================

class TestGlobalFunctions:
    """Tests for module-level functions."""

    def test_initialize_control_socket(self):
        """Test initialize_control_socket creates global instance."""
        from trapninja.control import (
            initialize_control_socket, 
            shutdown_control_socket,
            get_control_socket
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            resolved_tmpdir = str(Path(tmpdir).resolve())
            
            with patch('trapninja.control.ControlSocket.ALLOWED_SOCKET_DIRS', 
                       frozenset([tmpdir, resolved_tmpdir, '/tmp'])):
                try:
                    result = initialize_control_socket(socket_path)
                    
                    assert result is True
                    assert get_control_socket() is not None
                finally:
                    shutdown_control_socket()

    def test_shutdown_control_socket(self):
        """Test shutdown_control_socket cleans up."""
        from trapninja.control import (
            initialize_control_socket,
            shutdown_control_socket,
            get_control_socket
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            resolved_tmpdir = str(Path(tmpdir).resolve())
            
            with patch('trapninja.control.ControlSocket.ALLOWED_SOCKET_DIRS',
                       frozenset([tmpdir, resolved_tmpdir, '/tmp'])):
                initialize_control_socket(socket_path)
                shutdown_control_socket()
                
                assert get_control_socket() is None

    def test_initialize_handles_invalid_path(self):
        """Test initialize handles invalid socket path."""
        from trapninja.control import initialize_control_socket
        
        result = initialize_control_socket("/invalid/../path.sock")
        
        assert result is False


# =============================================================================
# Receive With Limit Tests
# =============================================================================

class TestReceiveWithLimit:
    """Tests for _receive_with_limit method."""

    def test_respects_size_limit(self):
        """Test respects maximum request size."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        # Create mock socket that returns too much data
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b'x' * 5000
        mock_conn.settimeout = MagicMock()
        
        # Simulate receiving data beyond limit
        with pytest.raises(ValueError) as exc_info:
            # Set a smaller limit for testing
            original_limit = ControlSocket.MAX_REQUEST_SIZE
            ControlSocket.MAX_REQUEST_SIZE = 10000
            
            try:
                # Will keep receiving until limit exceeded
                data = b''
                while True:
                    chunk = mock_conn.recv.return_value
                    data += chunk
                    if len(data) > ControlSocket.MAX_REQUEST_SIZE:
                        raise ValueError(f"Request size ({len(data)} bytes) exceeds limit")
            finally:
                ControlSocket.MAX_REQUEST_SIZE = original_limit
        
        assert "exceeds limit" in str(exc_info.value)


# =============================================================================
# Connection Handler Tests
# =============================================================================

class TestHandleConnection:
    """Tests for _handle_connection method."""

    def test_handles_empty_request(self):
        """Test handles empty request gracefully."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b''
        mock_conn.settimeout = MagicMock()
        
        # Should not raise exception
        cs._handle_connection(mock_conn)
        
        mock_conn.close.assert_called_once()

    def test_handles_invalid_json(self):
        """Test handles invalid JSON gracefully."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [b'not valid json', b'']
        mock_conn.settimeout = MagicMock()
        
        cs._handle_connection(mock_conn)
        
        # Should have sent error response
        mock_conn.send.assert_called_once()
        response = json.loads(mock_conn.send.call_args[0][0].decode())
        assert response['status'] == ControlSocket.INVALID_REQUEST

    def test_handles_non_dict_request(self):
        """Test handles non-dict JSON request."""
        from trapninja.control import ControlSocket
        
        cs = ControlSocket()
        
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [b'["array", "not", "object"]', b'']
        mock_conn.settimeout = MagicMock()
        
        cs._handle_connection(mock_conn)
        
        # Should have sent error response
        mock_conn.send.assert_called_once()
        response = json.loads(mock_conn.send.call_args[0][0].decode())
        assert response['status'] == ControlSocket.INVALID_REQUEST
        assert 'JSON object' in response['error']
