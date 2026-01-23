#!/usr/bin/env python3
"""
TrapNinja Test Suite - Daemon Module Tests

Tests for trapninja.daemon module - daemon control operations.

Author: TrapNinja Team
"""

import os
import sys
import time
import signal
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open


# =============================================================================
# Build Process Check Command Tests
# =============================================================================

class TestBuildProcessCheckCmd:
    """Tests for _build_process_check_cmd function."""

    def test_builds_command_with_pid(self):
        """Test command is built with own PID excluded."""
        from trapninja.daemon import _build_process_check_cmd
        
        cmd = _build_process_check_cmd(12345)
        
        assert "ps aux" in cmd
        assert "grep -i 'trapninja" in cmd
        assert "grep -v grep" in cmd
        assert "12345" in cmd

    def test_excludes_cli_commands(self):
        """Test command excludes CLI control commands."""
        from trapninja.daemon import _build_process_check_cmd
        
        cmd = _build_process_check_cmd(1)
        
        # The grep -v uses escaped dashes: \-\-start
        assert "start" in cmd
        assert "restart" in cmd
        assert "stop" in cmd
        assert "status" in cmd

    def test_different_pids_create_different_commands(self):
        """Test different PIDs create different commands."""
        from trapninja.daemon import _build_process_check_cmd
        
        cmd1 = _build_process_check_cmd(100)
        cmd2 = _build_process_check_cmd(200)
        
        assert " 100 " in cmd1
        assert " 200 " in cmd2
        assert cmd1 != cmd2


# =============================================================================
# Run Command Safe Tests
# =============================================================================

class TestRunCommandSafe:
    """Tests for run_command_safe function."""

    def test_returns_stdout_stripped(self):
        """Test returns stripped stdout."""
        from trapninja.daemon import run_command_safe
        
        result = run_command_safe("echo 'hello world'")
        
        assert result == "hello world"

    def test_returns_empty_on_timeout(self):
        """Test returns empty string on timeout."""
        from trapninja.daemon import run_command_safe
        
        # Command that takes too long
        result = run_command_safe("sleep 60", timeout=0.1)
        
        assert result == ""

    def test_returns_empty_on_error(self):
        """Test returns empty string on command error."""
        from trapninja.daemon import run_command_safe
        
        result = run_command_safe("nonexistent_command_xyz")
        
        # Should return empty or error output gracefully
        assert isinstance(result, str)

    def test_handles_multiline_output(self):
        """Test handles multiline output correctly."""
        from trapninja.daemon import run_command_safe
        
        result = run_command_safe("echo 'line1'; echo 'line2'")
        
        assert "line1" in result
        assert "line2" in result


# =============================================================================
# Start Daemon Tests
# =============================================================================

class TestStartDaemon:
    """Tests for start_daemon function."""

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.path.exists')
    @patch('trapninja.daemon.os.getpid')
    def test_detects_already_running(self, mock_getpid, mock_exists, mock_run_cmd):
        """Test detects when daemon is already running."""
        from trapninja.daemon import start_daemon
        
        mock_getpid.return_value = 99999
        mock_run_cmd.return_value = "user  12345  0.0  0.1  trapninja"
        mock_exists.return_value = False
        
        result = start_daemon()
        
        assert result == 1

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.getpid')
    @patch('trapninja.logger.setup_logging')
    @patch('trapninja.daemon.ensure_config_dir')
    @patch('subprocess.Popen')
    @patch('trapninja.daemon._verify_daemon_started')
    def test_spawns_daemon_process(self, mock_verify, mock_popen, mock_ensure, 
                                    mock_logging, mock_getpid, mock_run_cmd):
        """Test spawns daemon subprocess."""
        from trapninja.daemon import start_daemon
        
        mock_getpid.return_value = 99999
        mock_run_cmd.return_value = ""
        mock_process = MagicMock()
        mock_process.pid = 54321
        mock_popen.return_value = mock_process
        mock_verify.return_value = True
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_pid_file = f.name
        
        try:
            with patch('trapninja.daemon.PID_FILE', temp_pid_file):
                with patch('trapninja.daemon.os.path.exists', return_value=False):
                    result = start_daemon()
            
            assert result == 0
            mock_popen.assert_called_once()
        finally:
            # Cleanup
            if os.path.exists(temp_pid_file):
                os.unlink(temp_pid_file)

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.getpid')
    @patch('trapninja.logger.setup_logging')
    @patch('trapninja.daemon.ensure_config_dir')
    @patch('subprocess.Popen')
    @patch('trapninja.daemon._verify_daemon_started')
    def test_passes_shadow_mode_flag(self, mock_verify, mock_popen, mock_ensure,
                                      mock_logging, mock_getpid, mock_run_cmd):
        """Test passes shadow mode flag to subprocess."""
        from trapninja.daemon import start_daemon
        
        mock_getpid.return_value = 99999
        mock_run_cmd.return_value = ""
        mock_process = MagicMock()
        mock_process.pid = 54321
        mock_popen.return_value = mock_process
        mock_verify.return_value = True
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_pid_file = f.name
        
        try:
            with patch('trapninja.daemon.PID_FILE', temp_pid_file):
                with patch('trapninja.daemon.os.path.exists', return_value=False):
                    result = start_daemon(shadow_mode=True)
            
            # Check that --shadow-mode was passed
            call_args = mock_popen.call_args[0][0]
            assert '--shadow-mode' in call_args
        finally:
            # Cleanup
            if os.path.exists(temp_pid_file):
                os.unlink(temp_pid_file)

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.getpid')
    @patch('trapninja.logger.setup_logging')
    @patch('trapninja.daemon.ensure_config_dir')
    @patch('subprocess.Popen')
    @patch('trapninja.daemon._verify_daemon_started')
    def test_passes_capture_mode_argument(self, mock_verify, mock_popen, mock_ensure,
                                           mock_logging, mock_getpid, mock_run_cmd):
        """Test passes capture mode argument to subprocess."""
        from trapninja.daemon import start_daemon
        
        mock_getpid.return_value = 99999
        mock_run_cmd.return_value = ""
        mock_process = MagicMock()
        mock_process.pid = 54321
        mock_popen.return_value = mock_process
        mock_verify.return_value = True
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_pid_file = f.name
        
        try:
            with patch('trapninja.daemon.PID_FILE', temp_pid_file):
                with patch('trapninja.daemon.os.path.exists', return_value=False):
                    result = start_daemon(capture_mode='sniff')
            
            # Check that --capture-mode was passed
            call_args = mock_popen.call_args[0][0]
            assert '--capture-mode' in call_args
            assert 'sniff' in call_args
        finally:
            # Cleanup
            if os.path.exists(temp_pid_file):
                os.unlink(temp_pid_file)


# =============================================================================
# Verify Daemon Started Tests
# =============================================================================

class TestVerifyDaemonStarted:
    """Tests for _verify_daemon_started function."""

    @patch('trapninja.daemon.os.kill')
    @patch('trapninja.control.ControlSocket.send_command')
    @patch('time.sleep')
    def test_returns_true_when_socket_responds(self, mock_sleep, mock_send, mock_kill):
        """Test returns True when control socket responds."""
        from trapninja.daemon import _verify_daemon_started
        from trapninja.control import ControlSocket
        
        mock_send.return_value = {'status': ControlSocket.SUCCESS}
        
        result = _verify_daemon_started(12345, timeout=5)
        
        assert result is True

    @patch('trapninja.daemon.os.kill')
    @patch('trapninja.control.ControlSocket.send_command')
    @patch('time.sleep')
    def test_returns_false_when_process_dies(self, mock_sleep, mock_send, mock_kill):
        """Test returns False when process dies."""
        from trapninja.daemon import _verify_daemon_started
        
        # Process dies immediately
        mock_kill.side_effect = OSError("No such process")
        
        with patch('trapninja.daemon._show_daemon_crash_info'):
            result = _verify_daemon_started(12345, timeout=5)
        
        assert result is False

    @patch('trapninja.daemon.os.kill')
    @patch('trapninja.control.ControlSocket.send_command')
    @patch('time.time')
    @patch('time.sleep')
    def test_returns_true_after_timeout_if_process_running(self, mock_sleep, mock_time, 
                                                            mock_send, mock_kill):
        """Test returns True after timeout if process still running."""
        from trapninja.daemon import _verify_daemon_started
        
        # Simulate timeout scenario
        time_values = [0, 1, 2, 16, 17]  # Exceeds 15s timeout
        mock_time.side_effect = time_values
        mock_send.side_effect = ConnectionRefusedError()
        
        result = _verify_daemon_started(12345, timeout=15)
        
        # Should return True (benefit of the doubt if process exists)
        assert result is True


# =============================================================================
# Stop Daemon Tests
# =============================================================================

class TestStopDaemon:
    """Tests for stop_daemon function."""

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.path.exists')
    @patch('trapninja.daemon.os.getpid')
    def test_returns_zero_when_not_running(self, mock_getpid, mock_exists, mock_run_cmd):
        """Test returns 0 when daemon not running."""
        from trapninja.daemon import stop_daemon
        
        mock_getpid.return_value = 99999
        mock_exists.return_value = False
        mock_run_cmd.return_value = ""
        
        result = stop_daemon()
        
        assert result == 0

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.getpid')
    @patch('trapninja.daemon.os.kill')
    @patch('time.sleep')
    def test_sends_sigterm_to_process(self, mock_sleep, mock_kill, mock_getpid, 
                                       mock_run_cmd):
        """Test sends SIGTERM to running process."""
        from trapninja.daemon import stop_daemon
        
        mock_getpid.return_value = 99999
        
        # Create a real temp file for the test
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("12345")
            temp_pid_file = f.name
        
        try:
            # Simulate process terminating after SIGTERM
            kill_calls = [0]
            def kill_side_effect(pid, sig):
                kill_calls[0] += 1
                if sig == signal.SIGTERM:
                    return None
                if kill_calls[0] > 2:  # After SIGTERM, process gone
                    raise OSError("No such process")
                return None
            
            mock_kill.side_effect = kill_side_effect
            mock_run_cmd.side_effect = [
                "user  12345  0.0  0.1  trapninja",  # First check - running
                ""  # After stop - no processes
            ]
            
            with patch('trapninja.daemon.PID_FILE', temp_pid_file):
                with patch('trapninja.daemon.os.path.exists', return_value=True):
                    result = stop_daemon()
            
            # Should have tried to send SIGTERM
            assert any(call[0][1] == signal.SIGTERM for call in mock_kill.call_args_list)
        finally:
            # Cleanup
            if os.path.exists(temp_pid_file):
                os.unlink(temp_pid_file)


# =============================================================================
# Status Daemon Tests
# =============================================================================

class TestStatusDaemon:
    """Tests for status_daemon function."""

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.path.exists')
    @patch('trapninja.daemon.os.getpid')
    def test_returns_one_when_not_running(self, mock_getpid, mock_exists, mock_run_cmd):
        """Test returns 1 when daemon not running."""
        from trapninja.daemon import status_daemon
        
        mock_getpid.return_value = 99999
        mock_exists.return_value = False
        mock_run_cmd.return_value = ""
        
        result = status_daemon()
        
        assert result == 1

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.getpid')
    @patch('trapninja.daemon.os.kill')
    def test_returns_zero_when_running(self, mock_kill, mock_getpid, mock_run_cmd):
        """Test returns 0 when daemon is running."""
        from trapninja.daemon import status_daemon
        
        mock_getpid.return_value = 99999
        mock_run_cmd.side_effect = [
            "trapninja --foreground-daemon",  # ps command output
            "00:05:32"  # uptime output
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("12345")
            temp_pid_file = f.name
        
        try:
            with patch('trapninja.daemon.PID_FILE', temp_pid_file):
                with patch('trapninja.daemon.os.path.exists') as mock_exists:
                    mock_exists.side_effect = [True, True, False]  # PID file, PID file, LOG file
                    result = status_daemon()
            
            assert result == 0
        finally:
            # Cleanup
            if os.path.exists(temp_pid_file):
                os.unlink(temp_pid_file)

    @patch('trapninja.daemon.run_command_safe')
    @patch('trapninja.daemon.os.getpid')
    @patch('trapninja.daemon.os.kill')
    def test_removes_stale_pid_file(self, mock_kill, mock_getpid, mock_run_cmd):
        """Test removes stale PID file when process not running."""
        from trapninja.daemon import status_daemon
        
        mock_getpid.return_value = 99999
        mock_kill.side_effect = OSError("No such process")
        mock_run_cmd.return_value = ""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("12345")
            temp_pid_file = f.name
        
        try:
            with patch('trapninja.daemon.PID_FILE', temp_pid_file):
                with patch('trapninja.daemon.os.path.exists', return_value=True):
                    result = status_daemon()
            
            # Should return 1 (not running)
            assert result == 1
        finally:
            # Cleanup
            if os.path.exists(temp_pid_file):
                os.unlink(temp_pid_file)


# =============================================================================
# Restart Daemon Tests
# =============================================================================

class TestRestartDaemon:
    """Tests for restart_daemon function."""

    @patch('trapninja.daemon.stop_daemon')
    @patch('trapninja.daemon.start_daemon')
    @patch('time.sleep')
    def test_calls_stop_then_start(self, mock_sleep, mock_start, mock_stop):
        """Test calls stop_daemon then start_daemon."""
        from trapninja.daemon import restart_daemon
        
        mock_stop.return_value = 0
        mock_start.return_value = 0
        
        result = restart_daemon()
        
        mock_stop.assert_called_once()
        mock_start.assert_called_once()
        assert result == 0

    @patch('trapninja.daemon.stop_daemon')
    @patch('trapninja.daemon.start_daemon')
    @patch('time.sleep')
    def test_passes_mode_flags_to_start(self, mock_sleep, mock_start, mock_stop):
        """Test passes mode flags to start_daemon."""
        from trapninja.daemon import restart_daemon
        
        mock_stop.return_value = 0
        mock_start.return_value = 0
        
        result = restart_daemon(shadow_mode=True, mirror_mode=True, 
                                capture_mode='sniff', log_traps='/tmp/traps.log')
        
        mock_start.assert_called_once_with(
            shadow_mode=True,
            mirror_mode=True,
            parallel=False,
            capture_mode='sniff',
            log_traps='/tmp/traps.log'
        )

    @patch('trapninja.daemon.stop_daemon')
    @patch('trapninja.daemon.start_daemon')
    @patch('time.sleep')
    def test_returns_one_if_stop_fails(self, mock_sleep, mock_start, mock_stop):
        """Test returns 1 if stop_daemon fails."""
        from trapninja.daemon import restart_daemon
        
        mock_stop.return_value = 1
        mock_start.return_value = 0
        
        result = restart_daemon()
        
        assert result == 1


# =============================================================================
# Run Foreground Daemon Tests
# =============================================================================

class TestRunForegroundDaemon:
    """Tests for run_foreground_daemon function."""

    @patch('trapninja.logger.setup_logging')
    @patch('trapninja.daemon.ensure_config_dir')
    @patch('trapninja.daemon.run_service')
    def test_calls_run_service(self, mock_run_service, mock_ensure, mock_logging):
        """Test calls run_service with correct arguments."""
        from trapninja.daemon import run_foreground_daemon
        
        mock_run_service.return_value = 0
        
        result = run_foreground_daemon(
            debug=True,
            shadow_mode=True,
            capture_mode='socket'
        )
        
        mock_logging.assert_called_once_with(console=True)
        mock_ensure.assert_called_once()
        mock_run_service.assert_called_once_with(
            debug=True,
            shadow_mode=True,
            mirror_mode=False,
            parallel=False,
            capture_mode='socket',
            log_traps=None
        )
        assert result == 0

    @patch('trapninja.logger.setup_logging')
    @patch('trapninja.daemon.ensure_config_dir')
    @patch('trapninja.daemon.run_service')
    def test_returns_service_exit_code(self, mock_run_service, mock_ensure, mock_logging):
        """Test returns exit code from run_service."""
        from trapninja.daemon import run_foreground_daemon
        
        mock_run_service.return_value = 42
        
        result = run_foreground_daemon()
        
        assert result == 42


# =============================================================================
# Show Daemon Crash Info Tests
# =============================================================================

class TestShowDaemonCrashInfo:
    """Tests for _show_daemon_crash_info function."""

    @patch('trapninja.daemon.os.path.exists')
    def test_handles_missing_log_file(self, mock_exists):
        """Test handles missing log file gracefully."""
        from trapninja.daemon import _show_daemon_crash_info
        
        mock_exists.return_value = False
        
        # Should not raise exception
        _show_daemon_crash_info()

    def test_reads_log_file_tail(self):
        """Test reads last lines of log file."""
        from trapninja.daemon import _show_daemon_crash_info
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            for i in range(20):
                f.write(f"Log line {i}\n")
            temp_log = f.name
        
        try:
            with patch('trapninja.daemon.LOG_FILE', temp_log):
                _show_daemon_crash_info()
        finally:
            # Cleanup
            os.unlink(temp_log)
