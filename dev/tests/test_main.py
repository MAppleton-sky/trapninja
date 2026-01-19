#!/usr/bin/env python3
"""
TrapNinja Test Suite - Main Module Tests

Tests for trapninja.main module - application entry point.

Author: TrapNinja Team
"""

import sys
import pytest
from unittest.mock import patch, MagicMock


# =============================================================================
# Main Entry Point Tests
# =============================================================================

class TestMain:
    """Tests for main() function."""

    def test_returns_int(self):
        """Test main returns an integer."""
        from trapninja.main import main
        
        # Test with --help which should exit
        with patch('sys.argv', ['trapninja', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            # --help exits with 0
            assert exc_info.value.code == 0

    def test_handles_keyboard_interrupt(self):
        """Test handles KeyboardInterrupt gracefully."""
        from trapninja.main import main
        
        with patch('trapninja.main.create_argument_parser') as mock_parser:
            mock_parser.side_effect = KeyboardInterrupt()
            
            result = main()
            
            assert result == 1

    def test_handles_unexpected_exception(self):
        """Test handles unexpected exceptions."""
        from trapninja.main import main
        
        with patch('trapninja.main.create_argument_parser') as mock_parser:
            mock_parser.side_effect = RuntimeError("Unexpected error")
            
            result = main()
            
            assert result == 1

    def test_parses_arguments(self):
        """Test parses arguments correctly."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', 'daemon', 'status']):
            # Patch execute_command in main module (where it's imported)
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                mock_execute.assert_called_once()
                assert result == 0

    def test_handles_argument_type_error(self):
        """Test handles ArgumentTypeError."""
        from trapninja.main import main
        import argparse
        
        with patch('trapninja.main.create_argument_parser') as mock_create:
            mock_parser = MagicMock()
            mock_parser.parse_args.side_effect = argparse.ArgumentTypeError("Invalid value")
            mock_create.return_value = mock_parser
            
            result = main()
            
            assert result == 1


# =============================================================================
# Execute Command Integration Tests
# =============================================================================

class TestExecuteCommandIntegration:
    """Integration tests for command execution."""

    def test_daemon_status_command(self):
        """Test daemon status command execution."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', 'daemon', 'status']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0

    def test_filter_command(self):
        """Test filter command execution."""
        from trapninja.main import main
        
        # Use a valid filter subcommand
        with patch('sys.argv', ['trapninja', 'filter', 'list-blocked-ips']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0

    def test_ha_status_command(self):
        """Test HA status command execution."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', 'ha', 'status']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0

    def test_stats_summary_command(self):
        """Test stats summary command execution."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', 'stats', 'summary']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0


# =============================================================================
# Argument Parser Tests
# =============================================================================

class TestArgumentParser:
    """Tests for argument parser integration."""

    def test_creates_parser(self):
        """Test creates argument parser."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        
        assert parser is not None
        assert parser.prog == 'trapninja'

    def test_parser_has_subcommands(self):
        """Test parser has expected subcommands."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        
        # Parse with valid subcommand should work
        args = parser.parse_args(['daemon', 'status'])
        
        assert args.category == 'daemon'

    def test_help_flag(self):
        """Test --help flag exits with 0."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            # --help should exit with 0
            assert exc_info.value.code == 0


# =============================================================================
# Legacy Argument Support Tests
# =============================================================================

class TestLegacyArguments:
    """Tests for legacy flat-style argument support."""

    def test_legacy_status_flag(self):
        """Test legacy --status flag."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', '--status']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0

    def test_legacy_start_flag(self):
        """Test legacy --start flag."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', '--start']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0

    def test_legacy_stop_flag(self):
        """Test legacy --stop flag."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', '--stop']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0

    def test_legacy_restart_flag(self):
        """Test legacy --restart flag."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', '--restart']):
            with patch('trapninja.main.execute_command') as mock_execute:
                mock_execute.return_value = 0
                
                result = main()
                
                assert result == 0


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling in main module."""

    def test_prints_traceback_on_error(self, capsys):
        """Test prints traceback on unexpected error."""
        from trapninja.main import main
        
        with patch('trapninja.main.create_argument_parser') as mock_parser:
            mock_parser.side_effect = ValueError("Test error")
            
            result = main()
            
            captured = capsys.readouterr()
            assert 'Unexpected error' in captured.out
            assert result == 1

    def test_prints_operation_cancelled(self, capsys):
        """Test prints operation cancelled on KeyboardInterrupt."""
        from trapninja.main import main
        
        with patch('trapninja.main.create_argument_parser') as mock_parser:
            mock_parser.side_effect = KeyboardInterrupt()
            
            result = main()
            
            captured = capsys.readouterr()
            assert 'cancelled' in captured.out.lower()


# =============================================================================
# Module Structure Tests
# =============================================================================

class TestModuleStructure:
    """Tests for module structure."""

    def test_main_is_callable(self):
        """Test main is callable."""
        from trapninja.main import main
        
        assert callable(main)

    def test_module_has_name_guard(self):
        """Test module has if __name__ == '__main__' guard."""
        import inspect
        import trapninja.main as main_module
        
        source = inspect.getsource(main_module)
        
        assert "if __name__ ==" in source
        assert "__main__" in source

    def test_imports_from_cli_package(self):
        """Test imports from cli package."""
        from trapninja.main import create_argument_parser, execute_command
        
        assert callable(create_argument_parser)
        assert callable(execute_command)


# =============================================================================
# Exit Code Tests
# =============================================================================

class TestExitCodes:
    """Tests for exit codes."""

    def test_success_returns_zero(self):
        """Test successful execution returns 0."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', 'daemon', 'status']):
            with patch('trapninja.main.execute_command', return_value=0):
                result = main()
                
                assert result == 0

    def test_failure_returns_nonzero(self):
        """Test failed execution returns non-zero."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', 'daemon', 'status']):
            with patch('trapninja.main.execute_command', return_value=1):
                result = main()
                
                assert result == 1

    def test_propagates_execute_command_exit_code(self):
        """Test propagates execute_command exit code."""
        from trapninja.main import main
        
        with patch('sys.argv', ['trapninja', 'daemon', 'status']):
            with patch('trapninja.main.execute_command', return_value=42):
                result = main()
                
                assert result == 42


# =============================================================================
# Debug Mode Tests
# =============================================================================

class TestDebugMode:
    """Tests for debug mode."""

    def test_debug_flag_accepted(self):
        """Test --debug flag is accepted."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--debug', 'daemon', 'status'])
        
        assert args.debug is True

    def test_debug_flag_default_false(self):
        """Test --debug flag defaults to False."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'status'])
        
        assert args.debug is False


# =============================================================================
# JSON Output Tests
# =============================================================================

class TestJSONOutput:
    """Tests for JSON output flag."""

    def test_json_flag_accepted(self):
        """Test --json flag is accepted."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--json', 'daemon', 'status'])
        
        assert args.json is True

    def test_json_flag_default_false(self):
        """Test --json flag defaults to False."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'status'])
        
        assert args.json is False


# =============================================================================
# Config Directory Tests
# =============================================================================

class TestConfigDirectory:
    """Tests for config directory option."""

    def test_config_dir_option_accepted(self):
        """Test --config-dir option is accepted."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--config-dir', '/custom/config', 'daemon', 'status'])
        
        assert args.config_dir == '/custom/config'

    def test_config_dir_default_none(self):
        """Test --config-dir defaults to None."""
        from trapninja.cli import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'status'])
        
        assert args.config_dir is None
