#!/usr/bin/env python3
"""
TrapNinja Test Suite - CLI Output Tests

Tests for trapninja.cli.output module - output formatting and display.

Author: TrapNinja Team
"""

import sys
import json
import pytest
from io import StringIO
from unittest.mock import patch, MagicMock


class TestExitCode:
    """Tests for ExitCode enum."""

    def test_exit_code_values(self):
        """Test ExitCode enum values."""
        from trapninja.cli.output import ExitCode
        
        assert ExitCode.SUCCESS == 0
        assert ExitCode.ERROR == 1
        assert ExitCode.INVALID_INPUT == 2
        assert ExitCode.CONNECTION_ERROR == 3
        assert ExitCode.PERMISSION_ERROR == 4
        assert ExitCode.NOT_FOUND == 5
        assert ExitCode.TIMEOUT == 6
        assert ExitCode.CONFIGURATION_ERROR == 7

    def test_exit_code_is_int(self):
        """Test ExitCode values are integers."""
        from trapninja.cli.output import ExitCode
        
        assert isinstance(ExitCode.SUCCESS.value, int)
        assert isinstance(ExitCode.ERROR.value, int)


class TestCLIOutputInit:
    """Tests for CLIOutput initialization."""

    def test_default_init(self):
        """Test default initialization."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput()
        
        assert output.quiet is False
        assert output.json_output is False

    def test_init_with_quiet(self):
        """Test initialization with quiet mode."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(quiet=True)
        
        assert output.quiet is True

    def test_init_with_json(self):
        """Test initialization with JSON output."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        
        assert output.json_output is True

    def test_init_with_color_forced(self):
        """Test initialization with forced color."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=True)
        
        assert output.color is True

    def test_init_with_color_disabled(self):
        """Test initialization with disabled color."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        
        assert output.color is False


class TestCLIOutputSuccess:
    """Tests for CLIOutput.success method."""

    def test_success_prints_message(self, capsys):
        """Test success prints message to stdout."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.success("Operation completed")
        
        captured = capsys.readouterr()
        assert "Operation completed" in captured.out
        assert "[✓]" in captured.out

    def test_success_quiet_mode_no_output(self, capsys):
        """Test success in quiet mode produces no output."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(quiet=True)
        output.success("Operation completed")
        
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_success_json_output(self, capsys):
        """Test success with JSON output format."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        output.success("Operation completed", data={"key": "value"})
        
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["status"] == "success"
        assert result["message"] == "Operation completed"
        assert result["data"]["key"] == "value"


class TestCLIOutputError:
    """Tests for CLIOutput.error method."""

    def test_error_prints_to_stderr(self, capsys):
        """Test error prints to stderr."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.error("Something went wrong")
        
        captured = capsys.readouterr()
        assert "Something went wrong" in captured.err
        assert "[✗]" in captured.err

    def test_error_with_details(self, capsys):
        """Test error with additional details."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.error("Error occurred", details="Additional info")
        
        captured = capsys.readouterr()
        assert "Error occurred" in captured.err
        assert "Additional info" in captured.err

    def test_error_with_hint(self, capsys):
        """Test error with hint."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.error("Error occurred", hint="Try this instead")
        
        captured = capsys.readouterr()
        assert "Error occurred" in captured.err
        assert "Try this instead" in captured.err

    def test_error_with_exit_code(self):
        """Test error with exit code exits program."""
        from trapninja.cli.output import CLIOutput, ExitCode
        
        output = CLIOutput(color=False)
        
        with pytest.raises(SystemExit) as exc_info:
            output.error("Fatal error", exit_code=ExitCode.ERROR)
        
        assert exc_info.value.code == 1

    def test_error_json_output(self, capsys):
        """Test error with JSON output format."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        output.error("Something failed", details="More info", hint="Try again")
        
        captured = capsys.readouterr()
        result = json.loads(captured.err)
        assert result["status"] == "error"
        assert result["message"] == "Something failed"
        assert result["details"] == "More info"
        assert result["hint"] == "Try again"


class TestCLIOutputWarning:
    """Tests for CLIOutput.warning method."""

    def test_warning_prints_to_stderr(self, capsys):
        """Test warning prints to stderr."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.warning("Be careful")
        
        captured = capsys.readouterr()
        assert "Be careful" in captured.err
        assert "[!]" in captured.err

    def test_warning_quiet_mode_no_output(self, capsys):
        """Test warning in quiet mode produces no output."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(quiet=True)
        output.warning("Be careful")
        
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_warning_json_output(self, capsys):
        """Test warning with JSON output format."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        output.warning("Caution advised")
        
        captured = capsys.readouterr()
        result = json.loads(captured.err)
        assert result["status"] == "warning"
        assert result["message"] == "Caution advised"


class TestCLIOutputInfo:
    """Tests for CLIOutput.info method."""

    def test_info_prints_to_stdout(self, capsys):
        """Test info prints to stdout."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.info("FYI message")
        
        captured = capsys.readouterr()
        assert "FYI message" in captured.out
        assert "[i]" in captured.out

    def test_info_quiet_mode_no_output(self, capsys):
        """Test info in quiet mode produces no output."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(quiet=True)
        output.info("FYI message")
        
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_info_json_output(self, capsys):
        """Test info with JSON output format."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        output.info("Information", data={"count": 42})
        
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["status"] == "info"
        assert result["message"] == "Information"
        assert result["data"]["count"] == 42


class TestCLIOutputData:
    """Tests for CLIOutput.data method."""

    def test_data_prints_dict(self, capsys):
        """Test data prints dictionary."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.data({"key": "value", "number": 42})
        
        captured = capsys.readouterr()
        assert "key:" in captured.out
        assert "value" in captured.out

    def test_data_prints_list(self, capsys):
        """Test data prints list."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.data(["item1", "item2", "item3"])
        
        captured = capsys.readouterr()
        assert "- item1" in captured.out
        assert "- item2" in captured.out

    def test_data_with_title(self, capsys):
        """Test data with title."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.data({"key": "value"}, title="Results")
        
        captured = capsys.readouterr()
        assert "Results" in captured.out

    def test_data_json_output(self, capsys):
        """Test data with JSON output format."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        output.data({"key": "value"}, title="Results")
        
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["status"] == "data"
        assert result["title"] == "Results"
        assert result["data"]["key"] == "value"

    def test_data_quiet_mode_no_output(self, capsys):
        """Test data in quiet mode produces no output."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(quiet=True)
        output.data({"key": "value"})
        
        captured = capsys.readouterr()
        assert captured.out == ""


class TestCLIOutputTable:
    """Tests for CLIOutput.table method."""

    def test_table_prints_headers(self, capsys):
        """Test table prints headers."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.table(["Name", "Value"], [["foo", "bar"]])
        
        captured = capsys.readouterr()
        assert "Name" in captured.out
        assert "Value" in captured.out

    def test_table_prints_rows(self, capsys):
        """Test table prints rows."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.table(["Col1", "Col2"], [["a", "b"], ["c", "d"]])
        
        captured = capsys.readouterr()
        assert "a" in captured.out
        assert "b" in captured.out
        assert "c" in captured.out
        assert "d" in captured.out

    def test_table_with_title(self, capsys):
        """Test table with title."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.table(["Col"], [["val"]], title="My Table")
        
        captured = capsys.readouterr()
        assert "My Table" in captured.out

    def test_table_empty_rows(self, capsys):
        """Test table with empty rows."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.table(["Col1", "Col2"], [])
        
        captured = capsys.readouterr()
        assert "No data" in captured.out

    def test_table_json_output(self, capsys):
        """Test table with JSON output format."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        output.table(["Name", "Value"], [["foo", "bar"]])
        
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["status"] == "data"
        assert result["data"][0]["Name"] == "foo"
        assert result["data"][0]["Value"] == "bar"


class TestCLIOutputProgress:
    """Tests for CLIOutput progress methods."""

    def test_progress_prints_message(self, capsys):
        """Test progress prints message."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.progress("Loading")
        
        captured = capsys.readouterr()
        assert "Loading" in captured.out

    def test_progress_with_values(self, capsys):
        """Test progress with current/total values."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.progress("Processing", current=50, total=100)
        
        captured = capsys.readouterr()
        assert "50/100" in captured.out
        assert "50.0%" in captured.out

    def test_progress_quiet_mode(self, capsys):
        """Test progress in quiet mode produces no output."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(quiet=True)
        output.progress("Loading")
        
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_progress_json_mode(self, capsys):
        """Test progress in JSON mode produces no output."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        output.progress("Loading")
        
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_progress_done(self, capsys):
        """Test progress_done adds newline."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        output.progress("Test")
        output.progress_done()
        
        captured = capsys.readouterr()
        assert "\n" in captured.out


class TestCLIOutputConfirm:
    """Tests for CLIOutput.confirm method."""

    def test_confirm_yes_response(self):
        """Test confirm with 'yes' response."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput()
        
        with patch('builtins.input', return_value='yes'):
            result = output.confirm("Proceed?")
        
        assert result is True

    def test_confirm_y_response(self):
        """Test confirm with 'y' response."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput()
        
        with patch('builtins.input', return_value='y'):
            result = output.confirm("Proceed?")
        
        assert result is True

    def test_confirm_no_response(self):
        """Test confirm with 'no' response."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput()
        
        with patch('builtins.input', return_value='no'):
            result = output.confirm("Proceed?")
        
        assert result is False

    def test_confirm_empty_with_default_true(self):
        """Test confirm with empty response and default True."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput()
        
        with patch('builtins.input', return_value=''):
            result = output.confirm("Proceed?", default=True)
        
        assert result is True

    def test_confirm_empty_with_default_false(self):
        """Test confirm with empty response and default False."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput()
        
        with patch('builtins.input', return_value=''):
            result = output.confirm("Proceed?", default=False)
        
        assert result is False

    def test_confirm_json_mode_uses_default(self):
        """Test confirm in JSON mode uses default."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(json_output=True)
        
        result = output.confirm("Proceed?", default=True)
        
        assert result is True


class TestConfigureOutput:
    """Tests for configure_output function."""

    def test_configure_output_updates_global(self):
        """Test configure_output updates global output instance."""
        from trapninja.cli.output import configure_output, output
        
        # Configure with specific settings
        configure_output(quiet=True, json_output=True)
        
        # Import again to get updated reference
        from trapninja.cli.output import output as updated_output
        
        assert updated_output.quiet is True
        assert updated_output.json_output is True
        
        # Reset to defaults
        configure_output(quiet=False, json_output=False)


class TestCLIOutputColorization:
    """Tests for CLIOutput color functionality."""

    def test_colorize_with_color_enabled(self):
        """Test _colorize adds color codes when enabled."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=True)
        
        result = output._colorize("test", "red")
        
        assert "\033[91m" in result  # Red color code
        assert "\033[0m" in result   # Reset code
        assert "test" in result

    def test_colorize_with_color_disabled(self):
        """Test _colorize returns plain text when disabled."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=False)
        
        result = output._colorize("test", "red")
        
        assert result == "test"
        assert "\033[" not in result

    def test_colorize_unknown_color(self):
        """Test _colorize with unknown color returns plain text."""
        from trapninja.cli.output import CLIOutput
        
        output = CLIOutput(color=True)
        
        result = output._colorize("test", "unknown_color")
        
        assert result == "test"
