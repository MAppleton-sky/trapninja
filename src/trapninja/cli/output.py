#!/usr/bin/env python3
"""
TrapNinja CLI Output Module

Provides unified, consistent output formatting for all CLI commands.
Ensures consistent use of stdout/stderr and exit codes.

Usage:
    from .output import output
    
    output.success("Operation completed")
    output.error("Something went wrong")
    output.warning("Be careful")
    output.info("FYI")
"""

import sys
import json
from typing import Any, Dict, Optional, NoReturn
from enum import IntEnum


class ExitCode(IntEnum):
    """Standard exit codes for CLI commands."""
    SUCCESS = 0
    ERROR = 1
    INVALID_INPUT = 2
    CONNECTION_ERROR = 3
    PERMISSION_ERROR = 4
    NOT_FOUND = 5
    TIMEOUT = 6
    CONFIGURATION_ERROR = 7


class CLIOutput:
    """
    Unified output handler for CLI commands.
    
    Provides consistent formatting, coloring (when supported),
    and proper use of stdout/stderr.
    """
    
    # ANSI color codes (disabled by default, enabled if terminal supports)
    COLORS = {
        'reset': '\033[0m',
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'bold': '\033[1m',
        'dim': '\033[2m'
    }
    
    def __init__(self, color: bool = None, quiet: bool = False, json_output: bool = False):
        """
        Initialize CLI output handler.
        
        Args:
            color: Force color on/off (None = auto-detect)
            quiet: Suppress non-error output
            json_output: Output in JSON format
        """
        self.quiet = quiet
        self.json_output = json_output
        
        # Auto-detect color support
        if color is None:
            self.color = (
                sys.stdout.isatty() and 
                sys.stderr.isatty()
            )
        else:
            self.color = color
    
    def _colorize(self, text: str, color: str) -> str:
        """Apply color to text if enabled."""
        if self.color and color in self.COLORS:
            return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"
        return text
    
    def _format_prefix(self, prefix: str, color: str) -> str:
        """Format a message prefix with optional color."""
        if self.color:
            return self._colorize(f"[{prefix}]", color)
        return f"[{prefix}]"
    
    def success(self, message: str, data: Dict = None):
        """
        Print success message to stdout.
        
        Args:
            message: Success message
            data: Optional data to include (for JSON output)
        """
        if self.quiet:
            return
            
        if self.json_output:
            output = {"status": "success", "message": message}
            if data:
                output["data"] = data
            print(json.dumps(output))
        else:
            prefix = self._format_prefix("✓", "green")
            print(f"{prefix} {message}")
    
    def error(self, message: str, details: str = None, 
              hint: str = None, exit_code: ExitCode = None) -> Optional[NoReturn]:
        """
        Print error message to stderr.
        
        Args:
            message: Error message
            details: Optional additional details
            hint: Optional hint for resolution
            exit_code: If provided, exit with this code
            
        Returns:
            None, or exits if exit_code is provided
        """
        if self.json_output:
            output = {"status": "error", "message": message}
            if details:
                output["details"] = details
            if hint:
                output["hint"] = hint
            print(json.dumps(output), file=sys.stderr)
        else:
            prefix = self._format_prefix("✗", "red")
            print(f"{prefix} {message}", file=sys.stderr)
            
            if details:
                print(f"    {self._colorize(details, 'dim')}", file=sys.stderr)
            
            if hint:
                hint_prefix = self._colorize("Hint:", "yellow")
                print(f"    {hint_prefix} {hint}", file=sys.stderr)
        
        if exit_code is not None:
            sys.exit(exit_code)
    
    def warning(self, message: str, details: str = None):
        """
        Print warning message to stderr.
        
        Args:
            message: Warning message
            details: Optional additional details
        """
        if self.quiet:
            return
            
        if self.json_output:
            output = {"status": "warning", "message": message}
            if details:
                output["details"] = details
            print(json.dumps(output), file=sys.stderr)
        else:
            prefix = self._format_prefix("!", "yellow")
            print(f"{prefix} {message}", file=sys.stderr)
            
            if details:
                print(f"    {self._colorize(details, 'dim')}", file=sys.stderr)
    
    def info(self, message: str, data: Dict = None):
        """
        Print informational message to stdout.
        
        Args:
            message: Info message
            data: Optional data to include (for JSON output)
        """
        if self.quiet:
            return
            
        if self.json_output:
            output = {"status": "info", "message": message}
            if data:
                output["data"] = data
            print(json.dumps(output))
        else:
            prefix = self._format_prefix("i", "blue")
            print(f"{prefix} {message}")
    
    def data(self, data: Any, title: str = None):
        """
        Print data (dict, list, etc.) in formatted way.
        
        Args:
            data: Data to print
            title: Optional title
        """
        if self.quiet:
            return
            
        if self.json_output:
            output = {"status": "data"}
            if title:
                output["title"] = title
            output["data"] = data
            print(json.dumps(output, indent=2, default=str))
        else:
            if title:
                print(f"\n{self._colorize(title, 'bold')}")
                print("-" * len(title))
            
            if isinstance(data, dict):
                self._print_dict(data)
            elif isinstance(data, list):
                self._print_list(data)
            else:
                print(data)
    
    def _print_dict(self, d: Dict, indent: int = 0):
        """Pretty print a dictionary."""
        for key, value in d.items():
            prefix = "  " * indent
            key_str = self._colorize(f"{key}:", "bold") if indent == 0 else f"{key}:"
            
            if isinstance(value, dict):
                print(f"{prefix}{key_str}")
                self._print_dict(value, indent + 1)
            elif isinstance(value, list):
                print(f"{prefix}{key_str}")
                self._print_list(value, indent + 1)
            else:
                print(f"{prefix}{key_str} {value}")
    
    def _print_list(self, lst: list, indent: int = 0):
        """Pretty print a list."""
        prefix = "  " * indent
        for item in lst:
            if isinstance(item, dict):
                print(f"{prefix}-")
                self._print_dict(item, indent + 1)
            else:
                print(f"{prefix}- {item}")
    
    def table(self, headers: list, rows: list, title: str = None):
        """
        Print data as a table.
        
        Args:
            headers: Column headers
            rows: List of row data (lists or tuples)
            title: Optional table title
        """
        if self.quiet:
            return
            
        if self.json_output:
            # Convert to list of dicts
            data = [dict(zip(headers, row)) for row in rows]
            output = {"status": "data", "data": data}
            if title:
                output["title"] = title
            print(json.dumps(output, indent=2, default=str))
            return
        
        if not rows:
            print("No data to display.")
            return
        
        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        
        # Print title
        if title:
            print(f"\n{self._colorize(title, 'bold')}")
        
        # Print header
        header_row = " | ".join(
            self._colorize(h.ljust(widths[i]), 'bold') 
            for i, h in enumerate(headers)
        )
        print(header_row)
        print("-+-".join("-" * w for w in widths))
        
        # Print rows
        for row in rows:
            row_str = " | ".join(
                str(cell).ljust(widths[i]) 
                for i, cell in enumerate(row)
            )
            print(row_str)
    
    def progress(self, message: str, current: int = None, total: int = None):
        """
        Print progress message (overwrites current line).
        
        Args:
            message: Progress message
            current: Current progress value
            total: Total progress value
        """
        if self.quiet or self.json_output:
            return
        
        if current is not None and total is not None:
            pct = (current / total) * 100 if total > 0 else 0
            msg = f"\r{message}: {current}/{total} ({pct:.1f}%)"
        else:
            msg = f"\r{message}"
        
        print(msg, end='', flush=True)
    
    def progress_done(self):
        """Complete progress output with newline."""
        if not self.quiet and not self.json_output:
            print()  # Newline after progress
    
    def confirm(self, message: str, default: bool = False) -> bool:
        """
        Ask for user confirmation.
        
        Args:
            message: Confirmation prompt
            default: Default response if user just presses Enter
            
        Returns:
            True if confirmed, False otherwise
        """
        if self.json_output:
            # Can't prompt in JSON mode, use default
            return default
        
        suffix = " [Y/n]" if default else " [y/N]"
        response = input(f"{message}{suffix} ").strip().lower()
        
        if not response:
            return default
        
        return response in ('y', 'yes')


# Global output instance with default settings
output = CLIOutput()


def configure_output(color: bool = None, quiet: bool = False, json_output: bool = False):
    """
    Configure the global output instance.
    
    Args:
        color: Force color on/off (None = auto-detect)
        quiet: Suppress non-error output
        json_output: Output in JSON format
    """
    global output
    output = CLIOutput(color=color, quiet=quiet, json_output=json_output)
