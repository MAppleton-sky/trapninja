#!/usr/bin/env python3
"""
TrapNinja Parser Base Components

Shared components used across all parser modules:
- Custom help formatters for consistent CLI output
- Validation type converters for argparse
- Custom ArgumentParser with improved error handling
- Global options shared across all commands
"""

import argparse
import sys

from ..validation import InputValidator


# =============================================================================
# Custom Help Formatters
# =============================================================================

class TrapNinjaHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter that provides cleaner, more organized help output."""

    def __init__(self, prog, indent_increment=2, max_help_position=30, width=100):
        super().__init__(prog, indent_increment, max_help_position, width)

    def _format_action_invocation(self, action):
        """Format action invocation more cleanly."""
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = action.option_strings
            if action.nargs == 0:
                return ', '.join(parts)
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)
                return ', '.join(parts) + ' ' + args_string


class TrapNinjaRootHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Formatter for the root parser that shows command categories."""

    def __init__(self, prog, indent_increment=2, max_help_position=40, width=100):
        super().__init__(prog, indent_increment, max_help_position, width)


# =============================================================================
# Validation Type Converters
# =============================================================================

def validated_ip(value: str) -> str:
    """Validate and return IP address or raise ArgumentTypeError."""
    result = InputValidator.validate_ip(value)
    if result is None:
        raise argparse.ArgumentTypeError(f"Invalid IP address: '{value}'")
    return result


def validated_oid(value: str) -> str:
    """Validate and return OID or raise ArgumentTypeError."""
    result = InputValidator.validate_oid(value)
    if result is None:
        raise argparse.ArgumentTypeError(f"Invalid OID format: '{value}'")
    return result


def validated_tag(value: str) -> str:
    """Validate and return tag or raise ArgumentTypeError."""
    result = InputValidator.validate_tag(value)
    if result is None:
        raise argparse.ArgumentTypeError(
            f"Invalid tag: '{value}' (use alphanumeric and underscores only)"
        )
    return result


def validated_port(value: str) -> int:
    """Validate and return port number or raise ArgumentTypeError."""
    result = InputValidator.validate_port(value)
    if result is None:
        raise argparse.ArgumentTypeError(f"Invalid port: '{value}' (must be 1-65535)")
    return result


# =============================================================================
# Custom ArgumentParser
# =============================================================================

class TrapNinjaArgumentParser(argparse.ArgumentParser):
    """
    Custom ArgumentParser with improved error messages.

    Provides:
    - Clear, actionable error messages
    - Suggestions for correct usage
    - Category-aware help hints
    """

    def __init__(self, *args, command_category: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.command_category = command_category

    def error(self, message: str):
        """Override error handling to provide clearer messages."""
        sys.stderr.write('\n')
        sys.stderr.write(f'\033[91mError:\033[0m {message}\n')
        sys.stderr.write('\n')

        # Provide helpful hints based on the error
        if 'required' in message.lower() and 'argument' in message.lower():
            if self.command_category:
                sys.stderr.write(
                    f'  Run \033[93mtrapninja {self.command_category} --help\033[0m'
                    f' for available commands.\n'
                )
            else:
                sys.stderr.write(
                    '  Run \033[93mtrapninja --help\033[0m to see available'
                    ' command categories.\n'
                )
        elif 'invalid choice' in message.lower():
            sys.stderr.write(
                '  Run \033[93mtrapninja --help\033[0m to see valid commands.\n'
            )
        elif 'unrecognized arguments' in message.lower():
            sys.stderr.write('  Check the command syntax and required parameters.\n')
            if self.command_category:
                sys.stderr.write(
                    f'  Run \033[93mtrapninja {self.command_category} --help\033[0m'
                    f' for details.\n'
                )

        sys.stderr.write('\n')
        sys.exit(2)

    def format_help(self):
        """Format help with additional context."""
        return super().format_help()


# =============================================================================
# Global Options
# =============================================================================

def add_global_options(parser: argparse.ArgumentParser):
    """Add global options available to all commands."""
    global_group = parser.add_argument_group('Global Options')

    global_group.add_argument('--config-dir', type=str, metavar='PATH',
                              help='Configuration directory path')
    global_group.add_argument('--log-file', type=str, metavar='PATH',
                              help='Log file path')
    global_group.add_argument('--pid-file', type=str, metavar='PATH',
                              help='PID file path')
    global_group.add_argument('--debug', action='store_true',
                              help='Enable debug mode with verbose logging')
    global_group.add_argument('--json', action='store_true',
                              help='Output in JSON format')
    global_group.add_argument('--yes', '-y', action='store_true',
                              help='Skip confirmation prompts')
    global_group.add_argument('--verbose', action='store_true',
                              help='Verbose output')
