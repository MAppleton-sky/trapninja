#!/usr/bin/env python3
"""
TrapNinja CLI Module

Provides command-line interface functionality organized by concern:
- daemon_commands: Service control (start, stop, restart, status)
- filtering_commands: IP and OID blocking/unblocking
- ha_commands: High Availability configuration
- parser: Argument parsing setup
- validation: Input validation and sanitization
"""

__all__ = [
    'create_argument_parser',
    'execute_command',
    'InputValidator',
    'parse_size',
]

from .parser import create_argument_parser
from .validation import InputValidator, parse_size
from .executor import execute_command
