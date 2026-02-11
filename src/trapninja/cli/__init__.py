#!/usr/bin/env python3
"""
TrapNinja CLI Module

Provides command-line interface functionality organized by concern:
- parsers/      Modular argument parser definitions (per command category)
- daemon_commands: Service control (start, stop, restart, status)
- filtering_commands: IP and OID blocking/unblocking
- ha_commands: High Availability configuration
- validation: Input validation and sanitization
"""

__all__ = [
    'create_argument_parser',
    'execute_command',
    'InputValidator',
    'parse_size',
]

from .parsers import create_argument_parser
from .validation import InputValidator, parse_size
from .executor import execute_command
