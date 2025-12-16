#!/usr/bin/env python3
"""
TrapNinja - SNMP Trap Forwarder - Main Module (Refactored)

This version provides a clean entry point with modular CLI command handling.
All command implementations are organized in the cli/ subdirectory for better
maintainability and testing.

Architecture:
    - cli/parser.py: Argument parsing setup
    - cli/validation.py: Input validation and sanitization
    - cli/daemon_commands.py: Daemon control (start, stop, status)
    - cli/filtering_commands.py: IP and OID filtering
    - cli/ha_commands.py: High Availability configuration
    - cli/executor.py: Command orchestration
"""

import sys
import argparse

from .cli import create_argument_parser, execute_command


def main() -> int:
    """
    Main entry point with clean separation of concerns

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    try:
        # Create argument parser
        parser = create_argument_parser()

        # Parse arguments
        try:
            args = parser.parse_args()
        except argparse.ArgumentTypeError as e:
            print(f"Argument validation error: {e}")
            return 1

        # Execute the requested command
        return execute_command(args)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
