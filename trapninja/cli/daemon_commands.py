#!/usr/bin/env python3
"""
TrapNinja Daemon Commands Module

Handles daemon control operations (start, stop, restart, status) via command-line interface.
"""

from ..daemon import start_daemon, stop_daemon, restart_daemon, status_daemon, run_foreground_daemon


def start() -> int:
    """
    Start the TrapNinja daemon

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print("Starting TrapNinja daemon with HA support...")
    return start_daemon()


def stop() -> int:
    """
    Stop the TrapNinja daemon

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    return stop_daemon()


def restart() -> int:
    """
    Restart the TrapNinja daemon

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print("Restarting TrapNinja daemon with HA support...")
    return restart_daemon()


def status() -> int:
    """
    Check TrapNinja daemon status

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    return status_daemon()


def run_foreground(debug: bool = False) -> int:
    """
    Run TrapNinja in foreground mode

    Args:
        debug: Enable debug logging

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print("Running TrapNinja in foreground with HA support...")
    if debug:
        print("Debug mode enabled")
    return run_foreground_daemon(debug=debug)
