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


def run_foreground(debug: bool = False, shadow_mode: bool = False, 
                   mirror_mode: bool = False, parallel: bool = False,
                   capture_mode: str = None, log_traps: str = None) -> int:
    """
    Run TrapNinja in foreground mode

    Args:
        debug: Enable debug logging
        shadow_mode: Run in shadow mode (observe only, no forwarding)
        mirror_mode: Run in mirror mode (parallel capture and forward)
        parallel: Enable parallel operation (sniff capture)
        capture_mode: Force capture mode (auto, sniff, socket)
        log_traps: Log all observed traps to file

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print("Running TrapNinja in foreground with HA support...")
    
    if shadow_mode:
        print("Shadow mode: ENABLED (observe only, no forwarding)")
        print("Using sniff capture to run alongside existing trap receivers")
    elif mirror_mode:
        print("Mirror mode: ENABLED (parallel capture and forward)")
        print("Using sniff capture to run alongside existing trap receivers")
    elif parallel:
        print("Parallel mode: ENABLED (sniff capture for coexistence)")
    
    if capture_mode:
        print(f"Capture mode: {capture_mode.upper()}")
    
    if log_traps:
        print(f"Logging all traps to: {log_traps}")
    
    if debug:
        print("Debug mode enabled")
    
    return run_foreground_daemon(
        debug=debug, 
        shadow_mode=shadow_mode,
        mirror_mode=mirror_mode,
        parallel=parallel,
        capture_mode=capture_mode,
        log_traps=log_traps
    )
