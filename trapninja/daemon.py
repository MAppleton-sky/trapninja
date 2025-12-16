#!/usr/bin/env python3
"""
TrapNinja Daemon Module - Python 3.6 Compatible Version

Handles daemon control operations (start, stop, status, restart).
Fixed to ensure Python 3.6 compatibility by avoiding subprocess.run() with capture_output parameter.
"""
import os
import sys
import time
import signal
import logging
import subprocess

from .config import PID_FILE, LOG_FILE, ensure_config_dir
from .service import run_service

# Get logger instance
logger = logging.getLogger("trapninja")


def run_command_safe(command, timeout=30):
    """
    Run a command safely with Python 3.6 compatibility

    Args:
        command (str): Command to run
        timeout (int): Timeout in seconds

    Returns:
        str: Command output
    """
    try:
        # Use Popen instead of subprocess.run for Python 3.6 compatibility
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = process.communicate(timeout=timeout)
        return stdout.strip()
    except subprocess.TimeoutExpired:
        process.kill()
        return ""
    except Exception:
        return ""


def start_daemon():
    """
    Start the daemon process - Python 3.6 compatible version

    Returns:
        int: 0 on success, non-zero on failure
    """
    # Get our own PID to exclude from the check
    own_pid = os.getpid()

    # Check for running instances, excluding our own process
    cmd = f"ps aux | grep -i 'trapninja\\|trapNinja' | grep -v grep | grep -v \" {own_pid} \" | grep -v \"grep\""
    processes = run_command_safe(cmd)

    if processes:
        print("TrapNinja appears to be already running:")
        print(processes)

        # Check if PID file exists
        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE, 'r') as f:
                    pid = int(f.read().strip())
                print(f"PID file indicates instance running with PID {pid}")
            except (ValueError, IOError) as e:
                print(f"Error reading PID file: {e}")
        else:
            print("No PID file found but process is running. Possible orphaned process.")

        print("\nUse --stop before starting a new instance, or --restart to restart.")
        return 1

    # If PID file exists but no process is running
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            # Try to check if the process is running
            try:
                os.kill(pid, 0)
                # Double-check this isn't our own process
                if pid != own_pid:
                    print(f"TrapNinja is already running with PID {pid}")
                    return 1
            except OSError:
                # Process not running - remove stale PID file
                os.remove(PID_FILE)
                print("Stale PID file removed")
        except (ValueError, IOError):
            # PID file is invalid
            try:
                os.remove(PID_FILE)
                print("Invalid PID file removed")
            except:
                pass

    print("Starting TrapNinja daemon...")

    # Set up logging before daemonizing
    from .logger import setup_logging
    setup_logging(console=False)

    # Ensure config directory exists
    ensure_config_dir()

    # Create a subprocess that will run independently
    try:
        # Build the command without the --start argument
        script_path = os.path.abspath(sys.argv[0])
        args = [sys.executable, script_path, "--foreground"]

        # Copy any other arguments except --start
        for arg in sys.argv[1:]:
            if arg != "--start" and arg != "--foreground":
                args.append(arg)

        # Python 3.6 compatible way to start detached process
        if os.name == 'posix':  # Unix/Linux/MacOS
            # Create null file objects for stdin/stdout/stderr
            devnull = open(os.devnull, 'w')

            daemon_process = subprocess.Popen(
                args,
                stdout=devnull,
                stderr=devnull,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid  # Create new session (detach from parent)
            )
        else:  # Windows
            daemon_process = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )

        # Write the daemon process PID to the file
        daemon_pid = daemon_process.pid
        with open(PID_FILE, 'w') as f:
            f.write(str(daemon_pid))

        print(f"TrapNinja daemon started successfully with PID {daemon_pid}")
        return 0

    except Exception as e:
        print(f"Error starting daemon: {e}")
        # Clean up in case of failure
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except:
                pass
        return 1


def stop_daemon():
    """
    Stop the daemon process - Python 3.6 compatible version

    Returns:
        int: 0 on success, non-zero on failure
    """
    # Get our own PID to exclude from the check
    own_pid = os.getpid()

    # Check for PID file
    pid_from_file = None
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid_from_file = int(f.read().strip())
            print(f"Found PID file with PID: {pid_from_file}")
        except (ValueError, IOError) as e:
            print(f"Error reading PID file: {e}")
            if os.path.exists(PID_FILE):
                try:
                    os.remove(PID_FILE)
                    print("Removed invalid PID file")
                except:
                    pass
    else:
        print("No PID file found")

    # Find all running instances, excluding our own stop command
    cmd = f"ps aux | grep -i 'trapninja\\|trapNinja' | grep -v grep | grep -v '\\-\\-status' | grep -v '\\-\\-stop' | grep -v \" {own_pid} \""
    processes = run_command_safe(cmd)

    if not processes:
        print("No TrapNinja processes found running")
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
                print("Removed stale PID file")
            except:
                pass
        return 0

    print("Found running TrapNinja processes:")
    print(processes)

    # Process the ps output to get PIDs
    pids = []
    for line in processes.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) > 1:
                try:
                    pid = int(parts[1])
                    # Make sure we're not trying to kill our own process
                    if pid != own_pid:
                        pids.append(pid)
                except ValueError:
                    continue

    if not pids:
        print("No TrapNinja processes to stop")
        return 0

    print(f"Attempting to stop {len(pids)} TrapNinja processes")

    # Try to stop each process
    for pid in pids:
        try:
            # First try SIGTERM for graceful shutdown
            print(f"Sending SIGTERM to process {pid}...")
            os.kill(pid, signal.SIGTERM)

            # Wait for process to terminate
            max_wait = 10  # seconds
            terminated = False
            for _ in range(max_wait):
                try:
                    # Check if process still exists
                    os.kill(pid, 0)
                    time.sleep(1)
                except OSError:
                    # Process is gone
                    print(f"Process {pid} stopped successfully")
                    terminated = True
                    break

            # If process didn't terminate gracefully, use SIGKILL
            if not terminated:
                print(f"Process {pid} did not stop gracefully, sending SIGKILL...")
                try:
                    os.kill(pid, signal.SIGKILL)
                    print(f"Process {pid} forcefully terminated")
                except OSError:
                    print(f"Process {pid} already terminated")
        except OSError as e:
            print(f"Error stopping process {pid}: {e}")

    # Clean up PID file
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
            print("Removed PID file")
        except:
            pass

    # Verify all processes are stopped
    time.sleep(1)
    cmd = f"ps aux | grep -i 'trapninja\\|trapNinja' | grep -v grep | grep -v '\\-\\-status' | grep -v '\\-\\-stop' | grep -v \" {own_pid} \""
    remaining = run_command_safe(cmd)

    if remaining:
        print("\nWARNING: Some TrapNinja processes may still be running:")
        print(remaining)
        return 1
    else:
        print("All TrapNinja processes have been stopped")
        return 0


def status_daemon():
    """
    Check the status of the daemon - Python 3.6 compatible version

    Returns:
        int: 0 if running, 1 if not running, 2 on error
    """
    # Get our own PID to exclude from the check
    own_pid = os.getpid()

    # First check for PID file
    if not os.path.exists(PID_FILE):
        # No PID file, but check for running processes anyway
        cmd = f"ps aux | grep -i 'trapninja\\|trapNinja' | grep -v grep | grep -v \" {own_pid} \" | grep -v \"\\-\\-status\" | grep -v \"\\-\\-stop\" | grep -v \"\\-\\-start\""
        processes = run_command_safe(cmd)

        if processes:
            print("TrapNinja appears to be running but PID file is missing:")
            print(processes)
            return 0
        else:
            print("TrapNinja is not running")
            return 1

    try:
        # Read PID from file
        with open(PID_FILE, 'r') as f:
            pid_str = f.read().strip()
            try:
                pid = int(pid_str)
            except ValueError:
                print(f"Invalid PID in PID file: '{pid_str}'")
                print("Removing corrupted PID file")
                try:
                    os.remove(PID_FILE)
                except:
                    pass
                return 2

        # Check if process is running
        try:
            os.kill(pid, 0)
            print(f"TrapNinja is running with PID {pid}")

            # Get the command line of the process
            cmd_line = run_command_safe(f"ps -p {pid} -o command=")
            if cmd_line:
                print(f"Process command line: {cmd_line}")

            # Show additional status info
            uptime = run_command_safe(f"ps -o etime= -p {pid}")
            if uptime:
                print(f"Uptime: {uptime}")

            # Check for log file and show recent entries
            if os.path.exists(LOG_FILE):
                print("\nRecent log entries:")
                try:
                    # Python 3.6 compatible way to show recent log entries
                    with subprocess.Popen(['tail', '-n', '5', LOG_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          universal_newlines=True) as proc:
                        stdout, stderr = proc.communicate()
                        if stdout:
                            print(stdout)
                except:
                    print("Could not read recent log entries")
            else:
                print(f"\nWARNING: Log file {LOG_FILE} not found")

            return 0

        except OSError:
            print("TrapNinja is not running (stale PID file)")
            try:
                os.remove(PID_FILE)
                print("Removed stale PID file")
            except:
                pass

            # Check if it's running under a different PID
            cmd = f"ps aux | grep -i 'trapninja\\|trapNinja' | grep -v grep | grep -v \" {own_pid} \" | grep -v \"\\-\\-status\" | grep -v \"\\-\\-stop\" | grep -v \"\\-\\-start\""
            processes = run_command_safe(cmd)

            if processes:
                print("\nHowever, TrapNinja appears to be running with a different PID:")
                print(processes)
                return 0
            return 1
    except Exception as e:
        print(f"Error checking status: {e}")
        print("Checking for running processes anyway...")
        cmd = f"ps aux | grep -i 'trapninja\\|trapNinja' | grep -v grep | grep -v \" {own_pid} \" | grep -v \"\\-\\-status\" | grep -v \"\\-\\-stop\" | grep -v \"\\-\\-start\""
        processes = run_command_safe(cmd)

        if processes:
            print("TrapNinja appears to be running:")
            print(processes)
            return 0
        return 2


def restart_daemon():
    """
    Restart the daemon

    Returns:
        int: 0 on success, non-zero on failure
    """
    stop_result = stop_daemon()
    time.sleep(2)  # Give it a moment to fully shut down
    start_result = start_daemon()

    return 0 if (stop_result == 0 and start_result == 0) else 1


def run_foreground_daemon(debug=False, shadow_mode=False, mirror_mode=False,
                          parallel=False, capture_mode=None, log_traps=None):
    """
    Run the daemon in foreground mode

    Args:
        debug (bool): Whether to run in debug mode with more verbose logging
        shadow_mode (bool): Observe only mode (no forwarding)
        mirror_mode (bool): Parallel capture and forward mode
        parallel (bool): Enable sniff capture for coexistence
        capture_mode (str): Force capture mode (auto, sniff, socket)
        log_traps (str): Log all traps to this file

    Returns:
        int: Exit code from the service
    """
    from .logger import setup_logging

    # Set up logging with console output
    setup_logging(console=True)
    ensure_config_dir()

    # Run directly (not as daemon)
    return run_service(
        debug=debug,
        shadow_mode=shadow_mode,
        mirror_mode=mirror_mode,
        parallel=parallel,
        capture_mode=capture_mode,
        log_traps=log_traps
    )