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


def _build_process_check_cmd(own_pid: int) -> str:
    """
    Build the ps command to find running TrapNinja processes.
    
    Excludes:
    - grep itself
    - CLI commands (--start, --restart, --stop, --status)
    - The calling process (own_pid)
    
    Args:
        own_pid: PID of the calling process to exclude
        
    Returns:
        Shell command string for finding TrapNinja daemon processes
    """
    return (
        f"ps aux | grep -i 'trapninja\\|trapNinja' | grep -v grep "
        f"| grep -v '\\-\\-start' | grep -v '\\-\\-restart' "
        f"| grep -v '\\-\\-stop' | grep -v '\\-\\-status' "
        f"| grep -v \" {own_pid} \""
    )


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
    Start the daemon process with startup verification.
    
    After spawning the daemon, waits briefly and verifies it started
    successfully by checking the control socket.

    Returns:
        int: 0 on success, non-zero on failure
    """
    # Get our own PID to exclude from the check
    own_pid = os.getpid()

    # Check for running instances, excluding our own process and CLI commands
    cmd = _build_process_check_cmd(own_pid)
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
        # Build the command using --foreground-daemon (hidden arg for daemon mode)
        script_path = os.path.abspath(sys.argv[0])
        args = [sys.executable, script_path, "--foreground-daemon"]

        # Daemon control arguments that should NOT be passed to the subprocess
        # These are mutually exclusive with --foreground-daemon and would cause crashes
        DAEMON_CONTROL_ARGS = {
            '--start', '--stop', '--restart', '--status', '--foreground',
            '--foreground-daemon'
        }

        # Copy runtime configuration arguments, filtering out daemon control commands
        for arg in sys.argv[1:]:
            if arg not in DAEMON_CONTROL_ARGS:
                args.append(arg)

        # Python 3.6 compatible way to start detached process
        if os.name == 'posix':  # Unix/Linux/MacOS
            # Use DEVNULL for clean file handle management
            # Note: subprocess.DEVNULL properly handles the file descriptor
            daemon_process = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid,  # Create new session (detach from parent)
                close_fds=True  # Close inherited file descriptors
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

        print(f"Daemon process spawned with PID {daemon_pid}")
        
        # Verify daemon started successfully
        print("Verifying daemon startup...")
        if _verify_daemon_started(daemon_pid, timeout=15):
            print(f"✓ TrapNinja daemon started successfully with PID {daemon_pid}")
            return 0
        else:
            print(f"✗ Daemon may not have started correctly. Check logs at {LOG_FILE}")
            return 1

    except Exception as e:
        print(f"Error starting daemon: {e}")
        # Clean up in case of failure
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except:
                pass
        return 1


def _verify_daemon_started(pid: int, timeout: int = 15) -> bool:
    """
    Verify the daemon started successfully.
    
    Checks:
    1. Process is still running
    2. Control socket responds to ping
    3. Logs file shows successful initialization
    
    Args:
        pid: Daemon process ID
        timeout: Maximum seconds to wait (default 15 for complex setups)
        
    Returns:
        True if daemon started successfully
    """
    import time
    from .control import ControlSocket
    
    start_time = time.time()
    last_status = ""
    socket_attempts = 0
    
    # Give daemon a moment to initialize
    time.sleep(1.5)
    
    while time.time() - start_time < timeout:
        # Check process is still running
        try:
            os.kill(pid, 0)
        except OSError:
            # Process died - try to get info from log file
            print(f"  Daemon process {pid} exited unexpectedly")
            _show_daemon_crash_info()
            return False
        
        # Try to ping control socket
        try:
            socket_attempts += 1
            response = ControlSocket.send_command('ping', timeout=2.0)
            if response.get('status') == ControlSocket.SUCCESS:
                return True
            # Got response but not success - log it
            new_status = f"Got response: {response.get('status')}"
            if new_status != last_status:
                print(f"  {new_status}")
                last_status = new_status
        except ConnectionRefusedError:
            # Control socket not ready yet - this is normal during startup
            if socket_attempts == 5:  # Only show once
                print(f"  Waiting for control socket...")
        except FileNotFoundError:
            # Socket file doesn't exist yet
            pass
        except Exception as e:
            # Log unexpected errors after a few attempts
            if socket_attempts > 3:
                new_status = f"Socket error: {type(e).__name__}"
                if new_status != last_status:
                    print(f"  {new_status}")
                    last_status = new_status
        
        time.sleep(0.5)
    
    # Timeout reached - check if process at least exists
    try:
        os.kill(pid, 0)
        # Process exists but control socket not responding
        print(f"  Warning: Control socket not responding after {timeout}s, but process {pid} is running")
        print(f"  Daemon may still be initializing (complex HA/cache setup).")
        print(f"  Check status with: --status")
        print(f"  Check logs at: {LOG_FILE}")
        return True  # Give benefit of the doubt
    except OSError:
        print(f"  Daemon process {pid} died during startup")
        _show_daemon_crash_info()
        return False


def _show_daemon_crash_info():
    """
    Show relevant information when daemon crashes during startup.
    Reads the last few lines of the log file for context.
    """
    if os.path.exists(LOG_FILE):
        try:
            print(f"\n  Recent log entries from {LOG_FILE}:")
            with open(LOG_FILE, 'r') as f:
                # Read last 1KB of file
                f.seek(0, 2)  # Go to end
                size = f.tell()
                f.seek(max(0, size - 2048))  # Go back up to 2KB
                lines = f.read().splitlines()
                # Show last 10 lines
                for line in lines[-10:]:
                    print(f"    {line}")
        except Exception as e:
            print(f"  Could not read log file: {e}")
    else:
        print(f"  Log file not found: {LOG_FILE}")
        print(f"  Check if daemon has write access to log directory")


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

    # Find all running instances, excluding our own stop command and other CLI commands
    cmd = _build_process_check_cmd(own_pid)
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
    remaining = run_command_safe(_build_process_check_cmd(own_pid))

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
        processes = run_command_safe(_build_process_check_cmd(own_pid))

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
            processes = run_command_safe(_build_process_check_cmd(own_pid))

            if processes:
                print("\nHowever, TrapNinja appears to be running with a different PID:")
                print(processes)
                return 0
            return 1
    except Exception as e:
        print(f"Error checking status: {e}")
        print("Checking for running processes anyway...")
        processes = run_command_safe(_build_process_check_cmd(own_pid))

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