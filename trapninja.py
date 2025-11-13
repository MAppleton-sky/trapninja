#!/usr/bin/env python3
"""
TrapNinja - SNMP Trap Forwarder - eBPF Enhanced Version

A daemon service that listens for SNMP traps on specified UDP ports,
filters them based on configured rules, and forwards them to
designated destinations. This implementation includes eBPF acceleration
for high-performance, low-CPU usage packet processing.

Performance enhancements:
- eBPF kernel-space packet filtering and processing
- Asynchronous packet processing with worker threads
- Memory pool for packet buffers
- Efficient configuration loading
- Caching for expensive operations
- Optimized data structures for lookups
- Improved thread management
"""

__version__ = '0.4.0'
__author__ = 'Matthew Appleton'

import sys
import os
import time
import argparse


def display_banner():
    """Display TrapNinja banner"""
    banner = """
  _____                _   _ _       _       
 |_   _| __ __ _ _ __ | \ | (_)_ __ (_) __ _ 
   | || '__/ _` | '_ \|  \| | | '_ \| |/ _` |
   | || | | (_| | |_) | |\  | | | | | | (_| |
   |_||_|  \__,_| .__/|_| \_|_|_| |_| |\__,_|
                |_|               |___|
                         
         v{} - eBPF Enhanced SNMP Trap Forwarder
    """.format(__version__)
    print(banner)


def check_ebpf_support():
    """
    Check if eBPF is supported on this system

    Returns:
        tuple: (supported, error_message)
    """
    try:
        # Check if running as root (required for eBPF)
        if os.geteuid() != 0:
            return False, "eBPF acceleration requires root privileges"

        # Add BCC installation path for cmake-built installations
        BCC_PATHS = [
            '/usr/lib/python3.9/site-packages',
            '/usr/lib64/python3.9/site-packages',
            '/usr/local/lib/python{}.{}/site-packages'.format(
                sys.version_info.major, sys.version_info.minor
            ),
            '/usr/lib64/python{}.{}/site-packages'.format(
                sys.version_info.major, sys.version_info.minor
            ),
        ]

        for path in BCC_PATHS:
            if os.path.exists(path) and path not in sys.path:
                sys.path.insert(0, path)

        # Try to import BCC
        try:
            from bcc import BPF
        except ImportError:
            return False, "BCC (BPF Compiler Collection) not installed"
        except AttributeError as e:
            return False, f"BCC version mismatch with system libraries: {e}"
        except Exception as e:
            return False, f"Error checking eBPF support: {e}"

        # Check kernel version
        import platform
        kernel_version = platform.release().split("-")[0]
        major, minor = map(int, kernel_version.split(".")[:2])

        if major < 4 or (major == 4 and minor < 4):
            return False, f"Kernel {kernel_version} does not fully support eBPF (4.4+ required)"

        return True, "eBPF support available"
    except Exception as e:
        return False, f"Error checking eBPF support: {e}"


def display_ebpf_status():
    """Display eBPF support status"""
    supported, message = check_ebpf_support()

    if supported:
        print("\033[92m[✓] eBPF acceleration available\033[0m")
    else:
        print("\033[93m[!] eBPF acceleration not available:\033[0m", message)
        print("    Run 'sudo ./install_ebpf_deps.sh' to install required dependencies")
        print("    You can still use TrapNinja without eBPF, but with higher CPU usage")

    print("")


def main():
    """
    Main entry point with enhanced startup logic
    and better exception handling

    Returns:
        int: Exit code
    """
    # Display banner
    display_banner()

    # Check for eBPF support
    display_ebpf_status()

    # Import just once at the start for better performance
    from trapninja.main import main as main_entry

    # Try to run with optimized bytecode
    if not sys.flags.optimize:
        print("Note: For best performance, run with python -O")

    try:
        # Start the application
        start_time = time.time()
        result = main_entry()
        elapsed = time.time() - start_time
        print(f"TrapNinja execution completed in {elapsed:.2f} seconds")
        return result
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt")
        return 1
    except Exception as e:
        print(f"Error during execution: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())