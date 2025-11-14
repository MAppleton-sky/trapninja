#!/usr/bin/env python3
"""
TrapNinja - SNMP Trap Forwarder - Main Entry Point

A daemon service that listens for SNMP traps on specified UDP ports,
filters them based on configured rules, and forwards them to
designated destinations.

This entry point provides:
- eBPF acceleration detection and graceful fallback
- Enhanced startup checks and system compatibility verification
- Feature detection and reporting
- Performance monitoring and optimization hints
- Improved error handling and user guidance
"""

import sys
import os
import time

# Import version information from single source of truth
from trapninja.__version__ import (
    __version__,
    __author__,
    has_feature,
    get_available_features,
    get_version_banner
)


def display_banner():
    """Display TrapNinja banner with version and feature information"""
    print(get_version_banner())


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
        
        # Add BCC installation paths for cmake-built installations
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
        try:
            major, minor = map(int, kernel_version.split(".")[:2])
        except ValueError:
            return False, f"Could not parse kernel version: {kernel_version}"
        
        if major < 4 or (major == 4 and minor < 4):
            return False, f"Kernel {kernel_version} does not fully support eBPF (4.4+ required)"
        
        return True, "eBPF support available"
    except Exception as e:
        return False, f"Error checking eBPF support: {e}"


def display_ebpf_status():
    """Display eBPF support status and guidance"""
    # Check if eBPF feature is enabled in this version
    if not has_feature('ebpf'):
        print("\033[93m[i] eBPF feature not included in this version\033[0m")
        print("")
        return
    
    supported, message = check_ebpf_support()
    
    if supported:
        print("\033[92m[✓] eBPF acceleration available\033[0m")
    else:
        print("\033[93m[!] eBPF acceleration not available:\033[0m", message)
        print("    Run 'sudo ./install_ebpf_deps.sh' to install required dependencies")
        print("    You can still use TrapNinja without eBPF, but with higher CPU usage")
    
    print("")


def display_feature_status():
    """Display status of available features"""
    features = get_available_features()
    
    # Group features by category
    core_features = ['basic_forwarding', 'filtering', 'multi_port', 'metrics']
    advanced_features = ['ebpf', 'ha', 'snmpv3', 'cli_v2']
    
    print("Feature Status:")
    print("  Core Features:")
    for feature in core_features:
        if feature in features and features[feature]:
            status = "\033[92m✓\033[0m"
        else:
            status = "\033[91m✗\033[0m"
        feature_name = feature.replace('_', ' ').title()
        print(f"    {status} {feature_name}")
    
    print("  Advanced Features:")
    for feature in advanced_features:
        if feature in features and features[feature]:
            status = "\033[92m✓\033[0m"
        else:
            status = "\033[91m✗\033[0m"
        feature_name = feature.replace('_', ' ').title()
        if feature == 'ha':
            feature_name = 'High Availability'
        elif feature == 'snmpv3':
            feature_name = 'SNMPv3 Decryption'
        elif feature == 'cli_v2':
            feature_name = 'CLI v2 (Modular)'
        print(f"    {status} {feature_name}")
    
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
    
    # Display feature status
    display_feature_status()
    
    # Check for eBPF support if available
    display_ebpf_status()
    
    # Import main entry point
    from trapninja.main import main as main_entry
    
    # Optimization hint
    if not sys.flags.optimize:
        print("\033[93m[i] For best performance, run with: python -O trapninja.py\033[0m")
        print("")
    
    try:
        # Start the application
        start_time = time.time()
        result = main_entry()
        elapsed = time.time() - start_time
        
        print(f"\n\033[92mTrapNinja execution completed in {elapsed:.2f} seconds\033[0m")
        return result
        
    except KeyboardInterrupt:
        print("\n\033[93mExiting due to keyboard interrupt\033[0m")
        return 1
        
    except Exception as e:
        print(f"\n\033[91mError during execution: {e}\033[0m")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
