#!/usr/bin/env python3
"""
BCC Location Finder for RHEL 8

The python3-bcc package on RHEL 8 installs to non-standard locations.
This script finds where BCC is actually installed.
"""

import subprocess
import os
import sys

print("=" * 60)
print(" Finding BCC Python module location on RHEL 8")
print("=" * 60)

# Method 1: Use rpm to find where python3-bcc installed files
print("\n[1] Checking rpm -ql python3-bcc...")
try:
    result = subprocess.run(['rpm', '-ql', 'python3-bcc'], capture_output=True, text=True)
    if result.returncode == 0:
        files = result.stdout.strip().split('\n')
        python_files = [f for f in files if '.py' in f or 'site-packages' in f]
        print(f"    Found {len(python_files)} Python-related files:")
        
        # Find the site-packages directory
        site_packages = set()
        for f in files:
            if 'site-packages/bcc' in f:
                # Extract the site-packages path
                idx = f.find('site-packages')
                if idx > 0:
                    site_packages.add(f[:idx + len('site-packages')])
        
        for sp in site_packages:
            print(f"    \033[92mBCC installed at: {sp}/bcc\033[0m")
        
        # Show first few files
        for f in python_files[:10]:
            print(f"      {f}")
        if len(python_files) > 10:
            print(f"      ... and {len(python_files) - 10} more files")
    else:
        print(f"    Error: {result.stderr}")
except Exception as e:
    print(f"    Error: {e}")

# Method 2: Search common RHEL 8 locations
print("\n[2] Searching common RHEL 8 BCC locations...")
rhel8_paths = [
    '/usr/lib/python3.6/site-packages',
    '/usr/lib64/python3.6/site-packages', 
    '/usr/lib/python3/dist-packages',
    '/usr/lib64/python3/dist-packages',
    '/usr/lib/python3.8/site-packages',
    '/usr/lib64/python3.8/site-packages',
]

found_paths = []
for path in rhel8_paths:
    bcc_path = os.path.join(path, 'bcc')
    if os.path.exists(bcc_path):
        print(f"    \033[92mFound: {bcc_path}\033[0m")
        found_paths.append(path)
    else:
        print(f"    Not at: {path}")

# Method 3: Use find command
print("\n[3] Using find command to locate bcc/__init__.py...")
try:
    result = subprocess.run(
        ['find', '/usr', '-name', '__init__.py', '-path', '*/bcc/*', '-type', 'f'],
        capture_output=True, text=True, timeout=30
    )
    if result.stdout.strip():
        for init_file in result.stdout.strip().split('\n'):
            bcc_dir = os.path.dirname(init_file)
            site_pkg = os.path.dirname(bcc_dir)
            print(f"    \033[92mFound: {bcc_dir}\033[0m")
            print(f"    Site-packages: {site_pkg}")
            if site_pkg not in found_paths:
                found_paths.append(site_pkg)
    else:
        print("    No bcc/__init__.py found")
except Exception as e:
    print(f"    Error: {e}")

# Method 4: Check what Python version the package was built for
print("\n[4] Checking python3-bcc package details...")
try:
    result = subprocess.run(['rpm', '-qi', 'python3-bcc'], capture_output=True, text=True)
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if any(x in line.lower() for x in ['name', 'version', 'arch', 'summary']):
                print(f"    {line}")
except Exception as e:
    print(f"    Error: {e}")

# Summary and fix
print("\n" + "=" * 60)
print(" SOLUTION")
print("=" * 60)

if found_paths:
    print(f"\nBCC is installed at: {found_paths}")
    print("\nTo fix TrapNinja, add this path to the BCC_PATHS in:")
    print("  - src/trapninja.py (check_ebpf_support function)")
    print("  - src/trapninja/ebpf.py (BCC_PATHS list)")
    print("\nOr test import now:")
    
    for path in found_paths:
        if path not in sys.path:
            sys.path.insert(0, path)
    
    print(f"\nAdded {found_paths} to sys.path")
    print("Attempting import...")
    
    try:
        from bcc import BPF
        print("\033[92m[✓] SUCCESS! BCC imported!\033[0m")
        import bcc
        print(f"    Version: {getattr(bcc, '__version__', 'unknown')}")
        print(f"    Location: {bcc.__file__}")
    except Exception as e:
        print(f"\033[91m[✗] Import failed: {e}\033[0m")
else:
    print("\nBCC Python bindings not found!")
    print("The RPM is installed but Python files may be missing.")
    print("\nTry reinstalling:")
    print("  sudo yum reinstall python3-bcc")
