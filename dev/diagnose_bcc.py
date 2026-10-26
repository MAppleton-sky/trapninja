#!/usr/bin/env python3
"""
BCC/eBPF Detection Diagnostic Script

Run this on your server to diagnose why BCC is not being detected:
    python3.12 -O dev/diagnose_bcc.py
  
Or with sudo to also test BPF compilation:
    sudo python3.12 -O dev/diagnose_bcc.py
"""

import sys
import os
import subprocess
import importlib
import socket


FAILURES = 0


def print_header(msg):
    print(f"\n{'='*60}")
    print(f" {msg}")
    print('='*60)


def print_ok(msg):
    print(f"\033[92m[✓]\033[0m {msg}")


def print_warn(msg):
    print(f"\033[93m[!]\033[0m {msg}")


def print_error(msg):
    global FAILURES
    FAILURES += 1
    print(f"\033[91m[✗]\033[0m {msg}")


def print_info(msg):
    print(f"    {msg}")


def main():
    print_header("TrapNinja Python 3.12 Host Compatibility")
    print(f"Python: {sys.executable}")
    print(f"Version: {sys.version}")
    print(f"Running as root: {os.geteuid() == 0}")
    if sys.version_info[:2] == (3, 12):
        print_ok("Running with Python 3.12")
    else:
        print_error("Run this diagnostic with Python 3.12")
    if sys.flags.optimize:
        print_ok("Python optimization mode (-O) is enabled")
    else:
        print_warn("Run with -O to match the production invocation")

    # Verify the interpreter can import TrapNinja's runtime dependencies.
    print_header("Check TrapNinja dependencies")
    dependency_modules = [
        ("scapy", "Scapy", True),
        ("redis", "redis-py", False),
        ("pysnmp", "PySNMP", False),
        ("pyasn1", "pyasn1", False),
        ("cryptography", "cryptography", False),
        ("Crypto.Cipher.AES", "PyCryptodome AES", False),
    ]
    for module_name, package_name, required in dependency_modules:
        try:
            importlib.import_module(module_name)
            print_ok(f"{package_name} imports successfully")
        except Exception as error:
            message = f"{package_name} import failed: {type(error).__name__}: {error}"
            if required:
                print_error(message)
            else:
                print_warn(message)

    # Opening and immediately closing an AF_PACKET socket does not attach a
    # filter or consume packets; it only verifies the process has raw-socket access.
    print_header("Check raw packet socket permission")
    try:
        packet_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)
        )
        packet_socket.close()
        print_ok("AF_PACKET raw socket can be opened")
    except Exception as error:
        print_error(f"AF_PACKET raw socket unavailable: {type(error).__name__}: {error}")
    
    # 1. Check RPM packages
    print_header("Step 1: Check installed RPM packages")
    try:
        result = subprocess.run(['rpm', '-qa'], capture_output=True, text=True)
        bcc_packages = [p for p in result.stdout.split('\n') if 'bcc' in p.lower()]
        if bcc_packages:
            print_ok(f"Found {len(bcc_packages)} BCC-related packages:")
            for pkg in bcc_packages:
                print_info(pkg)
        else:
            print_error("No BCC packages found via rpm -qa")
    except Exception as e:
        print_warn(f"Could not check RPM packages: {e}")
    
    # 2. Check pip packages
    print_header("Step 2: Check pip packages")
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'list'], 
                              capture_output=True, text=True)
        bcc_pip = [p for p in result.stdout.split('\n') if 'bcc' in p.lower()]
        if bcc_pip:
            print_warn(f"Found {len(bcc_pip)} 'bcc' pip packages (potential conflict!):")
            for pkg in bcc_pip:
                print_info(pkg)
            print_info("If this is 'bcc' by Will Sheffler, it conflicts with BCC!")
        else:
            print_ok("No conflicting pip 'bcc' packages found")
    except Exception as e:
        print_warn(f"Could not check pip packages: {e}")
    
    # 3. Search for bcc in site-packages
    print_header("Step 3: Search for BCC in Python paths")
    python_version = '{}.{}'.format(sys.version_info.major, sys.version_info.minor)
    search_paths = [
        # RHEL 8's system python3-bcc package may target Python 3.6.
        '/usr/lib/python3.6/site-packages',
        '/usr/lib64/python3.6/site-packages',
        '/usr/lib/python{}/site-packages'.format(python_version),
        '/usr/lib64/python{}/site-packages'.format(python_version),
        '/usr/lib/python3/site-packages',
        '/usr/lib64/python3/site-packages',
        '/usr/local/lib/python{}/site-packages'.format(python_version),
        '/usr/local/lib64/python{}/site-packages'.format(python_version),
    ]
    
    # Add current Python's site-packages
    import site
    search_paths.extend(site.getsitepackages())
    search_paths.append(site.getusersitepackages())
    
    # Remove duplicates while preserving order
    seen = set()
    unique_paths = []
    for p in search_paths:
        if p and p not in seen:
            seen.add(p)
            unique_paths.append(p)
    
    bcc_locations = []
    for path in unique_paths:
        bcc_path = os.path.join(path, 'bcc')
        if os.path.exists(bcc_path):
            # Check if it's real BCC or the wrong package
            init_file = os.path.join(bcc_path, '__init__.py')
            has_so = any(f.endswith('.so') for f in os.listdir(bcc_path) if os.path.isfile(os.path.join(bcc_path, f)))
            
            if os.path.exists(init_file):
                with open(init_file, 'r') as f:
                    content = f.read()
                
                if 'willsheffler' in content.lower() or 'Will Sheffler' in content:
                    print_warn(f"Wrong 'bcc' package found at: {bcc_path}")
                    print_info("This is the pip 'bcc' package, not BPF Compiler Collection!")
                    print_info("Remove the conflicting pip package before using BCC")
                elif has_so or 'BPF' in content:
                    print_ok(f"Real BCC found at: {bcc_path}")
                    bcc_locations.append(bcc_path)
                else:
                    print_warn(f"Unknown 'bcc' at: {bcc_path} (no .so files)")
            elif has_so:
                print_ok(f"Real BCC found at: {bcc_path} (has .so files)")
                bcc_locations.append(bcc_path)
        else:
            print_info(f"No bcc at: {path}")
    
    # 4. Try to import BCC
    print_header("Step 4: Attempt BCC import")
    
    # Add found paths to sys.path
    for loc in bcc_locations:
        parent = os.path.dirname(loc)
        if parent not in sys.path:
            sys.path.insert(0, parent)
            print_info(f"Added to sys.path: {parent}")
    
    try:
        from bcc import BPF
        print_ok(f"Successfully imported BCC!")
        
        # Try to get version
        try:
            import bcc
            if hasattr(bcc, '__version__'):
                print_info(f"BCC version: {bcc.__version__}")
        except:
            pass
        
        # Check where it was imported from
        import bcc
        print_info(f"Imported from: {bcc.__file__}")
        
    except ImportError as e:
        print_warn(f"BCC import failed: {e}; eBPF will need to fall back to Scapy")
    except AttributeError as e:
        print_warn(f"BCC import has a version mismatch: {e}")
    except Exception as e:
        print_warn(f"BCC import error: {type(e).__name__}: {e}")
    
    # 5. Test BPF compilation (requires root)
    print_header("Step 5: Test BPF compilation (requires root)")
    if os.geteuid() != 0:
        print_warn("Skipping BPF compilation test - not running as root")
        print_info("Run with: sudo python3.12 -O dev/diagnose_bcc.py")
    else:
        try:
            from bcc import BPF
            test_bpf = BPF(text="""
            int dummy(void *ctx) {
                return 0;
            }
            """)
            print_ok("BPF test program compiled successfully!")
            del test_bpf
        except NameError:
            print_warn("BPF not imported; eBPF will need to fall back to Scapy")
        except Exception as e:
            print_warn(f"BPF compilation failed: {e}")
    
    # 6. Check kernel version
    print_header("Step 6: Check kernel version")
    try:
        import platform
        kernel = platform.release()
        print_info(f"Kernel: {kernel}")
        
        major, minor = map(int, kernel.split("-")[0].split(".")[:2])
        if major > 4 or (major == 4 and minor >= 4):
            print_ok(f"Kernel {major}.{minor} supports eBPF (4.4+ required)")
        else:
            print_warn(f"Kernel {major}.{minor} may not fully support eBPF")
    except Exception as e:
        print_warn(f"Could not check kernel version: {e}")
    
    # 7. Summary and recommendations
    print_header("Summary and Recommendations")
    
    if bcc_locations:
        print_ok(f"BCC found at {len(bcc_locations)} location(s)")
        print_info("The paths TrapNinja should check:")
        for loc in bcc_locations:
            print_info(f"  - {os.path.dirname(loc)}")
    else:
        print_warn("BCC not found in expected locations; eBPF will need to fall back to Scapy")
        print_info("Install the approved RHEL BCC packages, then verify their Python 3.12 compatibility")
    
    if FAILURES:
        print(f"\nCompatibility check failed with {FAILURES} required check(s) failing.")
        sys.exit(1)
    print("\nRequired Python 3.12 host checks passed. Review any eBPF warnings before deployment.")
    print()


if __name__ == '__main__':
    main()
