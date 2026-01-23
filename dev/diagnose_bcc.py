#!/usr/bin/env python3
"""
BCC/eBPF Detection Diagnostic Script

Run this on your server to diagnose why BCC is not being detected:
  python3 diagnose_bcc.py
  
Or with sudo to also test BPF compilation:
  sudo python3 diagnose_bcc.py
"""

import sys
import os
import subprocess


def print_header(msg):
    print(f"\n{'='*60}")
    print(f" {msg}")
    print('='*60)


def print_ok(msg):
    print(f"\033[92m[✓]\033[0m {msg}")


def print_warn(msg):
    print(f"\033[93m[!]\033[0m {msg}")


def print_error(msg):
    print(f"\033[91m[✗]\033[0m {msg}")


def print_info(msg):
    print(f"    {msg}")


def main():
    print_header("BCC/eBPF Detection Diagnostic")
    print(f"Python: {sys.executable}")
    print(f"Version: {sys.version}")
    print(f"Running as root: {os.geteuid() == 0}")
    
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
    search_paths = [
        '/usr/lib/python3.9/site-packages',
        '/usr/lib64/python3.9/site-packages',
        '/usr/lib/python3/site-packages',
        '/usr/lib64/python3/site-packages',
        '/usr/local/lib/python3.9/site-packages',
        '/usr/local/lib64/python3.9/site-packages',
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
                    print_error(f"WRONG 'bcc' package at: {bcc_path}")
                    print_info("This is the pip 'bcc' package, not BPF Compiler Collection!")
                    print_info("Fix: pip uninstall bcc")
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
        print_error(f"ImportError: {e}")
    except AttributeError as e:
        print_error(f"AttributeError (version mismatch): {e}")
    except Exception as e:
        print_error(f"Unexpected error: {type(e).__name__}: {e}")
    
    # 5. Test BPF compilation (requires root)
    print_header("Step 5: Test BPF compilation (requires root)")
    if os.geteuid() != 0:
        print_warn("Skipping BPF compilation test - not running as root")
        print_info("Run with: sudo python3 diagnose_bcc.py")
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
            print_error("BPF not imported, cannot test compilation")
        except Exception as e:
            print_error(f"BPF compilation failed: {e}")
    
    # 6. Check kernel version
    print_header("Step 6: Check kernel version")
    try:
        import platform
        kernel = platform.release()
        print_info(f"Kernel: {kernel}")
        
        major, minor = map(int, kernel.split("-")[0].split(".")[:2])
        if major >= 4 and minor >= 4:
            print_ok(f"Kernel {major}.{minor} supports eBPF (4.4+ required)")
        else:
            print_error(f"Kernel {major}.{minor} may not fully support eBPF")
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
        print_error("BCC not found in expected locations")
        print_info("Install with: sudo yum install bcc bcc-tools python3-bcc")
    
    print()


if __name__ == '__main__':
    main()
