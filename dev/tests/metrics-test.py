#!/usr/bin/env python3
"""
TrapNinja Metrics Test

A comprehensive test script to verify the metrics functionality of TrapNinja.
Tests the unified metrics system that integrates with packet processor statistics.

Author: TrapNinja Team
Version: 2.0.0
"""
import os
import sys
import time
import json
import argparse

# Add parent directory to path to import trapninja modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Constants
TEST_DIR = os.path.abspath(os.path.dirname(__file__))
METRICS_DIR = os.path.join(TEST_DIR, "metrics_test")

# Create metrics directory if it doesn't exist
os.makedirs(METRICS_DIR, exist_ok=True)


def test_metrics_integration():
    """
    Test the integrated metrics system.
    
    Verifies that metrics from packet_processor are correctly
    exported by the metrics module.
    """
    print("=" * 60)
    print("Testing Unified Metrics Integration")
    print("=" * 60)
    
    # Import metrics module
    try:
        from trapninja.metrics import (
            init_metrics, get_metrics_summary, export_metrics,
            increment_blocked_ip, increment_blocked_oid,
            increment_redirected_ip, increment_redirected_oid,
            cleanup_metrics
        )
        print("✓ Metrics module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import metrics module: {e}")
        return False
    
    # Import packet processor
    try:
        from trapninja.packet_processor import (
            get_processor_stats, reset_processor_stats, _stats
        )
        print("✓ Packet processor module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import packet processor module: {e}")
        return False
    
    # Initialize metrics
    print("\nInitializing metrics system...")
    init_metrics(metrics_directory=METRICS_DIR, export_interval=5)
    print(f"✓ Metrics initialized with output to {METRICS_DIR}")
    
    # Reset processor stats for clean test
    reset_processor_stats()
    print("✓ Processor stats reset")
    
    # Simulate packet processing by directly incrementing stats
    print("\nSimulating packet processing...")
    
    # Simulate received/processed packets
    for _ in range(100):
        _stats.increment_processed()
    print("  - Simulated 100 processed packets")
    
    # Simulate forwarded packets
    for _ in range(80):
        _stats.increment_forwarded()
    print("  - Simulated 80 forwarded packets")
    
    # Simulate blocked packets
    for _ in range(10):
        _stats.increment_blocked()
    print("  - Simulated 10 blocked packets")
    
    # Simulate redirected packets
    for _ in range(5):
        _stats.increment_redirected()
    print("  - Simulated 5 redirected packets")
    
    # Simulate HA blocked packets
    for _ in range(3):
        _stats.increment_ha_blocked()
    print("  - Simulated 3 HA-blocked packets")
    
    # Simulate fast/slow path
    for _ in range(85):
        _stats.record_fast_path()
    for _ in range(15):
        _stats.record_slow_path()
    print("  - Simulated 85 fast path, 15 slow path hits")
    
    # Simulate cached packets
    for _ in range(90):
        _stats.increment_cached()
    for _ in range(2):
        _stats.increment_cache_failure()
    print("  - Simulated 90 cached, 2 cache failures")
    
    # Simulate detailed IP/OID tracking
    blocked_ips = ["192.168.1.100", "10.0.0.1", "192.168.1.100"]
    for ip in blocked_ips:
        increment_blocked_ip(ip)
    print(f"  - Added {len(blocked_ips)} blocked IP records")
    
    blocked_oids = ["1.3.6.1.4.1.9999.1.1.1", "1.3.6.1.4.1.8072.2.3.0.1"]
    for oid in blocked_oids:
        increment_blocked_oid(oid)
    print(f"  - Added {len(blocked_oids)} blocked OID records")
    
    redirected_ips = [
        ("10.0.0.2", "security"),
        ("192.168.2.100", "config"),
        ("10.0.0.2", "security")
    ]
    for ip, tag in redirected_ips:
        increment_redirected_ip(ip, tag)
    print(f"  - Added {len(redirected_ips)} redirected IP records")
    
    # Get and verify metrics summary
    print("\n" + "-" * 60)
    print("Metrics Summary (from get_metrics_summary):")
    print("-" * 60)
    
    metrics = get_metrics_summary()
    
    # Core metrics
    print(f"\nCore Packet Processing:")
    print(f"  Total Traps Received:  {metrics['total_traps_received']}")
    print(f"  Total Traps Forwarded: {metrics['total_traps_forwarded']}")
    print(f"  Total Traps Blocked:   {metrics['total_traps_blocked']}")
    print(f"  Total Traps Redirected: {metrics['total_traps_redirected']}")
    print(f"  Total Traps Dropped:   {metrics['total_traps_dropped']}")
    print(f"  Processing Errors:     {metrics['processing_errors']}")
    
    # HA metrics
    print(f"\nHA Metrics:")
    print(f"  HA Blocked:            {metrics['ha_blocked']}")
    ha_info = metrics.get('ha', {})
    print(f"  HA Enabled:            {ha_info.get('enabled', False)}")
    
    # Cache metrics
    print(f"\nCache Metrics:")
    print(f"  Traps Cached:          {metrics['traps_cached']}")
    print(f"  Cache Failures:        {metrics['cache_failures']}")
    
    # Performance metrics
    print(f"\nPerformance Metrics:")
    print(f"  Fast Path Hits:        {metrics['fast_path_hits']}")
    print(f"  Slow Path Hits:        {metrics['slow_path_hits']}")
    print(f"  Fast Path Ratio:       {metrics['fast_path_ratio']}%")
    print(f"  Processing Rate:       {metrics['processing_rate']} pkts/s")
    
    # Queue metrics
    print(f"\nQueue Metrics:")
    print(f"  Current Depth:         {metrics['queue_current_depth']}")
    print(f"  Max Depth:             {metrics['queue_max_depth']}")
    print(f"  Utilization:           {metrics['queue_utilization']:.2%}")
    
    # Detailed tracking
    print(f"\nDetailed Tracking:")
    print(f"  Blocked IPs:           {metrics['blocked_ips']}")
    print(f"  Blocked OIDs:          {metrics['blocked_oids']}")
    print(f"  Redirected IPs:        {metrics['redirected_ips']}")
    
    # Export metrics
    print("\n" + "-" * 60)
    print("Exporting Metrics to Files...")
    print("-" * 60)
    
    export_metrics()
    
    # Check metrics files
    prom_file = os.path.join(METRICS_DIR, "trapninja_metrics.prom")
    json_file = os.path.join(METRICS_DIR, "trapninja_metrics.json")
    
    if os.path.exists(prom_file):
        print(f"\n✓ Prometheus file created: {prom_file}")
        print("\nPrometheus file sample (first 30 lines):")
        print("-" * 40)
        with open(prom_file, 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines[:30]):
                print(line.rstrip())
            if len(lines) > 30:
                print(f"... ({len(lines) - 30} more lines)")
    else:
        print(f"\n✗ Prometheus file not created: {prom_file}")
        return False
    
    if os.path.exists(json_file):
        print(f"\n✓ JSON file created: {json_file}")
    else:
        print(f"\n✗ JSON file not created: {json_file}")
        return False
    
    # Verify values are non-zero
    print("\n" + "-" * 60)
    print("Verification:")
    print("-" * 60)
    
    checks = [
        ("total_traps_received", metrics['total_traps_received'], 100),
        ("total_traps_forwarded", metrics['total_traps_forwarded'], 80),
        ("total_traps_blocked", metrics['total_traps_blocked'], 10),
        ("total_traps_redirected", metrics['total_traps_redirected'], 5),
        ("ha_blocked", metrics['ha_blocked'], 3),
        ("fast_path_hits", metrics['fast_path_hits'], 85),
        ("slow_path_hits", metrics['slow_path_hits'], 15),
        ("traps_cached", metrics['traps_cached'], 90),
    ]
    
    all_passed = True
    for name, actual, expected in checks:
        if actual == expected:
            print(f"  ✓ {name}: {actual} (expected {expected})")
        else:
            print(f"  ✗ {name}: {actual} (expected {expected})")
            all_passed = False
    
    # Check fast path ratio
    expected_ratio = 85 / 100 * 100  # 85%
    if abs(metrics['fast_path_ratio'] - expected_ratio) < 1:
        print(f"  ✓ fast_path_ratio: {metrics['fast_path_ratio']}% (expected ~{expected_ratio}%)")
    else:
        print(f"  ✗ fast_path_ratio: {metrics['fast_path_ratio']}% (expected ~{expected_ratio}%)")
        all_passed = False
    
    # Cleanup
    cleanup_metrics()
    
    print("\n" + "=" * 60)
    if all_passed:
        print("All tests PASSED!")
    else:
        print("Some tests FAILED!")
    print("=" * 60)
    
    return all_passed


def test_processor_stats_directly():
    """
    Test the packet processor statistics directly.
    """
    print("=" * 60)
    print("Testing Packet Processor Stats Directly")
    print("=" * 60)
    
    try:
        from trapninja.packet_processor import (
            get_processor_stats, reset_processor_stats, AtomicStats
        )
    except ImportError as e:
        print(f"✗ Failed to import: {e}")
        return False
    
    # Create fresh stats
    stats = AtomicStats()
    
    # Test increments
    stats.increment_processed()
    stats.increment_processed()
    stats.increment_forwarded()
    stats.increment_blocked()
    stats.record_fast_path()
    stats.record_slow_path()
    
    summary = stats.get_summary()
    
    print(f"\nStats after increments:")
    print(f"  processed: {summary['processed']}")
    print(f"  forwarded: {summary['forwarded']}")
    print(f"  blocked: {summary['blocked']}")
    print(f"  fast_path_hits: {summary['fast_path_hits']}")
    print(f"  slow_path_hits: {summary['slow_path_hits']}")
    print(f"  fast_path_ratio: {summary['fast_path_ratio']}%")
    print(f"  processing_rate: {summary['processing_rate']} pkts/s")
    
    # Verify
    all_passed = True
    
    if summary['processed'] != 2:
        print(f"✗ processed should be 2, got {summary['processed']}")
        all_passed = False
    else:
        print("✓ processed count correct")
    
    if summary['fast_path_ratio'] != 50.0:
        print(f"✗ fast_path_ratio should be 50.0%, got {summary['fast_path_ratio']}%")
        all_passed = False
    else:
        print("✓ fast_path_ratio correct")
    
    return all_passed


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="TrapNinja Metrics Test")
    parser.add_argument('--integration', action='store_true', 
                        help='Test metrics integration with packet processor')
    parser.add_argument('--processor', action='store_true',
                        help='Test packet processor stats directly')
    parser.add_argument('--all', action='store_true',
                        help='Run all tests')
    args = parser.parse_args()
    
    if args.all or (not args.integration and not args.processor):
        # Run all tests
        results = []
        
        results.append(("Processor Stats", test_processor_stats_directly()))
        print("\n")
        results.append(("Metrics Integration", test_metrics_integration()))
        
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        all_passed = True
        for name, passed in results:
            status = "PASSED" if passed else "FAILED"
            print(f"  {name}: {status}")
            if not passed:
                all_passed = False
        
        return 0 if all_passed else 1
    
    if args.integration:
        return 0 if test_metrics_integration() else 1
    
    if args.processor:
        return 0 if test_processor_stats_directly() else 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
