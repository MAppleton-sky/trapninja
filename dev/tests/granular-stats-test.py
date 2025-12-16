#!/usr/bin/env python3
"""
TrapNinja Granular Statistics Test Suite

Tests for the per-IP, per-OID, and per-destination statistics system.

Usage:
    python3 tests/granular-stats-test.py [--all] [--quick]

Author: TrapNinja Team
"""

import sys
import os
import time
import json
import argparse
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_models():
    """Test the statistics data models."""
    print("\n=== Testing Statistics Models ===\n")
    
    try:
        from trapninja.stats.models import IPStats, OIDStats, DestinationStats, RateTracker
        
        # Test RateTracker
        print("Testing RateTracker...")
        tracker = RateTracker(window_seconds=10, max_samples=100)
        
        # Record some events
        for _ in range(50):
            tracker.record()
            time.sleep(0.01)  # Small delay
        
        rate = tracker.get_rate(10)
        count = tracker.get_count(10)
        print(f"  Recorded 50 events, rate={rate:.2f}/s, count={count}")
        assert count == 50, f"Expected 50, got {count}"
        print("  ✓ RateTracker working correctly")
        
        # Test IPStats
        print("\nTesting IPStats...")
        ip_stats = IPStats(ip_address="10.0.0.1")
        
        # Record some traps
        ip_stats.record_trap(oid="1.3.6.1.4.1.9.9.41.2.0.1", action="forwarded", destination="default")
        ip_stats.record_trap(oid="1.3.6.1.4.1.9.9.41.2.0.1", action="forwarded", destination="default")
        ip_stats.record_trap(oid="1.3.6.1.4.1.9.9.41.2.0.2", action="blocked")
        
        assert ip_stats.total_traps == 3, f"Expected 3 traps, got {ip_stats.total_traps}"
        assert ip_stats.forwarded == 2, f"Expected 2 forwarded, got {ip_stats.forwarded}"
        assert ip_stats.blocked == 1, f"Expected 1 blocked, got {ip_stats.blocked}"
        
        top_oids = ip_stats.get_top_oids(5)
        assert len(top_oids) == 2, f"Expected 2 OIDs, got {len(top_oids)}"
        print(f"  IP: {ip_stats.ip_address}")
        print(f"  Total: {ip_stats.total_traps}, Forwarded: {ip_stats.forwarded}, Blocked: {ip_stats.blocked}")
        print(f"  Top OIDs: {top_oids}")
        print("  ✓ IPStats working correctly")
        
        # Test OIDStats
        print("\nTesting OIDStats...")
        oid_stats = OIDStats(oid="1.3.6.1.4.1.9.9.41.2.0.1")
        
        oid_stats.record_trap("10.0.0.1", action="forwarded")
        oid_stats.record_trap("10.0.0.1", action="forwarded")
        oid_stats.record_trap("10.0.0.2", action="forwarded")
        
        assert oid_stats.total_traps == 3, f"Expected 3 traps, got {oid_stats.total_traps}"
        
        top_ips = oid_stats.get_top_ips(5)
        assert len(top_ips) == 2, f"Expected 2 IPs, got {len(top_ips)}"
        print(f"  OID: {oid_stats.oid}")
        print(f"  Total: {oid_stats.total_traps}")
        print(f"  Top IPs: {top_ips}")
        print("  ✓ OIDStats working correctly")
        
        # Test serialization
        print("\nTesting serialization...")
        ip_dict = ip_stats.to_dict()
        assert 'ip_address' in ip_dict
        assert 'total_traps' in ip_dict
        assert 'top_oids' in ip_dict
        print(f"  IP serialization: {len(json.dumps(ip_dict))} bytes")
        print("  ✓ Serialization working correctly")
        
        print("\n✓ All model tests passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ Model tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_collector():
    """Test the statistics collector."""
    print("\n=== Testing Statistics Collector ===\n")
    
    try:
        from trapninja.stats.collector import (
            GranularStatsCollector, CollectorConfig, LRUDict
        )
        
        # Test LRUDict
        print("Testing LRUDict...")
        lru = LRUDict(max_size=3)
        lru['a'] = 1
        lru['b'] = 2
        lru['c'] = 3
        lru['d'] = 4  # Should evict 'a'
        
        assert 'a' not in lru, "LRU eviction failed - 'a' should be evicted"
        assert 'd' in lru, "LRU failed - 'd' should be present"
        assert len(lru) == 3, f"Expected size 3, got {len(lru)}"
        print("  ✓ LRUDict working correctly")
        
        # Test Collector
        print("\nTesting GranularStatsCollector...")
        
        # Use a temp directory for metrics
        with tempfile.TemporaryDirectory() as tmpdir:
            config = CollectorConfig(
                max_ips=100,
                max_oids=50,
                max_destinations=10,
                cleanup_interval=300,
                stale_threshold=60,
                rate_window=10,
                export_interval=5,
                metrics_dir=tmpdir
            )
            
            collector = GranularStatsCollector(config)
            collector.start()
            
            # Record some traps
            print("  Recording test traps...")
            for i in range(100):
                ip = f"10.0.0.{i % 10}"
                oid = f"1.3.6.1.4.1.9.9.41.2.0.{i % 5}"
                collector.record_trap(
                    source_ip=ip,
                    oid=oid,
                    action="forwarded",
                    destination="default"
                )
            
            # Check totals
            summary = collector.get_summary()
            assert summary['totals']['traps'] == 100, f"Expected 100 traps, got {summary['totals']['traps']}"
            print(f"  Total traps recorded: {summary['totals']['traps']}")
            
            # Check unique counts
            assert summary['counts']['unique_ips'] == 10, f"Expected 10 IPs, got {summary['counts']['unique_ips']}"
            assert summary['counts']['unique_oids'] == 5, f"Expected 5 OIDs, got {summary['counts']['unique_oids']}"
            print(f"  Unique IPs: {summary['counts']['unique_ips']}")
            print(f"  Unique OIDs: {summary['counts']['unique_oids']}")
            
            # Test queries
            print("\n  Testing queries...")
            
            top_ips = collector.get_top_ips(5, sort_by='total')
            assert len(top_ips) == 5, f"Expected 5 top IPs, got {len(top_ips)}"
            print(f"  Top 5 IPs: {[ip['ip_address'] for ip in top_ips]}")
            
            top_oids = collector.get_top_oids(3, sort_by='total')
            assert len(top_oids) == 3, f"Expected 3 top OIDs, got {len(top_oids)}"
            print(f"  Top 3 OIDs: {[oid['oid'] for oid in top_oids]}")
            
            # Test IP detail
            ip_detail = collector.get_ip_stats("10.0.0.1")
            assert ip_detail is not None, "IP detail should not be None"
            assert ip_detail['total_traps'] == 10, f"Expected 10 traps for 10.0.0.1, got {ip_detail['total_traps']}"
            print(f"  IP 10.0.0.1 detail: {ip_detail['total_traps']} traps")
            
            # Test search
            search_results = collector.search_ips("10.0.0", limit=5)
            assert len(search_results) == 5, f"Expected 5 search results, got {len(search_results)}"
            print(f"  Search '10.0.0' returned {len(search_results)} results")
            
            # Test Prometheus export
            print("\n  Testing exports...")
            prom_output = collector.export_prometheus()
            assert 'trapninja_ip_traps_total' in prom_output
            print(f"  Prometheus export: {len(prom_output)} bytes")
            
            # Test JSON export
            json_output = collector.export_json()
            assert 'timestamp' in json_output
            print(f"  JSON export: {len(json.dumps(json_output))} bytes")
            
            # Wait for file export
            print("\n  Waiting for file export...")
            time.sleep(6)
            
            prom_file = os.path.join(tmpdir, "trapninja_granular.prom")
            json_file = os.path.join(tmpdir, "trapninja_granular.json")
            
            assert os.path.exists(prom_file), f"Prometheus file not created: {prom_file}"
            assert os.path.exists(json_file), f"JSON file not created: {json_file}"
            print(f"  ✓ Files exported to {tmpdir}")
            
            # Stop collector
            collector.stop()
        
        print("\n✓ All collector tests passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ Collector tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api():
    """Test the API functions."""
    print("\n=== Testing API Functions ===\n")
    
    try:
        from trapninja.stats.collector import (
            GranularStatsCollector, CollectorConfig, initialize_stats, shutdown_stats
        )
        from trapninja.stats.api import (
            get_top_ips, get_top_oids, get_ip_details, get_oid_details,
            get_stats_summary, query_stats, get_ip_oid_matrix, export_for_dashboard
        )
        
        # Initialize global collector
        with tempfile.TemporaryDirectory() as tmpdir:
            config = CollectorConfig(
                max_ips=100,
                max_oids=50,
                metrics_dir=tmpdir,
                export_interval=300  # Long interval - we don't need exports for this test
            )
            
            collector = initialize_stats(config)
            assert collector is not None, "Failed to initialize collector"
            
            # Record test data
            print("Recording test data...")
            for i in range(50):
                collector.record_trap(
                    source_ip=f"192.168.1.{i % 10}",
                    oid=f"1.3.6.1.4.1.2636.4.5.0.{i % 3}",
                    action="forwarded",
                    destination="default"
                )
            
            # Test API functions
            print("\nTesting API functions...")
            
            # get_stats_summary
            summary = get_stats_summary()
            assert 'totals' in summary, "Summary missing totals"
            print(f"  get_stats_summary(): {summary['totals']['traps']} traps")
            
            # get_top_ips
            top_ips = get_top_ips(5, 'total')
            assert len(top_ips) == 5, f"Expected 5 IPs, got {len(top_ips)}"
            print(f"  get_top_ips(5): {[ip['ip_address'] for ip in top_ips]}")
            
            # get_top_oids
            top_oids = get_top_oids(3, 'total')
            assert len(top_oids) == 3, f"Expected 3 OIDs, got {len(top_oids)}"
            print(f"  get_top_oids(3): {[oid['oid'] for oid in top_oids]}")
            
            # get_ip_details
            ip_detail = get_ip_details("192.168.1.1")
            assert ip_detail is not None, "IP detail should not be None"
            print(f"  get_ip_details('192.168.1.1'): {ip_detail['total_traps']} traps")
            
            # get_oid_details
            oid_detail = get_oid_details("1.3.6.1.4.1.2636.4.5.0.0")
            assert oid_detail is not None, "OID detail should not be None"
            print(f"  get_oid_details(): {oid_detail['total_traps']} traps")
            
            # query_stats
            query_result = query_stats('ips', filter_pattern='192.168.1', limit=10)
            assert 'results' in query_result, "Query result missing results"
            print(f"  query_stats('ips', filter='192.168.1'): {len(query_result['results'])} results")
            
            # get_ip_oid_matrix
            matrix = get_ip_oid_matrix(5, 3)
            assert 'ips' in matrix, "Matrix missing IPs"
            assert 'oids' in matrix, "Matrix missing OIDs"
            assert 'matrix' in matrix, "Matrix missing data"
            print(f"  get_ip_oid_matrix(5, 3): {len(matrix['ips'])} x {len(matrix['oids'])} matrix")
            
            # export_for_dashboard
            dashboard = export_for_dashboard()
            assert 'summary' in dashboard, "Dashboard missing summary"
            assert 'top_sources' in dashboard, "Dashboard missing top_sources"
            print(f"  export_for_dashboard(): {len(json.dumps(dashboard))} bytes")
            
            # Shutdown
            shutdown_stats()
        
        print("\n✓ All API tests passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ API tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_performance():
    """Test performance with high volume."""
    print("\n=== Performance Test ===\n")
    
    try:
        from trapninja.stats.collector import GranularStatsCollector, CollectorConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = CollectorConfig(
                max_ips=10000,
                max_oids=5000,
                metrics_dir=tmpdir,
                export_interval=300
            )
            
            collector = GranularStatsCollector(config)
            collector.start()
            
            # Test high volume recording
            num_traps = 100000
            print(f"Recording {num_traps:,} traps...")
            
            start_time = time.time()
            for i in range(num_traps):
                collector.record_trap(
                    source_ip=f"10.{(i // 256) % 256}.{i % 256}.{i % 256}",
                    oid=f"1.3.6.1.4.1.{i % 1000}.{i % 100}",
                    action="forwarded" if i % 10 != 0 else "blocked",
                    destination="default"
                )
            
            elapsed = time.time() - start_time
            rate = num_traps / elapsed
            
            print(f"  Recorded {num_traps:,} traps in {elapsed:.2f}s")
            print(f"  Rate: {rate:,.0f} traps/second")
            
            # Check summary
            summary = collector.get_summary()
            print(f"  Total tracked: {summary['totals']['traps']:,}")
            print(f"  Unique IPs: {summary['counts']['unique_ips']:,}")
            print(f"  Unique OIDs: {summary['counts']['unique_oids']:,}")
            
            # Test query performance
            print("\nQuery performance...")
            
            start_time = time.time()
            for _ in range(100):
                collector.get_top_ips(50)
            query_time = (time.time() - start_time) / 100 * 1000
            print(f"  get_top_ips(50): {query_time:.2f}ms avg")
            
            start_time = time.time()
            for _ in range(100):
                collector.get_snapshot()
            snapshot_time = (time.time() - start_time) / 100 * 1000
            print(f"  get_snapshot(): {snapshot_time:.2f}ms avg")
            
            # Clean up
            collector.stop()
            
            # Performance requirements
            min_rate = 50000  # At least 50k traps/second
            max_query_time = 50  # At most 50ms per query
            
            if rate < min_rate:
                print(f"\n⚠ Warning: Rate {rate:,.0f}/s below target {min_rate:,}/s")
            else:
                print(f"\n✓ Rate OK: {rate:,.0f}/s >= {min_rate:,}/s")
            
            if query_time > max_query_time:
                print(f"⚠ Warning: Query time {query_time:.2f}ms above target {max_query_time}ms")
            else:
                print(f"✓ Query time OK: {query_time:.2f}ms <= {max_query_time}ms")
        
        print("\n✓ Performance test completed!")
        return True
        
    except Exception as e:
        print(f"\n✗ Performance test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    parser = argparse.ArgumentParser(description="TrapNinja Granular Statistics Tests")
    parser.add_argument("--all", action="store_true", help="Run all tests including performance")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only")
    parser.add_argument("--models", action="store_true", help="Test models only")
    parser.add_argument("--collector", action="store_true", help="Test collector only")
    parser.add_argument("--api", action="store_true", help="Test API only")
    parser.add_argument("--performance", action="store_true", help="Test performance only")
    args = parser.parse_args()
    
    print("=" * 60)
    print("  TrapNinja Granular Statistics Test Suite")
    print("=" * 60)
    
    results = {}
    
    # Determine which tests to run
    run_all = not any([args.models, args.collector, args.api, args.performance])
    
    if run_all or args.models:
        results['models'] = test_models()
    
    if run_all or args.collector:
        results['collector'] = test_collector()
    
    if run_all or args.api:
        results['api'] = test_api()
    
    if args.all or args.performance:
        results['performance'] = test_performance()
    
    # Summary
    print("\n" + "=" * 60)
    print("  Test Summary")
    print("=" * 60 + "\n")
    
    passed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    
    for name, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {name:15} {status}")
    
    print(f"\n  Total: {passed} passed, {failed} failed")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
