#!/usr/bin/env python3
"""
TrapNinja Granular Statistics Module

Collects detailed per-IP, per-OID, and per-destination statistics
for visualization and analysis.

Features:
- Per-source IP tracking (trap counts, rates, top OIDs)
- Per-OID tracking (trap counts, rates, top source IPs)
- Per-destination tracking (forward counts, latency)
- Time-windowed statistics (hourly, daily rolling)
- Memory-bounded with configurable limits
- Prometheus export with dimensional labels
- JSON export for integrations
- CLI query interface

Author: TrapNinja Team
Version: 1.0.0
"""

from .collector import (
    GranularStatsCollector,
    CollectorConfig,
    get_stats_collector,
    initialize_stats,
    shutdown_stats,
)

from .models import (
    IPStats,
    OIDStats,
    DestinationStats,
    TimeWindow,
    StatsSnapshot,
    RateTracker,
)

from .api import (
    get_top_ips,
    get_top_oids,
    get_ip_details,
    get_oid_details,
    get_destination_stats,
    get_stats_summary,
    query_stats,
    get_ip_oid_matrix,
    get_time_series,
    export_for_dashboard,
)

__all__ = [
    # Collector
    'GranularStatsCollector',
    'CollectorConfig',
    'get_stats_collector',
    'initialize_stats',
    'shutdown_stats',
    
    # Models
    'IPStats',
    'OIDStats',
    'DestinationStats',
    'TimeWindow',
    'StatsSnapshot',
    'RateTracker',
    
    # API
    'get_top_ips',
    'get_top_oids',
    'get_ip_details',
    'get_oid_details',
    'get_destination_stats',
    'get_stats_summary',
    'query_stats',
    'get_ip_oid_matrix',
    'get_time_series',
    'export_for_dashboard',
]
