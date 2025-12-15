#!/usr/bin/env python3
"""
TrapNinja Granular Statistics API

Provides query functions for accessing granular statistics.
Designed for CLI tools and web frontend integration.

Author: TrapNinja Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from .collector import get_stats_collector

logger = logging.getLogger("trapninja")


def get_top_ips(n: int = 10, sort_by: str = 'total') -> List[Dict[str, Any]]:
    """
    Get top N source IPs.
    
    Args:
        n: Number of IPs to return (max 1000)
        sort_by: Sort criteria - 'total', 'rate', 'blocked', 'recent'
        
    Returns:
        List of IP statistics dictionaries
        
    Example:
        >>> ips = get_top_ips(10, sort_by='rate')
        >>> for ip in ips:
        ...     print(f"{ip['ip_address']}: {ip['rate_per_minute']}/min")
    """
    collector = get_stats_collector()
    if not collector:
        return []
    
    n = min(n, 1000)  # Limit to prevent memory issues
    return collector.get_top_ips(n, sort_by)


def get_top_oids(n: int = 10, sort_by: str = 'total') -> List[Dict[str, Any]]:
    """
    Get top N OIDs.
    
    Args:
        n: Number of OIDs to return (max 1000)
        sort_by: Sort criteria - 'total', 'rate', 'blocked', 'recent'
        
    Returns:
        List of OID statistics dictionaries
        
    Example:
        >>> oids = get_top_oids(10)
        >>> for oid in oids:
        ...     print(f"{oid['oid']}: {oid['total_traps']} traps")
    """
    collector = get_stats_collector()
    if not collector:
        return []
    
    n = min(n, 1000)
    return collector.get_top_oids(n, sort_by)


def get_ip_details(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed statistics for a specific IP.
    
    Args:
        ip_address: IP address to look up
        
    Returns:
        Dictionary with full IP stats including top OIDs,
        or None if IP not found
        
    Example:
        >>> details = get_ip_details("10.0.0.1")
        >>> if details:
        ...     print(f"Total: {details['total_traps']}")
        ...     for oid in details['top_oids']:
        ...         print(f"  {oid['oid']}: {oid['count']}")
    """
    collector = get_stats_collector()
    if not collector:
        return None
    
    return collector.get_ip_stats(ip_address)


def get_oid_details(oid: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed statistics for a specific OID.
    
    Args:
        oid: OID to look up
        
    Returns:
        Dictionary with full OID stats including top source IPs,
        or None if OID not found
        
    Example:
        >>> details = get_oid_details("1.3.6.1.4.1.9.9.41.2.0.1")
        >>> if details:
        ...     print(f"Total: {details['total_traps']}")
        ...     for ip in details['top_source_ips']:
        ...         print(f"  {ip['ip']}: {ip['count']}")
    """
    collector = get_stats_collector()
    if not collector:
        return None
    
    return collector.get_oid_stats(oid)


def get_destination_stats(destination: str = None) -> Any:
    """
    Get statistics for destinations.
    
    Args:
        destination: Specific destination to query, or None for all
        
    Returns:
        Dictionary for specific destination, or list of all destinations
        
    Example:
        >>> # Get all destinations
        >>> dests = get_destination_stats()
        >>> 
        >>> # Get specific destination
        >>> dest = get_destination_stats("default")
    """
    collector = get_stats_collector()
    if not collector:
        return [] if destination is None else None
    
    if destination:
        return collector.get_destination_stats(destination)
    else:
        return collector.get_all_destinations()


def get_stats_summary() -> Dict[str, Any]:
    """
    Get overall statistics summary.
    
    Returns:
        Dictionary with totals, counts, and rates
        
    Example:
        >>> summary = get_stats_summary()
        >>> print(f"Total traps: {summary['totals']['traps']}")
        >>> print(f"Rate: {summary['rates']['per_minute']}/min")
    """
    collector = get_stats_collector()
    if not collector:
        return {
            'error': 'Statistics collector not initialized',
            'totals': {'traps': 0},
            'counts': {'unique_ips': 0, 'unique_oids': 0},
            'rates': {'per_minute': 0}
        }
    
    return collector.get_summary()


def query_stats(
    query_type: str,
    filter_pattern: str = None,
    sort_by: str = 'total',
    limit: int = 100,
    include_details: bool = False
) -> Dict[str, Any]:
    """
    Flexible statistics query interface.
    
    Designed for web frontend queries with multiple parameters.
    
    Args:
        query_type: 'ips', 'oids', 'destinations', 'summary', 'snapshot'
        filter_pattern: Pattern to filter by (IP prefix, OID prefix)
        sort_by: Sort criteria ('total', 'rate', 'blocked', 'recent')
        limit: Maximum results to return
        include_details: Whether to include detailed breakdowns
        
    Returns:
        Query results dictionary
        
    Example:
        >>> # Get top 20 IPs from 10.0.x.x sorted by rate
        >>> result = query_stats(
        ...     query_type='ips',
        ...     filter_pattern='10.0.',
        ...     sort_by='rate',
        ...     limit=20
        ... )
    """
    collector = get_stats_collector()
    if not collector:
        return {
            'error': 'Statistics collector not initialized',
            'query_type': query_type,
            'results': []
        }
    
    result = {
        'query_type': query_type,
        'filter': filter_pattern,
        'sort_by': sort_by,
        'limit': limit,
        'timestamp': datetime.now().isoformat(),
    }
    
    limit = min(limit, 1000)  # Cap at 1000
    
    if query_type == 'ips':
        if filter_pattern:
            result['results'] = collector.search_ips(filter_pattern, limit)
        else:
            result['results'] = collector.get_top_ips(limit, sort_by)
    
    elif query_type == 'oids':
        if filter_pattern:
            result['results'] = collector.search_oids(filter_pattern, limit)
        else:
            result['results'] = collector.get_top_oids(limit, sort_by)
    
    elif query_type == 'destinations':
        result['results'] = collector.get_all_destinations()
    
    elif query_type == 'summary':
        result['results'] = collector.get_summary()
    
    elif query_type == 'snapshot':
        result['results'] = collector.get_snapshot().to_dict()
    
    else:
        result['error'] = f"Unknown query type: {query_type}"
        result['results'] = []
    
    result['count'] = len(result.get('results', []))
    return result


def get_ip_oid_matrix(top_n_ips: int = 10, top_n_oids: int = 10) -> Dict[str, Any]:
    """
    Get a matrix of top IPs vs top OIDs for heatmap visualization.
    
    Args:
        top_n_ips: Number of top IPs to include
        top_n_oids: Number of top OIDs to include
        
    Returns:
        Dictionary with IPs, OIDs, and matrix data
        
    Example response:
        {
            'ips': ['10.0.0.1', '10.0.0.2', ...],
            'oids': ['1.3.6.1...', '1.3.6.1...', ...],
            'matrix': [
                [100, 50, 0, ...],  # Counts for IP 0
                [0, 200, 30, ...],  # Counts for IP 1
                ...
            ]
        }
    """
    collector = get_stats_collector()
    if not collector:
        return {'ips': [], 'oids': [], 'matrix': []}
    
    # Get top IPs and OIDs
    top_ips = collector.get_top_ips(top_n_ips, sort_by='total')
    top_oids = collector.get_top_oids(top_n_oids, sort_by='total')
    
    ip_list = [ip['ip_address'] for ip in top_ips]
    oid_list = [oid['oid'] for oid in top_oids]
    
    # Build matrix
    matrix = []
    for ip_addr in ip_list:
        ip_stat = collector._ip_stats.get(ip_addr)
        row = []
        for oid in oid_list:
            count = ip_stat.oid_counts.get(oid, 0) if ip_stat else 0
            row.append(count)
        matrix.append(row)
    
    return {
        'ips': ip_list,
        'oids': oid_list,
        'matrix': matrix,
        'timestamp': datetime.now().isoformat()
    }


def get_time_series(
    entity_type: str,
    entity_id: str,
    window_minutes: int = 60,
    bucket_minutes: int = 1
) -> Dict[str, Any]:
    """
    Get time series data for an entity.
    
    Note: This provides approximate rates based on current rate tracker.
    For true time series, use an external time-series database.
    
    Args:
        entity_type: 'ip' or 'oid'
        entity_id: IP address or OID
        window_minutes: Time window to query
        bucket_minutes: Size of each time bucket
        
    Returns:
        Time series data (simplified - rates only)
    """
    collector = get_stats_collector()
    if not collector:
        return {'error': 'Collector not initialized'}
    
    # Get current stats
    if entity_type == 'ip':
        stats = collector.get_ip_stats(entity_id)
    elif entity_type == 'oid':
        stats = collector.get_oid_stats(entity_id)
    else:
        return {'error': f'Unknown entity type: {entity_type}'}
    
    if not stats:
        return {'error': f'{entity_type} not found: {entity_id}'}
    
    # Return current rate info (true time series would need historical storage)
    return {
        'entity_type': entity_type,
        'entity_id': entity_id,
        'current_rate_per_minute': stats['rate_per_minute'],
        'total_count': stats['total_traps'],
        'first_seen': stats['first_seen'],
        'last_seen': stats['last_seen'],
        'note': 'For full time series data, enable Redis persistence'
    }


def export_for_dashboard() -> Dict[str, Any]:
    """
    Export all data formatted for dashboard consumption.
    
    Returns comprehensive data structure suitable for web dashboards.
    
    Returns:
        Dashboard-ready data structure
    """
    collector = get_stats_collector()
    if not collector:
        return {'error': 'Collector not initialized'}
    
    summary = collector.get_summary()
    
    return {
        'timestamp': datetime.now().isoformat(),
        'summary': summary,
        'top_sources': {
            'by_volume': collector.get_top_ips(20, 'total'),
            'by_rate': collector.get_top_ips(20, 'rate'),
            'most_blocked': collector.get_top_ips(10, 'blocked'),
        },
        'top_oids': {
            'by_volume': collector.get_top_oids(20, 'total'),
            'by_rate': collector.get_top_oids(20, 'rate'),
        },
        'destinations': collector.get_all_destinations(),
        'matrix': get_ip_oid_matrix(10, 10),
    }
