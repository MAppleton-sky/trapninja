#!/usr/bin/env python3
"""
TrapNinja Test Suite - Statistics API Tests

Tests for trapninja.stats.api module - statistics query API.

Author: TrapNinja Team
"""

import pytest
from unittest.mock import patch, MagicMock


class TestGetTopIps:
    """Tests for get_top_ips API function."""

    def test_returns_empty_when_no_collector(self):
        """Test returns empty list when collector not initialized."""
        from trapninja.stats.api import get_top_ips
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_top_ips()
        
        assert result == []

    def test_returns_list(self):
        """Test returns list of IP stats."""
        from trapninja.stats.api import get_top_ips
        
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = [
            {'ip_address': '10.0.0.1', 'total_traps': 100}
        ]
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_top_ips(10)
        
        assert len(result) == 1
        assert result[0]['ip_address'] == '10.0.0.1'

    def test_limits_to_1000(self):
        """Test n is limited to 1000."""
        from trapninja.stats.api import get_top_ips
        
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = []
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            get_top_ips(5000)
        
        mock_collector.get_top_ips.assert_called_with(1000, 'total')

    def test_passes_sort_by(self):
        """Test sort_by parameter is passed."""
        from trapninja.stats.api import get_top_ips
        
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = []
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            get_top_ips(10, sort_by='rate')
        
        mock_collector.get_top_ips.assert_called_with(10, 'rate')


class TestGetTopOids:
    """Tests for get_top_oids API function."""

    def test_returns_empty_when_no_collector(self):
        """Test returns empty list when collector not initialized."""
        from trapninja.stats.api import get_top_oids
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_top_oids()
        
        assert result == []

    def test_returns_list(self):
        """Test returns list of OID stats."""
        from trapninja.stats.api import get_top_oids
        
        mock_collector = MagicMock()
        mock_collector.get_top_oids.return_value = [
            {'oid': '1.3.6.1.4.1.9.1', 'total_traps': 50}
        ]
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_top_oids(10)
        
        assert len(result) == 1
        assert result[0]['oid'] == '1.3.6.1.4.1.9.1'

    def test_limits_to_1000(self):
        """Test n is limited to 1000."""
        from trapninja.stats.api import get_top_oids
        
        mock_collector = MagicMock()
        mock_collector.get_top_oids.return_value = []
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            get_top_oids(2000)
        
        mock_collector.get_top_oids.assert_called_with(1000, 'total')


class TestGetIpDetails:
    """Tests for get_ip_details API function."""

    def test_returns_none_when_no_collector(self):
        """Test returns None when collector not initialized."""
        from trapninja.stats.api import get_ip_details
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_ip_details("10.0.0.1")
        
        assert result is None

    def test_returns_ip_stats(self):
        """Test returns IP statistics dict."""
        from trapninja.stats.api import get_ip_details
        
        mock_collector = MagicMock()
        mock_collector.get_ip_stats.return_value = {
            'ip_address': '10.0.0.1',
            'total_traps': 100,
            'top_oids': []
        }
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_ip_details("10.0.0.1")
        
        assert result['ip_address'] == '10.0.0.1'

    def test_limits_top_n_oids(self):
        """Test top_n_oids is limited to 500."""
        from trapninja.stats.api import get_ip_details
        
        mock_collector = MagicMock()
        mock_collector.get_ip_stats.return_value = {}
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            get_ip_details("10.0.0.1", top_n_oids=1000)
        
        mock_collector.get_ip_stats.assert_called_with("10.0.0.1", top_n_oids=500)


class TestGetOidDetails:
    """Tests for get_oid_details API function."""

    def test_returns_none_when_no_collector(self):
        """Test returns None when collector not initialized."""
        from trapninja.stats.api import get_oid_details
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_oid_details("1.3.6.1.4.1.9.1")
        
        assert result is None

    def test_returns_oid_stats(self):
        """Test returns OID statistics dict."""
        from trapninja.stats.api import get_oid_details
        
        mock_collector = MagicMock()
        mock_collector.get_oid_stats.return_value = {
            'oid': '1.3.6.1.4.1.9.1',
            'total_traps': 50
        }
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_oid_details("1.3.6.1.4.1.9.1")
        
        assert result['oid'] == '1.3.6.1.4.1.9.1'


class TestGetDestinationStats:
    """Tests for get_destination_stats API function."""

    def test_returns_empty_list_when_no_collector(self):
        """Test returns empty list when collector not initialized."""
        from trapninja.stats.api import get_destination_stats
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_destination_stats()
        
        assert result == []

    def test_returns_none_for_specific_when_no_collector(self):
        """Test returns None for specific destination when no collector."""
        from trapninja.stats.api import get_destination_stats
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_destination_stats("default")
        
        assert result is None

    def test_returns_all_destinations(self):
        """Test returns all destination stats."""
        from trapninja.stats.api import get_destination_stats
        
        mock_collector = MagicMock()
        mock_collector.get_all_destinations.return_value = [
            {'destination': 'default', 'total_forwarded': 100}
        ]
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_destination_stats()
        
        assert len(result) == 1

    def test_returns_specific_destination(self):
        """Test returns specific destination stats."""
        from trapninja.stats.api import get_destination_stats
        
        mock_collector = MagicMock()
        mock_collector.get_destination_stats.return_value = {
            'destination': 'voice',
            'total_forwarded': 50
        }
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_destination_stats("voice")
        
        assert result['destination'] == 'voice'


class TestGetStatsSummary:
    """Tests for get_stats_summary API function."""

    def test_returns_error_when_no_collector(self):
        """Test returns error dict when collector not initialized."""
        from trapninja.stats.api import get_stats_summary
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_stats_summary()
        
        assert 'error' in result

    def test_returns_summary(self):
        """Test returns summary dict."""
        from trapninja.stats.api import get_stats_summary
        
        mock_collector = MagicMock()
        mock_collector.get_summary.return_value = {
            'totals': {'traps': 1000},
            'counts': {'unique_ips': 50},
            'rates': {'per_minute': 10}
        }
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_stats_summary()
        
        assert 'totals' in result
        assert result['totals']['traps'] == 1000


class TestQueryStats:
    """Tests for query_stats API function."""

    def test_returns_error_when_no_collector(self):
        """Test returns error when collector not initialized."""
        from trapninja.stats.api import query_stats
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = query_stats('ips')
        
        assert 'error' in result

    def test_query_ips(self):
        """Test query for IPs."""
        from trapninja.stats.api import query_stats
        
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = [
            {'ip_address': '10.0.0.1'}
        ]
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = query_stats('ips', limit=10)
        
        assert result['query_type'] == 'ips'
        assert len(result['results']) == 1

    def test_query_ips_with_filter(self):
        """Test query for IPs with filter."""
        from trapninja.stats.api import query_stats
        
        mock_collector = MagicMock()
        mock_collector.search_ips.return_value = [
            {'ip_address': '10.0.0.1'}
        ]
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = query_stats('ips', filter_pattern='10.0.')
        
        mock_collector.search_ips.assert_called()

    def test_query_oids(self):
        """Test query for OIDs."""
        from trapninja.stats.api import query_stats
        
        mock_collector = MagicMock()
        mock_collector.get_top_oids.return_value = []
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = query_stats('oids')
        
        assert result['query_type'] == 'oids'

    def test_query_destinations(self):
        """Test query for destinations."""
        from trapninja.stats.api import query_stats
        
        mock_collector = MagicMock()
        mock_collector.get_all_destinations.return_value = []
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = query_stats('destinations')
        
        assert result['query_type'] == 'destinations'

    def test_query_summary(self):
        """Test query for summary."""
        from trapninja.stats.api import query_stats
        
        mock_collector = MagicMock()
        mock_collector.get_summary.return_value = {}
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = query_stats('summary')
        
        assert result['query_type'] == 'summary'

    def test_query_snapshot(self):
        """Test query for snapshot."""
        from trapninja.stats.api import query_stats
        
        mock_snapshot = MagicMock()
        mock_snapshot.to_dict.return_value = {}
        
        mock_collector = MagicMock()
        mock_collector.get_snapshot.return_value = mock_snapshot
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = query_stats('snapshot')
        
        assert result['query_type'] == 'snapshot'

    def test_query_unknown_type(self):
        """Test query with unknown type returns error."""
        from trapninja.stats.api import query_stats
        
        mock_collector = MagicMock()
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = query_stats('unknown_type')
        
        assert 'error' in result

    def test_query_limits_to_1000(self):
        """Test limit is capped at 1000."""
        from trapninja.stats.api import query_stats
        
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = []
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            query_stats('ips', limit=5000)
        
        mock_collector.get_top_ips.assert_called_with(1000, 'total')


class TestGetIpOidMatrix:
    """Tests for get_ip_oid_matrix API function."""

    def test_returns_empty_when_no_collector(self):
        """Test returns empty matrix when no collector."""
        from trapninja.stats.api import get_ip_oid_matrix
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_ip_oid_matrix()
        
        assert result['ips'] == []
        assert result['oids'] == []
        assert result['matrix'] == []

    def test_returns_matrix_structure(self):
        """Test returns proper matrix structure."""
        from trapninja.stats.api import get_ip_oid_matrix
        from trapninja.stats.models import IPStats
        from collections import Counter
        
        mock_collector = MagicMock()
        mock_collector.get_top_ips.return_value = [
            {'ip_address': '10.0.0.1'},
            {'ip_address': '10.0.0.2'}
        ]
        mock_collector.get_top_oids.return_value = [
            {'oid': 'oid1'},
            {'oid': 'oid2'}
        ]
        
        # Create mock IP stats
        mock_ip_stats = MagicMock()
        mock_ip_stats.oid_counts = Counter({'oid1': 10, 'oid2': 5})
        mock_collector._ip_stats = {'10.0.0.1': mock_ip_stats, '10.0.0.2': mock_ip_stats}
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_ip_oid_matrix(2, 2)
        
        assert 'ips' in result
        assert 'oids' in result
        assert 'matrix' in result
        assert 'timestamp' in result


class TestGetTimeSeries:
    """Tests for get_time_series API function."""

    def test_returns_error_when_no_collector(self):
        """Test returns error when no collector."""
        from trapninja.stats.api import get_time_series
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = get_time_series('ip', '10.0.0.1')
        
        assert 'error' in result

    def test_returns_error_for_unknown_entity_type(self):
        """Test returns error for unknown entity type."""
        from trapninja.stats.api import get_time_series
        
        mock_collector = MagicMock()
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_time_series('unknown', '10.0.0.1')
        
        assert 'error' in result

    def test_returns_error_when_ip_not_found(self):
        """Test returns error when IP not found."""
        from trapninja.stats.api import get_time_series
        
        mock_collector = MagicMock()
        mock_collector.get_ip_stats.return_value = None
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_time_series('ip', '10.0.0.1')
        
        assert 'error' in result

    def test_returns_time_series_for_ip(self):
        """Test returns time series data for IP."""
        from trapninja.stats.api import get_time_series
        
        mock_collector = MagicMock()
        mock_collector.get_ip_stats.return_value = {
            'rate_per_minute': 10.5,
            'total_traps': 100,
            'first_seen': '2024-01-01T00:00:00',
            'last_seen': '2024-01-01T01:00:00'
        }
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_time_series('ip', '10.0.0.1')
        
        assert result['entity_type'] == 'ip'
        assert result['entity_id'] == '10.0.0.1'
        assert 'current_rate_per_minute' in result

    def test_returns_time_series_for_oid(self):
        """Test returns time series data for OID."""
        from trapninja.stats.api import get_time_series
        
        mock_collector = MagicMock()
        mock_collector.get_oid_stats.return_value = {
            'rate_per_minute': 5.0,
            'total_traps': 50,
            'first_seen': '2024-01-01T00:00:00',
            'last_seen': '2024-01-01T01:00:00'
        }
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = get_time_series('oid', '1.3.6.1.4.1.9.1')
        
        assert result['entity_type'] == 'oid'


class TestExportForDashboard:
    """Tests for export_for_dashboard API function."""

    def test_returns_error_when_no_collector(self):
        """Test returns error when no collector."""
        from trapninja.stats.api import export_for_dashboard
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=None):
            result = export_for_dashboard()
        
        assert 'error' in result

    def test_returns_dashboard_data(self):
        """Test returns complete dashboard data."""
        from trapninja.stats.api import export_for_dashboard
        
        mock_collector = MagicMock()
        mock_collector.get_summary.return_value = {'totals': {'traps': 100}}
        mock_collector.get_top_ips.return_value = []
        mock_collector.get_top_oids.return_value = []
        mock_collector.get_all_destinations.return_value = []
        mock_collector._ip_stats = {}
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = export_for_dashboard()
        
        assert 'timestamp' in result
        assert 'summary' in result
        assert 'top_sources' in result
        assert 'top_oids' in result
        assert 'destinations' in result
        assert 'matrix' in result

    def test_dashboard_data_structure(self):
        """Test dashboard data has correct structure."""
        from trapninja.stats.api import export_for_dashboard
        
        mock_collector = MagicMock()
        mock_collector.get_summary.return_value = {'totals': {'traps': 100}}
        mock_collector.get_top_ips.return_value = [{'ip_address': '10.0.0.1'}]
        mock_collector.get_top_oids.return_value = [{'oid': '1.3.6.1'}]
        mock_collector.get_all_destinations.return_value = []
        mock_collector._ip_stats = {}
        
        with patch('trapninja.stats.api.get_stats_collector', return_value=mock_collector):
            result = export_for_dashboard()
        
        # Check nested structure
        assert 'by_volume' in result['top_sources']
        assert 'by_rate' in result['top_sources']
        assert 'most_blocked' in result['top_sources']
        assert 'by_volume' in result['top_oids']
        assert 'by_rate' in result['top_oids']
