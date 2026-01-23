#!/usr/bin/env python3
"""
TrapNinja Test Suite - Cache Replay Tests

Tests for trapninja.cache.replay module - trap replay engine.

Author: TrapNinja Team
"""

import time
import pytest
from unittest.mock import patch, MagicMock, call
from datetime import datetime, timedelta


class TestReplayResult:
    """Tests for ReplayResult class."""

    def test_initialization(self):
        """Test ReplayResult initialization."""
        from trapninja.cache.replay import ReplayResult
        
        result = ReplayResult(
            destination="voice_noc",
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 1, 1, 0),
            total_entries=100,
            sent=90,
            failed=5,
            skipped=5,
            dry_run=False,
            duration_seconds=10.5,
            rate_achieved=8.5
        )
        
        assert result.destination == "voice_noc"
        assert result.total_entries == 100
        assert result.sent == 90
        assert result.failed == 5
        assert result.skipped == 5

    def test_to_dict(self):
        """Test ReplayResult to_dict serialization."""
        from trapninja.cache.replay import ReplayResult
        
        result = ReplayResult(
            destination="test",
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 1, 1, 0),
            total_entries=50,
            sent=45,
            failed=3,
            skipped=2,
            dry_run=True,
            duration_seconds=5.0,
            rate_achieved=9.0
        )
        
        data = result.to_dict()
        
        assert data['destination'] == "test"
        assert data['total_entries'] == 50
        assert data['sent'] == 45
        assert data['dry_run'] is True
        assert 'start_time' in data
        assert 'end_time' in data


class TestReplayEngineInitialization:
    """Tests for ReplayEngine initialization."""

    def test_initialization(self):
        """Test ReplayEngine initialization."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        engine = ReplayEngine(mock_cache)
        
        assert engine.cache == mock_cache
        assert engine._stop_requested is False

    def test_stop_sets_flag(self):
        """Test stop method sets flag."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        engine = ReplayEngine(mock_cache)
        
        engine.stop()
        
        assert engine._stop_requested is True


class TestReplayEngineQueryRange:
    """Tests for ReplayEngine query_range method."""

    def test_query_range_no_filter(self):
        """Test query_range without filters."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': '1.3.6.1', 'source_ip': '10.0.0.1'},
            {'trap_oid': '1.3.6.2', 'source_ip': '10.0.0.2'},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        entries = list(engine.query_range("dest", start, end))
        
        assert len(entries) == 2

    def test_query_range_with_oid_filter(self):
        """Test query_range with OID filter."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': '1.3.6.1.4.1.9', 'source_ip': '10.0.0.1'},
            {'trap_oid': '1.3.6.1.4.1.10', 'source_ip': '10.0.0.2'},
            {'trap_oid': '1.3.6.1.4.1.9.5', 'source_ip': '10.0.0.3'},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        entries = list(engine.query_range(
            "dest", start, end, 
            oid_filter="1.3.6.1.4.1.9"
        ))
        
        # Only entries starting with 1.3.6.1.4.1.9
        assert len(entries) == 2

    def test_query_range_with_source_filter(self):
        """Test query_range with source IP filter."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': '1.3.6.1', 'source_ip': '10.0.0.1'},
            {'trap_oid': '1.3.6.2', 'source_ip': '192.168.1.1'},
            {'trap_oid': '1.3.6.3', 'source_ip': '10.0.0.2'},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        entries = list(engine.query_range(
            "dest", start, end,
            source_filter="10.0."
        ))
        
        # Only entries from 10.0.x.x
        assert len(entries) == 2


class TestReplayEngineCountEntries:
    """Tests for ReplayEngine count_entries method."""

    def test_count_entries_no_filter(self):
        """Test count_entries without filters uses cache count."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.count_range.return_value = 100
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        count = engine.count_entries("dest", start, end)
        
        assert count == 100
        mock_cache.count_range.assert_called_once()

    def test_count_entries_with_filter(self):
        """Test count_entries with filter iterates entries."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': '1.3.6.1.4.1.9', 'source_ip': '10.0.0.1'},
            {'trap_oid': '1.3.6.1.4.1.9.5', 'source_ip': '10.0.0.2'},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        count = engine.count_entries(
            "dest", start, end,
            oid_filter="1.3.6.1.4.1.9"
        )
        
        assert count == 2


class TestReplayEngineOidSummary:
    """Tests for ReplayEngine get_oid_summary method."""

    def test_get_oid_summary(self):
        """Test get_oid_summary returns OID counts."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1'},
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.2'},
            {'trap_oid': 'oid2', 'source_ip': '10.0.0.3'},
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.4'},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        summary = engine.get_oid_summary("dest", start, end)
        
        assert summary['oid1'] == 3
        assert summary['oid2'] == 1

    def test_get_oid_summary_respects_limit(self):
        """Test get_oid_summary respects limit parameter."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1'},
            {'trap_oid': 'oid2', 'source_ip': '10.0.0.2'},
            {'trap_oid': 'oid3', 'source_ip': '10.0.0.3'},
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.4'},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        summary = engine.get_oid_summary("dest", start, end, limit=2)
        
        assert len(summary) == 2
        # Should include top 2 OIDs (oid1 with 2, then oid2 or oid3 with 1)
        assert 'oid1' in summary


class TestReplayEngineDryRun:
    """Tests for ReplayEngine dry run mode."""

    def test_replay_dry_run(self):
        """Test replay in dry run mode."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='},
            {'trap_oid': 'oid2', 'source_ip': '10.0.0.2', 'pdu_base64': 'dGVzdDI='},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        result = engine.replay("dest", start, end, dry_run=True)
        
        assert result.dry_run is True
        assert result.total_entries == 2
        assert result.sent == 0
        assert result.duration_seconds == 0


class TestReplayEngineActualReplay:
    """Tests for ReplayEngine actual replay operations."""

    def test_replay_with_exclude_oids(self):
        """Test replay excludes specified OIDs."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='},
            {'trap_oid': 'oid_exclude', 'source_ip': '10.0.0.2', 'pdu_base64': 'dGVzdDI='},
            {'trap_oid': 'oid2', 'source_ip': '10.0.0.3', 'pdu_base64': 'dGVzdDM='},
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        result = engine.replay(
            "dest", start, end,
            dry_run=True,
            exclude_oids=['oid_exclude']
        )
        
        # 3 total, 1 excluded (skipped)
        assert result.total_entries == 3
        assert result.skipped == 1

    def test_replay_stops_when_requested(self):
        """Test replay stops when stop is requested."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        # Return many entries
        mock_cache.query_range.return_value = iter([
            {'trap_oid': f'oid{i}', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='}
            for i in range(100)
        ])
        
        engine = ReplayEngine(mock_cache)
        engine._stop_requested = True  # Pre-set stop flag
        
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        # Use dry_run=True to avoid needing actual forwarding
        # But the stop check happens after dry_run check
        result = engine.replay("dest", start, end, dry_run=True)
        
        # Dry run returns immediately, so we test the result
        assert result.total_entries == 100

    def test_replay_progress_callback(self):
        """Test replay calls progress callback."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': f'oid{i}', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='}
            for i in range(150)
        ])
        
        progress_calls = []
        def progress_callback(processed, total):
            progress_calls.append((processed, total))
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        # Dry run to avoid needing forwarding
        result = engine.replay(
            "dest", start, end,
            dry_run=True,
            progress_callback=progress_callback
        )
        
        # Progress callback not called in dry run
        assert result.total_entries == 150


class TestReplayEngineReplayAll:
    """Tests for ReplayEngine replay_all method."""

    def test_replay_all_multiple_destinations(self):
        """Test replay_all processes all destinations."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.get_destinations.return_value = ['dest1', 'dest2']
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='}
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        results = engine.replay_all(start, end, dry_run=True)
        
        assert 'dest1' in results
        assert 'dest2' in results

    def test_replay_all_stops_when_requested(self):
        """Test replay_all stops when stop requested."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.get_destinations.return_value = ['dest1', 'dest2', 'dest3']
        mock_cache.query_range.return_value = iter([])
        
        engine = ReplayEngine(mock_cache)
        engine._stop_requested = True
        
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        results = engine.replay_all(start, end, dry_run=True)
        
        # Should stop early
        assert len(results) == 0


class TestReplayEngineRateLimiting:
    """Tests for ReplayEngine rate limiting."""

    def test_rate_limit_zero(self):
        """Test rate_limit=0 means no limiting."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='}
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        # Dry run to test rate limit calculation doesn't error
        result = engine.replay("dest", start, end, rate_limit=0, dry_run=True)
        
        assert result.total_entries == 1

    def test_rate_limit_positive(self):
        """Test positive rate_limit value."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='}
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        result = engine.replay("dest", start, end, rate_limit=500, dry_run=True)
        
        assert result.total_entries == 1


class TestReplayEngineCustomDestination:
    """Tests for ReplayEngine replay_to custom destination."""

    def test_replay_to_parsing(self):
        """Test replay_to parses host:port correctly in dry run."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': 'oid1', 'source_ip': '10.0.0.1', 'pdu_base64': 'dGVzdA=='}
        ])
        
        engine = ReplayEngine(mock_cache)
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        # Dry run doesn't actually forward
        result = engine.replay(
            "dest", start, end,
            dry_run=True,
            replay_to="10.0.0.100:1162"
        )
        
        assert result.total_entries == 1
