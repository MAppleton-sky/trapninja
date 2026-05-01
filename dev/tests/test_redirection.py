#!/usr/bin/env python3
"""
TrapNinja Test Suite - Redirection Module Tests (Consolidated)

Tests for trapninja.redirection module after consolidation.

The refactored module delegates config loading to config.py and
provides:
- Periodic config refresh scheduling
- Cache clearing when config changes  
- Redirection lookup utilities

Author: TrapNinja Team
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from collections import defaultdict


class TestGetConfigPath:
    """Tests for get_config_path function."""

    def test_returns_full_path(self):
        """Test that get_config_path returns full path."""
        from trapninja.redirection import get_config_path
        
        with patch('trapninja.config.CONFIG_DIR', '/opt/trapninja/config'):
            result = get_config_path("test.json")
        
        assert result == "/opt/trapninja/config/test.json"

    def test_handles_various_filenames(self):
        """Test with various config filenames."""
        from trapninja.redirection import get_config_path
        
        with patch('trapninja.config.CONFIG_DIR', '/etc/trapninja'):
            assert get_config_path("redirected_ips.json") == "/etc/trapninja/redirected_ips.json"
            assert get_config_path("redirected_oids.json") == "/etc/trapninja/redirected_oids.json"
            assert get_config_path("destinations.json") == "/etc/trapninja/destinations.json"


class TestLookupRedirectionTag:
    """Tests for lookup_redirection_tag function."""

    def test_finds_ip_based_tag(self):
        """Test IP-based redirection lookup."""
        from trapninja import redirection
        
        # Clear cache first
        redirection.lookup_redirection_tag.cache_clear()
        
        # Mock config.py globals
        with patch('trapninja.config.redirected_ips', 
                   defaultdict(str, {"192.168.10.50": "security"})):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                result = redirection.lookup_redirection_tag("192.168.10.50", None)
        
        assert result == "security"

    def test_finds_oid_based_tag(self):
        """Test OID-based redirection lookup."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', defaultdict(str)):
            with patch('trapninja.config.redirected_oids', 
                       defaultdict(str, {"1.3.6.1.4.1.8072.2.3.0.1": "netsnmp"})):
                result = redirection.lookup_redirection_tag(
                    "192.168.1.1", "1.3.6.1.4.1.8072.2.3.0.1"
                )
        
        assert result == "netsnmp"

    def test_ip_takes_priority_over_oid(self):
        """Test that IP-based redirection takes priority."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', 
                   defaultdict(str, {"192.168.10.50": "ip_tag"})):
            with patch('trapninja.config.redirected_oids', 
                       defaultdict(str, {"1.3.6.1.4.1.8072.2.3.0.1": "oid_tag"})):
                result = redirection.lookup_redirection_tag(
                    "192.168.10.50", "1.3.6.1.4.1.8072.2.3.0.1"
                )
        
        # IP should take priority
        assert result == "ip_tag"

    def test_returns_empty_string_when_not_found(self):
        """Test empty string returned when no match."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', defaultdict(str)):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                result = redirection.lookup_redirection_tag(
                    "10.0.0.1", "1.3.6.1.2.1.1.1.0"
                )
        
        assert result == ""

    def test_caches_results(self):
        """Test that results are cached."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        mock_ips = defaultdict(str, {"192.168.1.1": "cached_tag"})
        
        with patch('trapninja.config.redirected_ips', mock_ips):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                # First call
                result1 = redirection.lookup_redirection_tag("192.168.1.1", None)
                
                # Change the mock data
                mock_ips["192.168.1.1"] = "new_tag"
                
                # Second call should return cached value
                result2 = redirection.lookup_redirection_tag("192.168.1.1", None)
        
        assert result1 == result2 == "cached_tag"

    def test_handles_none_oid(self):
        """Test lookup with None OID."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', 
                   defaultdict(str, {"10.0.0.1": "test_tag"})):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                result = redirection.lookup_redirection_tag("10.0.0.1", None)
        
        assert result == "test_tag"


class TestCheckForRedirection:
    """Tests for check_for_redirection function."""

    def test_returns_redirected_with_destinations(self):
        """Test successful redirection with destinations."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', 
                   defaultdict(str, {"192.168.10.50": "security"})):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                with patch('trapninja.config.redirected_destinations', 
                           defaultdict(list, {"security": [("127.0.0.1", 1362)]})):
                    is_redir, dests, tag = redirection.check_for_redirection(
                        "192.168.10.50", "1.3.6.1.4.1.8072.2.3.0.1"
                    )
        
        assert is_redir is True
        assert dests == [("127.0.0.1", 1362)]
        assert tag == "security"

    def test_returns_not_redirected_when_no_match(self):
        """Test no redirection when no rules match."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', defaultdict(str)):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                with patch('trapninja.config.redirected_destinations', defaultdict(list)):
                    is_redir, dests, tag = redirection.check_for_redirection(
                        "10.0.0.1", "1.3.6.1.2.1.1.1.0"
                    )
        
        assert is_redir is False
        assert dests == []
        assert tag is None

    def test_returns_not_redirected_when_tag_has_no_destinations(self):
        """Test no redirection when tag has no configured destinations."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', 
                   defaultdict(str, {"192.168.1.1": "orphan_tag"})):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                with patch('trapninja.config.redirected_destinations', defaultdict(list)):
                    is_redir, dests, tag = redirection.check_for_redirection(
                        "192.168.1.1", None
                    )
        
        assert is_redir is False
        assert dests == []

    def test_multiple_destinations(self):
        """Test redirection with multiple destinations."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        multi_dests = [
            ("127.0.0.1", 1362),
            ("127.0.0.1", 1462),
            ("10.0.0.100", 162)
        ]
        
        with patch('trapninja.config.redirected_ips', 
                   defaultdict(str, {"192.168.1.1": "multi"})):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                with patch('trapninja.config.redirected_destinations', 
                           defaultdict(list, {"multi": multi_dests})):
                    is_redir, dests, tag = redirection.check_for_redirection(
                        "192.168.1.1", None
                    )
        
        assert is_redir is True
        assert len(dests) == 3
        assert tag == "multi"


class TestClearRedirectionCaches:
    """Tests for clear_redirection_caches function."""

    def test_clears_lru_cache(self):
        """Test that LRU cache is cleared."""
        from trapninja import redirection
        
        redirection.lookup_redirection_tag.cache_clear()
        
        with patch('trapninja.config.redirected_ips', 
                   defaultdict(str, {"192.168.1.1": "tag1"})):
            with patch('trapninja.config.redirected_oids', defaultdict(str)):
                # Populate cache
                redirection.lookup_redirection_tag("192.168.1.1", None)
        
        # Verify cache has entry
        cache_info_before = redirection.lookup_redirection_tag.cache_info()
        assert cache_info_before.currsize > 0
        
        # Clear caches
        redirection.clear_redirection_caches()
        
        # Verify cache is empty
        cache_info_after = redirection.lookup_redirection_tag.cache_info()
        assert cache_info_after.currsize == 0


class TestLoadRedirectionConfig:
    """Tests for load_redirection_config function."""

    def test_calls_load_config(self):
        """Test that load_redirection_config delegates to config.load_config."""
        from trapninja import redirection
        
        with patch('trapninja.config.load_config') as mock_load:
            with patch('trapninja.config.redirected_ips', defaultdict(str)):
                with patch('trapninja.config.redirected_oids', defaultdict(str)):
                    with patch('trapninja.config.redirected_destinations', defaultdict(list)):
                        redirection.load_redirection_config()
        
        # Should call load_config with None callback
        mock_load.assert_called_once_with(None)

    def test_returns_config_globals(self):
        """Test that returns references to config.py globals."""
        from trapninja import redirection
        
        mock_ips = defaultdict(str, {"10.0.0.1": "test"})
        mock_oids = defaultdict(str, {"1.3.6.1": "oid_test"})
        mock_dests = defaultdict(list, {"test": [("127.0.0.1", 162)]})
        
        with patch('trapninja.config.load_config'):
            with patch('trapninja.config.redirected_ips', mock_ips):
                with patch('trapninja.config.redirected_oids', mock_oids):
                    with patch('trapninja.config.redirected_destinations', mock_dests):
                        ips, oids, dests = redirection.load_redirection_config()
        
        assert "10.0.0.1" in ips
        assert "1.3.6.1" in oids
        assert "test" in dests


class TestScheduleConfigCheck:
    """Tests for schedule_config_check function."""

    @patch('trapninja.redirection.Timer')
    def test_schedules_timer(self, mock_timer):
        """Test that timer is scheduled for next check."""
        from trapninja import redirection
        from trapninja.config import stop_event
        
        # Ensure stop_event is not set
        stop_event.clear()
        
        # Mock timer instance
        mock_timer_instance = MagicMock()
        mock_timer.return_value = mock_timer_instance
        
        with patch('trapninja.config.load_config', return_value=False):
            redirection.schedule_config_check(interval=30)
        
        # Timer should be created with correct interval
        mock_timer.assert_called()
        call_args = mock_timer.call_args
        assert call_args[0][0] == 30  # interval
        assert call_args[0][1] == redirection.schedule_config_check
        
        # Timer should be started
        mock_timer_instance.start.assert_called_once()

    @patch('trapninja.redirection.Timer')
    def test_does_not_schedule_when_stopping(self, mock_timer):
        """Test that timer is not scheduled when stop_event is set."""
        from trapninja import redirection
        from trapninja.config import stop_event
        
        # Set stop event
        stop_event.set()
        
        try:
            with patch('trapninja.config.load_config', return_value=False):
                redirection.schedule_config_check(interval=30)
            
            # Timer should not be created when stopping
            mock_timer.assert_not_called()
        finally:
            # Clean up
            stop_event.clear()

    @patch('trapninja.redirection.Timer')
    def test_clears_cache_when_config_changed(self, mock_timer):
        """Test that cache is cleared when config changes."""
        from trapninja import redirection
        from trapninja.config import stop_event
        
        stop_event.clear()
        mock_timer.return_value = MagicMock()
        
        with patch('trapninja.config.load_config', return_value=True):  # Config changed
            with patch.object(redirection, 'clear_redirection_caches') as mock_clear:
                redirection.schedule_config_check(interval=60)
        
        # Cache should be cleared when config changed
        mock_clear.assert_called_once()

    @patch('trapninja.redirection.Timer')
    def test_continues_on_exception(self, mock_timer):
        """Test that scheduling continues even after exception."""
        from trapninja import redirection
        from trapninja.config import stop_event
        
        stop_event.clear()
        mock_timer_instance = MagicMock()
        mock_timer.return_value = mock_timer_instance
        
        with patch('trapninja.config.load_config', side_effect=Exception("Test error")):
            # Should not raise
            redirection.schedule_config_check(interval=60)
        
        # Timer should still be scheduled despite error
        mock_timer.assert_called()
        mock_timer_instance.start.assert_called()


class TestIntegration:
    """Integration tests for redirection module with config.py."""

    def test_lookup_uses_config_globals(self):
        """Test that lookup correctly uses config.py globals."""
        from trapninja import redirection
        from trapninja import config
        
        # Save original values
        orig_ips = config.redirected_ips
        orig_oids = config.redirected_oids
        
        try:
            # Set config globals directly
            config.redirected_ips = defaultdict(str, {"10.10.10.10": "integration_test"})
            config.redirected_oids = defaultdict(str)
            
            redirection.lookup_redirection_tag.cache_clear()
            
            result = redirection.lookup_redirection_tag("10.10.10.10", None)
            
            assert result == "integration_test"
        finally:
            # Restore original values
            config.redirected_ips = orig_ips
            config.redirected_oids = orig_oids
            redirection.lookup_redirection_tag.cache_clear()

    def test_check_for_redirection_uses_config_globals(self):
        """Test that check_for_redirection uses config.py globals."""
        from trapninja import redirection
        from trapninja import config
        
        # Save original values
        orig_ips = config.redirected_ips
        orig_oids = config.redirected_oids
        orig_dests = config.redirected_destinations
        
        try:
            # Set config globals directly
            config.redirected_ips = defaultdict(str, {"20.20.20.20": "int_tag"})
            config.redirected_oids = defaultdict(str)
            config.redirected_destinations = defaultdict(list, {
                "int_tag": [("192.168.1.1", 162)]
            })
            
            redirection.lookup_redirection_tag.cache_clear()
            
            is_redir, dests, tag = redirection.check_for_redirection("20.20.20.20", None)
            
            assert is_redir is True
            assert tag == "int_tag"
            assert dests == [("192.168.1.1", 162)]
        finally:
            # Restore original values
            config.redirected_ips = orig_ips
            config.redirected_oids = orig_oids
            config.redirected_destinations = orig_dests
            redirection.lookup_redirection_tag.cache_clear()
