#!/usr/bin/env python3
"""
TrapNinja Test Suite - Redirection Module Tests

Tests for trapninja.redirection module.

Assumptions:
- IP validation uses the ipaddress module
- OID validation follows numeric dotted notation (e.g., 1.3.6.1.4.1.x)
- Redirection lookup prioritizes IP over OID
- lookup_redirection_tag uses LRU cache with maxsize=1024
- Configuration files are JSON format with [value, tag] pairs
- Destinations are converted to (ip, port) tuples

Author: TrapNinja Team
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from collections import defaultdict


class TestValidateIp:
    """Tests for validate_ip function."""

    @pytest.mark.parametrize("ip,expected", [
        ("192.168.1.1", "192.168.1.1"),
        ("10.0.0.1", "10.0.0.1"),
        ("172.16.0.1", "172.16.0.1"),
        ("255.255.255.255", "255.255.255.255"),
        ("0.0.0.0", "0.0.0.0"),
        ("127.0.0.1", "127.0.0.1"),
    ])
    def test_valid_ipv4_addresses(self, ip, expected):
        """Test validation of valid IPv4 addresses."""
        from trapninja.redirection import validate_ip
        
        result = validate_ip(ip)
        assert result == expected

    @pytest.mark.parametrize("ip", [
        "256.1.1.1",       # Octet > 255
        "192.168.1",       # Missing octet
        "192.168.1.1.1",   # Extra octet
        "192.168.1.a",     # Non-numeric
        "abc.def.ghi.jkl", # All non-numeric
        "",                # Empty string
        "192.168.1.1/24",  # CIDR notation (not plain IP)
        "192.168.1.-1",    # Negative octet
    ])
    def test_invalid_ipv4_addresses(self, ip):
        """Test rejection of invalid IPv4 addresses."""
        from trapninja.redirection import validate_ip
        
        result = validate_ip(ip)
        assert result is None

    def test_ipv6_address(self):
        """Test IPv6 address handling."""
        from trapninja.redirection import validate_ip
        
        # IPv6 should be valid
        result = validate_ip("::1")
        assert result == "::1"
        
        result = validate_ip("2001:db8::1")
        assert result == "2001:db8::1"


class TestValidateOid:
    """Tests for validate_oid function."""

    @pytest.mark.parametrize("oid,expected", [
        ("1.3.6.1.4.1.8072.2.3.0.1", "1.3.6.1.4.1.8072.2.3.0.1"),
        ("1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.3.0"),
        ("1.3", "1.3"),
        ("0.0", "0.0"),
        ("1.3.6.1.4.1.9.9.1.1.1", "1.3.6.1.4.1.9.9.1.1.1"),
    ])
    def test_valid_oids(self, oid, expected):
        """Test validation of valid OIDs."""
        from trapninja.redirection import validate_oid
        
        result = validate_oid(oid)
        assert result == expected

    @pytest.mark.parametrize("oid", [
        "invalid.oid",      # Non-numeric
        "1.3.6.1.abc",      # Mixed
        "",                 # Empty
        "1",                # Single number (no dots)
        "1.3.6.1.",         # Trailing dot
        ".1.3.6.1",         # Leading dot
        "1..3.6.1",         # Double dot
        "1.3.6.1.4.1.-1",   # Negative number
    ])
    def test_invalid_oids(self, oid):
        """Test rejection of invalid OIDs."""
        from trapninja.redirection import validate_oid
        
        result = validate_oid(oid)
        assert result is None


class TestGetConfigPath:
    """Tests for get_config_path function."""

    def test_returns_full_path(self, monkeypatch):
        """Test that get_config_path returns full path."""
        from trapninja.redirection import get_config_path
        
        # Mock CONFIG_DIR - patch where it's imported from (trapninja.config)
        with patch('trapninja.config.CONFIG_DIR', '/opt/trapninja/config'):
            result = get_config_path("test.json")
        
        assert result == "/opt/trapninja/config/test.json"


class TestSafeLoadJson:
    """Tests for safe_load_json function in redirection module."""

    def test_loads_valid_json(self, tmp_path):
        """Test loading valid JSON file."""
        from trapninja.redirection import safe_load_json
        
        json_file = tmp_path / "test.json"
        data = [["192.168.1.1", "tag1"], ["192.168.1.2", "tag2"]]
        json_file.write_text(json.dumps(data))
        
        result = safe_load_json(str(json_file), [])
        
        assert result == data

    def test_returns_fallback_on_missing(self, tmp_path):
        """Test fallback for missing file."""
        from trapninja.redirection import safe_load_json
        
        result = safe_load_json(str(tmp_path / "missing.json"), [])
        
        assert result == []

    def test_returns_fallback_on_invalid_json(self, tmp_path):
        """Test fallback for invalid JSON."""
        from trapninja.redirection import safe_load_json
        
        json_file = tmp_path / "invalid.json"
        json_file.write_text("{ not valid }")
        
        result = safe_load_json(str(json_file), ["fallback"])
        
        assert result == ["fallback"]


class TestLoadRedirectedIps:
    """Tests for load_redirected_ips function."""

    def test_loads_ip_redirections(self, tmp_path, monkeypatch):
        """Test loading IP redirection rules."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_ips.json"
        config_file.write_text(json.dumps([
            ["192.168.10.50", "security"],
            ["192.168.10.51", "network"]
        ]))
        
        redirection.redirected_ips_mtime = 0
        redirection.redirected_ips = defaultdict(str)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_ips()
        
        assert result["192.168.10.50"] == "security"
        assert result["192.168.10.51"] == "network"

    def test_validates_ip_entries(self, tmp_path, monkeypatch):
        """Test that invalid IPs are rejected."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_ips.json"
        config_file.write_text(json.dumps([
            ["192.168.10.50", "valid"],
            ["invalid.ip", "invalid"],
            ["999.999.999.999", "invalid2"]
        ]))
        
        redirection.redirected_ips_mtime = 0
        redirection.redirected_ips = defaultdict(str)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_ips()
        
        assert "192.168.10.50" in result
        assert "invalid.ip" not in result
        assert "999.999.999.999" not in result

    def test_validates_tag_is_string(self, tmp_path, monkeypatch):
        """Test that non-string tags are rejected."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_ips.json"
        config_file.write_text(json.dumps([
            ["192.168.10.50", "valid_tag"],
            ["192.168.10.51", 123],  # Invalid: numeric tag
            ["192.168.10.52", None]  # Invalid: null tag
        ]))
        
        redirection.redirected_ips_mtime = 0
        redirection.redirected_ips = defaultdict(str)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_ips()
        
        assert result["192.168.10.50"] == "valid_tag"
        assert "192.168.10.51" not in result
        assert "192.168.10.52" not in result

    def test_only_reloads_on_mtime_change(self, tmp_path, monkeypatch):
        """Test that file is only reloaded when modified."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_ips.json"
        config_file.write_text(json.dumps([["192.168.1.1", "tag1"]]))
        
        # Set mtime to current file mtime (no change)
        redirection.redirected_ips_mtime = os.path.getmtime(str(config_file))
        redirection.redirected_ips = defaultdict(str, {"10.0.0.1": "existing"})
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_ips()
        
        # Should return existing data (not reloaded)
        assert "10.0.0.1" in result
        assert "192.168.1.1" not in result


class TestLoadRedirectedOids:
    """Tests for load_redirected_oids function."""

    def test_loads_oid_redirections(self, tmp_path, monkeypatch):
        """Test loading OID redirection rules."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_oids.json"
        config_file.write_text(json.dumps([
            ["1.3.6.1.4.1.8072.2.3.0.1", "security"],
            ["1.3.6.1.4.1.9.9.1.1.1", "cisco"]
        ]))
        
        redirection.redirected_oids_mtime = 0
        redirection.redirected_oids = defaultdict(str)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_oids()
        
        assert result["1.3.6.1.4.1.8072.2.3.0.1"] == "security"
        assert result["1.3.6.1.4.1.9.9.1.1.1"] == "cisco"

    def test_validates_oid_entries(self, tmp_path, monkeypatch):
        """Test that invalid OIDs are rejected."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_oids.json"
        config_file.write_text(json.dumps([
            ["1.3.6.1.4.1.8072", "valid"],
            ["invalid.oid", "invalid"],
            ["", "empty"]
        ]))
        
        redirection.redirected_oids_mtime = 0
        redirection.redirected_oids = defaultdict(str)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_oids()
        
        assert "1.3.6.1.4.1.8072" in result
        assert "invalid.oid" not in result


class TestLoadRedirectedDestinations:
    """Tests for load_redirected_destinations function."""

    def test_loads_destination_groups(self, tmp_path, monkeypatch):
        """Test loading destination groups."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_destinations.json"
        config_file.write_text(json.dumps({
            "security": [["127.0.0.1", 1362]],
            "network": [["127.0.0.1", 1462], ["127.0.0.1", 1562]]
        }))
        
        redirection.redirected_destinations_mtime = 0
        redirection.redirected_destinations = defaultdict(list)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_destinations()
        
        assert result["security"] == [("127.0.0.1", 1362)]
        assert len(result["network"]) == 2

    def test_validates_destination_ports(self, tmp_path, monkeypatch):
        """Test that invalid ports are rejected."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_destinations.json"
        config_file.write_text(json.dumps({
            "valid": [["127.0.0.1", 162]],
            "invalid_port": [["127.0.0.1", 99999]],
            "negative_port": [["127.0.0.1", -1]],
            "zero_port": [["127.0.0.1", 0]]
        }))
        
        redirection.redirected_destinations_mtime = 0
        redirection.redirected_destinations = defaultdict(list)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_destinations()
        
        assert "valid" in result
        assert "invalid_port" not in result
        assert "negative_port" not in result
        assert "zero_port" not in result

    def test_validates_destination_ips(self, tmp_path, monkeypatch):
        """Test that invalid IPs are rejected."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_destinations.json"
        config_file.write_text(json.dumps({
            "valid": [["192.168.1.1", 162]],
            "invalid_ip": [["not.an.ip", 162]]
        }))
        
        redirection.redirected_destinations_mtime = 0
        redirection.redirected_destinations = defaultdict(list)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_destinations()
        
        assert "valid" in result
        assert "invalid_ip" not in result

    def test_converts_to_tuples(self, tmp_path, monkeypatch):
        """Test that destinations are converted to (ip, port) tuples."""
        from trapninja import redirection
        
        config_file = tmp_path / "redirected_destinations.json"
        config_file.write_text(json.dumps({
            "test": [["192.168.1.1", 162]]
        }))
        
        redirection.redirected_destinations_mtime = 0
        redirection.redirected_destinations = defaultdict(list)
        
        with patch.object(redirection, 'get_config_path', 
                         return_value=str(config_file)):
            result = redirection.load_redirected_destinations()
        
        assert result["test"][0] == ("192.168.1.1", 162)
        assert isinstance(result["test"][0], tuple)


class TestLookupRedirectionTag:
    """Tests for lookup_redirection_tag function."""

    def test_finds_ip_based_tag(self, monkeypatch):
        """Test IP-based redirection lookup."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str, {
            "192.168.10.50": "security"
        })
        redirection.redirected_oids = defaultdict(str)
        
        # Clear cache
        redirection.lookup_redirection_tag.cache_clear()
        
        result = redirection.lookup_redirection_tag("192.168.10.50", None)
        
        assert result == "security"

    def test_finds_oid_based_tag(self, monkeypatch):
        """Test OID-based redirection lookup."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_oids = defaultdict(str, {
            "1.3.6.1.4.1.8072.2.3.0.1": "netsnmp"
        })
        
        redirection.lookup_redirection_tag.cache_clear()
        
        result = redirection.lookup_redirection_tag(
            "192.168.1.1", "1.3.6.1.4.1.8072.2.3.0.1"
        )
        
        assert result == "netsnmp"

    def test_ip_takes_priority_over_oid(self, monkeypatch):
        """Test that IP-based redirection takes priority."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str, {
            "192.168.10.50": "ip_tag"
        })
        redirection.redirected_oids = defaultdict(str, {
            "1.3.6.1.4.1.8072.2.3.0.1": "oid_tag"
        })
        
        redirection.lookup_redirection_tag.cache_clear()
        
        result = redirection.lookup_redirection_tag(
            "192.168.10.50", "1.3.6.1.4.1.8072.2.3.0.1"
        )
        
        # IP should take priority
        assert result == "ip_tag"

    def test_returns_empty_string_when_not_found(self, monkeypatch):
        """Test empty string returned when no match."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_oids = defaultdict(str)
        
        redirection.lookup_redirection_tag.cache_clear()
        
        result = redirection.lookup_redirection_tag(
            "10.0.0.1", "1.3.6.1.2.1.1.1.0"
        )
        
        assert result == ""

    def test_caches_results(self, monkeypatch):
        """Test that results are cached."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str, {
            "192.168.1.1": "cached_tag"
        })
        
        redirection.lookup_redirection_tag.cache_clear()
        
        # First call
        result1 = redirection.lookup_redirection_tag("192.168.1.1", None)
        
        # Change the data
        redirection.redirected_ips["192.168.1.1"] = "new_tag"
        
        # Second call should return cached value
        result2 = redirection.lookup_redirection_tag("192.168.1.1", None)
        
        assert result1 == result2 == "cached_tag"


class TestCheckForRedirection:
    """Tests for check_for_redirection function."""

    def test_returns_redirected_with_destinations(self, monkeypatch):
        """Test successful redirection with destinations."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str, {
            "192.168.10.50": "security"
        })
        redirection.redirected_destinations = defaultdict(list, {
            "security": [("127.0.0.1", 1362)]
        })
        
        redirection.lookup_redirection_tag.cache_clear()
        
        is_redir, dests, tag = redirection.check_for_redirection(
            "192.168.10.50", "1.3.6.1.4.1.8072.2.3.0.1"
        )
        
        assert is_redir is True
        assert dests == [("127.0.0.1", 1362)]
        assert tag == "security"

    def test_returns_not_redirected_when_no_match(self, monkeypatch):
        """Test no redirection when no rules match."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_oids = defaultdict(str)
        
        redirection.lookup_redirection_tag.cache_clear()
        
        is_redir, dests, tag = redirection.check_for_redirection(
            "10.0.0.1", "1.3.6.1.2.1.1.1.0"
        )
        
        assert is_redir is False
        assert dests == []
        assert tag is None

    def test_returns_not_redirected_when_tag_has_no_destinations(self, monkeypatch):
        """Test no redirection when tag has no configured destinations."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str, {
            "192.168.1.1": "orphan_tag"
        })
        redirection.redirected_destinations = defaultdict(list)  # No destinations
        
        redirection.lookup_redirection_tag.cache_clear()
        
        is_redir, dests, tag = redirection.check_for_redirection(
            "192.168.1.1", None
        )
        
        assert is_redir is False
        assert dests == []

    def test_multiple_destinations(self, monkeypatch):
        """Test redirection with multiple destinations."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str, {
            "192.168.1.1": "multi"
        })
        redirection.redirected_destinations = defaultdict(list, {
            "multi": [
                ("127.0.0.1", 1362),
                ("127.0.0.1", 1462),
                ("10.0.0.100", 162)
            ]
        })
        
        redirection.lookup_redirection_tag.cache_clear()
        
        is_redir, dests, tag = redirection.check_for_redirection(
            "192.168.1.1", None
        )
        
        assert is_redir is True
        assert len(dests) == 3


class TestClearRedirectionCaches:
    """Tests for clear_redirection_caches function."""

    def test_clears_lru_cache(self, monkeypatch):
        """Test that LRU cache is cleared."""
        from trapninja import redirection
        
        redirection.redirected_ips = defaultdict(str, {
            "192.168.1.1": "tag1"
        })
        
        redirection.lookup_redirection_tag.cache_clear()
        
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

    def test_loads_all_configs(self, tmp_path, monkeypatch):
        """Test that all redirection configs are loaded."""
        from trapninja import redirection
        
        # Create config files
        (tmp_path / "redirected_ips.json").write_text(
            json.dumps([["192.168.1.1", "tag1"]])
        )
        (tmp_path / "redirected_oids.json").write_text(
            json.dumps([["1.3.6.1.4.1.8072", "tag2"]])
        )
        (tmp_path / "redirected_destinations.json").write_text(
            json.dumps({"tag1": [["127.0.0.1", 162]]})
        )
        
        # Reset mtimes
        redirection.redirected_ips_mtime = 0
        redirection.redirected_oids_mtime = 0
        redirection.redirected_destinations_mtime = 0
        
        def mock_get_config_path(filename):
            return str(tmp_path / filename)
        
        with patch.object(redirection, 'get_config_path', mock_get_config_path):
            ips, oids, dests = redirection.load_redirection_config()
        
        assert "192.168.1.1" in ips
        assert "1.3.6.1.4.1.8072" in oids
        assert "tag1" in dests


class TestScheduleConfigCheck:
    """Tests for schedule_config_check function."""

    @patch('trapninja.redirection.Timer')
    def test_schedules_timer(self, mock_timer, monkeypatch):
        """Test that timer is scheduled for next check."""
        from trapninja import redirection
        from trapninja.config import stop_event
        
        # Ensure stop_event is not set
        stop_event.clear()
        
        # Mock the load functions
        with patch.object(redirection, 'load_redirection_config'):
            with patch.object(redirection, 'clear_redirection_caches'):
                redirection.schedule_config_check(interval=30)
        
        # Timer should be started
        mock_timer.assert_called()
        call_args = mock_timer.call_args
        assert call_args[0][0] == 30  # interval

    @patch('trapninja.redirection.Timer')
    def test_does_not_schedule_when_stopping(self, mock_timer, monkeypatch):
        """Test that timer is not scheduled when stop_event is set."""
        from trapninja import redirection
        from trapninja.config import stop_event
        
        # Set stop event
        stop_event.set()
        
        try:
            with patch.object(redirection, 'load_redirection_config'):
                with patch.object(redirection, 'clear_redirection_caches'):
                    redirection.schedule_config_check(interval=30)
            
            # Timer should not be started when stopping
            mock_timer.assert_not_called()
        finally:
            # Clean up
            stop_event.clear()
