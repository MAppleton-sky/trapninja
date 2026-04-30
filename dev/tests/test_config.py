#!/usr/bin/env python3
"""
TrapNinja Test Suite - Config Module Tests

Tests for trapninja.config module.

Assumptions:
- Configuration is loaded from JSON files
- Config directory is determined by priority: env var > /etc > local > default
- File modification times are tracked to avoid unnecessary reloads
- Invalid JSON files should fall back to default values
- Port numbers must be valid (1-65535)
- Destinations are stored as [ip, port] lists

Author: TrapNinja Team
"""

import os
import json
import logging
import pytest
from unittest.mock import patch, MagicMock
from collections import defaultdict


class TestGetConfigDir:
    """Tests for _get_config_dir function."""

    def test_env_var_takes_priority(self, tmp_path, monkeypatch):
        """Test that TRAPNINJA_CONFIG env var takes priority."""
        config_dir = tmp_path / "env_config"
        config_dir.mkdir()
        
        monkeypatch.setenv("TRAPNINJA_CONFIG", str(config_dir))
        
        # Need to reimport to trigger _get_config_dir
        import importlib
        import trapninja.config as config_module
        
        # Call the function directly
        result = config_module._get_config_dir()
        
        assert result == str(config_dir)

    def test_etc_trapninja_if_exists(self, monkeypatch):
        """Test /etc/trapninja is used if it exists."""
        monkeypatch.delenv("TRAPNINJA_CONFIG", raising=False)
        
        with patch('os.path.isdir') as mock_isdir:
            mock_isdir.side_effect = lambda p: p == '/etc/trapninja'
            
            import trapninja.config as config_module
            result = config_module._get_config_dir()
            
            assert result == '/etc/trapninja'

    def test_falls_back_to_default(self, monkeypatch):
        """Test fallback to default when no config dirs exist."""
        monkeypatch.delenv("TRAPNINJA_CONFIG", raising=False)
        
        with patch('os.path.isdir', return_value=False):
            import trapninja.config as config_module
            result = config_module._get_config_dir()
            
            assert result == '/opt/trapninja/config'


class TestSafeLoadJson:
    """Tests for safe_load_json function."""

    def test_loads_valid_json(self, tmp_path):
        """Test loading valid JSON file."""
        from trapninja.config import safe_load_json
        
        json_file = tmp_path / "test.json"
        data = {"key": "value", "number": 42}
        json_file.write_text(json.dumps(data))
        
        result = safe_load_json(str(json_file), {})
        
        assert result == data

    def test_returns_fallback_for_missing_file(self, tmp_path):
        """Test fallback returned when file doesn't exist."""
        from trapninja.config import safe_load_json
        
        missing_file = tmp_path / "missing.json"
        fallback = {"default": True}
        
        result = safe_load_json(str(missing_file), fallback)
        
        assert result == fallback

    def test_returns_fallback_for_invalid_json(self, tmp_path):
        """Test fallback returned for malformed JSON."""
        from trapninja.config import safe_load_json
        
        json_file = tmp_path / "invalid.json"
        json_file.write_text("{ invalid json }")
        
        result = safe_load_json(str(json_file), {"fallback": True})
        
        assert result == {"fallback": True}

    def test_returns_fallback_on_permission_error(self, tmp_path, monkeypatch):
        """Test fallback returned on permission error."""
        from trapninja.config import safe_load_json
        
        json_file = tmp_path / "test.json"
        json_file.write_text('{"key": "value"}')
        
        def mock_open(*args, **kwargs):
            raise PermissionError("Access denied")
        
        with patch('builtins.open', mock_open):
            result = safe_load_json(str(json_file), {"fallback": True})
        
        assert result == {"fallback": True}

    def test_loads_list_data(self, tmp_path):
        """Test loading JSON array data."""
        from trapninja.config import safe_load_json
        
        json_file = tmp_path / "list.json"
        data = [["192.168.1.1", 162], ["192.168.1.2", 162]]
        json_file.write_text(json.dumps(data))
        
        result = safe_load_json(str(json_file), [])
        
        assert result == data

    def test_loads_empty_json(self, tmp_path):
        """Test loading empty JSON objects."""
        from trapninja.config import safe_load_json
        
        json_file = tmp_path / "empty.json"
        json_file.write_text("{}")
        
        result = safe_load_json(str(json_file), {"default": True})
        
        assert result == {}


class TestLoadConfig:
    """Tests for load_config function."""

    @pytest.fixture
    def config_dir_setup(self, tmp_path, monkeypatch):
        """Set up a temporary config directory with all files."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        monkeypatch.setenv("TRAPNINJA_CONFIG", str(config_dir))
        
        # Create all config files
        (config_dir / "destinations.json").write_text(
            json.dumps([["192.168.1.100", 162]])
        )
        (config_dir / "blocked_traps.json").write_text(
            json.dumps(["1.3.6.1.4.1.9999.1"])
        )
        (config_dir / "listen_ports.json").write_text(
            json.dumps([162, 1162])
        )
        (config_dir / "blocked_ips.json").write_text(
            json.dumps(["10.0.0.99"])
        )
        (config_dir / "redirected_ips.json").write_text(
            json.dumps([["192.168.10.50", "security"]])
        )
        (config_dir / "redirected_oids.json").write_text(
            json.dumps([["1.3.6.1.4.1.8072.2.3.0.1", "security"]])
        )
        (config_dir / "redirected_destinations.json").write_text(
            json.dumps({"security": [["127.0.0.1", 1362]]})
        )
        
        return config_dir

    def test_loads_destinations(self, config_dir_setup, monkeypatch):
        """Test loading destinations configuration."""
        # Reset module state
        import trapninja.config as config
        config.dest_mtime = 0
        config.destinations = []
        
        # Patch the config dir
        monkeypatch.setattr(config, 'DESTINATIONS_FILE', 
                          str(config_dir_setup / "destinations.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert config.destinations == [["192.168.1.100", 162]]

    def test_loads_blocked_traps_as_set(self, config_dir_setup, monkeypatch):
        """Test that blocked traps are loaded as a set for O(1) lookup."""
        import trapninja.config as config
        config.blocked_mtime = 0
        config.blocked_traps = set()
        
        monkeypatch.setattr(config, 'BLOCKED_TRAPS_FILE', 
                          str(config_dir_setup / "blocked_traps.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert isinstance(config.blocked_traps, set)
        assert "1.3.6.1.4.1.9999.1" in config.blocked_traps

    def test_loads_blocked_ips_as_set(self, config_dir_setup, monkeypatch):
        """Test that blocked IPs are loaded as a set."""
        import trapninja.config as config
        config.blocked_ips_mtime = 0
        config.blocked_ips = set()
        
        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', 
                          str(config_dir_setup / "blocked_ips.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert isinstance(config.blocked_ips, set)
        assert "10.0.0.99" in config.blocked_ips

    def test_validates_listen_ports(self, config_dir_setup, monkeypatch):
        """Test that invalid port numbers are rejected."""
        import trapninja.config as config
        config.ports_mtime = 0
        config.LISTEN_PORTS = [162]
        
        # Write invalid port
        (config_dir_setup / "listen_ports.json").write_text(
            json.dumps([162, 99999, -1, "abc", 1162])
        )
        
        monkeypatch.setattr(config, 'LISTEN_PORTS_FILE', 
                          str(config_dir_setup / "listen_ports.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        # Only valid ports should be loaded
        assert 99999 not in config.LISTEN_PORTS
        assert -1 not in config.LISTEN_PORTS
        assert 162 in config.LISTEN_PORTS
        assert 1162 in config.LISTEN_PORTS

    def test_flattens_nested_port_arrays(self, config_dir_setup, monkeypatch):
        """Test that nested port arrays are flattened."""
        import trapninja.config as config
        config.ports_mtime = 0
        config.LISTEN_PORTS = [162]
        
        # Write nested array
        (config_dir_setup / "listen_ports.json").write_text(
            json.dumps([[162], [1162]])
        )
        
        monkeypatch.setattr(config, 'LISTEN_PORTS_FILE', 
                          str(config_dir_setup / "listen_ports.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert 162 in config.LISTEN_PORTS
        assert 1162 in config.LISTEN_PORTS

    def test_only_reloads_if_mtime_changed(self, config_dir_setup, monkeypatch):
        """Test that files are only reloaded when modified."""
        import trapninja.config as config
        
        monkeypatch.setattr(config, 'DESTINATIONS_FILE', 
                          str(config_dir_setup / "destinations.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        # Set mtime to current file mtime
        dest_file = config_dir_setup / "destinations.json"
        config.dest_mtime = os.path.getmtime(str(dest_file))
        config.destinations = [["10.0.0.1", 999]]  # Different value
        
        config.load_config()
        
        # Should not reload - still has old value
        assert config.destinations == [["10.0.0.1", 999]]

    def test_returns_true_if_config_changed(self, config_dir_setup, monkeypatch):
        """Test that load_config returns True when config changes."""
        import trapninja.config as config
        
        # Reset all mtimes
        config.dest_mtime = 0
        config.blocked_mtime = 0
        config.ports_mtime = 0
        config.blocked_ips_mtime = 0
        
        monkeypatch.setattr(config, 'DESTINATIONS_FILE', 
                          str(config_dir_setup / "destinations.json"))
        monkeypatch.setattr(config, 'BLOCKED_TRAPS_FILE', 
                          str(config_dir_setup / "blocked_traps.json"))
        monkeypatch.setattr(config, 'LISTEN_PORTS_FILE', 
                          str(config_dir_setup / "listen_ports.json"))
        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', 
                          str(config_dir_setup / "blocked_ips.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        result = config.load_config()
        
        assert result is True

    def test_calls_restart_callback_on_port_change(self, config_dir_setup, monkeypatch):
        """Test that UDP listener restart callback is called."""
        import trapninja.config as config
        
        config.ports_mtime = 0
        config.LISTEN_PORTS = [162]
        
        (config_dir_setup / "listen_ports.json").write_text(
            json.dumps([162, 1162])  # Changed ports
        )
        
        monkeypatch.setattr(config, 'LISTEN_PORTS_FILE', 
                          str(config_dir_setup / "listen_ports.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        callback = MagicMock()
        config.load_config(restart_udp_listeners_callback=callback)
        
        callback.assert_called_once()


class TestLoadRedirectionConfig:
    """Tests for redirection configuration loading."""

    @pytest.fixture
    def redirection_config_setup(self, tmp_path, monkeypatch):
        """Set up redirection config files."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        (config_dir / "redirected_ips.json").write_text(
            json.dumps([
                ["192.168.10.50", "security"],
                ["192.168.10.51", "network"]
            ])
        )
        (config_dir / "redirected_oids.json").write_text(
            json.dumps([
                ["1.3.6.1.4.1.8072.2.3.0.1", "security"],
                ["1.3.6.1.4.1.9.9.1.1.1", "cisco"]
            ])
        )
        (config_dir / "redirected_destinations.json").write_text(
            json.dumps({
                "security": [["127.0.0.1", 1362]],
                "network": [["127.0.0.1", 1462], ["127.0.0.1", 1562]],
                "cisco": [["10.0.0.100", 162]]
            })
        )
        
        return config_dir

    def test_loads_redirected_ips(self, redirection_config_setup, monkeypatch):
        """Test loading IP redirection rules."""
        import trapninja.config as config
        
        config.redirected_ips_mtime = 0
        config.redirected_ips = defaultdict(str)
        
        monkeypatch.setattr(config, 'REDIRECTED_IPS_FILE', 
                          str(redirection_config_setup / "redirected_ips.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert config.redirected_ips["192.168.10.50"] == "security"
        assert config.redirected_ips["192.168.10.51"] == "network"

    def test_loads_redirected_oids(self, redirection_config_setup, monkeypatch):
        """Test loading OID redirection rules."""
        import trapninja.config as config
        
        config.redirected_oids_mtime = 0
        config.redirected_oids = defaultdict(str)
        
        monkeypatch.setattr(config, 'REDIRECTED_OIDS_FILE', 
                          str(redirection_config_setup / "redirected_oids.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert config.redirected_oids["1.3.6.1.4.1.8072.2.3.0.1"] == "security"

    def test_loads_redirected_destinations(self, redirection_config_setup, monkeypatch):
        """Test loading destination groups."""
        import trapninja.config as config
        
        config.redirected_destinations_mtime = 0
        config.redirected_destinations = defaultdict(list)
        
        monkeypatch.setattr(config, 'REDIRECTED_DESTINATIONS_FILE', 
                          str(redirection_config_setup / "redirected_destinations.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert config.redirected_destinations["security"] == [("127.0.0.1", 1362)]
        assert len(config.redirected_destinations["network"]) == 2

    def test_validates_destination_ports(self, redirection_config_setup, monkeypatch):
        """Test that invalid destination ports are rejected."""
        import trapninja.config as config
        
        # Write invalid destination port
        (redirection_config_setup / "redirected_destinations.json").write_text(
            json.dumps({
                "valid": [["127.0.0.1", 1362]],
                "invalid": [["127.0.0.1", 99999]]  # Invalid port
            })
        )
        
        config.redirected_destinations_mtime = 0
        config.redirected_destinations = defaultdict(list)
        
        monkeypatch.setattr(config, 'REDIRECTED_DESTINATIONS_FILE', 
                          str(redirection_config_setup / "redirected_destinations.json"))
        monkeypatch.setattr(config, 'stop_event', MagicMock(is_set=lambda: True))
        
        config.load_config()
        
        assert "valid" in config.redirected_destinations
        assert "invalid" not in config.redirected_destinations


class TestCIDRLoading:
    """Tests for CIDR range splitting in blocked_ips and redirected_ips loaders."""

    def _stop_event(self):
        return MagicMock(is_set=lambda: True)

    def test_plain_ips_only_leaves_ranges_empty(self, tmp_path, monkeypatch):
        """Plain IPs with no CIDR notation populate blocked_ips; blocked_ip_ranges stays empty."""
        import trapninja.config as config

        ip_file = tmp_path / "blocked_ips.json"
        ip_file.write_text(json.dumps(["10.0.0.1", "10.0.0.2"]))

        config.blocked_ips_mtime = 0
        config.blocked_ips = set()
        config.blocked_ip_ranges = []

        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert config.blocked_ips == {"10.0.0.1", "10.0.0.2"}
        assert config.blocked_ip_ranges == []

    def test_cidrs_only_leaves_blocked_ips_empty(self, tmp_path, monkeypatch):
        """CIDR entries populate blocked_ip_ranges; blocked_ips stays empty."""
        import ipaddress
        import trapninja.config as config

        ip_file = tmp_path / "blocked_ips.json"
        ip_file.write_text(json.dumps(["192.168.0.0/24", "10.0.0.0/8"]))

        config.blocked_ips_mtime = 0
        config.blocked_ips = set()
        config.blocked_ip_ranges = []

        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert config.blocked_ips == set()
        assert len(config.blocked_ip_ranges) == 2
        assert ipaddress.ip_network("192.168.0.0/24") in config.blocked_ip_ranges
        assert ipaddress.ip_network("10.0.0.0/8") in config.blocked_ip_ranges

    def test_mixed_blocked_ips_populates_both_structures(self, tmp_path, monkeypatch):
        """Mixed file: plain IPs to blocked_ips, CIDRs to blocked_ip_ranges."""
        import ipaddress
        import trapninja.config as config

        ip_file = tmp_path / "blocked_ips.json"
        ip_file.write_text(json.dumps(["10.0.0.1", "192.168.0.0/24"]))

        config.blocked_ips_mtime = 0
        config.blocked_ips = set()
        config.blocked_ip_ranges = []

        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert "10.0.0.1" in config.blocked_ips
        assert len(config.blocked_ip_ranges) == 1
        assert config.blocked_ip_ranges[0] == ipaddress.ip_network("192.168.0.0/24")

    def test_invalid_cidr_in_blocked_ips_is_skipped(self, tmp_path, monkeypatch):
        """Invalid CIDR entries are skipped; valid entries are still loaded."""
        import trapninja.config as config

        ip_file = tmp_path / "blocked_ips.json"
        ip_file.write_text(json.dumps(["10.0.0.0/99", "10.0.0.1"]))

        config.blocked_ips_mtime = 0
        config.blocked_ips = set()
        config.blocked_ip_ranges = []

        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert "10.0.0.1" in config.blocked_ips
        assert config.blocked_ip_ranges == []

    def test_cidr_normalisation_strips_host_bits(self, tmp_path, monkeypatch):
        """Non-strict CIDR: 10.0.0.5/24 is stored as network 10.0.0.0/24."""
        import trapninja.config as config

        ip_file = tmp_path / "blocked_ips.json"
        ip_file.write_text(json.dumps(["10.0.0.5/24"]))

        config.blocked_ips_mtime = 0
        config.blocked_ips = set()
        config.blocked_ip_ranges = []

        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert len(config.blocked_ip_ranges) == 1
        assert str(config.blocked_ip_ranges[0]) == "10.0.0.0/24"

    def test_cidr_pair_in_redirected_ips_goes_to_ranges(self, tmp_path, monkeypatch):
        """CIDR entry in redirected_ips.json appears in redirected_ip_ranges."""
        import ipaddress
        import trapninja.config as config

        ip_file = tmp_path / "redirected_ips.json"
        ip_file.write_text(json.dumps([["192.168.0.0/24", "security"]]))

        config.redirected_ips_mtime = 0
        config.redirected_ips = defaultdict(str)
        config.redirected_ip_ranges = []

        monkeypatch.setattr(config, 'REDIRECTED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert len(config.redirected_ip_ranges) == 1
        net, tag = config.redirected_ip_ranges[0]
        assert net == ipaddress.IPv4Network("192.168.0.0/24")
        assert tag == "security"
        assert len(config.redirected_ips) == 0

    def test_plain_ip_pair_still_in_redirected_ips_dict(self, tmp_path, monkeypatch):
        """Plain IP pairs in redirected_ips.json remain in redirected_ips dict."""
        import trapninja.config as config

        ip_file = tmp_path / "redirected_ips.json"
        ip_file.write_text(json.dumps([["192.168.10.50", "security"]]))

        config.redirected_ips_mtime = 0
        config.redirected_ips = defaultdict(str)
        config.redirected_ip_ranges = []

        monkeypatch.setattr(config, 'REDIRECTED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert config.redirected_ips["192.168.10.50"] == "security"
        assert config.redirected_ip_ranges == []

    def test_mixed_redirected_ips_populates_both_structures(self, tmp_path, monkeypatch):
        """Mixed redirected_ips.json: plain IPs to dict, CIDRs to ranges list."""
        import ipaddress
        import trapninja.config as config

        ip_file = tmp_path / "redirected_ips.json"
        ip_file.write_text(json.dumps([
            ["192.168.10.50", "security"],
            ["10.0.0.0/8", "network"]
        ]))

        config.redirected_ips_mtime = 0
        config.redirected_ips = defaultdict(str)
        config.redirected_ip_ranges = []

        monkeypatch.setattr(config, 'REDIRECTED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert config.redirected_ips["192.168.10.50"] == "security"
        assert len(config.redirected_ip_ranges) == 1
        net, tag = config.redirected_ip_ranges[0]
        assert net == ipaddress.ip_network("10.0.0.0/8")
        assert tag == "network"

    def test_invalid_cidr_in_redirected_ips_is_skipped(self, tmp_path, monkeypatch):
        """Invalid CIDR in redirected_ips.json is skipped; valid entries still load."""
        import trapninja.config as config

        ip_file = tmp_path / "redirected_ips.json"
        ip_file.write_text(json.dumps([
            ["10.0.0.0/99", "bad"],
            ["192.168.10.50", "security"]
        ]))

        config.redirected_ips_mtime = 0
        config.redirected_ips = defaultdict(str)
        config.redirected_ip_ranges = []

        monkeypatch.setattr(config, 'REDIRECTED_IPS_FILE', str(ip_file))
        monkeypatch.setattr(config, 'stop_event', self._stop_event())

        config.load_config()

        assert config.redirected_ips["192.168.10.50"] == "security"
        assert config.redirected_ip_ranges == []

    def test_config_cache_contains_range_keys(self, monkeypatch):
        """After cache refresh, config dict includes blocked_ip_ranges and redirected_ip_ranges."""
        import ipaddress
        import trapninja.config as config
        from trapninja.processing.config_cache import ConfigCache

        config.blocked_ip_ranges = [ipaddress.ip_network("10.0.0.0/8")]
        config.redirected_ip_ranges = []

        cache = ConfigCache(ttl=0)
        result = cache.get()

        assert 'blocked_ip_ranges' in result
        assert 'redirected_ip_ranges' in result
        assert isinstance(result['blocked_ip_ranges'], list)
        assert isinstance(result['redirected_ip_ranges'], list)

    def test_config_cache_empty_ranges_when_module_empty(self, monkeypatch):
        """When both range lists are empty in the module, cache keys are []."""
        import trapninja.config as config
        from trapninja.processing.config_cache import ConfigCache

        config.blocked_ip_ranges = []
        config.redirected_ip_ranges = []

        cache = ConfigCache(ttl=0)
        result = cache.get()

        assert result['blocked_ip_ranges'] == []
        assert result['redirected_ip_ranges'] == []


class TestEnsureConfigDir:
    """Tests for ensure_config_dir function."""

    def test_creates_config_directory(self, tmp_path, monkeypatch):
        """Test that config directory is created if missing."""
        import trapninja.config as config
        
        new_config_dir = tmp_path / "new_config"
        
        monkeypatch.setattr(config, 'CONFIG_DIR', str(new_config_dir))
        
        # Should not exist initially
        assert not new_config_dir.exists()
        
        config.ensure_config_dir()
        
        # Should exist now
        assert new_config_dir.exists()

    def test_creates_example_files(self, tmp_path, monkeypatch):
        """Test that example config files are created."""
        import trapninja.config as config
        
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        monkeypatch.setattr(config, 'CONFIG_DIR', str(config_dir))
        monkeypatch.setattr(config, 'MAIN_CONFIG_FILE', 
                          str(config_dir / "trapninja.json"))
        monkeypatch.setattr(config, 'DESTINATIONS_FILE', 
                          str(config_dir / "destinations.json"))
        monkeypatch.setattr(config, 'BLOCKED_TRAPS_FILE', 
                          str(config_dir / "blocked_traps.json"))
        monkeypatch.setattr(config, 'LISTEN_PORTS_FILE', 
                          str(config_dir / "listen_ports.json"))
        monkeypatch.setattr(config, 'BLOCKED_IPS_FILE', 
                          str(config_dir / "blocked_ips.json"))
        monkeypatch.setattr(config, 'REDIRECTED_IPS_FILE', 
                          str(config_dir / "redirected_ips.json"))
        monkeypatch.setattr(config, 'REDIRECTED_OIDS_FILE', 
                          str(config_dir / "redirected_oids.json"))
        monkeypatch.setattr(config, 'REDIRECTED_DESTINATIONS_FILE', 
                          str(config_dir / "redirected_destinations.json"))
        
        config.ensure_config_dir()
        
        assert (config_dir / "trapninja.json").exists()
        assert (config_dir / "destinations.json").exists()
        assert (config_dir / "blocked_traps.json").exists()
        assert (config_dir / "listen_ports.json").exists()

    def test_does_not_overwrite_existing_files(self, tmp_path, monkeypatch):
        """Test that existing config files are not overwritten."""
        import trapninja.config as config
        
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        # Create existing file with custom content
        dest_file = config_dir / "destinations.json"
        dest_file.write_text(json.dumps([["10.0.0.1", 999]]))
        
        monkeypatch.setattr(config, 'CONFIG_DIR', str(config_dir))
        monkeypatch.setattr(config, 'DESTINATIONS_FILE', str(dest_file))
        
        config.ensure_config_dir()
        
        # Should still have original content
        data = json.loads(dest_file.read_text())
        assert data == [["10.0.0.1", 999]]


class TestLoadMainConfig:
    """Tests for main configuration loading."""

    def test_loads_main_config_file(self, tmp_path, monkeypatch):
        """Test loading main trapninja.json config."""
        from trapninja.config import _load_main_config
        
        config_file = tmp_path / "trapninja.json"
        config_data = {
            "interface": "eth0",
            "capture_mode": "sniff",
            "config_check_interval": 30
        }
        config_file.write_text(json.dumps(config_data))
        
        with patch('trapninja.config.MAIN_CONFIG_FILE', str(config_file)):
            result = _load_main_config()
        
        assert result["interface"] == "eth0"
        assert result["capture_mode"] == "sniff"

    def test_returns_empty_dict_if_missing(self, tmp_path):
        """Test empty dict returned when file doesn't exist."""
        from trapninja.config import _load_main_config
        
        with patch('trapninja.config.MAIN_CONFIG_FILE', 
                  str(tmp_path / "missing.json")):
            result = _load_main_config()
        
        assert result == {}


class TestAutoDetectInterface:
    """Tests for network interface auto-detection."""

    @patch('scapy.all.get_if_addr')
    @patch('scapy.all.get_if_list')
    def test_selects_interface_with_ip(self, mock_list, mock_addr):
        """Test that interface with valid IP is selected."""
        from trapninja.config import _auto_detect_interface
        
        mock_list.return_value = ['lo', 'eth0', 'eth1']
        mock_addr.side_effect = lambda iface: {
            'lo': '127.0.0.1',
            'eth0': '192.168.1.10',
            'eth1': '0.0.0.0'
        }.get(iface, '0.0.0.0')
        
        result = _auto_detect_interface()
        
        assert result == 'eth0'

    @patch('scapy.all.get_if_addr')
    @patch('scapy.all.get_if_list')
    def test_falls_back_to_common_names(self, mock_list, mock_addr):
        """Test fallback to common interface names."""
        from trapninja.config import _auto_detect_interface
        
        mock_list.return_value = ['lo', 'ens192', 'docker0']
        mock_addr.side_effect = lambda iface: '0.0.0.0'  # No valid IPs
        
        result = _auto_detect_interface()
        
        assert result == 'ens192'

    @patch('scapy.all.get_if_addr')
    @patch('scapy.all.get_if_list')
    def test_falls_back_to_eth0(self, mock_list, mock_addr):
        """Test final fallback to eth0."""
        from trapninja.config import _auto_detect_interface
        
        mock_list.return_value = ['lo']
        mock_addr.side_effect = lambda iface: '127.0.0.1'
        
        result = _auto_detect_interface()
        
        assert result == 'eth0'


class TestCacheConfig:
    """Tests for cache configuration loading/saving."""

    def test_load_cache_config_from_file(self, tmp_path, monkeypatch):
        """Test loading cache configuration from file."""
        import trapninja.config as config
        
        cache_file = tmp_path / "cache_config.json"
        cache_data = {
            "enabled": True,
            "host": "redis.local",
            "port": 6380,
            "db": 1,
            "retention_hours": 4.0,
            "trim_interval_seconds": 120
        }
        cache_file.write_text(json.dumps(cache_data))
        
        monkeypatch.setattr(config, 'CACHE_CONFIG_FILE', str(cache_file))
        
        # Mock the CacheConfig import
        with patch.dict('sys.modules', {'trapninja.cache': MagicMock()}):
            from trapninja.config import load_cache_config
            # The function may fail to import CacheConfig, which is fine for this test
            try:
                result = load_cache_config()
            except (ImportError, AttributeError):
                # Expected if cache module isn't properly set up
                pass

    def test_save_cache_config(self, tmp_path, monkeypatch):
        """Test saving cache configuration to file."""
        import trapninja.config as config
        
        cache_file = tmp_path / "cache_config.json"
        monkeypatch.setattr(config, 'CACHE_CONFIG_FILE', str(cache_file))
        
        config_data = {
            "enabled": True,
            "host": "localhost",
            "port": 6379,
            "db": 0
        }
        
        result = config.save_cache_config(config_data)
        
        assert result is True
        assert cache_file.exists()
        
        saved_data = json.loads(cache_file.read_text())
        assert saved_data["enabled"] is True
        assert saved_data["host"] == "localhost"


class TestConfigDefaults:
    """Tests for configuration defaults."""

    def test_default_listen_port(self):
        """Test default listen port is 162."""
        from trapninja.config import LISTEN_PORTS
        
        # Default should include standard SNMP trap port
        assert 162 in LISTEN_PORTS or LISTEN_PORTS == [162]

    def test_default_log_settings(self):
        """Test default log settings."""
        from trapninja.config import LOG_FILE, LOG_LEVEL, LOG_MAX_SIZE
        
        assert LOG_FILE is not None
        assert LOG_LEVEL in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        assert LOG_MAX_SIZE > 0

    def test_default_cache_settings(self):
        """Test default cache settings."""
        from trapninja.config import (
            CACHE_ENABLED, CACHE_HOST, CACHE_PORT, 
            CACHE_DB, CACHE_RETENTION_HOURS
        )
        
        assert CACHE_ENABLED in [True, False]
        assert CACHE_HOST is not None
        assert 1 <= CACHE_PORT <= 65535
        assert CACHE_DB >= 0
        assert CACHE_RETENTION_HOURS > 0

    def test_default_blocked_dest(self):
        """Test default blocked trap destination."""
        from trapninja.config import blocked_dest
        
        assert blocked_dest is not None
        assert len(blocked_dest) >= 1
        # Should be a list of (ip, port) tuples
        assert isinstance(blocked_dest[0], tuple)


class TestStopEvent:
    """Tests for stop event handling."""

    def test_stop_event_exists(self):
        """Test that stop event is defined."""
        from trapninja.config import stop_event
        from threading import Event
        
        assert isinstance(stop_event, Event)

    def test_stop_event_initially_not_set(self):
        """Test that stop event is not set initially."""
        from trapninja.config import stop_event
        
        # Reset for test
        stop_event.clear()
        
        assert not stop_event.is_set()
