#!/usr/bin/env python3
"""
Tests for TrapNinja CLI Command Base Classes

Tests ConfigFileIO, ConfigListManager, ConfigPairListManager,
and ConfigGroupManager.

Author: TrapNinja Team
"""

import json
import os
import tempfile
import threading
import pytest
from unittest.mock import patch, MagicMock

from trapninja.cli.command_base import (
    ConfigFileIO,
    ConfigListManager,
    ConfigPairListManager,
    ConfigGroupManager,
    config_io,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def tmp_dir(tmp_path):
    """Provide a temporary directory for config files."""
    return str(tmp_path)


@pytest.fixture
def io():
    """Fresh ConfigFileIO instance per test."""
    return ConfigFileIO()


@pytest.fixture
def list_file(tmp_dir):
    """Path to a list-based config file."""
    return os.path.join(tmp_dir, "blocked_ips.json")


@pytest.fixture
def pair_file(tmp_dir):
    """Path to a pair-list config file."""
    return os.path.join(tmp_dir, "redirected_ips.json")


@pytest.fixture
def dest_file(tmp_dir):
    """Path to a redirect destinations config file."""
    return os.path.join(tmp_dir, "redirect_destinations.json")


@pytest.fixture
def group_file(tmp_dir):
    """Path to a group-based config file."""
    return os.path.join(tmp_dir, "redirect_destinations.json")


def dummy_ip_validator(value):
    """Simple IP validator for testing - accepts dotted quad format."""
    parts = value.split('.')
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return value
        except ValueError:
            pass
    return None


def dummy_oid_validator(value):
    """Simple OID validator for testing - accepts dot-separated digits."""
    if value and all(c.isdigit() or c == '.' for c in value):
        return value
    return None


def dummy_tag_validator(value):
    """Simple tag validator for testing - accepts alphanumeric + underscore."""
    if value and all(c.isalnum() or c in '_-' for c in value):
        return value
    return None


def dummy_port_validator(value):
    """Simple port validator for testing."""
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return port
    except (ValueError, TypeError):
        pass
    return None


# =============================================================================
# ConfigFileIO TESTS
# =============================================================================

class TestConfigFileIO:
    """Tests for the core JSON file I/O layer."""

    def test_load_nonexistent_returns_default(self, io, tmp_dir):
        path = os.path.join(tmp_dir, "does_not_exist.json")
        assert io.load(path, []) == []
        assert io.load(path, {}) == {}
        assert io.load(path, "fallback") == "fallback"

    def test_load_default_is_empty_list(self, io, tmp_dir):
        path = os.path.join(tmp_dir, "missing.json")
        assert io.load(path) == []

    def test_save_and_load(self, io, list_file):
        data = ["10.0.0.1", "10.0.0.2"]
        assert io.save(list_file, data) is True
        assert io.load(list_file) == data

    def test_save_dict(self, io, group_file):
        data = {"security": [["10.0.0.1", 162]]}
        assert io.save(group_file, data) is True
        assert io.load(group_file) == data

    def test_save_creates_valid_json(self, io, list_file):
        io.save(list_file, [1, 2, 3])
        with open(list_file, 'r') as f:
            assert json.load(f) == [1, 2, 3]

    def test_save_is_indented(self, io, list_file):
        io.save(list_file, {"a": 1})
        with open(list_file, 'r') as f:
            content = f.read()
        assert "  " in content  # indent=2

    def test_load_caches_result(self, io, list_file):
        io.save(list_file, ["cached"])
        result1 = io.load(list_file)
        # Modify file directly (bypassing cache)
        with open(list_file, 'w') as f:
            json.dump(["modified"], f)
        result2 = io.load(list_file)
        # Should still return cached value
        assert result2 == ["cached"]

    def test_save_updates_cache(self, io, list_file):
        io.save(list_file, ["v1"])
        assert io.load(list_file) == ["v1"]
        io.save(list_file, ["v2"])
        assert io.load(list_file) == ["v2"]

    def test_invalidate_specific(self, io, list_file):
        io.save(list_file, ["cached"])
        io.invalidate(list_file)
        # Modify file directly
        with open(list_file, 'w') as f:
            json.dump(["fresh"], f)
        assert io.load(list_file) == ["fresh"]

    def test_invalidate_all(self, io, tmp_dir):
        f1 = os.path.join(tmp_dir, "a.json")
        f2 = os.path.join(tmp_dir, "b.json")
        io.save(f1, ["a"])
        io.save(f2, ["b"])
        io.invalidate()
        # Modify both
        with open(f1, 'w') as f:
            json.dump(["aa"], f)
        with open(f2, 'w') as f:
            json.dump(["bb"], f)
        assert io.load(f1) == ["aa"]
        assert io.load(f2) == ["bb"]

    def test_load_corrupt_json_returns_default(self, io, list_file):
        with open(list_file, 'w') as f:
            f.write("{corrupt json!!!}")
        assert io.load(list_file, []) == []

    def test_save_cleans_up_temp_on_error(self, io, tmp_dir):
        # Try to save to a directory that doesn't exist
        bad_path = os.path.join(tmp_dir, "nonexistent_dir", "file.json")
        result = io.save(bad_path, ["data"])
        assert result is False
        # Temp file should not linger
        assert not os.path.exists(f"{bad_path}.tmp")

    def test_thread_safety_concurrent_saves(self, io, list_file):
        """Verify concurrent saves don't corrupt the file."""
        errors = []

        def writer(value):
            try:
                for _ in range(20):
                    io.save(list_file, [value])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # File should be valid JSON
        with open(list_file, 'r') as f:
            data = json.load(f)
        assert isinstance(data, list)


# =============================================================================
# ConfigListManager TESTS
# =============================================================================

class TestConfigListManager:
    """Tests for the list-based config manager (block/unblock)."""

    @pytest.fixture
    def manager(self, list_file):
        return ConfigListManager(
            file_path_getter=lambda: list_file,
            validator=dummy_ip_validator,
            item_name="IP address",
        )

    def test_add_valid_item(self, manager, list_file, capsys):
        assert manager.add("10.0.0.1") is True
        assert "added to blocked list" in capsys.readouterr().out
        with open(list_file) as f:
            assert "10.0.0.1" in json.load(f)

    def test_add_duplicate_is_idempotent(self, manager, list_file, capsys):
        manager.add("10.0.0.1")
        assert manager.add("10.0.0.1") is True
        assert "already in blocked list" in capsys.readouterr().out
        with open(list_file) as f:
            data = json.load(f)
        assert data.count("10.0.0.1") == 1

    def test_add_invalid_returns_false(self, manager):
        assert manager.add("not_an_ip") is False

    def test_remove_existing_item(self, manager, list_file, capsys):
        manager.add("10.0.0.1")
        capsys.readouterr()  # clear
        assert manager.remove("10.0.0.1") is True
        assert "removed from blocked list" in capsys.readouterr().out
        with open(list_file) as f:
            assert "10.0.0.1" not in json.load(f)

    def test_remove_nonexistent_returns_true(self, manager, capsys):
        assert manager.remove("10.0.0.1") is True
        assert "is not in blocked list" in capsys.readouterr().out

    def test_remove_invalid_returns_false(self, manager):
        assert manager.remove("not_an_ip") is False

    def test_list_empty(self, manager, capsys):
        assert manager.list_all() is True
        assert "No IP address" in capsys.readouterr().out

    def test_list_with_items(self, manager, capsys):
        manager.add("10.0.0.2")
        manager.add("10.0.0.1")
        capsys.readouterr()  # clear
        assert manager.list_all() is True
        output = capsys.readouterr().out
        assert "10.0.0.1" in output
        assert "10.0.0.2" in output

    def test_list_items_sorted(self, manager, capsys):
        manager.add("10.0.0.3")
        manager.add("10.0.0.1")
        manager.add("10.0.0.2")
        capsys.readouterr()
        manager.list_all()
        output = capsys.readouterr().out
        lines = [l.strip() for l in output.splitlines() if l.strip().startswith("- ")]
        assert lines == ["- 10.0.0.1", "- 10.0.0.2", "- 10.0.0.3"]

    def test_handles_corrupted_non_list_data(self, manager, list_file):
        # Write a dict instead of a list
        with open(list_file, 'w') as f:
            json.dump({"not": "a_list"}, f)
        config_io.invalidate(list_file)
        # add should handle gracefully
        assert manager.add("10.0.0.1") is True


# =============================================================================
# ConfigPairListManager TESTS
# =============================================================================

class TestConfigPairListManager:
    """Tests for pair-list redirection manager."""

    @pytest.fixture
    def manager(self, pair_file, dest_file):
        # Pre-populate destinations so tag validation passes
        with open(dest_file, 'w') as f:
            json.dump({"security": [["10.1.1.100", 162]], "voice": []}, f)
        return ConfigPairListManager(
            file_path_getter=lambda: pair_file,
            dest_file_path_getter=lambda: dest_file,
            key_validator=dummy_ip_validator,
            tag_validator=dummy_tag_validator,
            key_name="IP",
        )

    def test_add_new_rule(self, manager, pair_file, capsys):
        assert manager.add("10.0.0.1", "security") is True
        assert "will be redirected" in capsys.readouterr().out
        with open(pair_file) as f:
            data = json.load(f)
        assert ["10.0.0.1", "security"] in data

    def test_add_duplicate_is_idempotent(self, manager, capsys):
        manager.add("10.0.0.1", "security")
        capsys.readouterr()
        assert manager.add("10.0.0.1", "security") is True
        assert "already redirected" in capsys.readouterr().out

    def test_add_updates_existing_tag(self, manager, capsys):
        manager.add("10.0.0.1", "security")
        capsys.readouterr()
        assert manager.add("10.0.0.1", "voice") is True
        output = capsys.readouterr().out
        assert "Updated" in output
        assert "'security' -> 'voice'" in output

    def test_add_invalid_tag_fails(self, manager, dest_file, capsys):
        # Tag doesn't exist in destinations
        assert manager.add("10.0.0.1", "nonexistent") is False
        assert "not found in redirect destinations" in capsys.readouterr().out

    def test_add_invalid_key_fails(self, manager):
        assert manager.add("bad_ip", "security") is False

    def test_remove_existing(self, manager, capsys):
        manager.add("10.0.0.1", "security")
        capsys.readouterr()
        assert manager.remove("10.0.0.1") is True
        assert "removed from redirection list" in capsys.readouterr().out

    def test_remove_nonexistent(self, manager, capsys):
        assert manager.remove("10.0.0.1") is True
        assert "is not in redirection list" in capsys.readouterr().out

    def test_list_empty(self, manager, capsys):
        assert manager.list_all() is True
        assert "No IPs are currently redirected" in capsys.readouterr().out

    def test_list_with_items(self, manager, capsys):
        manager.add("10.0.0.1", "security")
        manager.add("10.0.0.2", "voice")
        capsys.readouterr()
        manager.list_all()
        output = capsys.readouterr().out
        assert "10.0.0.1" in output
        assert "security" in output
        assert "10.0.0.2" in output
        assert "voice" in output


# =============================================================================
# ConfigGroupManager TESTS
# =============================================================================

class TestConfigGroupManager:
    """Tests for redirect destination group manager."""

    @pytest.fixture
    def manager(self, group_file):
        return ConfigGroupManager(
            file_path_getter=lambda: group_file,
            ip_validator=dummy_ip_validator,
            port_validator=dummy_port_validator,
            tag_validator=dummy_tag_validator,
        )

    def test_add_new_group_and_dest(self, manager, group_file, capsys):
        assert manager.add("security", "10.1.1.100", 162) is True
        assert "Added" in capsys.readouterr().out
        with open(group_file) as f:
            data = json.load(f)
        assert data == {"security": [["10.1.1.100", 162]]}

    def test_add_to_existing_group(self, manager, capsys):
        manager.add("security", "10.1.1.100", 162)
        capsys.readouterr()
        assert manager.add("security", "10.1.1.101", 162) is True
        assert "Added" in capsys.readouterr().out

    def test_add_duplicate_is_idempotent(self, manager, capsys):
        manager.add("security", "10.1.1.100", 162)
        capsys.readouterr()
        assert manager.add("security", "10.1.1.100", 162) is True
        assert "already exists" in capsys.readouterr().out

    def test_add_invalid_ip(self, manager):
        assert manager.add("security", "not_ip", 162) is False

    def test_add_invalid_port(self, manager):
        assert manager.add("security", "10.1.1.100", 99999) is False

    def test_add_invalid_tag(self, manager):
        assert manager.add("", "10.1.1.100", 162) is False

    def test_remove_existing(self, manager, capsys):
        manager.add("security", "10.1.1.100", 162)
        capsys.readouterr()
        assert manager.remove("security", "10.1.1.100", 162) is True
        output = capsys.readouterr().out
        assert "Removed" in output
        assert "group now empty and removed" in output

    def test_remove_keeps_group_with_remaining(self, manager, group_file, capsys):
        manager.add("security", "10.1.1.100", 162)
        manager.add("security", "10.1.1.101", 162)
        capsys.readouterr()
        manager.remove("security", "10.1.1.100", 162)
        with open(group_file) as f:
            data = json.load(f)
        assert "security" in data
        assert len(data["security"]) == 1

    def test_remove_nonexistent_tag(self, manager, capsys):
        assert manager.remove("nosuchtag", "10.0.0.1", 162) is False
        assert "not found" in capsys.readouterr().out

    def test_remove_nonexistent_dest(self, manager, capsys):
        manager.add("security", "10.1.1.100", 162)
        capsys.readouterr()
        assert manager.remove("security", "10.1.1.200", 162) is True
        assert "not found in group" in capsys.readouterr().out

    def test_list_empty(self, manager, capsys):
        assert manager.list_all() is True
        assert "No redirect destination groups" in capsys.readouterr().out

    def test_list_with_groups(self, manager, capsys):
        manager.add("security", "10.1.1.100", 162)
        manager.add("voice", "10.2.2.200", 514)
        capsys.readouterr()
        manager.list_all()
        output = capsys.readouterr().out
        assert "[security]" in output
        assert "10.1.1.100:162" in output
        assert "[voice]" in output
        assert "10.2.2.200:514" in output


# =============================================================================
# BACKWARD COMPATIBILITY TESTS
# =============================================================================

class TestBackwardCompatibility:
    """Ensure the refactored filtering_commands maintains the same API."""

    def test_config_manager_import(self):
        """ConfigManager is still importable from filtering_commands."""
        from trapninja.cli.filtering_commands import ConfigManager, config_manager
        assert config_manager is not None
        assert hasattr(config_manager, 'load_json')
        assert hasattr(config_manager, 'save_json')
        assert hasattr(config_manager, 'invalidate_cache')

    def test_config_manager_delegates_to_config_io(self, tmp_dir):
        from trapninja.cli.filtering_commands import ConfigManager
        cm = ConfigManager()
        path = os.path.join(tmp_dir, "compat_test.json")
        assert cm.save_json(path, [1, 2, 3]) is True
        assert cm.load_json(path) == [1, 2, 3]
        cm.invalidate_cache(path)

    def test_all_public_functions_exist(self):
        """All original public functions are still importable."""
        from trapninja.cli import filtering_commands as fc
        expected = [
            'block_ip', 'unblock_ip', 'list_blocked_ips',
            'block_oid', 'unblock_oid', 'list_blocked_oids',
            'redirect_ip', 'unredirect_ip', 'list_redirected_ips',
            'redirect_oid', 'unredirect_oid', 'list_redirected_oids',
            'add_redirect_destination', 'remove_redirect_destination',
            'list_redirect_destinations',
            'show_redirection_help',
        ]
        for func_name in expected:
            assert hasattr(fc, func_name), f"Missing function: {func_name}"
            assert callable(getattr(fc, func_name)), f"Not callable: {func_name}"
