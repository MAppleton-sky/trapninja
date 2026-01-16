#!/usr/bin/env python3
"""
TrapNinja Test Suite - CLI Parser Tests

Tests for trapninja.cli.parser module - argument parsing.

Author: TrapNinja Team
"""

import pytest
import argparse
from unittest.mock import patch, MagicMock


class TestCreateArgumentParser:
    """Tests for create_argument_parser function."""

    def test_creates_parser(self):
        """Test create_argument_parser returns ArgumentParser."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_prog_name(self):
        """Test parser has correct prog name."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        assert parser.prog == 'trapninja'

    def test_parser_has_subparsers(self):
        """Test parser has subparsers for categories."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        # Check that subparsers exist
        has_subparsers = False
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                has_subparsers = True
                break
        
        assert has_subparsers


class TestCategorySubparsers:
    """Tests for category subparsers."""

    def test_daemon_category_exists(self):
        """Test daemon category exists."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        # Find subparsers
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                if 'daemon' in action.choices:
                    return
        
        pytest.fail("daemon category not found")

    def test_filter_category_exists(self):
        """Test filter category exists."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                if 'filter' in action.choices:
                    return
        
        pytest.fail("filter category not found")

    def test_ha_category_exists(self):
        """Test ha category exists."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                if 'ha' in action.choices:
                    return
        
        pytest.fail("ha category not found")

    def test_snmpv3_category_exists(self):
        """Test snmpv3 category exists."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                if 'snmpv3' in action.choices:
                    return
        
        pytest.fail("snmpv3 category not found")

    def test_cache_category_exists(self):
        """Test cache category exists."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                if 'cache' in action.choices:
                    return
        
        pytest.fail("cache category not found")

    def test_stats_category_exists(self):
        """Test stats category exists."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                if 'stats' in action.choices:
                    return
        
        pytest.fail("stats category not found")


class TestGlobalOptions:
    """Tests for global options."""

    def test_config_dir_option(self):
        """Test --config-dir global option."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--config-dir', '/opt/config'])
        
        assert args.config_dir == '/opt/config'

    def test_log_file_option(self):
        """Test --log-file global option."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--log-file', '/var/log/trap.log'])
        
        assert args.log_file == '/var/log/trap.log'

    def test_debug_option(self):
        """Test --debug global option."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--debug'])
        
        assert args.debug is True

    def test_json_option(self):
        """Test --json global option."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--json'])
        
        assert args.json is True

    def test_yes_option(self):
        """Test --yes/-y global option."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--yes'])
        
        assert args.yes is True

    def test_y_shorthand(self):
        """Test -y shorthand option."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['-y'])
        
        assert args.yes is True


class TestDaemonCommands:
    """Tests for daemon command parsing."""

    def test_daemon_start(self):
        """Test daemon start parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'start'])
        
        assert args.category == 'daemon'
        assert args.command == 'start'

    def test_daemon_stop(self):
        """Test daemon stop parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'stop'])
        
        assert args.category == 'daemon'
        assert args.command == 'stop'

    def test_daemon_status(self):
        """Test daemon status parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'status'])
        
        assert args.category == 'daemon'
        assert args.command == 'status'

    def test_daemon_foreground(self):
        """Test daemon foreground parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'foreground'])
        
        assert args.category == 'daemon'
        assert args.command == 'foreground'

    def test_daemon_start_with_shadow_mode(self):
        """Test daemon start with --shadow-mode."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'start', '--shadow-mode'])
        
        assert args.shadow_mode is True

    def test_daemon_start_with_mirror_mode(self):
        """Test daemon start with --mirror-mode."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['daemon', 'start', '--mirror-mode'])
        
        assert args.mirror_mode is True


class TestFilterCommands:
    """Tests for filter command parsing."""

    def test_filter_block_ip(self):
        """Test filter block-ip parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['filter', 'block-ip', '192.168.1.1'])
        
        assert args.category == 'filter'
        assert args.command == 'block-ip'
        assert args.ip == '192.168.1.1'

    def test_filter_unblock_ip(self):
        """Test filter unblock-ip parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['filter', 'unblock-ip', '10.0.0.1'])
        
        assert args.category == 'filter'
        assert args.command == 'unblock-ip'
        assert args.ip == '10.0.0.1'

    def test_filter_list_blocked_ips(self):
        """Test filter list-blocked-ips parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['filter', 'list-blocked-ips'])
        
        assert args.category == 'filter'
        assert args.command == 'list-blocked-ips'

    def test_filter_block_oid(self):
        """Test filter block-oid parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['filter', 'block-oid', '1.3.6.1.4.1.9'])
        
        assert args.category == 'filter'
        assert args.command == 'block-oid'
        assert args.oid == '1.3.6.1.4.1.9'

    def test_filter_redirect_ip_with_tag(self):
        """Test filter redirect-ip with --tag."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['filter', 'redirect-ip', '10.0.0.1', '--tag', 'noc_team'])
        
        assert args.category == 'filter'
        assert args.command == 'redirect-ip'
        assert args.ip == '10.0.0.1'
        assert args.tag == 'noc_team'


class TestHACommands:
    """Tests for HA command parsing."""

    def test_ha_status(self):
        """Test ha status parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['ha', 'status'])
        
        assert args.category == 'ha'
        assert args.command == 'status'

    def test_ha_configure(self):
        """Test ha configure parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args([
            'ha', 'configure',
            '--mode', 'primary',
            '--peer', '192.168.1.102'
        ])
        
        assert args.category == 'ha'
        assert args.command == 'configure'
        assert args.mode == 'primary'
        assert args.ha_peer_host == '192.168.1.102'

    def test_ha_promote(self):
        """Test ha promote parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['ha', 'promote'])
        
        assert args.category == 'ha'
        assert args.command == 'promote'

    def test_ha_promote_force(self):
        """Test ha promote --force parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['ha', 'promote', '--force'])
        
        assert args.force is True

    def test_ha_demote(self):
        """Test ha demote parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['ha', 'demote'])
        
        assert args.category == 'ha'
        assert args.command == 'demote'


class TestCacheCommands:
    """Tests for cache command parsing."""

    def test_cache_status(self):
        """Test cache status parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['cache', 'status'])
        
        assert args.category == 'cache'
        assert args.command == 'status'

    def test_cache_query(self):
        """Test cache query parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        # Use = syntax to avoid argparse interpreting -2h as an option
        args = parser.parse_args([
            'cache', 'query',
            '--destination', 'default',
            '--from=-2h',
            '--to=now'
        ])
        
        assert args.category == 'cache'
        assert args.command == 'query'
        assert args.destination == 'default'
        assert args.from_time == '-2h'
        assert args.to_time == 'now'

    def test_cache_replay(self):
        """Test cache replay parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args([
            'cache', 'replay',
            '--destination', 'voice_noc',
            '--from=14:30',
            '--to=15:45',
            '--rate-limit', '1000'
        ])
        
        assert args.category == 'cache'
        assert args.command == 'replay'
        assert args.destination == 'voice_noc'
        assert args.rate_limit == 1000

    def test_cache_replay_dry_run(self):
        """Test cache replay --dry-run parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        # Use = syntax to avoid argparse interpreting -1h as an option
        args = parser.parse_args([
            'cache', 'replay',
            '--destination', 'default',
            '--from=-1h',
            '--to=now',
            '--dry-run'
        ])
        
        assert args.dry_run is True

    def test_cache_clear(self):
        """Test cache clear parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['cache', 'clear'])
        
        assert args.category == 'cache'
        assert args.command == 'clear'


class TestStatsCommands:
    """Tests for stats command parsing."""

    def test_stats_summary(self):
        """Test stats summary parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['stats', 'summary'])
        
        assert args.category == 'stats'
        assert args.command == 'summary'

    def test_stats_top_ips(self):
        """Test stats top-ips parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['stats', 'top-ips', '-n', '20'])
        
        assert args.category == 'stats'
        assert args.command == 'top-ips'
        assert args.count == 20

    def test_stats_top_oids_with_sort(self):
        """Test stats top-oids with --sort."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['stats', 'top-oids', '-s', 'rate'])
        
        assert args.category == 'stats'
        assert args.command == 'top-oids'
        assert args.sort == 'rate'

    def test_stats_ip_detail(self):
        """Test stats ip detail parsing."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['stats', 'ip', '10.0.0.1'])
        
        assert args.category == 'stats'
        assert args.command == 'ip'
        assert args.ip == '10.0.0.1'


class TestValidatedTypeConverters:
    """Tests for validated type converters."""

    def test_validated_ip_valid(self):
        """Test validated_ip with valid IP."""
        from trapninja.cli.parser import validated_ip
        
        result = validated_ip("192.168.1.1")
        
        assert result == "192.168.1.1"

    def test_validated_ip_invalid(self):
        """Test validated_ip with invalid IP."""
        from trapninja.cli.parser import validated_ip
        
        with pytest.raises(argparse.ArgumentTypeError):
            validated_ip("invalid.ip")

    def test_validated_oid_valid(self):
        """Test validated_oid with valid OID."""
        from trapninja.cli.parser import validated_oid
        
        result = validated_oid("1.3.6.1.4.1.9")
        
        assert result == "1.3.6.1.4.1.9"

    def test_validated_oid_invalid(self):
        """Test validated_oid with invalid OID."""
        from trapninja.cli.parser import validated_oid
        
        with pytest.raises(argparse.ArgumentTypeError):
            validated_oid("not.valid.oid")

    def test_validated_tag_valid(self):
        """Test validated_tag with valid tag."""
        from trapninja.cli.parser import validated_tag
        
        result = validated_tag("noc_team")
        
        assert result == "noc_team"

    def test_validated_tag_invalid(self):
        """Test validated_tag with invalid tag."""
        from trapninja.cli.parser import validated_tag
        
        with pytest.raises(argparse.ArgumentTypeError):
            validated_tag("invalid tag!")

    def test_validated_port_valid(self):
        """Test validated_port with valid port."""
        from trapninja.cli.parser import validated_port
        
        result = validated_port("162")
        
        assert result == 162

    def test_validated_port_invalid(self):
        """Test validated_port with invalid port."""
        from trapninja.cli.parser import validated_port
        
        with pytest.raises(argparse.ArgumentTypeError):
            validated_port("99999")


class TestTrapNinjaArgumentParser:
    """Tests for TrapNinjaArgumentParser custom class."""

    def test_custom_error_handling(self):
        """Test custom error exits with code 2."""
        from trapninja.cli.parser import TrapNinjaArgumentParser
        
        parser = TrapNinjaArgumentParser()
        
        with pytest.raises(SystemExit) as exc_info:
            parser.error("Test error")
        
        assert exc_info.value.code == 2

    def test_command_category_attribute(self):
        """Test command_category attribute is set."""
        from trapninja.cli.parser import TrapNinjaArgumentParser
        
        parser = TrapNinjaArgumentParser(command_category='test')
        
        assert parser.command_category == 'test'


class TestLegacyArguments:
    """Tests for legacy flat-style argument support."""

    def test_legacy_start(self):
        """Test legacy --start argument."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--start'])
        
        assert args.start is True

    def test_legacy_stop(self):
        """Test legacy --stop argument."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--stop'])
        
        assert args.stop is True

    def test_legacy_status(self):
        """Test legacy --status argument."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--status'])
        
        assert args.status is True

    def test_legacy_block_ip(self):
        """Test legacy --block-ip argument."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--block-ip', '10.0.0.1'])
        
        assert args.block_ip == '10.0.0.1'

    def test_legacy_ha_status(self):
        """Test legacy --ha-status argument."""
        from trapninja.cli.parser import create_argument_parser
        
        parser = create_argument_parser()
        args = parser.parse_args(['--ha-status'])
        
        assert args.ha_status is True
