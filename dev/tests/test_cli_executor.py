#!/usr/bin/env python3
"""
TrapNinja Test Suite - CLI Executor Tests

Tests for trapninja.cli.executor module - command execution routing.

Updated to reflect v0.8.0 Command Registry architecture:
  - Subcommand dispatch is handled by registry.dispatch_subcommand()
  - Legacy dispatch is handled by registry.dispatch_legacy()
  - Per-category _execute_*_command functions have been removed in
    favour of the declarative command registry (registry.py).

Author: TrapNinja Team
"""

import pytest
from argparse import Namespace
from unittest.mock import patch, MagicMock


class TestExecuteCommand:
    """Tests for execute_command function."""

    def test_routes_to_subcommand_handler(self):
        """Test execute_command routes subcommand through registry dispatch."""
        from trapninja.cli.executor import execute_command

        args = Namespace(
            category='daemon',
            command='status',
            foreground_daemon=False,
            # Globals that update_global_config checks:
            interface=None, config_dir=None, log_file=None, pid_file=None,
            log_max_size=None, log_backup_count=None, log_compress=None, ports=None,
        )

        with patch('trapninja.cli.executor.dispatch_subcommand') as mock_dispatch:
            mock_dispatch.return_value = 0

            result = execute_command(args)

            mock_dispatch.assert_called_once_with(args, 'daemon', 'status')
            assert result == 0

    def test_foreground_daemon_handled_first(self):
        """Test --foreground-daemon is handled before routing."""
        from trapninja.cli.executor import execute_command

        args = Namespace(
            category='daemon',
            command='start',
            foreground_daemon=True,
            debug=False,
            shadow_mode=False,
            mirror_mode=False,
            parallel=False,
            capture_mode=None,
            log_traps=None,
            log_level=None,
        )

        with patch('trapninja.cli.executor._execute_foreground_daemon') as mock_fg:
            mock_fg.return_value = 0

            result = execute_command(args)

            mock_fg.assert_called_once_with(args)

    def test_no_category_executes_legacy(self):
        """Test no category falls back to legacy dispatch via registry."""
        from trapninja.cli.executor import execute_command

        args = Namespace(
            category=None,
            command=None,
            foreground_daemon=False,
            start=True,
            # Globals that update_global_config checks:
            interface=None, config_dir=None, log_file=None, pid_file=None,
            log_max_size=None, log_backup_count=None, log_compress=None, ports=None,
        )

        with patch('trapninja.cli.executor.dispatch_legacy') as mock_legacy:
            mock_legacy.return_value = 0

            result = execute_command(args)

            mock_legacy.assert_called_once_with(args)

    def test_no_command_shows_missing_help(self):
        """Test subcommand category with no command shows help."""
        from trapninja.cli.executor import execute_command

        args = Namespace(
            category='filter',
            command=None,
            foreground_daemon=False,
            interface=None, config_dir=None, log_file=None, pid_file=None,
            log_max_size=None, log_backup_count=None, log_compress=None, ports=None,
        )

        with patch('trapninja.cli.executor._show_missing_command_help') as mock_help:
            mock_help.return_value = 1

            result = execute_command(args)

            mock_help.assert_called_once_with('filter')
            assert result == 1

    def test_help_command_shows_category_help(self):
        """Test 'help' as command shows category help."""
        from trapninja.cli.executor import execute_command

        args = Namespace(
            category='daemon',
            command='help',
            foreground_daemon=False,
            interface=None, config_dir=None, log_file=None, pid_file=None,
            log_max_size=None, log_backup_count=None, log_compress=None, ports=None,
        )

        with patch('trapninja.cli.executor._show_category_help') as mock_help:
            mock_help.return_value = 0

            result = execute_command(args)

            mock_help.assert_called_once_with('daemon')
            assert result == 0


class TestRegistrySubcommandDispatch:
    """Tests for dispatch_subcommand through the registry."""

    def test_daemon_start(self):
        """Test daemon start routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(
            shadow_mode=False, mirror_mode=False,
            parallel=False, capture_mode=None, log_traps=None,
        )

        with patch('trapninja.cli.daemon_commands') as mock_daemon:
            mock_daemon.start.return_value = 0

            result = dispatch_subcommand(args, 'daemon', 'start')

            mock_daemon.start.assert_called_once()
            assert result == 0

    def test_daemon_stop(self):
        """Test daemon stop routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.daemon_commands') as mock_daemon:
            mock_daemon.stop.return_value = 0

            result = dispatch_subcommand(args, 'daemon', 'stop')

            mock_daemon.stop.assert_called_once()

    def test_daemon_status(self):
        """Test daemon status routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.daemon_commands') as mock_daemon:
            mock_daemon.status.return_value = 0

            result = dispatch_subcommand(args, 'daemon', 'status')

            mock_daemon.status.assert_called_once()

    def test_unknown_command_returns_one(self, capsys):
        """Test unknown subcommand returns exit code 1."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        result = dispatch_subcommand(args, 'daemon', 'unknown_cmd')

        assert result == 1
        captured = capsys.readouterr()
        assert 'Unknown' in captured.out


class TestRegistryFilterDispatch:
    """Tests for filter command dispatch through registry."""

    def test_filter_block_ip(self):
        """Test filter block-ip routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(ip='10.0.0.1')

        with patch('trapninja.cli.filtering_commands') as mock_filter:
            mock_filter.block_ip.return_value = True

            result = dispatch_subcommand(args, 'filter', 'block-ip')

            mock_filter.block_ip.assert_called_once_with('10.0.0.1')
            assert result == 0  # True → exit 0

    def test_filter_unblock_ip(self):
        """Test filter unblock-ip routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(ip='10.0.0.1')

        with patch('trapninja.cli.filtering_commands') as mock_filter:
            mock_filter.unblock_ip.return_value = True

            result = dispatch_subcommand(args, 'filter', 'unblock-ip')

            mock_filter.unblock_ip.assert_called_once_with('10.0.0.1')

    def test_filter_list_blocked_ips(self):
        """Test filter list-blocked-ips routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.filtering_commands') as mock_filter:
            mock_filter.list_blocked_ips.return_value = True

            result = dispatch_subcommand(args, 'filter', 'list-blocked-ips')

            mock_filter.list_blocked_ips.assert_called_once()

    def test_filter_block_oid(self):
        """Test filter block-oid routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(oid='1.3.6.1.4')

        with patch('trapninja.cli.filtering_commands') as mock_filter:
            mock_filter.block_oid.return_value = True

            result = dispatch_subcommand(args, 'filter', 'block-oid')

            mock_filter.block_oid.assert_called_once_with('1.3.6.1.4')

    def test_filter_redirect_ip(self):
        """Test filter redirect-ip routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(ip='10.0.0.1', tag='noc')

        with patch('trapninja.cli.filtering_commands') as mock_filter:
            mock_filter.redirect_ip.return_value = True

            result = dispatch_subcommand(args, 'filter', 'redirect-ip')

            mock_filter.redirect_ip.assert_called_once_with('10.0.0.1', 'noc')


class TestRegistryHADispatch:
    """Tests for HA command dispatch through registry."""

    def test_ha_status(self):
        """Test ha status routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.ha_commands') as mock_ha:
            mock_ha.show_ha_status.return_value = True

            result = dispatch_subcommand(args, 'ha', 'status')

            mock_ha.show_ha_status.assert_called_once()
            assert result == 0

    def test_ha_configure(self):
        """Test ha configure routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(
            mode='primary',
            ha_peer_host='192.168.1.102',
            priority=100,
            peer_port=8162,
            listen_port=8162,
            ha_mode=None, ha_priority=None,
            ha_peer_port=None, ha_listen_port=None,
        )

        with patch('trapninja.cli.ha_commands') as mock_ha:
            mock_ha.configure_ha.return_value = True

            result = dispatch_subcommand(args, 'ha', 'configure')

            mock_ha.configure_ha.assert_called_once()

    def test_ha_promote(self):
        """Test ha promote routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(force=False)

        with patch('trapninja.cli.ha_commands') as mock_ha:
            mock_ha.promote_to_primary.return_value = True

            result = dispatch_subcommand(args, 'ha', 'promote')

            mock_ha.promote_to_primary.assert_called_once_with(force=False)

    def test_ha_promote_force(self):
        """Test ha promote --force routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(force=True)

        with patch('trapninja.cli.ha_commands') as mock_ha:
            mock_ha.promote_to_primary.return_value = True

            result = dispatch_subcommand(args, 'ha', 'promote')

            mock_ha.promote_to_primary.assert_called_once_with(force=True)

    def test_ha_demote(self):
        """Test ha demote routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.ha_commands') as mock_ha:
            mock_ha.demote_to_secondary.return_value = True

            result = dispatch_subcommand(args, 'ha', 'demote')

            mock_ha.demote_to_secondary.assert_called_once()


class TestRegistryCacheDispatch:
    """Tests for cache command dispatch through registry."""

    def test_cache_status(self):
        """Test cache status routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(verbose=False)

        with patch('trapninja.cli.cache_commands') as mock_cache:
            mock_cache.show_cache_status.return_value = True

            result = dispatch_subcommand(args, 'cache', 'status')

            mock_cache.show_cache_status.assert_called_once()

    def test_cache_query(self):
        """Test cache query routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(
            destination='default',
            from_time='-2h',
            to_time='now',
            limit=20,
        )

        with patch('trapninja.cli.cache_commands') as mock_cache:
            mock_cache.query_cache.return_value = True

            result = dispatch_subcommand(args, 'cache', 'query')

            mock_cache.query_cache.assert_called_once()

    def test_cache_replay(self):
        """Test cache replay routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(
            destination='voice_noc',
            from_time='14:30',
            to_time='15:45',
            rate_limit=500,
            dry_run=False,
            oid_filter=None,
            source_filter=None,
            exclude_oid=None,
            replay_to=None,
            yes=False,
        )

        with patch('trapninja.cli.cache_commands') as mock_cache:
            mock_cache.replay_cache.return_value = True

            result = dispatch_subcommand(args, 'cache', 'replay')

            mock_cache.replay_cache.assert_called_once()

    def test_cache_clear(self):
        """Test cache clear routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(destination='default', yes=True)

        with patch('trapninja.cli.cache_commands') as mock_cache:
            mock_cache.clear_cache.return_value = True

            result = dispatch_subcommand(args, 'cache', 'clear')

            mock_cache.clear_cache.assert_called_once()


class TestRegistryStatsDispatch:
    """Tests for stats command dispatch through registry."""

    def test_stats_summary(self):
        """Test stats summary routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.stats_commands') as mock_stats:
            mock_stats.handle_stats_summary.return_value = 0

            result = dispatch_subcommand(args, 'stats', 'summary')

            mock_stats.handle_stats_summary.assert_called_once_with(args)

    def test_stats_top_ips(self):
        """Test stats top-ips routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.stats_commands') as mock_stats:
            mock_stats.handle_stats_top_ips.return_value = 0

            result = dispatch_subcommand(args, 'stats', 'top-ips')

            mock_stats.handle_stats_top_ips.assert_called_once()

    def test_stats_export(self):
        """Test stats export routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.stats_commands') as mock_stats:
            mock_stats.handle_stats_export.return_value = 0

            result = dispatch_subcommand(args, 'stats', 'export')

            mock_stats.handle_stats_export.assert_called_once()


class TestRegistrySNMPv3Dispatch:
    """Tests for SNMPv3 command dispatch through registry."""

    def test_snmpv3_list_users(self):
        """Test snmpv3 list-users routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.snmpv3_commands') as mock_snmpv3:
            mock_snmpv3.handle_snmpv3_list_users.return_value = 0

            result = dispatch_subcommand(args, 'snmpv3', 'list-users')

            mock_snmpv3.handle_snmpv3_list_users.assert_called_once()

    def test_snmpv3_status(self):
        """Test snmpv3 status routes through registry."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace()

        with patch('trapninja.cli.snmpv3_commands') as mock_snmpv3:
            mock_snmpv3.handle_snmpv3_status.return_value = 0

            result = dispatch_subcommand(args, 'snmpv3', 'status')

            mock_snmpv3.handle_snmpv3_status.assert_called_once()


class TestLegacyDispatch:
    """Tests for legacy flat-style dispatch through registry."""

    def test_legacy_start(self):
        """Test legacy --start routes through registry to daemon start."""
        from trapninja.cli.registry import dispatch_legacy

        args = Namespace(
            start=True,
            shadow_mode=False, mirror_mode=False,
            parallel=False, capture_mode=None, log_traps=None,
        )
        # Set all other legacy attrs to falsy so they don't match first
        for attr in ['configure_ha', 'disable_ha', 'ha_status', 'promote',
                     'demote', 'force_failover', 'ha_help', 'ha_sync',
                     'sync_status', 'sync_help', 'block_ip', 'unblock_ip',
                     'list_blocked_ips', 'stop', 'restart', 'status',
                     'foreground']:
            if not hasattr(args, attr):
                setattr(args, attr, None)

        with patch('trapninja.cli.daemon_commands') as mock_daemon:
            mock_daemon.start.return_value = 0

            result = dispatch_legacy(args)

            mock_daemon.start.assert_called_once()
            assert result == 0

    def test_legacy_block_ip(self):
        """Test legacy --block-ip routes through registry to filter block-ip."""
        from trapninja.cli.registry import dispatch_legacy

        args = Namespace(block_ip='10.0.0.1')
        # Set all higher-priority legacy attrs to falsy
        for attr in ['configure_ha', 'disable_ha', 'ha_status', 'promote',
                     'demote', 'force_failover', 'ha_help', 'ha_sync',
                     'sync_status', 'sync_help']:
            setattr(args, attr, None)

        with patch('trapninja.cli.filtering_commands') as mock_filter:
            mock_filter.block_ip.return_value = True

            result = dispatch_legacy(args)

            mock_filter.block_ip.assert_called_once_with('10.0.0.1')
            assert result == 0

    def test_legacy_ha_status(self):
        """Test legacy --ha-status routes through registry to ha status."""
        from trapninja.cli.registry import dispatch_legacy

        args = Namespace(ha_status=True)
        # Set higher-priority attrs to falsy
        for attr in ['configure_ha', 'disable_ha']:
            setattr(args, attr, None)

        with patch('trapninja.cli.ha_commands') as mock_ha:
            mock_ha.show_ha_status.return_value = True

            result = dispatch_legacy(args)

            mock_ha.show_ha_status.assert_called_once()
            assert result == 0

    def test_legacy_no_match_returns_none(self):
        """Test legacy dispatch returns None when nothing matches."""
        from trapninja.cli.registry import dispatch_legacy

        # Empty namespace with nothing set
        args = Namespace()

        result = dispatch_legacy(args)

        assert result is None


class TestShowMissingCommandHelp:
    """Tests for _show_missing_command_help function."""

    def test_shows_help_for_category(self, capsys):
        """Test shows help for a category."""
        from trapninja.cli.executor import _show_missing_command_help

        result = _show_missing_command_help('daemon')

        assert result == 1
        captured = capsys.readouterr()
        assert "No command specified" in captured.out
        assert "daemon" in captured.out

    def test_shows_examples(self, capsys):
        """Test shows examples for known categories."""
        from trapninja.cli.executor import _show_missing_command_help

        result = _show_missing_command_help('filter')

        captured = capsys.readouterr()
        assert "Quick examples" in captured.out


class TestUpdateGlobalConfig:
    """Tests for update_global_config function."""

    def test_updates_interface(self):
        """Test updates INTERFACE from args."""
        from trapninja.cli.executor import update_global_config
        from trapninja import config

        original = config.INTERFACE
        args = Namespace(interface='eth1')

        # Ensure other attributes don't exist
        for attr in ['config_dir', 'log_file', 'pid_file', 'log_max_size',
                     'log_backup_count', 'log_compress', 'ports']:
            if not hasattr(args, attr):
                setattr(args, attr, None)

        try:
            update_global_config(args)
            assert config.INTERFACE == 'eth1'
        finally:
            config.INTERFACE = original

    def test_updates_config_dir(self, tmp_path):
        """Test updates CONFIG_DIR from args."""
        from trapninja.cli.executor import update_global_config
        from trapninja import config

        original = config.CONFIG_DIR
        args = Namespace(config_dir=str(tmp_path))

        # Ensure other attributes exist
        for attr in ['interface', 'log_file', 'pid_file', 'log_max_size',
                     'log_backup_count', 'log_compress', 'ports']:
            if not hasattr(args, attr):
                setattr(args, attr, None)

        try:
            update_global_config(args)
            assert config.CONFIG_DIR == str(tmp_path)
        finally:
            config.CONFIG_DIR = original
