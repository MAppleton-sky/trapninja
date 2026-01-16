#!/usr/bin/env python3
"""
TrapNinja Test Suite - CLI Executor Tests

Tests for trapninja.cli.executor module - command execution routing.

Author: TrapNinja Team
"""

import pytest
from argparse import Namespace
from unittest.mock import patch, MagicMock


class TestExecuteCommand:
    """Tests for execute_command function."""

    def test_routes_to_subcommand_handler(self):
        """Test execute_command routes to subcommand handler."""
        from trapninja.cli.executor import execute_command
        
        args = Namespace(
            category='daemon',
            command='status',
            foreground_daemon=False
        )
        
        with patch('trapninja.cli.executor.daemon_commands') as mock_daemon:
            mock_daemon.status.return_value = 0
            
            result = execute_command(args)
            
            mock_daemon.status.assert_called_once()

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
            log_level=None
        )
        
        with patch('trapninja.cli.executor._execute_foreground_daemon') as mock_fg:
            mock_fg.return_value = 0
            
            result = execute_command(args)
            
            mock_fg.assert_called_once_with(args)

    def test_no_category_executes_legacy(self):
        """Test no category falls back to legacy execution."""
        from trapninja.cli.executor import execute_command
        
        args = Namespace(
            category=None,
            command=None,
            foreground_daemon=False,
            start=True
        )
        
        with patch('trapninja.cli.executor._execute_legacy_command') as mock_legacy:
            mock_legacy.return_value = 0
            
            result = execute_command(args)
            
            mock_legacy.assert_called_once()


class TestExecuteDaemonCommand:
    """Tests for _execute_daemon_command function."""

    def test_daemon_start(self):
        """Test daemon start command execution."""
        from trapninja.cli.executor import _execute_daemon_command
        
        args = Namespace(
            shadow_mode=False,
            mirror_mode=False,
            parallel=False,
            capture_mode=None,
            log_traps=None
        )
        
        with patch('trapninja.cli.executor.daemon_commands') as mock_daemon:
            mock_daemon.start.return_value = 0
            
            result = _execute_daemon_command(args, 'start')
            
            mock_daemon.start.assert_called_once()
            assert result == 0

    def test_daemon_stop(self):
        """Test daemon stop command execution."""
        from trapninja.cli.executor import _execute_daemon_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.daemon_commands') as mock_daemon:
            mock_daemon.stop.return_value = 0
            
            result = _execute_daemon_command(args, 'stop')
            
            mock_daemon.stop.assert_called_once()

    def test_daemon_status(self):
        """Test daemon status command execution."""
        from trapninja.cli.executor import _execute_daemon_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.daemon_commands') as mock_daemon:
            mock_daemon.status.return_value = 0
            
            result = _execute_daemon_command(args, 'status')
            
            mock_daemon.status.assert_called_once()

    def test_daemon_no_command_shows_help(self):
        """Test daemon with no command shows help."""
        from trapninja.cli.executor import _execute_daemon_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor._show_missing_command_help') as mock_help:
            mock_help.return_value = 1
            
            result = _execute_daemon_command(args, None)
            
            mock_help.assert_called_once_with('daemon')

    def test_daemon_unknown_command(self, capsys):
        """Test daemon with unknown command returns error."""
        from trapninja.cli.executor import _execute_daemon_command
        
        args = Namespace()
        
        result = _execute_daemon_command(args, 'unknown_cmd')
        
        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown daemon command" in captured.out


class TestExecuteFilterCommand:
    """Tests for _execute_filter_command function."""

    def test_filter_block_ip(self):
        """Test filter block-ip command execution."""
        from trapninja.cli.executor import _execute_filter_command
        
        args = Namespace(ip='10.0.0.1')
        
        with patch('trapninja.cli.executor.filtering_commands') as mock_filter:
            mock_filter.block_ip.return_value = True
            
            result = _execute_filter_command(args, 'block-ip')
            
            mock_filter.block_ip.assert_called_once_with('10.0.0.1')
            assert result == 0

    def test_filter_unblock_ip(self):
        """Test filter unblock-ip command execution."""
        from trapninja.cli.executor import _execute_filter_command
        
        args = Namespace(ip='10.0.0.1')
        
        with patch('trapninja.cli.executor.filtering_commands') as mock_filter:
            mock_filter.unblock_ip.return_value = True
            
            result = _execute_filter_command(args, 'unblock-ip')
            
            mock_filter.unblock_ip.assert_called_once_with('10.0.0.1')

    def test_filter_list_blocked_ips(self):
        """Test filter list-blocked-ips command execution."""
        from trapninja.cli.executor import _execute_filter_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.filtering_commands') as mock_filter:
            mock_filter.list_blocked_ips.return_value = True
            
            result = _execute_filter_command(args, 'list-blocked-ips')
            
            mock_filter.list_blocked_ips.assert_called_once()

    def test_filter_block_oid(self):
        """Test filter block-oid command execution."""
        from trapninja.cli.executor import _execute_filter_command
        
        args = Namespace(oid='1.3.6.1.4')
        
        with patch('trapninja.cli.executor.filtering_commands') as mock_filter:
            mock_filter.block_oid.return_value = True
            
            result = _execute_filter_command(args, 'block-oid')
            
            mock_filter.block_oid.assert_called_once_with('1.3.6.1.4')

    def test_filter_redirect_ip(self):
        """Test filter redirect-ip command execution."""
        from trapninja.cli.executor import _execute_filter_command
        
        args = Namespace(ip='10.0.0.1', tag='noc')
        
        with patch('trapninja.cli.executor.filtering_commands') as mock_filter:
            mock_filter.redirect_ip.return_value = True
            
            result = _execute_filter_command(args, 'redirect-ip')
            
            mock_filter.redirect_ip.assert_called_once_with('10.0.0.1', 'noc')


class TestExecuteHACommand:
    """Tests for _execute_ha_command function."""

    def test_ha_status(self):
        """Test ha status command execution."""
        from trapninja.cli.executor import _execute_ha_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.ha_commands') as mock_ha:
            mock_ha.show_ha_status.return_value = True
            
            result = _execute_ha_command(args, 'status')
            
            mock_ha.show_ha_status.assert_called_once()
            assert result == 0

    def test_ha_configure(self):
        """Test ha configure command execution."""
        from trapninja.cli.executor import _execute_ha_command
        
        args = Namespace(
            mode='primary',
            ha_peer_host='192.168.1.102',
            priority=100,
            peer_port=8162,
            listen_port=8162
        )
        
        with patch('trapninja.cli.executor.ha_commands') as mock_ha:
            mock_ha.configure_ha.return_value = True
            
            result = _execute_ha_command(args, 'configure')
            
            mock_ha.configure_ha.assert_called_once()

    def test_ha_promote(self):
        """Test ha promote command execution."""
        from trapninja.cli.executor import _execute_ha_command
        
        args = Namespace(force=False)
        
        with patch('trapninja.cli.executor.ha_commands') as mock_ha:
            mock_ha.promote_to_primary.return_value = True
            
            result = _execute_ha_command(args, 'promote')
            
            mock_ha.promote_to_primary.assert_called_once_with(force=False)

    def test_ha_promote_force(self):
        """Test ha promote --force command execution."""
        from trapninja.cli.executor import _execute_ha_command
        
        args = Namespace(force=True)
        
        with patch('trapninja.cli.executor.ha_commands') as mock_ha:
            mock_ha.promote_to_primary.return_value = True
            
            result = _execute_ha_command(args, 'promote')
            
            mock_ha.promote_to_primary.assert_called_once_with(force=True)

    def test_ha_demote(self):
        """Test ha demote command execution."""
        from trapninja.cli.executor import _execute_ha_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.ha_commands') as mock_ha:
            mock_ha.demote_to_secondary.return_value = True
            
            result = _execute_ha_command(args, 'demote')
            
            mock_ha.demote_to_secondary.assert_called_once()


class TestExecuteCacheCommand:
    """Tests for _execute_cache_command function."""

    def test_cache_status(self):
        """Test cache status command execution."""
        from trapninja.cli.executor import _execute_cache_command
        
        args = Namespace(verbose=False, yes=False)
        
        with patch('trapninja.cli.executor.cache_commands') as mock_cache:
            mock_cache.show_cache_status.return_value = True
            
            result = _execute_cache_command(args, 'status')
            
            mock_cache.show_cache_status.assert_called_once()

    def test_cache_query(self):
        """Test cache query command execution."""
        from trapninja.cli.executor import _execute_cache_command
        
        args = Namespace(
            destination='default',
            from_time='-2h',
            to_time='now',
            limit=20,
            verbose=False,
            yes=False
        )
        
        with patch('trapninja.cli.executor.cache_commands') as mock_cache:
            mock_cache.query_cache.return_value = True
            
            result = _execute_cache_command(args, 'query')
            
            mock_cache.query_cache.assert_called_once()

    def test_cache_replay(self):
        """Test cache replay command execution."""
        from trapninja.cli.executor import _execute_cache_command
        
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
            verbose=False,
            yes=False
        )
        
        with patch('trapninja.cli.executor.cache_commands') as mock_cache:
            mock_cache.replay_cache.return_value = True
            
            result = _execute_cache_command(args, 'replay')
            
            mock_cache.replay_cache.assert_called_once()

    def test_cache_clear(self):
        """Test cache clear command execution."""
        from trapninja.cli.executor import _execute_cache_command
        
        args = Namespace(destination='default', verbose=False, yes=True)
        
        with patch('trapninja.cli.executor.cache_commands') as mock_cache:
            mock_cache.clear_cache.return_value = True
            
            result = _execute_cache_command(args, 'clear')
            
            mock_cache.clear_cache.assert_called_once()


class TestExecuteStatsCommand:
    """Tests for _execute_stats_command function."""

    def test_stats_summary(self):
        """Test stats summary command execution."""
        from trapninja.cli.executor import _execute_stats_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.stats_commands') as mock_stats:
            mock_stats.handle_stats_summary.return_value = 0
            
            result = _execute_stats_command(args, 'summary')
            
            mock_stats.handle_stats_summary.assert_called_once_with(args)

    def test_stats_top_ips(self):
        """Test stats top-ips command execution."""
        from trapninja.cli.executor import _execute_stats_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.stats_commands') as mock_stats:
            mock_stats.handle_stats_top_ips.return_value = 0
            
            result = _execute_stats_command(args, 'top-ips')
            
            mock_stats.handle_stats_top_ips.assert_called_once()

    def test_stats_export(self):
        """Test stats export command execution."""
        from trapninja.cli.executor import _execute_stats_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.stats_commands') as mock_stats:
            mock_stats.handle_stats_export.return_value = 0
            
            result = _execute_stats_command(args, 'export')
            
            mock_stats.handle_stats_export.assert_called_once()


class TestExecuteSNMPv3Command:
    """Tests for _execute_snmpv3_command function."""

    def test_snmpv3_list_users(self):
        """Test snmpv3 list-users command execution."""
        from trapninja.cli.executor import _execute_snmpv3_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.snmpv3_commands') as mock_snmpv3:
            mock_snmpv3.handle_snmpv3_list_users.return_value = 0
            
            result = _execute_snmpv3_command(args, 'list-users')
            
            mock_snmpv3.handle_snmpv3_list_users.assert_called_once()

    def test_snmpv3_status(self):
        """Test snmpv3 status command execution."""
        from trapninja.cli.executor import _execute_snmpv3_command
        
        args = Namespace()
        
        with patch('trapninja.cli.executor.snmpv3_commands') as mock_snmpv3:
            mock_snmpv3.handle_snmpv3_status.return_value = 0
            
            result = _execute_snmpv3_command(args, 'status')
            
            mock_snmpv3.handle_snmpv3_status.assert_called_once()


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


class TestExecuteLegacyCommand:
    """Tests for _execute_legacy_command function."""

    def test_legacy_start(self):
        """Test legacy --start command."""
        from trapninja.cli.executor import _execute_legacy_command
        
        args = Namespace(
            start=True,
            stop=False,
            restart=False,
            status=False,
            foreground=False,
            shadow_mode=False,
            mirror_mode=False,
            parallel=False,
            capture_mode=None,
            log_traps=None
        )
        
        # Set all other attributes to False/None
        for attr in ['configure_ha', 'disable_ha', 'ha_status', 'promote', 
                     'demote', 'force_failover', 'ha_help', 'ha_sync',
                     'sync_status', 'sync_help', 'block_ip', 'unblock_ip',
                     'list_blocked_ips', 'interface', 'config_dir',
                     'log_file', 'pid_file', 'log_max_size', 'log_backup_count',
                     'log_compress', 'ports']:
            if not hasattr(args, attr):
                setattr(args, attr, None if attr not in ['list_blocked_ips'] else False)
        
        with patch('trapninja.cli.executor.daemon_commands') as mock_daemon:
            mock_daemon.start.return_value = 0
            
            result = _execute_legacy_command(args)
            
            mock_daemon.start.assert_called_once()

    def test_legacy_block_ip(self):
        """Test legacy --block-ip command."""
        from trapninja.cli.executor import _execute_legacy_command
        
        args = Namespace(
            block_ip='10.0.0.1',
            start=False,
            stop=False,
            restart=False,
            status=False
        )
        
        # Set many attributes to False/None for the command routing
        for attr in ['configure_ha', 'disable_ha', 'ha_status', 'promote',
                     'demote', 'force_failover', 'ha_help', 'ha_sync',
                     'sync_status', 'sync_help', 'unblock_ip', 'list_blocked_ips',
                     'interface', 'config_dir', 'log_file', 'pid_file',
                     'log_max_size', 'log_backup_count', 'log_compress', 'ports']:
            if not hasattr(args, attr):
                setattr(args, attr, None if attr not in ['list_blocked_ips'] else False)
        
        with patch('trapninja.cli.executor.filtering_commands') as mock_filter:
            mock_filter.block_ip.return_value = True
            
            result = _execute_legacy_command(args)
            
            mock_filter.block_ip.assert_called_once_with('10.0.0.1')

    def test_legacy_ha_status(self):
        """Test legacy --ha-status command."""
        from trapninja.cli.executor import _execute_legacy_command
        
        args = Namespace(
            ha_status=True,
            configure_ha=False,
            disable_ha=False,
            promote=False,
            demote=False,
            force_failover=False,
            ha_help=False,
            ha_sync=False,
            sync_status=False,
            sync_help=False
        )
        
        # Set other attributes
        for attr in ['start', 'stop', 'restart', 'status', 'foreground',
                     'block_ip', 'unblock_ip', 'list_blocked_ips',
                     'interface', 'config_dir', 'log_file', 'pid_file',
                     'log_max_size', 'log_backup_count', 'log_compress', 'ports']:
            if not hasattr(args, attr):
                setattr(args, attr, None if attr not in ['list_blocked_ips'] else False)
        
        with patch('trapninja.cli.executor.ha_commands') as mock_ha:
            mock_ha.show_ha_status.return_value = True
            
            result = _execute_legacy_command(args)
            
            mock_ha.show_ha_status.assert_called_once()
