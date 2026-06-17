#!/usr/bin/env python3
"""
TrapNinja Test Suite - Metrics Commands Tests

Tests for trapninja.cli.metrics_commands.show_metrics_live() and
_print_metrics_summary(), plus registry/parser wiring for the new
'metrics show' subcommand introduced in Phase 1 CLI gap work.
"""

import json
import pytest
from argparse import Namespace
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _full_metrics() -> dict:
    """Return a representative metrics dict with all Phase 1 keys populated."""
    return {
        'timestamp': '2026-06-17T12:00:00.000000',
        'uptime_seconds': 3600.0,
        'total_traps_received': 10000,
        'total_traps_forwarded': 9800,
        'total_traps_blocked': 150,
        'total_traps_redirected': 50,
        'total_traps_dropped': 0,
        'queue_current_depth': 5,
        'queue_max_depth': 200,
        'queue_capacity': 200000,
        'queue_utilization': 0.000025,
        'pipeline_timing': {
            'queue_wait_seconds': {
                'p50': 0.001, 'p95': 0.005, 'p99': 0.010,
                'max': 0.020, 'samples': 4096,
            },
            'processing_duration_seconds': {
                'p50': 0.002, 'p95': 0.008, 'p99': 0.015,
                'max': 0.050, 'samples': 4096,
            },
        },
        'resource': {
            'rss_bytes': 52428800,
            'open_fds': 42,
            'gc_collections': {'0': 1000, '1': 50, '2': 3},
        },
        'socket_drops': {162: 7},
        'ebpf': {},
    }


def _empty_phase1_metrics() -> dict:
    """Return metrics dict with empty Phase 1 sections (pre-first-export state)."""
    return {
        'timestamp': '2026-06-17T12:00:00.000000',
        'uptime_seconds': 10.0,
        'total_traps_received': 0,
        'total_traps_forwarded': 0,
        'total_traps_blocked': 0,
        'total_traps_redirected': 0,
        'total_traps_dropped': 0,
        'queue_current_depth': 0,
        'queue_max_depth': 0,
        'queue_capacity': 200000,
        'queue_utilization': 0.0,
        'pipeline_timing': {},
        'resource': {},
        'socket_drops': {},
        'ebpf': {},
    }


# ---------------------------------------------------------------------------
# show_metrics_live() — daemon path
# ---------------------------------------------------------------------------

class TestShowMetricsLiveDaemon:

    def test_daemon_success_returns_zero(self, capsys):
        """show_metrics_live() returns 0 when daemon responds successfully."""
        from trapninja.cli.metrics_commands import show_metrics_live

        metrics = _full_metrics()
        response = {'status': 0, 'data': {'metrics': metrics}}

        with patch('trapninja.control.ControlSocket') as mock_cs:
            mock_cs.SUCCESS = 0
            mock_cs.send_command.return_value = response
            result = show_metrics_live()

        assert result == 0

    def test_daemon_success_prints_section_headers(self, capsys):
        """Output contains all four section headers when daemon responds."""
        from trapninja.cli.metrics_commands import show_metrics_live

        metrics = _full_metrics()
        response = {'status': 0, 'data': {'metrics': metrics}}

        with patch('trapninja.control.ControlSocket') as mock_cs:
            mock_cs.SUCCESS = 0
            mock_cs.send_command.return_value = response
            show_metrics_live()

        out = capsys.readouterr().out
        assert 'TRAP TOTALS' in out
        assert 'QUEUE' in out
        assert 'PIPELINE LATENCY' in out
        assert 'RESOURCE' in out
        assert 'CAPTURE-MODE DROP VISIBILITY' in out


# ---------------------------------------------------------------------------
# show_metrics_live() — file fallback path
# ---------------------------------------------------------------------------

class TestShowMetricsLiveFallback:

    def test_connection_refused_falls_back_to_file(self, capsys):
        """ConnectionRefusedError from daemon falls back to file read, returns 0."""
        from trapninja.cli.metrics_commands import show_metrics_live

        metrics = _full_metrics()

        with patch('trapninja.control.ControlSocket') as mock_cs:
            mock_cs.send_command.side_effect = ConnectionRefusedError()
            with patch('trapninja.cli.metrics_commands._get_metrics_from_file',
                       return_value=metrics):
                result = show_metrics_live()

        assert result == 0

    def test_both_fail_returns_one(self, capsys):
        """When both daemon and file fail, returns 1 with error message."""
        from trapninja.cli.metrics_commands import show_metrics_live

        with patch('trapninja.control.ControlSocket') as mock_cs:
            mock_cs.send_command.side_effect = ConnectionRefusedError()
            with patch('trapninja.cli.metrics_commands._get_metrics_from_file',
                       return_value=None):
                result = show_metrics_live()

        assert result == 1
        out = capsys.readouterr().out
        assert 'Could not retrieve' in out


# ---------------------------------------------------------------------------
# show_metrics_live() — JSON output
# ---------------------------------------------------------------------------

class TestShowMetricsLiveJson:

    def test_json_output_is_valid_json(self, capsys):
        """--json output is parseable JSON matching the input metrics dict."""
        from trapninja.cli.metrics_commands import show_metrics_live

        metrics = _full_metrics()
        response = {'status': 0, 'data': {'metrics': metrics}}

        with patch('trapninja.control.ControlSocket') as mock_cs:
            mock_cs.SUCCESS = 0
            mock_cs.send_command.return_value = response
            result = show_metrics_live(json_output=True)

        assert result == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed['total_traps_received'] == metrics['total_traps_received']

    def test_pretty_json_is_indented(self, capsys):
        """--json --pretty output is indented (multi-line)."""
        from trapninja.cli.metrics_commands import show_metrics_live

        metrics = _full_metrics()
        response = {'status': 0, 'data': {'metrics': metrics}}

        with patch('trapninja.control.ControlSocket') as mock_cs:
            mock_cs.SUCCESS = 0
            mock_cs.send_command.return_value = response
            show_metrics_live(json_output=True, pretty=True)

        out = capsys.readouterr().out
        assert '\n' in out
        assert '  ' in out  # indentation present


# ---------------------------------------------------------------------------
# _print_metrics_summary() — graceful degradation
# ---------------------------------------------------------------------------

class TestPrintMetricsSummaryDegradation:

    def test_empty_phase1_fields_do_not_raise(self, capsys):
        """Empty pipeline_timing/resource/socket_drops/ebpf dicts don't raise."""
        from trapninja.cli.metrics_commands import _print_metrics_summary

        _print_metrics_summary(_empty_phase1_metrics())  # must not raise

    def test_empty_pipeline_timing_prints_no_samples(self, capsys):
        """Empty pipeline_timing prints the 'no samples yet' fallback."""
        from trapninja.cli.metrics_commands import _print_metrics_summary

        _print_metrics_summary(_empty_phase1_metrics())
        out = capsys.readouterr().out
        assert 'No samples yet' in out

    def test_empty_resource_prints_not_available(self, capsys):
        """Empty resource dict prints '(not available)'."""
        from trapninja.cli.metrics_commands import _print_metrics_summary

        _print_metrics_summary(_empty_phase1_metrics())
        out = capsys.readouterr().out
        assert '(not available)' in out

    def test_empty_drops_prints_no_drop_data(self, capsys):
        """Empty socket_drops and ebpf print 'no drop data' fallback."""
        from trapninja.cli.metrics_commands import _print_metrics_summary

        _print_metrics_summary(_empty_phase1_metrics())
        out = capsys.readouterr().out
        assert 'no drop data' in out

    def test_socket_mode_drops_printed_ebpf_section_absent(self, capsys):
        """With only socket_drops populated, socket section prints; no eBPF per-key lines."""
        from trapninja.cli.metrics_commands import _print_metrics_summary

        metrics = _empty_phase1_metrics()
        metrics['socket_drops'] = {162: 42}

        _print_metrics_summary(metrics)
        out = capsys.readouterr().out
        assert 'Port 162' in out
        assert 'AF_PACKET' not in out
        assert 'Perf-buffer' not in out

    def test_ebpf_mode_both_keys_printed(self, capsys):
        """With only ebpf populated, both raw_socket_drops and lost_samples lines appear."""
        from trapninja.cli.metrics_commands import _print_metrics_summary

        metrics = _empty_phase1_metrics()
        metrics['ebpf'] = {'raw_socket_drops': 5, 'lost_samples': 2}

        _print_metrics_summary(metrics)
        out = capsys.readouterr().out
        assert 'AF_PACKET raw socket drops' in out
        assert 'Perf-buffer lost notifications' in out

    def test_populated_pipeline_timing_prints_latency(self, capsys):
        """With populated pipeline_timing, p99 values appear in output."""
        from trapninja.cli.metrics_commands import _print_metrics_summary

        _print_metrics_summary(_full_metrics())
        out = capsys.readouterr().out
        assert 'Queue Wait' in out
        assert 'Processing Time' in out
        assert 'p99' in out


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------

class TestRegistryWiring:

    def test_metrics_show_dispatches_to_show_metrics_live(self):
        """dispatch_subcommand('metrics', 'show') calls show_metrics_live."""
        from trapninja.cli.registry import dispatch_subcommand

        args = Namespace(json=False, pretty=False)

        with patch('trapninja.cli.metrics_commands.show_metrics_live',
                   return_value=0) as mock_fn:
            result = dispatch_subcommand(args, 'metrics', 'show')

        mock_fn.assert_called_once_with(json_output=False, pretty=False)
        assert result == 0

    def test_legacy_metrics_show_routes_to_show(self):
        """Legacy --metrics-show dispatch routes to metrics show handler."""
        from trapninja.cli.registry import dispatch_legacy

        args = Namespace(metrics_show=True, json=False, pretty=False)
        # Set all higher-priority legacy attrs to falsy
        for attr in ['configure_ha', 'disable_ha', 'ha_status', 'promote',
                     'demote', 'force_failover', 'ha_help', 'ha_sync',
                     'sync_status', 'sync_help', 'block_ip', 'unblock_ip',
                     'list_blocked_ips', 'block_oid', 'unblock_oid',
                     'list_blocked_oids', 'redirect_ip', 'unredirect_ip',
                     'list_redirected_ips', 'redirect_oid', 'unredirect_oid',
                     'list_redirected_oids', 'add_redirect_dest',
                     'remove_redirect_dest', 'list_redirect_dests',
                     'redirection_help', 'snmpv3_add_user', 'snmpv3_remove_user',
                     'snmpv3_list_users', 'snmpv3_show_user', 'snmpv3_status',
                     'snmpv3_test_decrypt', 'cache_status', 'cache_query',
                     'cache_replay', 'cache_clear', 'cache_trim', 'cache_help',
                     'failover_status', 'failover_detect', 'failover_replay',
                     'failover_help', 'queue_stats', 'stats_summary',
                     'stats_top_ips', 'stats_top_oids', 'stats_ip', 'stats_oid',
                     'stats_destinations', 'stats_dashboard', 'stats_export',
                     'stats_reset', 'stats_help', 'stats_debug', 'shadow_status',
                     'shadow_export', 'metrics_config', 'metrics_set_dir',
                     'metrics_add_label', 'metrics_remove_label',
                     'metrics_set_interval', 'metrics_help']:
            setattr(args, attr, None)

        with patch('trapninja.cli.metrics_commands.show_metrics_live',
                   return_value=0) as mock_fn:
            result = dispatch_legacy(args)

        assert result == 0
        mock_fn.assert_called_once()


# ---------------------------------------------------------------------------
# Parser wiring
# ---------------------------------------------------------------------------

class TestParserWiring:

    def test_metrics_show_parses_category_and_command(self):
        """'trapninja metrics show' sets category='metrics', command='show'."""
        from trapninja.cli.parser import create_argument_parser

        parser = create_argument_parser()
        args = parser.parse_args(['metrics', 'show'])
        assert getattr(args, 'command_category', None) == 'metrics'
        assert args.command == 'show'

    def test_metrics_show_json_flag(self):
        """'trapninja --json metrics show' sets args.json=True (global flag before subcommand)."""
        from trapninja.cli.parser import create_argument_parser

        parser = create_argument_parser()
        args = parser.parse_args(['--json', 'metrics', 'show'])
        assert args.json is True

    def test_metrics_show_pretty_flag(self):
        """'trapninja --json metrics show --pretty' sets both flags correctly."""
        from trapninja.cli.parser import create_argument_parser

        parser = create_argument_parser()
        args = parser.parse_args(['--json', 'metrics', 'show', '--pretty'])
        assert args.json is True
        assert args.pretty is True

    def test_parser_construction_succeeds_for_all_categories(self):
        """Parser construction does not raise for any command category."""
        from trapninja.cli.parser import create_argument_parser

        parser = create_argument_parser()  # must not raise (no argparse conflicts)
        assert parser is not None

    def test_legacy_metrics_show_flag_parses(self):
        """'trapninja --metrics-show' parses without error."""
        from trapninja.cli.parser import create_argument_parser

        parser = create_argument_parser()
        args = parser.parse_args(['--metrics-show'])
        assert getattr(args, 'metrics_show', False) is True
