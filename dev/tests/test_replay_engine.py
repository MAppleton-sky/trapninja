#!/usr/bin/env python3
"""
Tests for TrapNinja capture file replay engine.

All tests run standalone — no running daemon, no Redis, no network required.
network.packet_queue is mocked throughout to isolate replay from production.
"""
import os
import queue
import tempfile
import time
import unittest
from dataclasses import dataclass
from unittest.mock import MagicMock, patch, PropertyMock


# =============================================================================
# TEST FIXTURE HELPERS
# =============================================================================

def _make_snmp_v1_payload() -> bytes:
    """Minimal valid SNMP v1 PDU bytes (version byte = 0x00)."""
    return bytes([0x30, 0x0b, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63])


def _make_snmp_v2c_payload() -> bytes:
    """Minimal valid SNMP v2c PDU bytes (version byte = 0x01)."""
    return bytes([0x30, 0x0b, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63])


def _make_snmp_v3_payload() -> bytes:
    """Minimal valid SNMP v3 PDU bytes (version byte = 0x03)."""
    return bytes([0x30, 0x0b, 0x02, 0x01, 0x03, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63])


def _make_snmp_pcap_file(version: str = 'v2c', src_ip: str = '10.0.0.1',
                          dst_port: int = 162, count: int = 1) -> str:
    """
    Write a temporary pcap file containing SNMP packets.
    Returns the file path. Caller is responsible for cleanup.
    """
    from scapy.all import IP, UDP, Raw, wrpcap
    
    payload_map = {
        'v1': _make_snmp_v1_payload(),
        'v2c': _make_snmp_v2c_payload(),
        'v3': _make_snmp_v3_payload(),
    }
    payload = payload_map.get(version, _make_snmp_v2c_payload())
    packets = [
        IP(src=src_ip, dst='192.168.1.1') / UDP(sport=20000, dport=dst_port) / Raw(load=payload)
        for _ in range(count)
    ]
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    wrpcap(path, packets)
    return path


def _make_mixed_version_pcap(v1_count: int, v2c_count: int, v3_count: int,
                              src_ip: str = '10.0.0.1', dst_port: int = 162) -> str:
    """
    Write a temporary pcap file containing mixed SNMP version packets.
    Returns the file path. Caller is responsible for cleanup.
    """
    from scapy.all import IP, UDP, Raw, wrpcap
    
    packets = []
    for _ in range(v1_count):
        packets.append(
            IP(src=src_ip, dst='192.168.1.1') / UDP(sport=20000, dport=dst_port) / Raw(load=_make_snmp_v1_payload())
        )
    for _ in range(v2c_count):
        packets.append(
            IP(src=src_ip, dst='192.168.1.1') / UDP(sport=20000, dport=dst_port) / Raw(load=_make_snmp_v2c_payload())
        )
    for _ in range(v3_count):
        packets.append(
            IP(src=src_ip, dst='192.168.1.1') / UDP(sport=20000, dport=dst_port) / Raw(load=_make_snmp_v3_payload())
        )
    
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    wrpcap(path, packets)
    return path


def _make_multi_source_pcap(src_ips: list, dst_port: int = 162) -> str:
    """
    Write a temporary pcap file with packets from multiple source IPs.
    Returns the file path. Caller is responsible for cleanup.
    """
    from scapy.all import IP, UDP, Raw, wrpcap
    
    packets = []
    for src_ip in src_ips:
        packets.append(
            IP(src=src_ip, dst='192.168.1.1') / UDP(sport=20000, dport=dst_port) / Raw(load=_make_snmp_v2c_payload())
        )
    
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    wrpcap(path, packets)
    return path


# =============================================================================
# TEST CLASSES
# =============================================================================

class TestReplayMetrics(unittest.TestCase):
    """Tests for ReplayMetrics dataclass."""

    def test_metrics_initial_state(self):
        """ReplayMetrics() has all counters at zero and replay_start_wall_time is recent."""
        from trapninja.replay_engine import ReplayMetrics
        
        before = time.time()
        metrics = ReplayMetrics()
        after = time.time()
        
        self.assertEqual(metrics.replay_packets_read, 0)
        self.assertEqual(metrics.replay_packets_injected, 0)
        self.assertEqual(metrics.replay_packets_skipped, 0)
        self.assertEqual(metrics.replay_packets_failed, 0)
        self.assertEqual(metrics.replay_snmp_v1_count, 0)
        self.assertEqual(metrics.replay_snmp_v2c_count, 0)
        self.assertEqual(metrics.replay_snmp_v3_count, 0)
        self.assertEqual(metrics.replay_snmp_unknown_count, 0)
        self.assertGreaterEqual(metrics.replay_start_wall_time, before)
        self.assertLessEqual(metrics.replay_start_wall_time, after)


class TestSnmpVersionDetection(unittest.TestCase):
    """Tests for SNMP version detection heuristics."""

    def test_detect_v1(self):
        """_detect_snmp_version correctly identifies SNMP v1."""
        from trapninja.replay_engine import _detect_snmp_version
        self.assertEqual(_detect_snmp_version(_make_snmp_v1_payload()), 'v1')

    def test_detect_v2c(self):
        """_detect_snmp_version correctly identifies SNMP v2c."""
        from trapninja.replay_engine import _detect_snmp_version
        self.assertEqual(_detect_snmp_version(_make_snmp_v2c_payload()), 'v2c')

    def test_detect_v3(self):
        """_detect_snmp_version correctly identifies SNMP v3."""
        from trapninja.replay_engine import _detect_snmp_version
        self.assertEqual(_detect_snmp_version(_make_snmp_v3_payload()), 'v3')

    def test_detect_unknown_empty(self):
        """_detect_snmp_version returns 'unknown' for empty payload."""
        from trapninja.replay_engine import _detect_snmp_version
        self.assertEqual(_detect_snmp_version(b''), 'unknown')

    def test_detect_unknown_short(self):
        """_detect_snmp_version returns 'unknown' for too-short payload."""
        from trapninja.replay_engine import _detect_snmp_version
        self.assertEqual(_detect_snmp_version(b'\x30\x05'), 'unknown')

    def test_detect_unknown_garbage(self):
        """_detect_snmp_version returns 'unknown' for garbage and does not raise."""
        from trapninja.replay_engine import _detect_snmp_version
        # Should not raise
        result = _detect_snmp_version(b'\xff\xff\xff\xff\xff')
        self.assertEqual(result, 'unknown')


class TestProductionSafetyGate(unittest.TestCase):
    """Tests for production safety gate."""

    def setUp(self):
        """Set up temporary PID file for tests."""
        self.temp_pid_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False)
        self.temp_pid_file.close()
        self.addCleanup(lambda: os.unlink(self.temp_pid_file.name) if os.path.exists(self.temp_pid_file.name) else None)

    def test_safe_when_no_pid_file(self):
        """Safety gate returns safe when PID file does not exist."""
        from trapninja.replay_engine import _check_production_safety
        
        with patch('trapninja.config.PID_FILE', '/nonexistent/path/trapninja.pid'):
            is_safe, reason = _check_production_safety()
            self.assertTrue(is_safe)
            self.assertIn('no live daemon', reason.lower())

    def test_safe_when_stale_pid_file(self):
        """Safety gate returns safe when PID file contains dead process."""
        from trapninja.replay_engine import _check_production_safety
        
        # Write a PID that definitely doesn't exist
        with open(self.temp_pid_file.name, 'w') as f:
            f.write('99999999')
        
        with patch('trapninja.config.PID_FILE', self.temp_pid_file.name):
            is_safe, reason = _check_production_safety()
            self.assertTrue(is_safe)
            self.assertIn('stale', reason.lower())

    def test_unsafe_when_live_pid(self):
        """Safety gate returns unsafe when PID file contains live process."""
        from trapninja.replay_engine import _check_production_safety
        
        # Write our own PID - we are definitely alive
        with open(self.temp_pid_file.name, 'w') as f:
            f.write(str(os.getpid()))
        
        with patch('trapninja.config.PID_FILE', self.temp_pid_file.name):
            is_safe, reason = _check_production_safety()
            self.assertFalse(is_safe)
            self.assertIn('Live TrapNinja daemon detected', reason)

    def test_skip_check_bypasses_gate(self):
        """skip_check=True bypasses the safety gate."""
        from trapninja.replay_engine import _check_production_safety
        
        # Write our own PID
        with open(self.temp_pid_file.name, 'w') as f:
            f.write(str(os.getpid()))
        
        with patch('trapninja.config.PID_FILE', self.temp_pid_file.name):
            is_safe, reason = _check_production_safety(skip_check=True)
            self.assertTrue(is_safe)
            self.assertIn('skipped', reason.lower())

    def test_env_var_override(self):
        """TRAPNINJA_REPLAY_ALLOW=1 overrides the safety gate."""
        from trapninja.replay_engine import _check_production_safety
        
        # Write our own PID
        with open(self.temp_pid_file.name, 'w') as f:
            f.write(str(os.getpid()))
        
        old_env = os.environ.get('TRAPNINJA_REPLAY_ALLOW')
        try:
            os.environ['TRAPNINJA_REPLAY_ALLOW'] = '1'
            with patch('trapninja.config.PID_FILE', self.temp_pid_file.name):
                is_safe, reason = _check_production_safety()
                self.assertTrue(is_safe)
                self.assertIn('env override', reason.lower())
        finally:
            if old_env is None:
                os.environ.pop('TRAPNINJA_REPLAY_ALLOW', None)
            else:
                os.environ['TRAPNINJA_REPLAY_ALLOW'] = old_env


class TestReplayEngineFileValidation(unittest.TestCase):
    """Tests for replay engine file validation."""

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    def test_nonexistent_file_returns_error(self, mock_safety, mock_queue):
        """Engine returns error code 1 for non-existent file."""
        from trapninja.replay_engine import ReplayEngine
        
        engine = ReplayEngine(capture_file='/nonexistent/path/traps.pcap')
        result = engine.run()
        self.assertEqual(result, 1)

    @unittest.skipIf(os.name == 'nt', "File permissions behave differently on Windows")
    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    def test_unreadable_file_returns_error(self, mock_safety, mock_queue):
        """Engine returns error code 1 for unreadable file."""
        from trapninja.replay_engine import ReplayEngine
        
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            path = f.name
        
        try:
            os.chmod(path, 0o000)
            engine = ReplayEngine(capture_file=path)
            result = engine.run()
            self.assertEqual(result, 1)
        finally:
            os.chmod(path, 0o644)
            os.unlink(path)


class TestReplayEngineDryRun(unittest.TestCase):
    """Tests for replay engine dry run mode."""

    def setUp(self):
        """Create temporary pcap files for tests."""
        self.pcap_path = None

    def tearDown(self):
        """Clean up temporary files."""
        if self.pcap_path and os.path.exists(self.pcap_path):
            os.unlink(self.pcap_path)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_dry_run_does_not_call_put_nowait(self, mock_safety, mock_queue):
        """Dry run mode does not inject packets."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=5)
        
        engine = ReplayEngine(capture_file=self.pcap_path, dry_run=True)
        engine.run()
        
        mock_queue.put_nowait.assert_not_called()

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_dry_run_increments_read_counter(self, mock_safety, mock_queue):
        """Dry run mode increments read counter."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=5)
        
        engine = ReplayEngine(capture_file=self.pcap_path, dry_run=True)
        engine.run()
        
        self.assertEqual(engine.metrics.replay_packets_read, 5)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_dry_run_increments_injected_counter(self, mock_safety, mock_queue):
        """Dry run mode increments injected counter (counts as 'would have been injected')."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=5)
        
        engine = ReplayEngine(capture_file=self.pcap_path, dry_run=True)
        engine.run()
        
        self.assertEqual(engine.metrics.replay_packets_injected, 5)


class TestReplayEngineNormalRun(unittest.TestCase):
    """Tests for replay engine normal operation."""

    def setUp(self):
        """Create temporary pcap files for tests."""
        self.pcap_path = None

    def tearDown(self):
        """Clean up temporary files."""
        if self.pcap_path and os.path.exists(self.pcap_path):
            os.unlink(self.pcap_path)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_correct_dict_format_injected(self, mock_safety, mock_queue):
        """Engine injects packets with correct dict format."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', src_ip='10.1.2.3', dst_port=162, count=1)
        
        engine = ReplayEngine(capture_file=self.pcap_path)
        engine.run()
        
        mock_queue.put_nowait.assert_called_once()
        call_args = mock_queue.put_nowait.call_args[0][0]
        
        self.assertIsInstance(call_args, dict)
        self.assertEqual(call_args['src_ip'], '10.1.2.3')
        self.assertEqual(call_args['dst_port'], 162)
        self.assertIsInstance(call_args['payload'], bytes)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_version_counters_increment(self, mock_safety, mock_queue):
        """Engine correctly increments version counters for mixed SNMP versions."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_mixed_version_pcap(v1_count=3, v2c_count=4, v3_count=2)
        
        engine = ReplayEngine(capture_file=self.pcap_path)
        engine.run()
        
        self.assertEqual(engine.metrics.replay_snmp_v1_count, 3)
        self.assertEqual(engine.metrics.replay_snmp_v2c_count, 4)
        self.assertEqual(engine.metrics.replay_snmp_v3_count, 2)
        self.assertEqual(engine.metrics.replay_snmp_unknown_count, 0)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_non_snmp_port_skipped(self, mock_safety, mock_queue):
        """Engine skips packets not destined for LISTEN_PORTS."""
        from trapninja.replay_engine import ReplayEngine
        
        # Create pcap with non-standard port
        self.pcap_path = _make_snmp_pcap_file(version='v2c', dst_port=9999, count=1)
        
        engine = ReplayEngine(capture_file=self.pcap_path)
        engine.run()
        
        self.assertEqual(engine.metrics.replay_packets_skipped, 1)
        mock_queue.put_nowait.assert_not_called()

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_queue_full_increments_failed_not_raises(self, mock_safety, mock_queue):
        """Engine handles queue.Full without raising, increments failed counter."""
        from trapninja.replay_engine import ReplayEngine
        
        mock_queue.put_nowait.side_effect = queue.Full()
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=3)
        
        engine = ReplayEngine(capture_file=self.pcap_path)
        result = engine.run()
        
        # Should not raise, should return success
        self.assertEqual(result, 0)
        self.assertEqual(engine.metrics.replay_packets_failed, 3)
        self.assertEqual(engine.metrics.replay_packets_injected, 0)


class TestReplayEngineFiltering(unittest.TestCase):
    """Tests for replay engine source IP filtering."""

    def setUp(self):
        """Create temporary pcap files for tests."""
        self.pcap_path = None

    def tearDown(self):
        """Clean up temporary files."""
        if self.pcap_path and os.path.exists(self.pcap_path):
            os.unlink(self.pcap_path)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_filter_src_ip_excludes_non_matching(self, mock_safety, mock_queue):
        """Source IP filter excludes non-matching packets."""
        from trapninja.replay_engine import ReplayEngine
        
        # Create pcap with multiple source IPs: 2 from 10.0.0.1, 1 from 10.0.0.2
        self.pcap_path = _make_multi_source_pcap(['10.0.0.1', '10.0.0.1', '10.0.0.2'])
        
        engine = ReplayEngine(capture_file=self.pcap_path, filter_src_ip='10.0.0.1')
        engine.run()
        
        self.assertEqual(engine.metrics.replay_packets_injected, 2)
        self.assertEqual(engine.metrics.replay_packets_skipped, 1)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_filter_src_ip_none_injects_all(self, mock_safety, mock_queue):
        """No source IP filter injects all packets."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_multi_source_pcap(['10.0.0.1', '10.0.0.2', '10.0.0.3'])
        
        engine = ReplayEngine(capture_file=self.pcap_path, filter_src_ip=None)
        engine.run()
        
        self.assertEqual(engine.metrics.replay_packets_injected, 3)


class TestReplayCountLooping(unittest.TestCase):
    """Tests for replay count and looping behavior."""

    def setUp(self):
        """Create temporary pcap files for tests."""
        self.pcap_path = None

    def tearDown(self):
        """Clean up temporary files."""
        if self.pcap_path and os.path.exists(self.pcap_path):
            os.unlink(self.pcap_path)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_replay_count_1_reads_file_once(self, mock_safety, mock_queue):
        """replay_count=1 reads file exactly once."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=5)
        
        engine = ReplayEngine(capture_file=self.pcap_path, replay_count=1)
        engine.run()
        
        self.assertEqual(engine.metrics.replay_packets_read, 5)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_replay_count_2_reads_file_twice(self, mock_safety, mock_queue):
        """replay_count=2 reads file twice."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=5)
        
        engine = ReplayEngine(capture_file=self.pcap_path, replay_count=2)
        engine.run()
        
        self.assertEqual(engine.metrics.replay_packets_read, 10)

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.replay_engine._check_production_safety', return_value=(True, 'test'))
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_replay_count_0_stops_on_stop_event(self, mock_safety, mock_queue):
        """replay_count=0 stops on stop_event without reading packets."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=5)
        
        # Create a mock stop_event that is already set
        mock_stop_event = MagicMock()
        mock_stop_event.is_set.return_value = True
        
        with patch('trapninja.config.stop_event', mock_stop_event):
            engine = ReplayEngine(capture_file=self.pcap_path, replay_count=0)
            result = engine.run()
        
        self.assertEqual(result, 0)
        # Should stop immediately without reading any packets
        self.assertEqual(engine.metrics.replay_packets_read, 0)


class TestSafetyGateIntegration(unittest.TestCase):
    """Tests for safety gate integration with ReplayEngine."""

    def setUp(self):
        """Create temporary pcap files for tests."""
        self.pcap_path = None

    def tearDown(self):
        """Clean up temporary files."""
        if self.pcap_path and os.path.exists(self.pcap_path):
            os.unlink(self.pcap_path)

    @patch('trapninja.network.packet_queue')
    def test_safety_gate_blocks_run(self, mock_queue):
        """Safety gate blocks engine run and returns exit code 2."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=5)
        
        with patch('trapninja.replay_engine._check_production_safety', 
                   return_value=(False, 'Live daemon detected (PID 123)')):
            engine = ReplayEngine(capture_file=self.pcap_path, skip_safety_check=False)
            result = engine.run()
        
        self.assertEqual(result, 2)
        mock_queue.put_nowait.assert_not_called()

    @patch('trapninja.network.packet_queue')
    @patch('trapninja.config.LISTEN_PORTS', [162])
    def test_skip_safety_allows_run(self, mock_queue):
        """skip_safety_check=True allows run even when daemon detected."""
        from trapninja.replay_engine import ReplayEngine
        
        self.pcap_path = _make_snmp_pcap_file(version='v2c', count=1)
        
        # Even with a live daemon, skip_safety_check=True should proceed
        engine = ReplayEngine(capture_file=self.pcap_path, skip_safety_check=True)
        result = engine.run()
        
        self.assertEqual(result, 0)
        self.assertEqual(engine.metrics.replay_packets_injected, 1)


class TestReplayCommandsCLI(unittest.TestCase):
    """Tests for replay CLI commands module."""

    @patch('trapninja.replay_engine.ReplayEngine')
    def test_run_replay_validates_file(self, mock_engine_class):
        """CLI validates capture file before constructing engine."""
        from trapninja.cli.replay_commands import run_replay
        from argparse import Namespace
        
        args = Namespace(capture_file='/nonexistent/file.pcap')
        result = run_replay(args)
        
        self.assertEqual(result, 1)
        mock_engine_class.assert_not_called()

    @patch('trapninja.replay_engine.ReplayEngine')
    def test_run_replay_missing_file_arg(self, mock_engine_class):
        """CLI returns error when capture_file is missing."""
        from trapninja.cli.replay_commands import run_replay
        from argparse import Namespace
        
        args = Namespace()  # No capture_file attribute
        result = run_replay(args)
        
        self.assertEqual(result, 1)
        mock_engine_class.assert_not_called()


if __name__ == '__main__':
    unittest.main()
