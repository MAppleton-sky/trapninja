#!/usr/bin/env python3
"""
TrapNinja eBPF Fragmentation Tests

Validates that the eBPF capture mode correctly handles fragmented SNMP traps.

Coverage:
  - Non-first fragment detection via frag_off field parsing
  - Fragment reassembly through FragmentReassemblyBuffer in eBPF mode
  - Non-fragmented traps are unaffected (no regression)
  - Fragment reassembly disabled: warning logged, no silent loss
  - create_capture() accepts and forwards fragment_buffer parameter
  - try_ebpf_capture() initialises fragment reassembly before capture

All tests use synthetic packet bytes (no network I/O, no BCC/kernel).
"""

import queue
import socket
import struct
import threading
import time
import os
import sys
import tempfile
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# ---------------------------------------------------------------------------
# Path setup – mirrors the approach in conftest.py
# ---------------------------------------------------------------------------
TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# ---------------------------------------------------------------------------
# Helpers – synthetic raw packet construction
# ---------------------------------------------------------------------------

def _build_ip_header(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    ip_id: int,
    frag_offset_units: int,   # offset in 8-byte units (same as IP header field)
    mf: bool,
    payload_len: int,
) -> bytes:
    """
    Build a minimal 20-byte IP header.

    Args:
        src_ip: Source IP address string
        dst_ip: Destination IP address string
        protocol: IP protocol number (17 = UDP)
        ip_id: IP identification field
        frag_offset_units: Fragment offset in 8-byte units (0 for first/complete)
        mf: More Fragments flag
        payload_len: Length of the payload following this header
    Returns:
        20-byte IP header bytes
    """
    version_ihl = (4 << 4) | 5  # IPv4, IHL=5 (20 bytes)
    dscp = 0
    total_length = 20 + payload_len

    df_flag = 0
    mf_flag = 1 if mf else 0
    # frag_off field: [Reserved=0][DF][MF][offset high 5 bits] [offset low 8 bits]
    flags_frag = ((df_flag << 14) | (mf_flag << 13) | (frag_offset_units & 0x1FFF))

    ttl = 64
    checksum = 0  # Not computed – kernel ignores in test context

    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    return struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl, dscp, total_length, ip_id, flags_frag,
        ttl, protocol, checksum,
        src_bytes, dst_bytes,
    )


def _build_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    """Build an 8-byte UDP header."""
    length = 8 + payload_len
    checksum = 0
    return struct.pack('!HHHH', src_port, dst_port, length, checksum)


def _build_ethernet_header(
    eth_type: int = 0x0800,  # IPv4
) -> bytes:
    """Build a minimal 14-byte Ethernet header (addresses are zeroes)."""
    src_mac = b'\x00' * 6
    dst_mac = b'\x00' * 6
    return dst_mac + src_mac + struct.pack('!H', eth_type)


def _build_complete_packet(
    src_ip: str,
    dst_port: int,
    snmp_payload: bytes,
    src_port: int = 12345,
) -> bytes:
    """Build a complete, unfragmented Ethernet+IP+UDP+payload packet."""
    udp_hdr = _build_udp_header(src_port, dst_port, len(snmp_payload))
    udp_segment = udp_hdr + snmp_payload
    ip_hdr = _build_ip_header(
        src_ip=src_ip,
        dst_ip='10.0.0.1',
        protocol=17,
        ip_id=0x1234,
        frag_offset_units=0,
        mf=False,
        payload_len=len(udp_segment),
    )
    eth_hdr = _build_ethernet_header()
    return eth_hdr + ip_hdr + udp_segment


def _build_fragment_packets(
    src_ip: str,
    dst_port: int,
    snmp_payload: bytes,
    src_port: int = 12345,
    ip_id: int = 0xABCD,
    fragment_size: int = 1480,  # bytes of IP payload per fragment (multiple of 8)
) -> list:
    """
    Build a list of fragmented Ethernet+IP packets for a UDP datagram.

    The first fragment contains the UDP header + first chunk of SNMP payload.
    Subsequent fragments contain SNMP payload continuation only (no UDP header).

    Args:
        src_ip: Source IP
        dst_port: UDP destination port
        snmp_payload: Complete SNMP payload to fragment
        src_port: UDP source port
        ip_id: IP identification (same for all fragments)
        fragment_size: Maximum IP payload bytes per fragment (must be multiple of 8)

    Returns:
        List of raw packet bytes (Ethernet + IP + fragment data)
    """
    eth_hdr = _build_ethernet_header()

    # Full UDP segment (header + payload) — this is what gets fragmented
    udp_hdr = _build_udp_header(src_port, dst_port, len(snmp_payload))
    full_udp = udp_hdr + snmp_payload

    # Fragment the UDP segment into chunks
    chunks = []
    offset = 0
    while offset < len(full_udp):
        chunk = full_udp[offset:offset + fragment_size]
        chunks.append((offset, chunk))
        offset += len(chunk)

    packets = []
    for idx, (byte_offset, chunk) in enumerate(chunks):
        is_last = (idx == len(chunks) - 1)
        frag_offset_units = byte_offset // 8
        mf = not is_last

        ip_hdr = _build_ip_header(
            src_ip=src_ip,
            dst_ip='10.0.0.1',
            protocol=17,
            ip_id=ip_id,
            frag_offset_units=frag_offset_units,
            mf=mf,
            payload_len=len(chunk),
        )
        packets.append(eth_hdr + ip_hdr + chunk)

    return packets


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def packet_q():
    """Small packet queue for testing."""
    return queue.Queue(maxsize=100)


@pytest.fixture
def stop_ev():
    """Pre-cleared stop event."""
    ev = threading.Event()
    return ev


@pytest.fixture
def fragment_buffer():
    """Real FragmentReassemblyBuffer with short timeout for tests."""
    from trapninja.core.fragmentation import FragmentReassemblyBuffer
    buf = FragmentReassemblyBuffer(
        timeout_seconds=2.0,
        max_buffer_mb=10.0,
        max_datagrams=1000,
    )
    yield buf
    buf.shutdown()


@pytest.fixture
def capture_no_frag(packet_q, stop_ev):
    """MinimalTrapCapture instance WITHOUT fragment buffer."""
    from trapninja.ebpf import MinimalTrapCapture
    return MinimalTrapCapture(
        interface='eth0',
        listen_ports=[162],
        queue_ref=packet_q,
        stop_event_ref=stop_ev,
        fragment_buffer=None,
    )


@pytest.fixture
def capture_with_frag(packet_q, stop_ev, fragment_buffer):
    """MinimalTrapCapture instance WITH fragment buffer."""
    from trapninja.ebpf import MinimalTrapCapture
    return MinimalTrapCapture(
        interface='eth0',
        listen_ports=[162],
        queue_ref=packet_q,
        stop_event_ref=stop_ev,
        fragment_buffer=fragment_buffer,
    )


# ---------------------------------------------------------------------------
# Helper – drive _raw_capture_loop with fake packets
# ---------------------------------------------------------------------------

def _run_loop_with_packets(capture, packets, stop_ev, delay_before_stop=0.05):
    """
    Run _raw_capture_loop in a background thread, feeding it synthetic packets
    via a mocked raw socket, then stop it.

    Args:
        capture: MinimalTrapCapture instance (raw_socket must be set)
        packets: List of raw packet bytes to deliver in order
        stop_ev: threading.Event – will be set after all packets delivered
        delay_before_stop: Seconds to wait after final packet before setting stop_ev
    """
    import select as select_mod

    packet_iter = iter(packets)
    current_packet = [None]

    def fake_recv(bufsize):
        try:
            pkt = next(packet_iter)
            current_packet[0] = pkt
            return pkt
        except StopIteration:
            # Signal done
            time.sleep(delay_before_stop)
            stop_ev.set()
            # Return a too-short packet so the loop discards and then exits
            return b'\x00' * 10

    def fake_select(rlist, wlist, xlist, timeout):
        if stop_ev.is_set():
            return [], [], []
        return rlist, [], []

    mock_sock = MagicMock()
    mock_sock.recv.side_effect = fake_recv
    capture.raw_socket = mock_sock

    with patch('select.select', side_effect=fake_select):
        t = threading.Thread(target=capture._raw_capture_loop, daemon=True)
        t.start()
        t.join(timeout=5.0)

    return t


# ---------------------------------------------------------------------------
# Tests: fragment detection logic (unit-level, no socket)
# ---------------------------------------------------------------------------

class TestFragmentDetectionLogic:
    """
    Verify that the IP frag_off field is parsed correctly using the same
    struct.unpack pattern used in _raw_capture_loop.
    """

    def _parse_frag_field(self, mf: bool, offset_units: int) -> dict:
        """Parse a synthetic IP header and return fragment flags."""
        ip_hdr = _build_ip_header(
            src_ip='1.2.3.4',
            dst_ip='5.6.7.8',
            protocol=17,
            ip_id=0x1111,
            frag_offset_units=offset_units,
            mf=mf,
            payload_len=100,
        )
        iph = struct.unpack('!BBHHHBBH4s4s', ip_hdr[:20])
        frag_field = iph[4]
        return {
            'mf': bool(frag_field & 0x2000),
            'offset': frag_field & 0x1FFF,
            'is_fragment': bool((frag_field & 0x2000) or (frag_field & 0x1FFF)),
        }

    def test_complete_packet_no_fragment_flags(self):
        """Non-fragmented packet: MF=0, offset=0."""
        result = self._parse_frag_field(mf=False, offset_units=0)
        assert result['mf'] is False
        assert result['offset'] == 0
        assert result['is_fragment'] is False

    def test_first_fragment_mf_set(self):
        """First fragment: MF=1, offset=0."""
        result = self._parse_frag_field(mf=True, offset_units=0)
        assert result['mf'] is True
        assert result['offset'] == 0
        # First fragment IS a fragment (MF=1)
        assert result['is_fragment'] is True

    def test_non_first_fragment_offset_nonzero(self):
        """Non-first fragment: MF may be set or not, but offset > 0."""
        result = self._parse_frag_field(mf=True, offset_units=185)  # 185 * 8 = 1480
        assert result['offset'] == 185
        assert result['is_fragment'] is True

    def test_last_fragment_mf_clear_offset_nonzero(self):
        """Last fragment: MF=0, offset>0."""
        result = self._parse_frag_field(mf=False, offset_units=185)
        assert result['mf'] is False
        assert result['offset'] == 185
        assert result['is_fragment'] is True

    def test_maximum_fragment_offset(self):
        """Maximum possible offset (13 bits = 8191)."""
        result = self._parse_frag_field(mf=False, offset_units=8191)
        assert result['offset'] == 8191
        assert result['is_fragment'] is True


# ---------------------------------------------------------------------------
# Tests: create_capture / MinimalTrapCapture API
# ---------------------------------------------------------------------------

class TestCreateCaptureFragmentBuffer:
    """Verify create_capture() passes fragment_buffer to the capture instance."""

    def test_create_capture_without_buffer(self, packet_q, stop_ev):
        """create_capture() with no fragment_buffer defaults to None."""
        from trapninja.ebpf import create_capture
        cap = create_capture('eth0', [162], packet_q, stop_ev)
        assert cap.fragment_buffer is None

    def test_create_capture_with_buffer(self, packet_q, stop_ev, fragment_buffer):
        """create_capture() forwards fragment_buffer to MinimalTrapCapture."""
        from trapninja.ebpf import create_capture
        cap = create_capture('eth0', [162], packet_q, stop_ev,
                             fragment_buffer=fragment_buffer)
        assert cap.fragment_buffer is fragment_buffer

    def test_init_stores_fragment_buffer(self, packet_q, stop_ev, fragment_buffer):
        """MinimalTrapCapture stores fragment_buffer as instance attribute."""
        from trapninja.ebpf import MinimalTrapCapture
        cap = MinimalTrapCapture('eth0', [162], packet_q, stop_ev,
                                 fragment_buffer=fragment_buffer)
        assert cap.fragment_buffer is fragment_buffer


# ---------------------------------------------------------------------------
# Tests: non-fragmented packet passthrough (no regression)
# ---------------------------------------------------------------------------

class TestNonFragmentedPacketPassthrough:
    """Non-fragmented traps in eBPF mode must continue to work exactly as before."""

    def test_complete_snmp_trap_queued(self, capture_no_frag, packet_q, stop_ev):
        """A complete (non-fragmented) UDP packet is queued correctly."""
        snmp_payload = b'\x30\x26' + b'\x00' * 36  # synthetic SNMP-ish bytes
        raw_pkt = _build_complete_packet('10.1.1.1', 162, snmp_payload)

        _run_loop_with_packets(capture_no_frag, [raw_pkt], stop_ev)

        assert not packet_q.empty()
        item = packet_q.get_nowait()
        assert item['src_ip'] == '10.1.1.1'
        assert item['dst_port'] == 162
        assert item['payload'] == snmp_payload

    def test_non_matching_port_not_queued(self, capture_no_frag, packet_q, stop_ev):
        """Packets on non-configured ports are not queued."""
        snmp_payload = b'\x30\x10' + b'\x00' * 14
        # Send to port 9999 (not in listen_ports=[162])
        raw_pkt = _build_complete_packet('10.1.1.2', 9999, snmp_payload)

        _run_loop_with_packets(capture_no_frag, [raw_pkt], stop_ev)

        assert packet_q.empty()

    def test_non_udp_packet_ignored(self, capture_no_frag, packet_q, stop_ev):
        """Non-UDP (ICMP) packets are not queued."""
        eth_hdr = _build_ethernet_header()
        # Protocol 1 = ICMP
        ip_hdr = _build_ip_header('10.1.1.3', '10.0.0.1', 1, 0x1111, 0, False, 8)
        raw_pkt = eth_hdr + ip_hdr + b'\x08\x00\x00\x00\x00\x00\x00\x00'

        _run_loop_with_packets(capture_no_frag, [raw_pkt], stop_ev)

        assert packet_q.empty()

    def test_fragment_buffer_absent_does_not_affect_complete_packets(
        self, capture_no_frag, packet_q, stop_ev
    ):
        """Fragment buffer being None does not affect non-fragmented processing."""
        snmp_payload = b'\x30\x20' + b'\x00' * 30
        raw_pkt = _build_complete_packet('10.1.1.4', 162, snmp_payload)

        assert capture_no_frag.fragment_buffer is None
        _run_loop_with_packets(capture_no_frag, [raw_pkt], stop_ev)

        assert not packet_q.empty()
        item = packet_q.get_nowait()
        assert item['src_ip'] == '10.1.1.4'


# ---------------------------------------------------------------------------
# Tests: fragment reassembly disabled — observable warning, no silent loss
# ---------------------------------------------------------------------------

class TestFragmentReassemblyDisabled:
    """When fragment_buffer is None, fragments must not be silently dropped."""

    def test_non_first_fragment_logs_warning_when_disabled(
        self, capture_no_frag, packet_q, stop_ev, caplog
    ):
        """
        A non-first fragment arriving with reassembly disabled must emit a
        WARNING so operators know large traps may be lost.
        """
        import logging
        snmp_payload = b'\x00' * 1500
        fragments = _build_fragment_packets('10.2.2.2', 162, snmp_payload,
                                            fragment_size=1480)
        # Send only the second (non-first) fragment
        non_first_frag = fragments[1]

        with caplog.at_level(logging.WARNING, logger='trapninja'):
            _run_loop_with_packets(capture_no_frag, [non_first_frag], stop_ev)

        # Must emit a warning mentioning fragment reassembly is disabled
        warning_texts = [r.message for r in caplog.records
                         if r.levelno >= logging.WARNING]
        assert any('fragment' in w.lower() for w in warning_texts), \
            f"Expected fragment warning in: {warning_texts}"

    def test_non_first_fragment_not_queued_when_disabled(
        self, capture_no_frag, packet_q, stop_ev
    ):
        """Non-first fragment with no buffer must not produce a queue item."""
        snmp_payload = b'\x00' * 1500
        fragments = _build_fragment_packets('10.2.2.3', 162, snmp_payload,
                                            fragment_size=1480)
        non_first_frag = fragments[1]

        _run_loop_with_packets(capture_no_frag, [non_first_frag], stop_ev)

        assert packet_q.empty()


# ---------------------------------------------------------------------------
# Tests: fragment reassembly enabled — full pipeline
# ---------------------------------------------------------------------------

class TestFragmentReassemblyEnabled:
    """When fragment_buffer is provided, fragments must be reassembled and forwarded."""

    def test_two_fragment_trap_reassembled(
        self, capture_with_frag, packet_q, stop_ev
    ):
        """
        A 2-fragment SNMP trap is reassembled and queued as a single item with
        the correct src_ip, dst_port, and complete SNMP payload.
        """
        snmp_payload = b'\x30' + b'\x01' * 1500
        fragments = _build_fragment_packets(
            '10.3.3.1', 162, snmp_payload,
            ip_id=0xBEEF,
            fragment_size=1480,  # fragment_size must be multiple of 8
        )
        assert len(fragments) == 2, "Expected exactly 2 fragments for this payload size"

        _run_loop_with_packets(capture_with_frag, fragments, stop_ev)

        assert not packet_q.empty(), "Expected reassembled packet in queue"
        item = packet_q.get_nowait()
        assert item['src_ip'] == '10.3.3.1'
        assert item['dst_port'] == 162
        assert item['payload'] == snmp_payload

    def test_three_fragment_trap_reassembled(
        self, capture_with_frag, packet_q, stop_ev
    ):
        """A 3-fragment trap is fully reassembled in order."""
        snmp_payload = b'\x30' + b'\x02' * 3000
        fragments = _build_fragment_packets(
            '10.3.3.2', 162, snmp_payload,
            ip_id=0xCAFE,
            fragment_size=1480,
        )
        assert len(fragments) == 3

        _run_loop_with_packets(capture_with_frag, fragments, stop_ev)

        assert not packet_q.empty()
        item = packet_q.get_nowait()
        assert item['payload'] == snmp_payload

    def test_reassembled_packet_has_correct_dst_port(
        self, capture_with_frag, packet_q, stop_ev
    ):
        """Reassembled trap preserves the original UDP destination port."""
        snmp_payload = b'\x30' + b'\x03' * 1500
        fragments = _build_fragment_packets(
            '10.3.3.3', 1162, snmp_payload,  # non-standard port 1162
            ip_id=0xDEAD,
            fragment_size=1480,
        )
        # capture_with_frag listens on [162] — port 1162 is not in listen_ports
        # Rebuild a capture that listens on 1162
        from trapninja.ebpf import MinimalTrapCapture
        cap = MinimalTrapCapture(
            interface='eth0',
            listen_ports=[1162],
            queue_ref=packet_q,
            stop_event_ref=stop_ev,
            fragment_buffer=capture_with_frag.fragment_buffer,
        )

        _run_loop_with_packets(cap, fragments, stop_ev)

        assert not packet_q.empty()
        item = packet_q.get_nowait()
        assert item['dst_port'] == 1162

    def test_non_matching_port_not_queued_after_reassembly(
        self, capture_with_frag, packet_q, stop_ev
    ):
        """
        Reassembled trap whose UDP port is not in listen_ports must not be queued.
        capture_with_frag listens on [162], trap is sent to port 9999.
        """
        snmp_payload = b'\x30' + b'\x04' * 1500
        fragments = _build_fragment_packets(
            '10.3.3.4', 9999, snmp_payload,  # wrong port
            ip_id=0xFACE,
            fragment_size=1480,
        )

        _run_loop_with_packets(capture_with_frag, fragments, stop_ev)

        assert packet_q.empty()

    def test_fragment_stats_incremented(
        self, capture_with_frag, packet_q, stop_ev, fragment_buffer
    ):
        """Fragment statistics (completed) are incremented after reassembly."""
        initial_stats = fragment_buffer.get_stats()
        initial_completed = initial_stats.get('datagrams_completed', 0)

        snmp_payload = b'\x30' + b'\x05' * 1500
        fragments = _build_fragment_packets(
            '10.3.3.5', 162, snmp_payload,
            ip_id=0x1234,
            fragment_size=1480,
        )

        _run_loop_with_packets(capture_with_frag, fragments, stop_ev)

        final_stats = fragment_buffer.get_stats()
        assert final_stats['datagrams_completed'] == initial_completed + 1
        assert final_stats['fragments_received'] >= 2

    def test_complete_packet_not_fed_to_reassembly(
        self, capture_with_frag, packet_q, stop_ev, fragment_buffer
    ):
        """A non-fragmented packet bypasses the reassembly buffer entirely."""
        initial_stats = fragment_buffer.get_stats()

        snmp_payload = b'\x30\x20' + b'\x00' * 30
        raw_pkt = _build_complete_packet('10.3.3.6', 162, snmp_payload)

        _run_loop_with_packets(capture_with_frag, [raw_pkt], stop_ev)

        # Reassembly buffer should not have been touched
        final_stats = fragment_buffer.get_stats()
        assert final_stats['fragments_received'] == initial_stats['fragments_received']

        assert not packet_q.empty()
        item = packet_q.get_nowait()
        assert item['payload'] == snmp_payload


# ---------------------------------------------------------------------------
# Helpers – stub Scapy so core.capture can be imported without Scapy installed
# ---------------------------------------------------------------------------

def _stub_scapy():
    """
    Insert minimal Scapy stubs into sys.modules so trapninja.core.capture
    can be imported without Scapy being installed.  Returns a context manager
    that removes the stubs on exit.
    """
    import sys
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        scapy_mods = {
            'scapy': MagicMock(),
            'scapy.all': MagicMock(),
        }
        # Patch only if not already present (avoids stomping a real Scapy install)
        to_restore = {}
        for name, stub in scapy_mods.items():
            if name not in sys.modules:
                sys.modules[name] = stub
                to_restore[name] = None
            else:
                to_restore[name] = sys.modules[name]

        # Also clear cached trapninja.core.capture if it was already loaded
        # without the stub, so it gets re-imported cleanly.
        capture_key = 'trapninja.core.capture'
        old_capture = sys.modules.pop(capture_key, None)
        service_init_key = 'trapninja.core.service_init'
        old_si = sys.modules.pop(service_init_key, None)

        try:
            yield
        finally:
            for name, orig in to_restore.items():
                if orig is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = orig
            # Restore or remove the capture module cache
            if old_capture is not None:
                sys.modules[capture_key] = old_capture
            else:
                sys.modules.pop(capture_key, None)
            if old_si is not None:
                sys.modules[service_init_key] = old_si
            else:
                sys.modules.pop(service_init_key, None)

    return _ctx()


# ---------------------------------------------------------------------------
# Tests: try_ebpf_capture() fragment initialisation
# ---------------------------------------------------------------------------

class TestTryEbpfCaptureFragmentInit:
    """
    try_ebpf_capture() must call initialize_fragment_reassembly() before
    creating the capture instance, and must pass the buffer to create_capture().
    """

    def test_fragment_reassembly_initialized_before_capture(self):
        """
        When fragment_reassembly is enabled in config, try_ebpf_capture must
        initialize the buffer and pass it to create_capture().
        """
        with _stub_scapy():
            from trapninja.core.capture import try_ebpf_capture
            from trapninja.core.service_init import SubsystemHandles

            handles = SubsystemHandles()

            mock_capture_instance = MagicMock()
            mock_capture_instance.start.return_value = True

            captured_kwargs = {}

            def fake_create_capture(*args, **kwargs):
                captured_kwargs.update(kwargs)
                return mock_capture_instance

            mock_frag_buf = MagicMock()

            def fake_init_frag(h):
                h.fragment_buffer = mock_frag_buf
                h.fragment_reassembly_enabled = True

            with patch('trapninja.core.capture.modules') as mock_modules, \
                 patch('trapninja.core.capture.initialize_fragment_reassembly',
                       side_effect=fake_init_frag) as mock_init_frag, \
                 patch('trapninja.core.capture.packet_queue', MagicMock()), \
                 patch('trapninja.core.capture.stop_event', MagicMock()), \
                 patch('trapninja.core.capture.INTERFACE', 'eth0'), \
                 patch('trapninja.core.capture.LISTEN_PORTS', [162]):

                mock_modules.ebpf.is_supported.return_value = True
                mock_modules.ebpf.check_dependencies.return_value = True
                mock_modules.ebpf.create_capture.side_effect = fake_create_capture

                result = try_ebpf_capture(handles)

            assert result is True
            mock_init_frag.assert_called_once_with(handles)
            # fragment_buffer must be forwarded to create_capture
            assert captured_kwargs.get('fragment_buffer') is mock_frag_buf
            assert handles.fragment_buffer is mock_frag_buf

    def test_fragment_reassembly_disabled_no_buffer_passed(self):
        """When fragment_reassembly is disabled, None is passed to create_capture."""
        with _stub_scapy():
            from trapninja.core.capture import try_ebpf_capture
            from trapninja.core.service_init import SubsystemHandles

            handles = SubsystemHandles()  # fragment_buffer=None, disabled=False

            mock_capture_instance = MagicMock()
            mock_capture_instance.start.return_value = True

            captured_kwargs = {}

            def fake_create_capture(*args, **kwargs):
                captured_kwargs.update(kwargs)
                return mock_capture_instance

            def fake_init_frag(h):
                # Simulate disabled: nothing set on handles
                pass

            with patch('trapninja.core.capture.modules') as mock_modules, \
                 patch('trapninja.core.capture.initialize_fragment_reassembly',
                       side_effect=fake_init_frag), \
                 patch('trapninja.core.capture.packet_queue', MagicMock()), \
                 patch('trapninja.core.capture.stop_event', MagicMock()), \
                 patch('trapninja.core.capture.INTERFACE', 'eth0'), \
                 patch('trapninja.core.capture.LISTEN_PORTS', [162]):

                mock_modules.ebpf.is_supported.return_value = True
                mock_modules.ebpf.check_dependencies.return_value = True
                mock_modules.ebpf.create_capture.side_effect = fake_create_capture

                result = try_ebpf_capture(handles)

            assert result is True
            assert captured_kwargs.get('fragment_buffer') is None


# ---------------------------------------------------------------------------
# Tests: capture_config.json fragment_reassembly block
# ---------------------------------------------------------------------------

class TestCaptureConfigFragmentBlock:
    """The active capture_config.json must contain the fragment_reassembly block."""

    def test_capture_config_has_fragment_reassembly_block(self):
        """capture_config.json contains a fragment_reassembly section."""
        config_path = SRC_DIR / 'config' / 'capture_config.json'
        assert config_path.exists(), f"capture_config.json not found at {config_path}"

        with open(config_path) as f:
            cfg = json.load(f)

        assert 'fragment_reassembly' in cfg, \
            "fragment_reassembly block missing from capture_config.json"
        frag = cfg['fragment_reassembly']
        assert 'enabled' in frag
        assert 'timeout_seconds' in frag
        assert 'max_buffer_mb' in frag
        assert 'max_datagrams' in frag

    def test_capture_config_fragment_reassembly_disabled_by_default(self):
        """fragment_reassembly.enabled defaults to false (opt-in for operators)."""
        config_path = SRC_DIR / 'config' / 'capture_config.json'
        with open(config_path) as f:
            cfg = json.load(f)

        assert cfg['fragment_reassembly']['enabled'] is False, \
            "fragment_reassembly should default to disabled (operator opt-in)"
