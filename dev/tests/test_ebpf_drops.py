#!/usr/bin/env python3
"""
TrapNinja Test Suite - eBPF Raw Socket Drop Tests

Tests for the AF_PACKET-level drop counter introduced in Phase 1 Part B2
addendum: get_ebpf_raw_socket_drops(), _active_raw_socket lifecycle, and
the interaction between the cumulative accumulator and the kernel's
reset-on-read PACKET_STATISTICS behaviour.
"""

import struct
import threading
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_ebpf_drop_state(ebpf_mod):
    """Reset module-level drop state between tests."""
    ebpf_mod._active_raw_socket = None
    ebpf_mod._raw_socket_drops_cumulative = 0


# ---------------------------------------------------------------------------
# get_ebpf_raw_socket_drops() — no active socket
# ---------------------------------------------------------------------------

class TestGetEbpfRawSocketDropsNoSocket:

    def test_no_socket_returns_zero(self):
        """With no active socket, returns 0 without raising."""
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)

        result = ebpf.get_ebpf_raw_socket_drops()
        assert result == 0

    def test_no_socket_returns_prior_cumulative(self):
        """With no active socket, returns whatever cumulative total was built up."""
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)
        ebpf._raw_socket_drops_cumulative = 42

        result = ebpf.get_ebpf_raw_socket_drops()
        assert result == 42

        _reset_ebpf_drop_state(ebpf)  # clean up


# ---------------------------------------------------------------------------
# get_ebpf_raw_socket_drops() — with a mock socket
# ---------------------------------------------------------------------------

class TestGetEbpfRawSocketDropsWithSocket:

    def _make_mock_socket(self, tp_packets: int, tp_drops: int):
        """Return a mock socket whose getsockopt returns the given values."""
        sock = MagicMock()
        sock.getsockopt.return_value = struct.pack('=II', tp_packets, tp_drops)
        return sock

    def test_single_read_accumulates_drops(self):
        """A mock getsockopt returning 5 drops produces cumulative total of 5."""
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)

        ebpf._active_raw_socket = self._make_mock_socket(100, 5)
        result = ebpf.get_ebpf_raw_socket_drops()

        assert result == 5
        _reset_ebpf_drop_state(ebpf)

    def test_two_reads_accumulate(self):
        """
        Calling twice with 5 drops then 3 drops yields 8 cumulative.

        This is the critical correctness test: the kernel resets tp_drops
        to 0 after each read, so the function must add each read's delta
        to its own running total rather than returning the raw value.
        """
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)

        sock = MagicMock()
        sock.getsockopt.side_effect = [
            struct.pack('=II', 100, 5),
            struct.pack('=II', 50, 3),
        ]
        ebpf._active_raw_socket = sock

        first = ebpf.get_ebpf_raw_socket_drops()
        second = ebpf.get_ebpf_raw_socket_drops()

        assert first == 5
        assert second == 8, (
            f"Expected cumulative 8 (5+3), got {second}. "
            "Accumulator must compensate for kernel reset-on-read behaviour."
        )
        _reset_ebpf_drop_state(ebpf)

    def test_oserror_returns_last_cumulative_does_not_raise(self):
        """If getsockopt raises OSError, return last cumulative total without raising."""
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)
        ebpf._raw_socket_drops_cumulative = 10

        sock = MagicMock()
        sock.getsockopt.side_effect = OSError("socket closed")
        ebpf._active_raw_socket = sock

        result = ebpf.get_ebpf_raw_socket_drops()
        assert result == 10

        _reset_ebpf_drop_state(ebpf)

    def test_oserror_logs_at_debug_not_warning(self, caplog):
        """OSError from getsockopt is logged at DEBUG level, not WARNING or ERROR."""
        import logging
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)

        sock = MagicMock()
        sock.getsockopt.side_effect = OSError("no stats")
        ebpf._active_raw_socket = sock

        with caplog.at_level(logging.DEBUG, logger="trapninja"):
            ebpf.get_ebpf_raw_socket_drops()

        # Must log at debug
        debug_msgs = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("AF_PACKET" in r.message for r in debug_msgs), (
            "Expected a DEBUG log mentioning AF_PACKET on getsockopt failure"
        )

        # Must NOT log at warning or error
        loud_msgs = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(loud_msgs) == 0, (
            f"Expected no WARNING/ERROR logs on OSError, got: {[r.message for r in loud_msgs]}"
        )

        _reset_ebpf_drop_state(ebpf)


# ---------------------------------------------------------------------------
# _active_raw_socket lifecycle — _init_raw_capture and stop
# ---------------------------------------------------------------------------

class TestActiveRawSocketLifecycle:

    def test_init_raw_capture_sets_active_socket(self):
        """After a successful _init_raw_capture(), _active_raw_socket matches self.raw_socket.

        Mocks the entire socket module used by ebpf.py so that AF_PACKET
        (Linux-only constant) does not need to exist on the test platform.
        """
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)

        mock_sock = MagicMock()

        # Build a mock socket module that has AF_PACKET so the call inside
        # _init_raw_capture() doesn't fail on platforms without it (Windows).
        mock_socket_module = MagicMock()
        mock_socket_module.AF_PACKET = 17
        mock_socket_module.SOCK_RAW = 3
        mock_socket_module.htons.return_value = 0x0008
        mock_socket_module.socket.return_value = mock_sock

        capture = ebpf.MinimalTrapCapture.__new__(ebpf.MinimalTrapCapture)
        capture.raw_socket = None
        capture.interface = "any"
        capture.capture_thread = None

        with patch('trapninja.ebpf.socket', mock_socket_module), \
             patch('trapninja.ebpf.threading.Thread') as mock_thread_cls:
            mock_thread_cls.return_value = MagicMock()
            result = capture._init_raw_capture()

        assert result is True
        assert ebpf._active_raw_socket is mock_sock

        _reset_ebpf_drop_state(ebpf)

    def test_stop_clears_active_socket(self):
        """After stop(), _active_raw_socket is set to None when it matched self.raw_socket."""
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)

        mock_sock = MagicMock()
        ebpf._active_raw_socket = mock_sock

        capture = ebpf.MinimalTrapCapture.__new__(ebpf.MinimalTrapCapture)
        capture.raw_socket = mock_sock
        capture.bpf = None

        capture.stop()

        assert ebpf._active_raw_socket is None
        _reset_ebpf_drop_state(ebpf)

    def test_stop_does_not_clear_unrelated_socket(self):
        """stop() uses 'is' check — does not clear a different socket set by a newer instance."""
        import trapninja.ebpf as ebpf
        _reset_ebpf_drop_state(ebpf)

        old_sock = MagicMock()
        new_sock = MagicMock()
        ebpf._active_raw_socket = new_sock  # a newer instance already registered

        capture = ebpf.MinimalTrapCapture.__new__(ebpf.MinimalTrapCapture)
        capture.raw_socket = old_sock  # this is the older instance stopping
        capture.bpf = None

        capture.stop()

        # The newer socket reference must still be registered
        assert ebpf._active_raw_socket is new_sock
        _reset_ebpf_drop_state(ebpf)
