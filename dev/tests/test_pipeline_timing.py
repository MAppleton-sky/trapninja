#!/usr/bin/env python3
"""
TrapNinja Test Suite - Pipeline Timing Tests

Tests for trapninja.processing.pipeline_timing — the Phase 1 load-test
instrumentation that tracks per-stage latency (queue wait + processing duration)
using lock-free ring buffers.

Author: TrapNinja Team
"""

import queue
import threading
import time
import pytest
from unittest.mock import patch, MagicMock


# =============================================================================
# RING BUFFER
# =============================================================================

class TestRingBuffer:
    """Tests for RingBuffer correctness and wraparound behaviour."""

    def test_snapshot_empty(self):
        """Empty buffer returns empty list."""
        from trapninja.processing.pipeline_timing import RingBuffer

        buf = RingBuffer(size=16)
        assert buf.snapshot() == []

    def test_record_and_snapshot_before_wraparound(self):
        """Records up to capacity; snapshot contains all written values."""
        from trapninja.processing.pipeline_timing import RingBuffer

        buf = RingBuffer(size=10)
        for i in range(10):
            buf.record(float(i))

        snap = buf.snapshot()
        assert len(snap) == 10
        assert set(snap) == set(range(10))

    def test_snapshot_partial_fill(self):
        """Snapshot reflects only the samples written so far."""
        from trapninja.processing.pipeline_timing import RingBuffer

        buf = RingBuffer(size=100)
        for i in range(5):
            buf.record(float(i))

        snap = buf.snapshot()
        assert len(snap) == 5

    def test_wraparound_caps_length(self):
        """After writing more than size samples, snapshot length stays capped at size."""
        from trapninja.processing.pipeline_timing import RingBuffer

        size = 16
        buf = RingBuffer(size=size)
        for i in range(size * 3):
            buf.record(float(i))

        snap = buf.snapshot()
        assert len(snap) == size

    def test_wraparound_overwrites_oldest(self):
        """After wraparound, oldest values are replaced by newest."""
        from trapninja.processing.pipeline_timing import RingBuffer

        buf = RingBuffer(size=4)
        for i in range(4):
            buf.record(float(i))  # 0, 1, 2, 3

        # Write one more — should overwrite oldest slot (0)
        buf.record(99.0)

        snap = buf.snapshot()
        assert len(snap) == 4
        assert 99.0 in snap
        # Value 0 should no longer be present (overwritten)
        assert 0.0 not in snap

    def test_record_is_o1(self):
        """record() completes in constant time regardless of buffer size."""
        from trapninja.processing.pipeline_timing import RingBuffer

        buf = RingBuffer(size=4096)
        t0 = time.monotonic()
        for i in range(4096):
            buf.record(float(i))
        elapsed = time.monotonic() - t0

        # Should finish well under 1 second even on slow CI hardware
        assert elapsed < 1.0


# =============================================================================
# PERCENTILE SUMMARY
# =============================================================================

class TestPercentileSummary:
    """Tests for _percentile_summary helper."""

    def test_empty_input_returns_zeros(self):
        """Empty sample list returns all-zero result without raising."""
        from trapninja.processing.pipeline_timing import _percentile_summary

        result = _percentile_summary([], (50, 95, 99))
        assert result['p50'] == 0.0
        assert result['p95'] == 0.0
        assert result['p99'] == 0.0
        assert result['max'] == 0.0
        assert result['samples'] == 0

    def test_ordering_invariant(self):
        """p50 <= p95 <= p99 <= max for a known dataset."""
        from trapninja.processing.pipeline_timing import _percentile_summary

        samples = list(range(1000))
        result = _percentile_summary(samples, (50, 95, 99))

        assert result['p50'] <= result['p95']
        assert result['p95'] <= result['p99']
        assert result['p99'] <= result['max']

    def test_max_is_correct(self):
        """max should equal the largest sample in the set."""
        from trapninja.processing.pipeline_timing import _percentile_summary

        samples = list(range(1000))
        result = _percentile_summary(samples, (50, 95, 99))

        assert result['max'] == 999.0

    def test_samples_count(self):
        """samples key equals len(input)."""
        from trapninja.processing.pipeline_timing import _percentile_summary

        samples = list(range(200))
        result = _percentile_summary(samples, (50,))

        assert result['samples'] == 200

    def test_single_sample(self):
        """Single-element list: all percentiles equal that value."""
        from trapninja.processing.pipeline_timing import _percentile_summary

        result = _percentile_summary([42.0], (50, 95, 99))

        assert result['p50'] == 42.0
        assert result['p95'] == 42.0
        assert result['p99'] == 42.0
        assert result['max'] == 42.0


# =============================================================================
# PIPELINE TIMING COLLECTOR
# =============================================================================

class TestPipelineTimingCollector:
    """Tests for PipelineTimingCollector registration and percentile computation."""

    def test_compute_percentiles_no_workers(self):
        """No registered workers yields all-zero result without raising."""
        from trapninja.processing.pipeline_timing import PipelineTimingCollector

        collector = PipelineTimingCollector(enabled=True)
        result = collector.compute_percentiles()

        assert 'queue_wait_seconds' in result
        assert 'processing_duration_seconds' in result
        assert result['queue_wait_seconds']['samples'] == 0
        assert result['processing_duration_seconds']['samples'] == 0

    def test_register_worker_returns_buffers(self):
        """register_worker returns a WorkerTimingBuffers instance."""
        from trapninja.processing.pipeline_timing import (
            PipelineTimingCollector, WorkerTimingBuffers
        )

        collector = PipelineTimingCollector(enabled=True)
        buffers = collector.register_worker(0)

        assert isinstance(buffers, WorkerTimingBuffers)
        assert buffers.worker_id == 0

    def test_register_same_worker_twice_replaces(self):
        """Calling register_worker with the same id returns a fresh buffer pair."""
        from trapninja.processing.pipeline_timing import PipelineTimingCollector

        collector = PipelineTimingCollector(enabled=True)
        b1 = collector.register_worker(0)
        b1.queue_wait.record(99.0)

        b2 = collector.register_worker(0)
        # Fresh buffer — no samples yet
        assert b2.queue_wait.snapshot() == []

    def test_unregister_worker_removes_buffers(self):
        """unregister_worker removes the worker's buffers from future percentile calls."""
        from trapninja.processing.pipeline_timing import PipelineTimingCollector

        collector = PipelineTimingCollector(enabled=True)
        buffers = collector.register_worker(7)
        buffers.queue_wait.record(0.5)

        collector.unregister_worker(7)
        result = collector.compute_percentiles()

        assert result['queue_wait_seconds']['samples'] == 0

    def test_compute_percentiles_includes_all_workers(self):
        """Samples from multiple workers are all included in the aggregate."""
        from trapninja.processing.pipeline_timing import PipelineTimingCollector

        collector = PipelineTimingCollector(enabled=True)
        for worker_id in range(3):
            buf = collector.register_worker(worker_id)
            for _ in range(10):
                buf.queue_wait.record(float(worker_id) * 0.001)

        result = collector.compute_percentiles()
        assert result['queue_wait_seconds']['samples'] == 30


# =============================================================================
# CONCURRENCY
# =============================================================================

class TestConcurrency:
    """
    Concurrent write + read must not deadlock or raise.

    Torn reads (a percentile computation seeing one partially-overwritten slot)
    are an accepted, documented property of the lock-free design. These tests
    only assert that no exception occurs and the result shape is always valid.
    """

    def test_concurrent_record_and_compute(self):
        """Writers and a reader run concurrently without raising."""
        from trapninja.processing.pipeline_timing import PipelineTimingCollector

        collector = PipelineTimingCollector(enabled=True)
        num_workers = 4
        buffers = [collector.register_worker(i) for i in range(num_workers)]

        errors = []
        stop = threading.Event()

        def writer(buf):
            while not stop.is_set():
                buf.queue_wait.record(time.monotonic())
                buf.processing_duration.record(time.monotonic())

        def reader():
            while not stop.is_set():
                try:
                    result = collector.compute_percentiles()
                    assert 'queue_wait_seconds' in result
                    assert 'processing_duration_seconds' in result
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=writer, args=(b,), daemon=True) for b in buffers]
        threads.append(threading.Thread(target=reader, daemon=True))
        for t in threads:
            t.start()

        time.sleep(0.3)
        stop.set()
        for t in threads:
            t.join(timeout=2.0)

        assert errors == [], f"Exceptions during concurrent access: {errors}"


# =============================================================================
# END-TO-END: WORKERS + QUEUE
# =============================================================================

class TestEndToEnd:
    """
    Run synthetic packets through start_workers() and verify timing is recorded.

    Tests the _capture_ts → _dequeue_ts → queue_wait path and confirms that
    packets without _capture_ts only contribute to processing_duration, not
    queue_wait — the correct behaviour for replayed packets.
    """

    def test_packets_with_capture_ts_contribute_to_queue_wait(self):
        """Packets carrying _capture_ts must contribute to queue_wait_seconds."""
        from trapninja.processing.pipeline_timing import (
            get_pipeline_timing_collector,
            reset_pipeline_timing_collector,
        )
        from trapninja.processing.worker import PacketWorker

        reset_pipeline_timing_collector()

        pq = queue.Queue()
        stop_event = threading.Event()

        worker = PacketWorker(
            worker_id=99,
            packet_queue=pq,
            stop_event=stop_event,
            batch_size=10,
            timeout=0.2,
        )

        # Inject packets with _capture_ts
        capture_ts = time.monotonic() - 0.01  # 10ms ago
        for _ in range(5):
            pq.put({'src_ip': '127.0.0.1', 'dst_port': 162,
                    'payload': b'\x30\x00', '_capture_ts': capture_ts})

        thread = worker.start()
        # Wait for packets to be processed but read percentiles BEFORE the worker
        # unregisters its buffers during shutdown (unregister_worker fires in _run's
        # shutdown tail, before thread.join() returns).
        time.sleep(0.5)
        result = get_pipeline_timing_collector().compute_percentiles()
        stop_event.set()
        thread.join(timeout=2.0)

        # queue_wait should have samples (>=5 packets with _capture_ts)
        assert result['queue_wait_seconds']['samples'] > 0

    def test_packets_without_capture_ts_skip_queue_wait(self):
        """Replay-style packets (no _capture_ts) must not contribute to queue_wait."""
        from trapninja.processing.pipeline_timing import (
            get_pipeline_timing_collector,
            reset_pipeline_timing_collector,
        )
        from trapninja.processing.worker import PacketWorker

        reset_pipeline_timing_collector()

        pq = queue.Queue()
        stop_event = threading.Event()

        worker = PacketWorker(
            worker_id=98,
            packet_queue=pq,
            stop_event=stop_event,
            batch_size=10,
            timeout=0.2,
        )

        # Inject packets WITHOUT _capture_ts (simulates replay path)
        for _ in range(5):
            pq.put({'src_ip': '127.0.0.1', 'dst_port': 162,
                    'payload': b'\x30\x00'})

        thread = worker.start()
        # Read before shutdown — see note in test above
        time.sleep(0.5)
        result = get_pipeline_timing_collector().compute_percentiles()
        stop_event.set()
        thread.join(timeout=2.0)

        # queue_wait should have no samples (no _capture_ts on any packet)
        assert result['queue_wait_seconds']['samples'] == 0
        # processing_duration should have samples (all packets were processed)
        assert result['processing_duration_seconds']['samples'] > 0

    def test_all_packets_contribute_to_processing_duration(self):
        """Both replay and live packets contribute to processing_duration."""
        from trapninja.processing.pipeline_timing import (
            get_pipeline_timing_collector,
            reset_pipeline_timing_collector,
        )
        from trapninja.processing.worker import PacketWorker

        reset_pipeline_timing_collector()

        pq = queue.Queue()
        stop_event = threading.Event()

        worker = PacketWorker(
            worker_id=97,
            packet_queue=pq,
            stop_event=stop_event,
            batch_size=20,
            timeout=0.2,
        )

        capture_ts = time.monotonic()
        for _ in range(3):
            pq.put({'src_ip': '127.0.0.1', 'dst_port': 162,
                    'payload': b'\x30\x00', '_capture_ts': capture_ts})
        for _ in range(3):
            pq.put({'src_ip': '127.0.0.2', 'dst_port': 162,
                    'payload': b'\x30\x00'})

        thread = worker.start()
        # Read before shutdown — see note in test above
        time.sleep(0.5)
        result = get_pipeline_timing_collector().compute_percentiles()
        stop_event.set()
        thread.join(timeout=2.0)

        assert result['processing_duration_seconds']['samples'] >= 6


# =============================================================================
# MICROBENCHMARK (informational)
# =============================================================================

class TestMicrobenchmark:
    """
    Measure timing overhead ratio: enabled vs disabled.

    The bound is generous (3x) to avoid CI flakiness on slow machines;
    it is tight enough to catch a regression like someone adding a lock
    to the write path (which would push the ratio well above 3x under
    multi-worker load).
    """

    def test_overhead_ratio_under_3x(self):
        """Worker with timing enabled should not be more than 3x slower than disabled."""
        from trapninja.processing.pipeline_timing import (
            PipelineTimingCollector,
            reset_pipeline_timing_collector,
        )
        from trapninja.processing.worker import PacketWorker

        N = 200
        payload = b'\x30\x00'

        def run_with_timing(enabled):
            reset_pipeline_timing_collector()

            # Patch the singleton to return a collector with the desired enabled state
            fake_collector = PipelineTimingCollector(enabled=enabled, ring_size=512)
            with patch(
                'trapninja.processing.worker.get_pipeline_timing_collector',
                return_value=fake_collector,
            ):
                pq = queue.Queue()
                stop_event = threading.Event()
                worker = PacketWorker(
                    worker_id=50, packet_queue=pq,
                    stop_event=stop_event, batch_size=50, timeout=0.1,
                )

                capture_ts = time.monotonic()
                for _ in range(N):
                    pq.put({'src_ip': '127.0.0.1', 'dst_port': 162,
                            'payload': payload, '_capture_ts': capture_ts})

                t0 = time.monotonic()
                thread = worker.start()
                pq.join()
                elapsed = time.monotonic() - t0
                stop_event.set()
                thread.join(timeout=2.0)

            return elapsed

        time_enabled = run_with_timing(True)
        time_disabled = run_with_timing(False)

        if time_disabled > 0:
            ratio = time_enabled / time_disabled
            # Log for visibility; do not assert exact value (too flaky on CI)
            print(f"\nTiming overhead ratio: {ratio:.2f}x "
                  f"(enabled={time_enabled*1000:.1f}ms, "
                  f"disabled={time_disabled*1000:.1f}ms)")
            # Windows time.monotonic() has higher per-call overhead; use 6.0x
            # there so the guard still catches a genuine regression (10x+) while
            # passing normal variability on both platforms.
            import sys
            threshold = 6.0 if sys.platform == 'win32' else 3.0
            assert ratio < threshold, (
                f"Timing overhead too high: {ratio:.2f}x — "
                f"check for accidental lock on write path"
            )


# =============================================================================
# SINGLETON ISOLATION
# =============================================================================

class TestSingletonIsolation:
    """
    Verify get_pipeline_timing_collector() returns a stable singleton and
    reset_pipeline_timing_collector() produces a fresh instance.

    Documents the assumption that replay and live daemon always run as
    separate processes (true process isolation cannot be unit-tested, but
    the singleton reset behaviour covers the intra-process guarantee).
    """

    def test_singleton_same_instance(self):
        """Two consecutive calls return the same object."""
        from trapninja.processing.pipeline_timing import (
            get_pipeline_timing_collector,
            reset_pipeline_timing_collector,
        )

        reset_pipeline_timing_collector()
        c1 = get_pipeline_timing_collector()
        c2 = get_pipeline_timing_collector()

        assert c1 is c2

    def test_reset_yields_new_instance(self):
        """After reset, get_pipeline_timing_collector() returns a different object."""
        from trapninja.processing.pipeline_timing import (
            get_pipeline_timing_collector,
            reset_pipeline_timing_collector,
        )

        reset_pipeline_timing_collector()
        c1 = get_pipeline_timing_collector()

        reset_pipeline_timing_collector()
        c2 = get_pipeline_timing_collector()

        assert c1 is not c2

    def test_reset_clears_registered_workers(self):
        """After reset, no workers are registered in the new collector."""
        from trapninja.processing.pipeline_timing import (
            get_pipeline_timing_collector,
            reset_pipeline_timing_collector,
        )

        reset_pipeline_timing_collector()
        c1 = get_pipeline_timing_collector()
        c1.register_worker(0)

        reset_pipeline_timing_collector()
        c2 = get_pipeline_timing_collector()

        # Fresh collector should have no workers
        result = c2.compute_percentiles()
        assert result['queue_wait_seconds']['samples'] == 0
