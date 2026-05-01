#!/usr/bin/env python3
"""
TrapNinja Packet Processing Workers

High-performance worker threads for SNMP trap packet processing.
Each worker pulls packets from a shared queue and processes them
through the filtering/forwarding pipeline.

Key optimisations:
    - Batch processing with adaptive batch sizes
    - Cached configuration (30s TTL via ConfigCache)
    - Fast path for SNMPv2c (byte-level, no Scapy)
    - Minimal per-packet logging

Architecture:
    PacketWorker inherits from PacketHandler (packet_handler.py) for
    the processing pipeline and adds thread lifecycle management,
    batch collection, and periodic logging.

Author: TrapNinja Team
Version: 2.0.0
"""

import time
import queue
import threading
import logging
from typing import Optional, List, Dict, Any

from .stats import StatsCollector, get_global_stats
from .packet_handler import PacketHandler

# Re-export from submodules for backward-compatible import paths.
# Tests and downstream code may import these from worker rather than
# the specific submodule.  The canonical implementations live in
# config_cache.py and forwarder.py respectively.
from .config_cache import ConfigCache, _config_cache      # noqa: F401
from .forwarder import forward_packet                      # noqa: F401

logger = logging.getLogger("trapninja")


# =============================================================================
# PACKET WORKER
# =============================================================================

class PacketWorker(PacketHandler):
    """
    High-performance packet processing worker.

    Inherits processing pipeline from PacketHandler and adds:
    - Thread lifecycle management (start, stop, join)
    - Batch collection from shared queue
    - Periodic summary logging
    """

    def __init__(
        self,
        worker_id: int,
        packet_queue: queue.Queue,
        stop_event: threading.Event,
        batch_size: int = 50,
        timeout: float = 0.5
    ):
        """
        Initialise packet worker.

        Args:
            worker_id: Unique worker identifier
            packet_queue: Queue to read packets from
            stop_event: Event to signal shutdown
            batch_size: Maximum packets per batch
            timeout: Timeout for queue reads
        """
        self.worker_id = worker_id
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.batch_size = batch_size
        self.timeout = timeout

        self.stats = StatsCollector()
        self._thread: Optional[threading.Thread] = None
        self._packets_since_log = 0
        self._log_interval = 1000

        # Initialise packet handler state (granular stats, cache refs)
        self._init_handler()

    def start(self) -> threading.Thread:
        """
        Start worker thread.

        Returns:
            Worker thread
        """
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"PacketWorker-{self.worker_id}"
        )
        self._thread.start()
        logger.info(f"Packet worker {self.worker_id} started")
        return self._thread

    def _run(self):
        """Main worker loop — collect batches and process."""
        batch = []

        while not self.stop_event.is_set():
            try:
                # Collect a batch
                deadline = time.time() + self.timeout

                while len(batch) < self.batch_size:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break

                    try:
                        packet = self.packet_queue.get(
                            timeout=min(remaining, 0.05)
                        )
                        batch.append(packet)
                    except queue.Empty:
                        break

                # Process batch if we have packets
                if batch:
                    self._process_batch(batch)
                    batch.clear()

            except Exception as e:
                logger.error(f"Worker {self.worker_id} error: {e}")
                batch.clear()

        # Final flush
        self.stats.flush()
        logger.info(f"Packet worker {self.worker_id} stopped")

    def _process_batch(self, batch: List[Dict[str, Any]]):
        """Process a batch of packets."""
        for packet in batch:
            self._process_packet(packet)
            try:
                self.packet_queue.task_done()
            except ValueError:
                pass

        self._packets_since_log += len(batch)

        # Periodic logging
        if self._packets_since_log >= self._log_interval:
            stats = get_global_stats()
            if stats.should_log_summary():
                logger.info(
                    f"Processing: received_60s={stats.received_last_60s}, "
                    f"fast_path={stats.fast_path_ratio:.1f}%"
                )
            self._packets_since_log = 0


# =============================================================================
# WORKER MANAGEMENT
# =============================================================================

_workers: List[PacketWorker] = []


def start_workers(
    packet_queue: queue.Queue,
    stop_event: threading.Event = None,
    num_workers: int = None
) -> List[threading.Thread]:
    """
    Start packet processing workers.

    Args:
        packet_queue: Queue to process packets from
        stop_event: Event to signal shutdown
        num_workers: Number of workers (default: 2x CPU cores, max 32)

    Returns:
        List of worker threads
    """
    global _workers
    import multiprocessing

    if stop_event is None:
        try:
            from ..config import stop_event as config_stop_event
            stop_event = config_stop_event
        except ImportError:
            stop_event = threading.Event()

    if num_workers is None:
        cpu_count = multiprocessing.cpu_count()
        num_workers = min(cpu_count * 2, 32)

    threads = []
    for i in range(num_workers):
        worker = PacketWorker(i, packet_queue, stop_event)
        _workers.append(worker)
        threads.append(worker.start())

    logger.info(f"Started {num_workers} packet processing workers")
    return threads


def get_processor_stats() -> Dict[str, Any]:
    """Get current processor statistics."""
    return get_global_stats().to_dict()


def reset_processor_stats():
    """Reset processor statistics."""
    from .stats import reset_global_stats
    reset_global_stats()
