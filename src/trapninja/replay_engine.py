#!/usr/bin/env python3
"""
TrapNinja Capture File Replay Engine

Development and testing tool. Reads pcap/pcapng capture files and injects
packets into the existing processing pipeline (network.packet_queue) exactly
as if they had arrived from the network.

IMPORTANT: This is NOT for use on live production instances.
           Injected packets are processed and forwarded to real destinations.

Injection point: network.packet_queue (dict format: src_ip, dst_port, payload)
This is the same queue used by all live capture paths (eBPF, sniff, UDP socket).

Replay metrics are held in-process only and are NEVER merged with production
counters (_queue_stats, shared stats module, Prometheus metrics files).
"""

import atexit
import logging
import os
import queue
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

logger = logging.getLogger("trapninja")


# =============================================================================
# REPLAY METRICS
# =============================================================================

@dataclass
class ReplayMetrics:
    """
    Replay-specific counters. Held on the ReplayEngine instance only.

    NEVER added to:
    - network._queue_stats
    - the shared stats/granular stats module
    - production Prometheus .prom files in the metrics directory

    Written only to an ephemeral trapninja_replay.prom file that is
    created on replay start and deleted on replay end or process exit.
    """
    replay_packets_read: int = 0
    replay_packets_injected: int = 0
    replay_packets_skipped: int = 0
    replay_packets_failed: int = 0
    replay_duration_seconds: float = 0.0
    replay_source_file: str = ""
    replay_snmp_v1_count: int = 0
    replay_snmp_v2c_count: int = 0
    replay_snmp_v3_count: int = 0
    replay_snmp_unknown_count: int = 0
    replay_start_wall_time: float = field(default_factory=time.time)


# =============================================================================
# SNMP VERSION DETECTION
# =============================================================================

def _detect_snmp_version(payload: bytes) -> str:
    """
    Heuristic SNMP version detection from raw PDU bytes.

    SNMP PDUs are BER-encoded ASN.1 SEQUENCEs. Handles both short-form
    and long-form length encoding:
      - Short form (length <= 127): single byte with value
      - Long form (length > 127): first byte 0x80 | num_octets, then length bytes

    Returns: 'v1', 'v2c', 'v3', or 'unknown'
    Never raises — returns 'unknown' on any parse failure.
    """
    try:
        if len(payload) < 5:
            return 'unknown'

        # Check for SEQUENCE tag
        if payload[0] != 0x30:
            return 'unknown'

        # Skip SEQUENCE length (handles short and long form)
        pos = 1
        length_byte = payload[pos]
        if length_byte & 0x80:
            # Long form: high bit set, low 7 bits = number of length bytes
            num_len_bytes = length_byte & 0x7F
            pos += 1 + num_len_bytes
        else:
            # Short form
            pos += 1

        if pos + 3 > len(payload):
            return 'unknown'

        # Check for INTEGER tag (version field)
        if payload[pos] != 0x02:
            return 'unknown'
        pos += 1

        # Check that INTEGER length is 1
        if payload[pos] != 0x01:
            return 'unknown'
        pos += 1

        # Read version byte
        version_byte = payload[pos]

        if version_byte == 0x00:
            return 'v1'
        elif version_byte == 0x01:
            return 'v2c'
        elif version_byte == 0x03:
            return 'v3'
        else:
            return 'unknown'

    except Exception:
        return 'unknown'


# =============================================================================
# PRODUCTION SAFETY GATE
# =============================================================================

def _check_production_safety(skip_check: bool = False) -> Tuple[bool, str]:
    """
    Detect whether a live TrapNinja daemon is running on this host.

    Check order:
      1. If skip_check=True: return (True, "safety check skipped by flag")
      2. If env var TRAPNINJA_REPLAY_ALLOW=1: return (True, "env override set")
      3. If PID_FILE exists and contains a live PID: return (False, reason_str)
      4. Otherwise: return (True, "no live daemon detected")

    Uses os.kill(pid, 0) — sends no signal, only checks process existence.
    Treats stale PID file (dead process) or unreadable PID as safe.

    Returns:
        Tuple[bool, str]: (is_safe, human_readable_reason)
    """
    from .config import PID_FILE

    # 1. Skip check if flag is set
    if skip_check:
        return (True, "safety check skipped by flag")

    # 2. Environment variable override
    if os.environ.get('TRAPNINJA_REPLAY_ALLOW') == '1':
        return (True, "env override set (TRAPNINJA_REPLAY_ALLOW=1)")

    # 3. Check PID file
    if not os.path.exists(PID_FILE):
        return (True, "no live daemon detected (no PID file)")

    try:
        with open(PID_FILE, 'r') as f:
            pid_str = f.read().strip()
            if not pid_str:
                return (True, "no live daemon detected (empty PID file)")
            pid = int(pid_str)
    except (IOError, ValueError) as e:
        # Unreadable or invalid PID file — treat as safe
        return (True, f"no live daemon detected (PID file unreadable: {e})")

    # Check if process is alive using signal 0
    try:
        os.kill(pid, 0)
        # Process exists — not safe
        return (False, f"Live TrapNinja daemon detected (PID {pid})")
    except OSError:
        # Process does not exist — stale PID file, safe
        return (True, "no live daemon detected (stale PID file)")


# =============================================================================
# REPLAY ENGINE
# =============================================================================

class ReplayEngine:
    """
    Reads pcap/pcapng capture files and injects packets into the TrapNinja
    processing pipeline as if received from the network.

    Usage:
        engine = ReplayEngine(
            capture_file="/path/to/traps.pcap",
            replay_realtime=False,
            replay_count=1,
            filter_src_ip=None,
            dry_run=False,
        )
        exit_code = engine.run()
        print(engine.metrics)
    """

    # Warning banner for when safety gate blocks
    SAFETY_BANNER = """\
╔══════════════════════════════════════════════════════════════╗
║  ⚠  WARNING: Live TrapNinja daemon detected                  ║
║                                                              ║
║  {reason:<60}║
║                                                              ║
║  Replay injects packets into the live pipeline. On a         ║
║  production system this WILL forward traps to real           ║
║  network management destinations.                            ║
║                                                              ║
║  To proceed anyway, use ONE of:                              ║
║    CLI flag : --i-know-this-is-not-production                ║
║    Env var  : TRAPNINJA_REPLAY_ALLOW=1                       ║
╚══════════════════════════════════════════════════════════════╝"""

    def __init__(
        self,
        capture_file: str,
        replay_realtime: bool = False,
        replay_count: int = 1,
        filter_src_ip: Optional[str] = None,
        dry_run: bool = False,
        skip_safety_check: bool = False,
    ):
        """
        Initialize the replay engine.

        Args:
            capture_file: Path to pcap/pcapng file (must be validated before init)
            replay_realtime: Honour inter-packet timestamps from pcap
            replay_count: Number of replay passes (0 = loop until interrupted)
            filter_src_ip: Only inject packets from this source IP
            dry_run: Parse/count but do not call put_nowait()
            skip_safety_check: Bypass production safety gate
        """
        self.capture_file = capture_file
        self.replay_realtime = replay_realtime
        self.replay_count = replay_count
        self.filter_src_ip = filter_src_ip
        self.dry_run = dry_run
        self.skip_safety_check = skip_safety_check

        self.metrics = ReplayMetrics()
        self.metrics.replay_source_file = capture_file

        self._last_prom_write_time = 0.0
        self._prom_write_interval = 10.0  # Write at most every 10 seconds
        self._atexit_registered = False

    def run(self) -> int:
        """
        Execute the replay operation.

        Returns:
            Exit code: 0=success, 1=error, 2=safety gate blocked
        """
        from .config import LISTEN_PORTS, LOG_FILE, stop_event
        from .network import packet_queue

        # 1. Safety check
        is_safe, reason = _check_production_safety(skip_check=self.skip_safety_check)
        if not is_safe:
            print(self.SAFETY_BANNER.format(reason=reason))
            return 2

        # 2. Validate capture file exists and is readable
        if not os.path.exists(self.capture_file):
            print(f"Error: capture file not found: {self.capture_file}")
            return 1
        if not os.path.isfile(self.capture_file):
            print(f"Error: path is not a file: {self.capture_file}")
            return 1
        if not os.access(self.capture_file, os.R_OK):
            print(f"Error: capture file is not readable: {self.capture_file}")
            return 1

        # 3. Register atexit handler
        if not self._atexit_registered:
            atexit.register(self._delete_ephemeral_prom)
            self._atexit_registered = True

        # 4. Print replay start banner
        mode_str = "[DRY RUN] " if self.dry_run else ""
        print(f"\n{mode_str}TrapNinja Capture Replay Starting")
        print(f"  Source: {self.capture_file}")
        print(f"  Realtime: {self.replay_realtime}")
        print(f"  Passes: {self.replay_count if self.replay_count > 0 else 'infinite (Ctrl-C to stop)'}")
        if self.filter_src_ip:
            print(f"  Filter: {self.filter_src_ip}")
        print()

        # Track start time
        start_time = time.time()
        self.metrics.replay_start_wall_time = start_time

        try:
            # Lazy import Scapy for performance
            from scapy.all import PcapReader, IP, UDP

            pass_number = 0
            infinite_loop = (self.replay_count == 0)

            while True:
                # Check stop event at start of each pass
                if stop_event.is_set():
                    logger.info("Replay stopped by stop_event")
                    break

                pass_number += 1

                # Check if we've completed all passes (for finite loop)
                if not infinite_loop and pass_number > self.replay_count:
                    break

                logger.info(f"Replay pass {pass_number} starting")

                prev_packet_time = None

                try:
                    with PcapReader(self.capture_file) as pcap_reader:
                        for packet in pcap_reader:
                            # Check stop event during packet iteration
                            if stop_event.is_set():
                                break

                            self.metrics.replay_packets_read += 1

                            # Check for IP and UDP layers
                            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                                self.metrics.replay_packets_skipped += 1
                                continue

                            ip_layer = packet[IP]
                            udp_layer = packet[UDP]

                            src_ip = ip_layer.src
                            dst_port = udp_layer.dport

                            # Source IP filter
                            if self.filter_src_ip and src_ip != self.filter_src_ip:
                                self.metrics.replay_packets_skipped += 1
                                continue

                            # Port filter - only replay packets to LISTEN_PORTS
                            if dst_port not in LISTEN_PORTS:
                                self.metrics.replay_packets_skipped += 1
                                continue

                            # Extract payload
                            payload = bytes(udp_layer.payload)

                            # Detect SNMP version for stats
                            version = _detect_snmp_version(payload)
                            if version == 'v1':
                                self.metrics.replay_snmp_v1_count += 1
                            elif version == 'v2c':
                                self.metrics.replay_snmp_v2c_count += 1
                            elif version == 'v3':
                                self.metrics.replay_snmp_v3_count += 1
                            else:
                                self.metrics.replay_snmp_unknown_count += 1

                            # Realtime mode: sleep between packets
                            if self.replay_realtime and prev_packet_time is not None:
                                delta = float(packet.time) - prev_packet_time
                                # Cap at 5 seconds to avoid stalls on gaps
                                if 0 < delta < 5.0:
                                    time.sleep(delta)
                            prev_packet_time = float(packet.time)

                            # Inject or count
                            if self.dry_run:
                                self.metrics.replay_packets_injected += 1
                                logger.debug(
                                    f"Replay (dry): {src_ip}:{dst_port} {version} {len(payload)}b"
                                )
                            else:
                                try:
                                    packet_queue.put_nowait({
                                        'src_ip': src_ip,
                                        'dst_port': dst_port,
                                        'payload': payload,
                                    })
                                    self.metrics.replay_packets_injected += 1
                                    logger.debug(
                                        f"Replay: {src_ip}:{dst_port} {version} {len(payload)}b"
                                    )
                                except queue.Full:
                                    self.metrics.replay_packets_failed += 1
                                    logger.warning(
                                        f"Queue full: replay packet from {src_ip} dropped"
                                    )

                            # Periodic .prom update
                            self._write_ephemeral_prom()

                except Exception as e:
                    logger.error(f"Error reading pcap file: {e}")
                    return 1

                logger.info(
                    f"Replay pass {pass_number} complete: "
                    f"{self.metrics.replay_packets_injected:,} injected"
                )

        except KeyboardInterrupt:
            print("\n\nReplay interrupted by user (Ctrl-C)")
        except ImportError as e:
            print(f"Error: Scapy not available: {e}")
            print("Install with: pip install scapy")
            return 1
        finally:
            # Record duration
            self.metrics.replay_duration_seconds = time.time() - start_time

            # Print summary
            self._print_summary()

            # Final .prom write and cleanup
            self._write_ephemeral_prom(force=True)
            self._delete_ephemeral_prom()

        return 0

    def _write_ephemeral_prom(self, force: bool = False) -> None:
        """
        Write current ReplayMetrics to {metrics_dir}/trapninja_replay.prom.

        The metrics directory is derived from LOG_FILE location.
        Updates at most every 10 seconds during replay.

        Args:
            force: Write immediately regardless of time since last write
        """
        from .config import LOG_FILE

        # Rate limit writes unless forced
        now = time.time()
        if not force and (now - self._last_prom_write_time) < self._prom_write_interval:
            return

        try:
            metrics_dir = os.path.join(os.path.dirname(LOG_FILE), "metrics")
            os.makedirs(metrics_dir, exist_ok=True)

            prom_path = os.path.join(metrics_dir, "trapninja_replay.prom")
            tmp_path = prom_path + ".tmp"

            content = f"""\
# HELP trapninja_replay_packets_read Total packets read from capture file
# TYPE trapninja_replay_packets_read gauge
trapninja_replay_packets_read {self.metrics.replay_packets_read}

# HELP trapninja_replay_packets_injected Packets injected into pipeline
# TYPE trapninja_replay_packets_injected gauge
trapninja_replay_packets_injected {self.metrics.replay_packets_injected}

# HELP trapninja_replay_packets_skipped Packets skipped (non-SNMP, filtered)
# TYPE trapninja_replay_packets_skipped gauge
trapninja_replay_packets_skipped {self.metrics.replay_packets_skipped}

# HELP trapninja_replay_packets_failed Packets failed (queue full etc)
# TYPE trapninja_replay_packets_failed gauge
trapninja_replay_packets_failed {self.metrics.replay_packets_failed}
"""

            # Atomic write: write to tmp then rename
            with open(tmp_path, 'w') as f:
                f.write(content)
            os.rename(tmp_path, prom_path)

            self._last_prom_write_time = now

        except Exception as e:
            # .prom write failure must never stop replay
            logger.debug(f"Failed to write replay .prom file: {e}")

    def _delete_ephemeral_prom(self) -> None:
        """
        Delete {metrics_dir}/trapninja_replay.prom if it exists.

        Called from atexit handler AND from the finally block in run().
        Catches ALL exceptions silently.
        """
        from .config import LOG_FILE

        try:
            metrics_dir = os.path.join(os.path.dirname(LOG_FILE), "metrics")
            prom_path = os.path.join(metrics_dir, "trapninja_replay.prom")

            if os.path.exists(prom_path):
                os.remove(prom_path)
        except Exception:
            pass

    def _print_summary(self) -> None:
        """Print the summary table to stdout."""
        mode_str = "[DRY RUN] " if self.dry_run else ""

        print(f"""
═══════════════════════════════════════════════
  {mode_str}TrapNinja Capture Replay — Summary
═══════════════════════════════════════════════
  Source file   : {self.metrics.replay_source_file}
  Duration      : {self.metrics.replay_duration_seconds:.1f}s
  Packets read  : {self.metrics.replay_packets_read:,}
  Injected      : {self.metrics.replay_packets_injected:,}
  Skipped       : {self.metrics.replay_packets_skipped:,}
  Failed        : {self.metrics.replay_packets_failed:,}
  ─────────────────────────────────────────────
  SNMP v1       : {self.metrics.replay_snmp_v1_count:,}
  SNMP v2c      : {self.metrics.replay_snmp_v2c_count:,}
  SNMP v3       : {self.metrics.replay_snmp_v3_count:,}
  Unknown       : {self.metrics.replay_snmp_unknown_count:,}
═══════════════════════════════════════════════
""")
