#!/usr/bin/env python3
"""
TrapNinja Processing Package

High-performance packet processing pipeline with:
- Fast SNMP parsing (direct byte scanning for SNMPv2c)
- Efficient forwarding (raw sockets with fallback)
- Batch processing workers
- Minimal per-packet overhead

Package Structure:
- parser.py: SNMP parsing and OID extraction
- forwarder.py: Packet forwarding logic
- worker.py: Processing worker threads
- stats.py: Processing statistics

Author: TrapNinja Team
Version: 2.0.0
"""

from .parser import (
    is_snmpv2c,
    extract_trap_oid_fast,
    parse_snmp_packet,
    get_snmp_version,
    decode_oid,
)

from .forwarder import (
    forward_packet,
    get_socket_pool,
    SocketPool,
)

from .worker import (
    PacketWorker,
    start_workers,
    get_processor_stats,
    reset_processor_stats,
)

from .stats import (
    ProcessingStats,
    get_global_stats,
    reset_global_stats,
)

__all__ = [
    # Parser
    'is_snmpv2c',
    'extract_trap_oid_fast',
    'parse_snmp_packet',
    'get_snmp_version',
    'decode_oid',
    # Forwarder
    'forward_packet',
    'get_socket_pool',
    'SocketPool',
    # Worker
    'PacketWorker',
    'start_workers',
    'get_processor_stats',
    'reset_processor_stats',
    # Stats
    'ProcessingStats',
    'get_global_stats',
    'reset_global_stats',
]

__version__ = '2.0.0'
