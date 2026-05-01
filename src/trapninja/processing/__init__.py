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
- packet_handler.py: Packet processing pipeline (filtering/routing/forwarding)
- config_cache.py: Thread-safe configuration cache with TTL
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
    shutdown_forwarder,
    SocketPool,
)

from .worker import (
    PacketWorker,
    start_workers,
    get_processor_stats,
    reset_processor_stats,
)

from .config_cache import (
    ConfigCache,
    get_config_cache,
)

from .packet_handler import (
    PacketHandler,
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
    'shutdown_forwarder',
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
    # Config Cache
    'ConfigCache',
    'get_config_cache',
    # Packet Handler
    'PacketHandler',
]

__version__ = '2.0.0'
