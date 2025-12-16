#!/usr/bin/env python3
"""
TrapNinja Core Constants

Centralized constants for SNMP protocol handling, ASN.1 parsing,
network configuration, and performance tuning.

All magic numbers and protocol-specific values should be defined here
to ensure consistency and maintainability across the codebase.

Author: TrapNinja Team
Version: 1.0.0
"""

# =============================================================================
# SNMP VERSION CONSTANTS
# =============================================================================

SNMP_V1 = 0
SNMP_V2C = 1
SNMP_V2 = 2
SNMP_V3 = 3

SNMP_VERSION_MAP = {
    0: "v1",
    1: "v2c",
    2: "v2",
    3: "v3"
}

SNMP_VERSION_REVERSE_MAP = {
    "v1": 0,
    "v2c": 1,
    "v2": 2,
    "v3": 3
}


# =============================================================================
# ASN.1 TAG CONSTANTS
# =============================================================================

# Universal class tags
ASN1_SEQUENCE = 0x30
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OID = 0x06
ASN1_BIT_STRING = 0x03

# Context-specific tags
ASN1_CONTEXT_0 = 0xA0
ASN1_CONTEXT_1 = 0xA1
ASN1_CONTEXT_2 = 0xA2
ASN1_CONTEXT_3 = 0xA3
ASN1_CONTEXT_4 = 0xA4
ASN1_CONTEXT_5 = 0xA5
ASN1_CONTEXT_6 = 0xA6
ASN1_CONTEXT_7 = 0xA7

# Application class tags
ASN1_IPADDRESS = 0x40
ASN1_COUNTER32 = 0x41
ASN1_GAUGE32 = 0x42
ASN1_TIMETICKS = 0x43
ASN1_OPAQUE = 0x44
ASN1_COUNTER64 = 0x46


# =============================================================================
# SNMP OID CONSTANTS
# =============================================================================

# snmpTrapOID.0 in dotted notation
SNMPTRAPOID_OID = "1.3.6.1.6.3.1.1.4.1.0"

# snmpTrapOID.0 as binary (for fast byte scanning)
SNMPTRAPOID_BYTES = b'\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00'

# sysUpTime.0
SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"

# Enterprise OID prefix
ENTERPRISE_PREFIX = "1.3.6.1.4.1"

# SNMP trap enterprise base
SNMP_TRAP_ENTERPRISE = "1.3.6.1.6.3.1.1.4.3.0"


# =============================================================================
# NETWORK CONSTANTS
# =============================================================================

# Default SNMP trap port
DEFAULT_TRAP_PORT = 162

# Default blocked trap forwarding port
DEFAULT_BLOCKED_PORT = 1462

# Source port for forwarding (traps come from 162)
DEFAULT_SOURCE_PORT = 162

# FORWARD_SOURCE_PORT: Port used when SENDING forwarded traps
# CRITICAL: This MUST be different from DEFAULT_TRAP_PORT (162)
# Using 162 for both sending and receiving causes a re-capture loop:
#   - sniff filter "udp port 162" matches sport=162 OR dport=162
#   - Forwarded packets with sport=162 get re-captured
#   - This creates exponential packet multiplication
# See: documentation/fixes/PACKET_RECAPTURE_LOOP_FIX.md
FORWARD_SOURCE_PORT = 10162

# Maximum UDP packet size
MAX_UDP_PACKET_SIZE = 65535

# Default socket receive buffer size (64MB for burst handling)
DEFAULT_SOCKET_BUFFER = 67108864

# Fallback socket buffer size (16MB)
FALLBACK_SOCKET_BUFFER = 16777216


# =============================================================================
# PERFORMANCE TUNING CONSTANTS
# =============================================================================

# Default queue size for packet processing
DEFAULT_QUEUE_SIZE = 200000

# Maximum queue size for extreme burst scenarios
MAX_QUEUE_SIZE = 500000

# Worker batch size for efficient processing
DEFAULT_BATCH_SIZE = 50

# Worker timeout in seconds
DEFAULT_WORKER_TIMEOUT = 0.5

# Configuration cache TTL in seconds
CONFIG_CACHE_TTL = 30.0

# Statistics logging interval in seconds
STATS_LOG_INTERVAL = 30.0


# =============================================================================
# HIGH AVAILABILITY CONSTANTS
# =============================================================================

# Default HA heartbeat interval
DEFAULT_HEARTBEAT_INTERVAL = 1.0

# Default HA heartbeat timeout
DEFAULT_HEARTBEAT_TIMEOUT = 3.0

# Default HA failover delay
DEFAULT_FAILOVER_DELAY = 2.0

# Default HA priority
DEFAULT_HA_PRIORITY = 100

# Default HA communication port
DEFAULT_HA_PORT = 60006


# =============================================================================
# SNMPV3 SECURITY CONSTANTS
# =============================================================================

# Security levels
SNMPV3_NOAUTH_NOPRIV = 0
SNMPV3_AUTH_NOPRIV = 1
SNMPV3_AUTH_PRIV = 3

# Authentication protocols
AUTH_PROTOCOL_NONE = "none"
AUTH_PROTOCOL_MD5 = "MD5"
AUTH_PROTOCOL_SHA = "SHA"
AUTH_PROTOCOL_SHA224 = "SHA224"
AUTH_PROTOCOL_SHA256 = "SHA256"
AUTH_PROTOCOL_SHA384 = "SHA384"
AUTH_PROTOCOL_SHA512 = "SHA512"

# Privacy protocols
PRIV_PROTOCOL_NONE = "none"
PRIV_PROTOCOL_DES = "DES"
PRIV_PROTOCOL_3DES = "3DES"
PRIV_PROTOCOL_AES = "AES"
PRIV_PROTOCOL_AES128 = "AES128"
PRIV_PROTOCOL_AES192 = "AES192"
PRIV_PROTOCOL_AES256 = "AES256"


# =============================================================================
# FILE PATH CONSTANTS
# =============================================================================

# Default configuration directory
DEFAULT_CONFIG_DIR = "/opt/trapninja/config"

# Default log directory
DEFAULT_LOG_DIR = "/var/log/trapninja"

# Default PID file
DEFAULT_PID_FILE = "/var/run/trapninja.pid"

# Default credentials file
DEFAULT_CREDENTIALS_FILE = "snmpv3_credentials.json"


# =============================================================================
# LOGGING CONSTANTS
# =============================================================================

# Default log level
DEFAULT_LOG_LEVEL = "INFO"

# Maximum log file size (10 MB)
DEFAULT_LOG_MAX_SIZE = 10 * 1024 * 1024

# Number of backup log files
DEFAULT_LOG_BACKUP_COUNT = 5
