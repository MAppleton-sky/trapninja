#!/usr/bin/env python3
"""
TrapNinja Test Fixtures - Sample Data

Contains SampleOIDs and SampleIPs classes with commonly used
test values for consistent testing across all modules.

Author: TrapNinja Team
"""


class SampleOIDs:
    """Common OIDs used in tests."""
    
    # Standard trap OIDs (SNMPv2-MIB)
    COLD_START = "1.3.6.1.6.3.1.1.5.1"
    WARM_START = "1.3.6.1.6.3.1.1.5.2"
    LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
    LINK_UP = "1.3.6.1.6.3.1.1.5.4"
    AUTH_FAILURE = "1.3.6.1.6.3.1.1.5.5"
    
    # Net-SNMP test OIDs
    NET_SNMP_TEST = "1.3.6.1.4.1.8072.2.3.0.1"
    NET_SNMP_ENTERPRISE = "1.3.6.1.4.1.8072.2.3"
    
    # Cisco OIDs
    CISCO_SYSLOG = "1.3.6.1.4.1.9.9.41.2.0.1"
    CISCO_CONFIG_CHANGE = "1.3.6.1.4.1.9.9.43.2.0.1"
    CISCO_ENTITY_FRU = "1.3.6.1.4.1.9.9.117.2.0.1"
    
    # Nokia OIDs
    NOKIA_ALARM = "1.3.6.1.4.1.6527.3.1.3.0.1"
    
    # Test/blocked OIDs
    BLOCKED_1 = "1.3.6.1.4.1.9999.1"
    BLOCKED_2 = "1.3.6.1.4.1.9999.2"
    BLOCKED_3 = "1.3.6.1.4.1.9999.3"
    
    # Redirected OIDs (map to service teams)
    REDIRECT_VOICE = "1.3.6.1.4.1.8072.2.3.0.99"
    REDIRECT_DATA = "1.3.6.1.4.1.9.9.117.2.0.1"
    REDIRECT_SECURITY = "1.3.6.1.4.1.9.9.41.2.0.99"


class SampleIPs:
    """Common IP addresses used in tests."""
    
    # Normal source IPs (not blocked, not redirected)
    NORMAL_1 = "192.168.1.50"
    NORMAL_2 = "192.168.1.51"
    NORMAL_3 = "192.168.1.52"
    
    # Blocked source IPs
    BLOCKED_1 = "10.0.0.99"
    BLOCKED_2 = "10.0.0.100"
    BLOCKED_3 = "172.16.0.50"
    
    # Redirected source IPs (map to service teams)
    REDIRECT_SECURITY_1 = "192.168.10.50"
    REDIRECT_SECURITY_2 = "192.168.10.51"
    REDIRECT_VOICE = "192.168.20.50"
    REDIRECT_DATA = "192.168.30.50"
    
    # Primary destinations (normal forwarding)
    DEST_PRIMARY = "192.168.1.100"
    DEST_SECONDARY = "192.168.1.101"
    DEST_TERTIARY = "192.168.1.102"
    
    # Service team destinations
    DEST_SECURITY_1 = "10.10.10.1"
    DEST_SECURITY_2 = "10.10.10.2"
    DEST_VOICE_1 = "10.20.20.1"
    DEST_DATA_1 = "10.30.30.1"
    DEST_DATA_2 = "10.30.30.2"
    
    # Blocked trap archive destination
    DEST_BLOCKED = "10.99.99.1"
