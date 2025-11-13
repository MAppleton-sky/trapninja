#!/usr/bin/env python3
"""
TrapNinja - SNMP Trap Forwarder

A daemon service that listens for SNMP traps on specified UDP ports,
filters them based on configured rules, and forwards them to
designated destinations.
"""

__version__ = '1.1.0'
__author__ = 'Matthew Appleton'

# Avoid circular imports - these will be imported in the modules that need them