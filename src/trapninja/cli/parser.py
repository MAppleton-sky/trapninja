#!/usr/bin/env python3
"""
TrapNinja Argument Parser - Compatibility Shim

This module has been refactored into the cli/parsers/ package for modularity.
All imports are re-exported here for backward compatibility.

New code should import from cli.parsers directly:
    from trapninja.cli.parsers import create_argument_parser
    from trapninja.cli.parsers.base import validated_ip, validated_oid, ...
"""

# Re-export everything for backward compatibility
from .parsers import create_argument_parser
from .parsers.base import (
    TrapNinjaHelpFormatter,
    TrapNinjaRootHelpFormatter,
    TrapNinjaArgumentParser,
    validated_ip,
    validated_oid,
    validated_tag,
    validated_port,
)

__all__ = [
    'create_argument_parser',
    'TrapNinjaHelpFormatter',
    'TrapNinjaRootHelpFormatter',
    'TrapNinjaArgumentParser',
    'validated_ip',
    'validated_oid',
    'validated_tag',
    'validated_port',
]
