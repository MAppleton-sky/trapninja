#!/usr/bin/env python3
"""
TrapNinja Input Validation Module

Provides comprehensive input validation and sanitization with security focus.
All user input is validated before processing to prevent injection attacks
and ensure data integrity.
"""

import re
import unicodedata
import ipaddress
from typing import Optional
from functools import lru_cache


class SecurityError(Exception):
    """Raised when input validation fails for security reasons"""
    pass


class InputValidator:
    """Enhanced input validation with security focus and caching"""

    # Precompiled regex patterns for better performance
    _DANGEROUS_PATTERNS = [
        re.compile(r'[;&|`$()]', re.IGNORECASE),  # Command injection
        re.compile(r'\.\./', re.IGNORECASE),  # Path traversal
        re.compile(r'<script', re.IGNORECASE),  # XSS-like patterns
        re.compile(r'javascript:', re.IGNORECASE),  # JavaScript injection
        re.compile(r'%[0-9a-f]{2}', re.IGNORECASE),  # URL encoding
        re.compile(r'\\x[0-9a-f]{2}', re.IGNORECASE),  # Hex encoding
    ]

    _OID_PATTERN = re.compile(r'^[0-2](\.\d+)*$')
    _TAG_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

    # Reserved names that shouldn't be used as tags
    _RESERVED_NAMES = frozenset([
        'default', 'admin', 'root', 'system', 'config',
        'null', 'undefined', 'none', 'true', 'false'
    ])

    @classmethod
    @lru_cache(maxsize=1024)
    def sanitize_string(cls, input_str: str, max_length: int = 255,
                        allow_special: bool = False) -> Optional[str]:
        """
        Enhanced string sanitization with caching

        Args:
            input_str: String to sanitize
            max_length: Maximum allowed length
            allow_special: Whether to allow special characters

        Returns:
            Sanitized string or None if invalid
        """
        if not isinstance(input_str, str) or not input_str.strip():
            return None

        # Remove control characters
        sanitized = ''.join(
            char for char in input_str
            if unicodedata.category(char)[0] != 'C'
        )

        # Length check
        if len(sanitized) > max_length:
            print(f"Input too long: {len(sanitized)} > {max_length}")
            return None

        # Security pattern check
        if not allow_special:
            for pattern in cls._DANGEROUS_PATTERNS:
                if pattern.search(sanitized):
                    print(f"Dangerous pattern detected in input: {sanitized}")
                    return None

        return sanitized.strip()

    @classmethod
    @lru_cache(maxsize=512)
    def validate_ip(cls, ip_str: str) -> Optional[str]:
        """
        Cached IP validation

        Args:
            ip_str: IP address string to validate

        Returns:
            Valid IP address string or None
        """
        if not isinstance(ip_str, str):
            return None

        sanitized = cls.sanitize_string(ip_str, max_length=45)
        if not sanitized:
            return None

        try:
            ip_obj = ipaddress.ip_address(sanitized)
            return str(ip_obj)
        except ValueError:
            print(f"Invalid IP address: {sanitized}")
            return None

    @classmethod
    @lru_cache(maxsize=512)
    def validate_oid(cls, oid_str: str) -> Optional[str]:
        """
        Enhanced OID validation with caching

        Args:
            oid_str: OID string to validate

        Returns:
            Valid OID string or None
        """
        if not isinstance(oid_str, str):
            return None

        sanitized = cls.sanitize_string(oid_str, max_length=1000)
        if not sanitized:
            return None

        if not cls._OID_PATTERN.match(sanitized):
            print(f"Invalid OID format: {sanitized}")
            return None

        # Additional validation
        components = sanitized.split('.')

        if len(components) < 2 or len(components) > 128:
            print(f"OID component count invalid: {len(components)}")
            return None

        try:
            for i, component in enumerate(components):
                value = int(component)

                # First arc validation
                if i == 0 and value not in [0, 1, 2]:
                    print(f"First OID component must be 0, 1, or 2: {value}")
                    return None

                # Second arc validation
                if i == 1 and int(components[0]) in [0, 1] and value > 39:
                    print(f"Second OID component too large: {value}")
                    return None

                # Range check
                if value < 0 or value > 4294967295:
                    print(f"OID component out of range: {value}")
                    return None
        except ValueError:
            print(f"Non-numeric OID component in: {sanitized}")
            return None

        return sanitized

    @classmethod
    @lru_cache(maxsize=256)
    def validate_port(cls, port_value) -> Optional[int]:
        """
        Cached port validation

        Args:
            port_value: Port number (string or int)

        Returns:
            Valid port number or None
        """
        try:
            if isinstance(port_value, str):
                sanitized = cls.sanitize_string(port_value, max_length=10)
                if not sanitized:
                    return None
                port = int(sanitized)
            else:
                port = int(port_value)

            if not (1 <= port <= 65535):
                print(f"Port out of range: {port}")
                return None

            return port
        except (ValueError, TypeError):
            print(f"Invalid port value: {port_value}")
            return None

    @classmethod
    @lru_cache(maxsize=256)
    def validate_tag(cls, tag_str: str) -> Optional[str]:
        """
        Cached tag validation

        Args:
            tag_str: Tag string to validate

        Returns:
            Valid tag string or None
        """
        if not isinstance(tag_str, str):
            return None

        sanitized = cls.sanitize_string(tag_str, max_length=64)
        if not sanitized:
            return None

        if not cls._TAG_PATTERN.match(sanitized):
            print(f"Invalid tag format: {sanitized}")
            return None

        if sanitized.lower() in cls._RESERVED_NAMES:
            print(f"Tag name is reserved: {sanitized}")
            return None

        return sanitized


def parse_size(size_str: str) -> Optional[int]:
    """
    Parse a size string with optional suffix (K, M, G) to bytes

    Args:
        size_str: Size string (e.g., "10M", "1G", "500K")

    Returns:
        Size in bytes or None if invalid
    """
    if not isinstance(size_str, str):
        return None

    # Sanitize input
    sanitized_size = InputValidator.sanitize_string(size_str, max_length=20)
    if not sanitized_size:
        return None

    try:
        # Pattern to match number followed by optional suffix
        pattern = r'^([\d.]+)([KMG])?B?$'
        match = re.match(pattern, sanitized_size, re.IGNORECASE)

        if not match:
            return None

        num_str, suffix = match.groups()

        # Validate number
        try:
            num = float(num_str)
            if num < 0:
                print(f"Size cannot be negative: {num}")
                return None
            if num > 1024 ** 4:  # Reasonable upper limit (1TB)
                print(f"Size too large: {num}")
                return None
        except ValueError:
            return None

        # Apply suffix multiplier
        if suffix is None:
            result = int(num)
        elif suffix.upper() == 'K':
            result = int(num * 1024)
        elif suffix.upper() == 'M':
            result = int(num * 1024 * 1024)
        elif suffix.upper() == 'G':
            result = int(num * 1024 * 1024 * 1024)
        else:
            return None

        # Final sanity check
        if result < 0 or result > 2 ** 63 - 1:  # Max signed 64-bit
            print(f"Computed size out of range: {result}")
            return None

        return result
    except Exception as e:
        print(f"Error parsing size '{sanitized_size}': {e}")
        return None
