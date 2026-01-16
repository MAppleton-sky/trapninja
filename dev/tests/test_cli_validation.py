#!/usr/bin/env python3
"""
TrapNinja Test Suite - CLI Validation Tests

Tests for trapninja.cli.validation module - input validation and sanitization.

Author: TrapNinja Team
"""

import pytest
from unittest.mock import patch


class TestInputValidatorSanitizeString:
    """Tests for InputValidator.sanitize_string method."""

    def test_sanitize_basic_string(self):
        """Test sanitizing a basic string."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string("hello world")
        
        assert result == "hello world"

    def test_sanitize_strips_whitespace(self):
        """Test sanitization strips leading/trailing whitespace."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string("  test string  ")
        
        assert result == "test string"

    def test_sanitize_empty_string_returns_none(self):
        """Test empty string returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string("")
        
        assert result is None

    def test_sanitize_whitespace_only_returns_none(self):
        """Test whitespace-only string returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string("   ")
        
        assert result is None

    def test_sanitize_non_string_returns_none(self):
        """Test non-string input returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string(12345)
        
        assert result is None

    def test_sanitize_too_long_returns_none(self):
        """Test string exceeding max_length returns None."""
        from trapninja.cli.validation import InputValidator
        
        long_string = "a" * 300
        result = InputValidator.sanitize_string(long_string, max_length=255)
        
        assert result is None

    def test_sanitize_custom_max_length(self):
        """Test custom max_length is respected."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string("short", max_length=10)
        
        assert result == "short"

    def test_sanitize_detects_command_injection(self):
        """Test detection of command injection characters."""
        from trapninja.cli.validation import InputValidator
        
        # Test various dangerous patterns
        assert InputValidator.sanitize_string("test;ls") is None
        assert InputValidator.sanitize_string("test|cat") is None
        assert InputValidator.sanitize_string("test`whoami`") is None
        assert InputValidator.sanitize_string("test$(pwd)") is None

    def test_sanitize_detects_path_traversal(self):
        """Test detection of path traversal attempts."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string("../etc/passwd")
        
        assert result is None

    def test_sanitize_allow_special_bypasses_checks(self):
        """Test allow_special=True bypasses dangerous pattern checks."""
        from trapninja.cli.validation import InputValidator
        
        # Clear the cache to ensure fresh result
        InputValidator.sanitize_string.cache_clear()
        
        result = InputValidator.sanitize_string("/path/to/file", allow_special=True)
        
        assert result == "/path/to/file"

    def test_sanitize_removes_control_characters(self):
        """Test control characters are removed."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.sanitize_string("test\x00\x01string")
        
        assert result == "teststring"


class TestInputValidatorValidateIP:
    """Tests for InputValidator.validate_ip method."""

    def test_valid_ipv4(self):
        """Test valid IPv4 address."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("192.168.1.1")
        
        assert result == "192.168.1.1"

    def test_valid_ipv4_localhost(self):
        """Test localhost IPv4."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("127.0.0.1")
        
        assert result == "127.0.0.1"

    def test_valid_ipv6(self):
        """Test valid IPv6 address."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("::1")
        
        assert result == "::1"

    def test_valid_ipv6_full(self):
        """Test full IPv6 address."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("2001:db8:85a3::8a2e:370:7334")
        
        assert result is not None

    def test_invalid_ip_returns_none(self):
        """Test invalid IP returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("not.an.ip")
        
        assert result is None

    def test_invalid_ip_octet_out_of_range(self):
        """Test IP with octet > 255 returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("256.1.1.1")
        
        assert result is None

    def test_ip_with_port_returns_none(self):
        """Test IP with port suffix returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("192.168.1.1:8080")
        
        assert result is None

    def test_non_string_returns_none(self):
        """Test non-string input returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip(12345)
        
        assert result is None

    def test_empty_string_returns_none(self):
        """Test empty string returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_ip("")
        
        assert result is None


class TestInputValidatorValidateOID:
    """Tests for InputValidator.validate_oid method."""

    def test_valid_oid(self):
        """Test valid OID."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("1.3.6.1.4.1.9.9.41.2.0.1")
        
        assert result == "1.3.6.1.4.1.9.9.41.2.0.1"

    def test_valid_oid_short(self):
        """Test short valid OID."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("1.3")
        
        assert result == "1.3"

    def test_oid_starting_with_0(self):
        """Test OID starting with 0."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("0.0.1")
        
        assert result == "0.0.1"

    def test_oid_starting_with_2(self):
        """Test OID starting with 2."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("2.999.3.6")
        
        assert result == "2.999.3.6"

    def test_invalid_oid_starting_with_3(self):
        """Test OID starting with 3 is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("3.1.2")
        
        assert result is None

    def test_invalid_oid_not_numeric(self):
        """Test non-numeric OID is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("1.3.abc.1")
        
        assert result is None

    def test_invalid_oid_single_component(self):
        """Test single component OID is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("1")
        
        assert result is None

    def test_second_arc_validation(self):
        """Test second arc validation for arcs 0 and 1."""
        from trapninja.cli.validation import InputValidator
        
        # First arc 0 or 1, second arc must be <= 39
        result = InputValidator.validate_oid("0.40.1")
        
        assert result is None

    def test_empty_string_returns_none(self):
        """Test empty string returns None."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_oid("")
        
        assert result is None


class TestInputValidatorValidatePort:
    """Tests for InputValidator.validate_port method."""

    def test_valid_port_int(self):
        """Test valid port as integer."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port(162)
        
        assert result == 162

    def test_valid_port_string(self):
        """Test valid port as string."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port("8080")
        
        assert result == 8080

    def test_port_min_value(self):
        """Test minimum valid port."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port(1)
        
        assert result == 1

    def test_port_max_value(self):
        """Test maximum valid port."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port(65535)
        
        assert result == 65535

    def test_port_zero_invalid(self):
        """Test port 0 is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port(0)
        
        assert result is None

    def test_port_too_high_invalid(self):
        """Test port > 65535 is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port(65536)
        
        assert result is None

    def test_port_negative_invalid(self):
        """Test negative port is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port(-1)
        
        assert result is None

    def test_port_non_numeric_invalid(self):
        """Test non-numeric port is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_port("abc")
        
        assert result is None


class TestInputValidatorValidateTag:
    """Tests for InputValidator.validate_tag method."""

    def test_valid_tag_alphanumeric(self):
        """Test valid alphanumeric tag."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_tag("noc_team")
        
        assert result == "noc_team"

    def test_valid_tag_with_hyphen(self):
        """Test valid tag with hyphen."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_tag("voice-team")
        
        assert result == "voice-team"

    def test_valid_tag_uppercase(self):
        """Test uppercase tag."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_tag("NOC")
        
        assert result == "NOC"

    def test_tag_with_spaces_invalid(self):
        """Test tag with spaces is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_tag("noc team")
        
        assert result is None

    def test_tag_with_special_chars_invalid(self):
        """Test tag with special characters is invalid."""
        from trapninja.cli.validation import InputValidator
        
        result = InputValidator.validate_tag("noc@team")
        
        assert result is None

    def test_reserved_tag_names(self):
        """Test reserved tag names are rejected."""
        from trapninja.cli.validation import InputValidator
        
        # Clear cache for fresh results
        InputValidator.validate_tag.cache_clear()
        
        assert InputValidator.validate_tag("default") is None
        assert InputValidator.validate_tag("admin") is None
        assert InputValidator.validate_tag("root") is None
        assert InputValidator.validate_tag("system") is None
        assert InputValidator.validate_tag("null") is None

    def test_tag_too_long_invalid(self):
        """Test tag exceeding max length is invalid."""
        from trapninja.cli.validation import InputValidator
        
        long_tag = "a" * 100
        result = InputValidator.validate_tag(long_tag)
        
        assert result is None


class TestParseSize:
    """Tests for parse_size function."""

    def test_parse_bytes(self):
        """Test parsing bytes without suffix."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("1024")
        
        assert result == 1024

    def test_parse_kilobytes(self):
        """Test parsing kilobytes."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("10K")
        
        assert result == 10 * 1024

    def test_parse_megabytes(self):
        """Test parsing megabytes."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("10M")
        
        assert result == 10 * 1024 * 1024

    def test_parse_gigabytes(self):
        """Test parsing gigabytes."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("1G")
        
        assert result == 1024 * 1024 * 1024

    def test_parse_lowercase_suffix(self):
        """Test parsing with lowercase suffix."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("5m")
        
        assert result == 5 * 1024 * 1024

    def test_parse_with_b_suffix(self):
        """Test parsing with B suffix."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("10MB")
        
        assert result == 10 * 1024 * 1024

    def test_parse_decimal(self):
        """Test parsing decimal values."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("1.5G")
        
        assert result == int(1.5 * 1024 * 1024 * 1024)

    def test_parse_invalid_suffix(self):
        """Test parsing with invalid suffix returns None."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("10T")  # Terabytes not supported
        
        assert result is None

    def test_parse_negative_returns_none(self):
        """Test parsing negative value returns None."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("-10M")
        
        assert result is None

    def test_parse_non_string_returns_none(self):
        """Test parsing non-string returns None."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size(12345)
        
        assert result is None

    def test_parse_empty_returns_none(self):
        """Test parsing empty string returns None."""
        from trapninja.cli.validation import parse_size
        
        result = parse_size("")
        
        assert result is None


class TestSecurityError:
    """Tests for SecurityError exception."""

    def test_security_error_exists(self):
        """Test SecurityError exception exists."""
        from trapninja.cli.validation import SecurityError
        
        assert issubclass(SecurityError, Exception)

    def test_security_error_message(self):
        """Test SecurityError can be raised with message."""
        from trapninja.cli.validation import SecurityError
        
        with pytest.raises(SecurityError, match="test error"):
            raise SecurityError("test error")


class TestValidationCaching:
    """Tests for validation method caching."""

    def test_ip_validation_cached(self):
        """Test IP validation results are cached."""
        from trapninja.cli.validation import InputValidator
        
        # Clear cache
        InputValidator.validate_ip.cache_clear()
        
        # First call
        result1 = InputValidator.validate_ip("10.0.0.1")
        # Second call should be cached
        result2 = InputValidator.validate_ip("10.0.0.1")
        
        assert result1 == result2
        # Check cache info
        info = InputValidator.validate_ip.cache_info()
        assert info.hits >= 1

    def test_oid_validation_cached(self):
        """Test OID validation results are cached."""
        from trapninja.cli.validation import InputValidator
        
        # Clear cache
        InputValidator.validate_oid.cache_clear()
        
        # First call
        result1 = InputValidator.validate_oid("1.3.6.1.4")
        # Second call should be cached
        result2 = InputValidator.validate_oid("1.3.6.1.4")
        
        assert result1 == result2
        info = InputValidator.validate_oid.cache_info()
        assert info.hits >= 1
