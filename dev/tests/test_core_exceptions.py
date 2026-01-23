#!/usr/bin/env python3
"""
TrapNinja Test Suite - Core Exceptions Tests

Tests for trapninja.core.exceptions module.

Assumptions:
- All exceptions inherit from TrapNinjaError
- Exceptions should be raisable with appropriate arguments
- Exception messages should be informative
- The `details` attribute provides additional context
- Exceptions should support str() conversion

Author: TrapNinja Team
"""

import pytest


class TestTrapNinjaError:
    """Tests for the base TrapNinjaError exception."""

    def test_basic_instantiation(self):
        """Test basic exception creation."""
        from trapninja.core.exceptions import TrapNinjaError
        
        exc = TrapNinjaError("Test error")
        assert exc.message == "Test error"
        assert exc.details is None

    def test_instantiation_with_details(self):
        """Test exception creation with details."""
        from trapninja.core.exceptions import TrapNinjaError
        
        exc = TrapNinjaError("Test error", details="additional info")
        assert exc.message == "Test error"
        assert exc.details == "additional info"

    def test_str_without_details(self):
        """Test string representation without details."""
        from trapninja.core.exceptions import TrapNinjaError
        
        exc = TrapNinjaError("Test error")
        assert str(exc) == "Test error"

    def test_str_with_details(self):
        """Test string representation with details."""
        from trapninja.core.exceptions import TrapNinjaError
        
        exc = TrapNinjaError("Test error", details="more info")
        assert str(exc) == "Test error: more info"

    def test_is_exception(self):
        """Test that TrapNinjaError is an Exception."""
        from trapninja.core.exceptions import TrapNinjaError
        
        assert issubclass(TrapNinjaError, Exception)
        
        with pytest.raises(TrapNinjaError):
            raise TrapNinjaError("Test error")


class TestConfigurationExceptions:
    """Tests for configuration-related exceptions."""

    def test_configuration_error_inheritance(self):
        """Test ConfigurationError inherits from TrapNinjaError."""
        from trapninja.core.exceptions import ConfigurationError, TrapNinjaError
        
        assert issubclass(ConfigurationError, TrapNinjaError)

    def test_config_file_not_found_error(self):
        """Test ConfigFileNotFoundError."""
        from trapninja.core.exceptions import ConfigFileNotFoundError
        
        exc = ConfigFileNotFoundError("/path/to/config.json")
        
        assert exc.file_path == "/path/to/config.json"
        assert "not found" in str(exc).lower()
        assert "/path/to/config.json" in str(exc)

    def test_config_parse_error(self):
        """Test ConfigParseError."""
        from trapninja.core.exceptions import ConfigParseError
        
        exc = ConfigParseError("/path/to/config.json", "Invalid JSON at line 5")
        
        assert exc.file_path == "/path/to/config.json"
        assert exc.parse_error == "Invalid JSON at line 5"
        assert "parse" in str(exc).lower()

    def test_config_validation_error(self):
        """Test ConfigValidationError."""
        from trapninja.core.exceptions import ConfigValidationError
        
        exc = ConfigValidationError("port", 99999, "Port must be 1-65535")
        
        assert exc.field == "port"
        assert exc.value == 99999
        assert exc.reason == "Port must be 1-65535"
        assert "invalid" in str(exc).lower()


class TestParsingExceptions:
    """Tests for SNMP parsing exceptions."""

    def test_parsing_error_inheritance(self):
        """Test ParsingError inherits from TrapNinjaError."""
        from trapninja.core.exceptions import ParsingError, TrapNinjaError
        
        assert issubclass(ParsingError, TrapNinjaError)

    def test_invalid_snmp_packet(self):
        """Test InvalidSNMPPacket exception."""
        from trapninja.core.exceptions import InvalidSNMPPacket
        
        exc = InvalidSNMPPacket("Malformed header")
        assert exc.reason == "Malformed header"
        assert exc.source_ip is None
        assert "invalid snmp packet" in str(exc).lower()

    def test_invalid_snmp_packet_with_source_ip(self):
        """Test InvalidSNMPPacket with source IP."""
        from trapninja.core.exceptions import InvalidSNMPPacket
        
        exc = InvalidSNMPPacket("Malformed header", source_ip="192.168.1.100")
        
        assert exc.reason == "Malformed header"
        assert exc.source_ip == "192.168.1.100"
        assert "192.168.1.100" in str(exc)

    def test_unsupported_snmp_version(self):
        """Test UnsupportedSNMPVersion exception."""
        from trapninja.core.exceptions import UnsupportedSNMPVersion
        
        exc = UnsupportedSNMPVersion(99)
        
        assert exc.version == 99
        assert "unsupported" in str(exc).lower()
        assert "version" in str(exc).lower()

    def test_oid_extraction_error(self):
        """Test OIDExtractionError exception."""
        from trapninja.core.exceptions import OIDExtractionError
        
        exc = OIDExtractionError("No snmpTrapOID.0 found")
        
        assert exc.reason == "No snmpTrapOID.0 found"
        assert "extract" in str(exc).lower()


class TestForwardingExceptions:
    """Tests for packet forwarding exceptions."""

    def test_forwarding_error_inheritance(self):
        """Test ForwardingError inherits from TrapNinjaError."""
        from trapninja.core.exceptions import ForwardingError, TrapNinjaError
        
        assert issubclass(ForwardingError, TrapNinjaError)

    def test_no_destinations_error(self):
        """Test NoDestinationsError."""
        from trapninja.core.exceptions import NoDestinationsError
        
        exc = NoDestinationsError()
        
        assert "no destinations" in str(exc).lower()

    def test_socket_error(self):
        """Test SocketError exception."""
        from trapninja.core.exceptions import SocketError
        
        exc = SocketError("send", "Connection refused")
        
        assert exc.operation == "send"
        assert exc.error == "Connection refused"
        assert "socket" in str(exc).lower()

    def test_destination_unreachable(self):
        """Test DestinationUnreachable exception."""
        from trapninja.core.exceptions import DestinationUnreachable
        
        exc = DestinationUnreachable("192.168.1.100", 162, "Network unreachable")
        
        assert exc.destination == "192.168.1.100"
        assert exc.port == 162
        assert exc.error == "Network unreachable"
        assert "192.168.1.100:162" in str(exc)


class TestHAExceptions:
    """Tests for High Availability exceptions."""

    def test_ha_error_inheritance(self):
        """Test HAError inherits from TrapNinjaError."""
        from trapninja.core.exceptions import HAError, TrapNinjaError
        
        assert issubclass(HAError, TrapNinjaError)

    def test_ha_initialization_error(self):
        """Test HAInitializationError."""
        from trapninja.core.exceptions import HAInitializationError
        
        exc = HAInitializationError("Cannot bind to port 60006")
        
        assert exc.reason == "Cannot bind to port 60006"
        assert "initialize" in str(exc).lower()

    def test_ha_peer_communication_error(self):
        """Test HAPeerCommunicationError."""
        from trapninja.core.exceptions import HAPeerCommunicationError
        
        exc = HAPeerCommunicationError("192.168.1.101", 60006, "Connection timeout")
        
        assert exc.peer_host == "192.168.1.101"
        assert exc.peer_port == 60006
        assert exc.error == "Connection timeout"
        assert "peer" in str(exc).lower()

    def test_ha_split_brain_error(self):
        """Test HASplitBrainError."""
        from trapninja.core.exceptions import HASplitBrainError
        
        exc = HASplitBrainError("primary", "primary")
        
        assert exc.local_state == "primary"
        assert exc.peer_state == "primary"
        assert "split-brain" in str(exc).lower()

    def test_ha_state_transition_error(self):
        """Test HAStateTransitionError."""
        from trapninja.core.exceptions import HAStateTransitionError
        
        exc = HAStateTransitionError("secondary", "primary", "Peer still active")
        
        assert exc.current_state == "secondary"
        assert exc.target_state == "primary"
        assert exc.reason == "Peer still active"
        assert "secondary" in str(exc)
        assert "primary" in str(exc)


class TestSecurityExceptions:
    """Tests for security-related exceptions."""

    def test_security_error_inheritance(self):
        """Test SecurityError inherits from TrapNinjaError."""
        from trapninja.core.exceptions import SecurityError, TrapNinjaError
        
        assert issubclass(SecurityError, TrapNinjaError)

    def test_snmpv3_decryption_error(self):
        """Test SNMPv3DecryptionError."""
        from trapninja.core.exceptions import SNMPv3DecryptionError
        
        exc = SNMPv3DecryptionError("Invalid key")
        
        assert exc.reason == "Invalid key"
        assert exc.engine_id is None
        assert "decryption" in str(exc).lower()

    def test_snmpv3_decryption_error_with_engine_id(self):
        """Test SNMPv3DecryptionError with engine ID."""
        from trapninja.core.exceptions import SNMPv3DecryptionError
        
        exc = SNMPv3DecryptionError("Invalid key", engine_id="0x80001234")
        
        assert exc.reason == "Invalid key"
        assert exc.engine_id == "0x80001234"
        assert "0x80001234" in str(exc)

    def test_credential_not_found_error(self):
        """Test CredentialNotFoundError."""
        from trapninja.core.exceptions import CredentialNotFoundError
        
        exc = CredentialNotFoundError("admin")
        
        assert exc.username == "admin"
        assert exc.engine_id is None
        assert "admin" in str(exc)

    def test_credential_not_found_error_with_engine_id(self):
        """Test CredentialNotFoundError with engine ID."""
        from trapninja.core.exceptions import CredentialNotFoundError
        
        exc = CredentialNotFoundError("admin", engine_id="0x80001234")
        
        assert exc.username == "admin"
        assert exc.engine_id == "0x80001234"
        assert "admin" in str(exc)
        assert "0x80001234" in str(exc)

    def test_authentication_error(self):
        """Test AuthenticationError."""
        from trapninja.core.exceptions import AuthenticationError
        
        exc = AuthenticationError("HMAC verification failed")
        
        assert exc.reason == "HMAC verification failed"
        assert "authentication" in str(exc).lower()

    def test_invalid_credentials_error(self):
        """Test InvalidCredentialsError."""
        from trapninja.core.exceptions import InvalidCredentialsError
        
        exc = InvalidCredentialsError("auth_key", "Key too short")
        
        assert exc.field == "auth_key"
        assert exc.reason == "Key too short"
        assert "auth_key" in str(exc)


class TestCaptureExceptions:
    """Tests for packet capture exceptions."""

    def test_capture_error_inheritance(self):
        """Test CaptureError inherits from TrapNinjaError."""
        from trapninja.core.exceptions import CaptureError, TrapNinjaError
        
        assert issubclass(CaptureError, TrapNinjaError)

    def test_interface_not_found_error(self):
        """Test InterfaceNotFoundError."""
        from trapninja.core.exceptions import InterfaceNotFoundError
        
        available = ["eth0", "lo", "ens192"]
        exc = InterfaceNotFoundError("eth99", available)
        
        assert exc.interface == "eth99"
        assert exc.available == available
        assert "eth99" in str(exc)
        assert "not found" in str(exc).lower()

    def test_capture_permission_error(self):
        """Test CapturePermissionError."""
        from trapninja.core.exceptions import CapturePermissionError
        
        exc = CapturePermissionError("raw socket creation")
        
        assert exc.operation == "raw socket creation"
        assert "permission" in str(exc).lower()
        assert "root" in str(exc).lower() or "CAP_NET_RAW" in str(exc)

    def test_ebpf_error(self):
        """Test EBPFError."""
        from trapninja.core.exceptions import EBPFError
        
        exc = EBPFError("attach", "Kernel version not supported")
        
        assert exc.operation == "attach"
        assert exc.error == "Kernel version not supported"
        assert "ebpf" in str(exc).lower()


class TestExceptionHierarchy:
    """Tests for the complete exception hierarchy."""

    def test_all_exceptions_inherit_from_base(self):
        """Test all exceptions inherit from TrapNinjaError."""
        from trapninja.core.exceptions import (
            TrapNinjaError,
            ConfigurationError, ConfigFileNotFoundError, ConfigParseError,
            ConfigValidationError,
            ParsingError, InvalidSNMPPacket, UnsupportedSNMPVersion,
            OIDExtractionError,
            ForwardingError, NoDestinationsError, SocketError,
            DestinationUnreachable,
            HAError, HAInitializationError, HAPeerCommunicationError,
            HASplitBrainError, HAStateTransitionError,
            SecurityError, SNMPv3DecryptionError, CredentialNotFoundError,
            AuthenticationError, InvalidCredentialsError,
            CaptureError, InterfaceNotFoundError, CapturePermissionError,
            EBPFError,
        )
        
        # List of all exception classes
        all_exceptions = [
            ConfigurationError, ConfigFileNotFoundError, ConfigParseError,
            ConfigValidationError,
            ParsingError, InvalidSNMPPacket, UnsupportedSNMPVersion,
            OIDExtractionError,
            ForwardingError, NoDestinationsError, SocketError,
            DestinationUnreachable,
            HAError, HAInitializationError, HAPeerCommunicationError,
            HASplitBrainError, HAStateTransitionError,
            SecurityError, SNMPv3DecryptionError, CredentialNotFoundError,
            AuthenticationError, InvalidCredentialsError,
            CaptureError, InterfaceNotFoundError, CapturePermissionError,
            EBPFError,
        ]
        
        for exc_class in all_exceptions:
            assert issubclass(exc_class, TrapNinjaError), \
                f"{exc_class.__name__} does not inherit from TrapNinjaError"

    def test_exception_categories(self):
        """Test exception category inheritance."""
        from trapninja.core.exceptions import (
            ConfigurationError, ConfigFileNotFoundError, ConfigParseError,
            ConfigValidationError,
            ParsingError, InvalidSNMPPacket, UnsupportedSNMPVersion,
            OIDExtractionError,
            ForwardingError, NoDestinationsError, SocketError,
            DestinationUnreachable,
            HAError, HAInitializationError, HAPeerCommunicationError,
            SecurityError, SNMPv3DecryptionError, CredentialNotFoundError,
            CaptureError, InterfaceNotFoundError, EBPFError,
        )
        
        # Configuration exceptions
        assert issubclass(ConfigFileNotFoundError, ConfigurationError)
        assert issubclass(ConfigParseError, ConfigurationError)
        assert issubclass(ConfigValidationError, ConfigurationError)
        
        # Parsing exceptions
        assert issubclass(InvalidSNMPPacket, ParsingError)
        assert issubclass(UnsupportedSNMPVersion, ParsingError)
        assert issubclass(OIDExtractionError, ParsingError)
        
        # Forwarding exceptions
        assert issubclass(NoDestinationsError, ForwardingError)
        assert issubclass(SocketError, ForwardingError)
        assert issubclass(DestinationUnreachable, ForwardingError)
        
        # HA exceptions
        assert issubclass(HAInitializationError, HAError)
        assert issubclass(HAPeerCommunicationError, HAError)
        
        # Security exceptions
        assert issubclass(SNMPv3DecryptionError, SecurityError)
        assert issubclass(CredentialNotFoundError, SecurityError)
        
        # Capture exceptions
        assert issubclass(InterfaceNotFoundError, CaptureError)
        assert issubclass(EBPFError, CaptureError)


class TestExceptionCatching:
    """Tests for exception catching patterns."""

    def test_catch_by_category(self):
        """Test catching exceptions by category."""
        from trapninja.core.exceptions import (
            ConfigurationError, ConfigFileNotFoundError
        )
        
        # Should be catchable by parent class
        with pytest.raises(ConfigurationError):
            raise ConfigFileNotFoundError("/path/to/config")

    def test_catch_by_base(self):
        """Test catching all TrapNinja exceptions."""
        from trapninja.core.exceptions import (
            TrapNinjaError, InvalidSNMPPacket
        )
        
        with pytest.raises(TrapNinjaError):
            raise InvalidSNMPPacket("Test error")

    def test_catch_specific_exception(self):
        """Test catching specific exception type."""
        from trapninja.core.exceptions import (
            ConfigurationError, ConfigFileNotFoundError
        )
        
        # Should not catch different exception types
        with pytest.raises(ConfigFileNotFoundError):
            try:
                raise ConfigFileNotFoundError("/path")
            except ConfigurationError as e:
                if isinstance(e, ConfigFileNotFoundError):
                    raise
                pytest.fail("Should have caught ConfigFileNotFoundError")
