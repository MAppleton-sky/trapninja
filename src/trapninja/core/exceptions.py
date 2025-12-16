#!/usr/bin/env python3
"""
TrapNinja Core Exceptions

Custom exception hierarchy for TrapNinja.
Provides specific exception types for different error categories
to enable precise error handling and informative error messages.

Author: TrapNinja Team
Version: 1.0.0
"""

from typing import Optional, Any


class TrapNinjaError(Exception):
    """
    Base exception for all TrapNinja errors.
    
    All custom exceptions in TrapNinja inherit from this class,
    allowing for catch-all error handling when needed.
    """
    
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.details = details
    
    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


# =============================================================================
# CONFIGURATION EXCEPTIONS
# =============================================================================

class ConfigurationError(TrapNinjaError):
    """
    Exception for configuration-related errors.
    
    Raised when configuration files are invalid, missing,
    or contain incorrect values.
    """
    pass


class ConfigFileNotFoundError(ConfigurationError):
    """Raised when a required configuration file is not found."""
    
    def __init__(self, file_path: str):
        super().__init__(
            f"Configuration file not found",
            details=file_path
        )
        self.file_path = file_path


class ConfigParseError(ConfigurationError):
    """Raised when a configuration file cannot be parsed."""
    
    def __init__(self, file_path: str, parse_error: str):
        super().__init__(
            f"Failed to parse configuration file",
            details=f"{file_path}: {parse_error}"
        )
        self.file_path = file_path
        self.parse_error = parse_error


class ConfigValidationError(ConfigurationError):
    """Raised when configuration values are invalid."""
    
    def __init__(self, field: str, value: Any, reason: str):
        super().__init__(
            f"Invalid configuration value for '{field}'",
            details=f"value={value}, reason={reason}"
        )
        self.field = field
        self.value = value
        self.reason = reason


# =============================================================================
# PARSING EXCEPTIONS
# =============================================================================

class ParsingError(TrapNinjaError):
    """
    Exception for SNMP packet parsing errors.
    
    Raised when a packet cannot be parsed as valid SNMP.
    """
    pass


class InvalidSNMPPacket(ParsingError):
    """Raised when packet is not valid SNMP."""
    
    def __init__(self, reason: str, source_ip: Optional[str] = None):
        message = "Invalid SNMP packet"
        if source_ip:
            message = f"Invalid SNMP packet from {source_ip}"
        super().__init__(message, details=reason)
        self.reason = reason
        self.source_ip = source_ip


class UnsupportedSNMPVersion(ParsingError):
    """Raised when SNMP version is not supported."""
    
    def __init__(self, version: int):
        super().__init__(
            f"Unsupported SNMP version",
            details=f"version={version}"
        )
        self.version = version


class OIDExtractionError(ParsingError):
    """Raised when OID cannot be extracted from packet."""
    
    def __init__(self, reason: str):
        super().__init__(
            "Failed to extract trap OID",
            details=reason
        )
        self.reason = reason


# =============================================================================
# FORWARDING EXCEPTIONS
# =============================================================================

class ForwardingError(TrapNinjaError):
    """
    Exception for packet forwarding errors.
    
    Raised when packets cannot be forwarded to destinations.
    """
    pass


class NoDestinationsError(ForwardingError):
    """Raised when no destinations are configured."""
    
    def __init__(self):
        super().__init__(
            "No destinations configured",
            details="Please configure at least one destination in destinations.json"
        )


class SocketError(ForwardingError):
    """Raised when socket operations fail."""
    
    def __init__(self, operation: str, error: str):
        super().__init__(
            f"Socket {operation} failed",
            details=error
        )
        self.operation = operation
        self.error = error


class DestinationUnreachable(ForwardingError):
    """Raised when a destination is unreachable."""
    
    def __init__(self, destination: str, port: int, error: str):
        super().__init__(
            f"Destination unreachable: {destination}:{port}",
            details=error
        )
        self.destination = destination
        self.port = port
        self.error = error


# =============================================================================
# HIGH AVAILABILITY EXCEPTIONS
# =============================================================================

class HAError(TrapNinjaError):
    """
    Exception for High Availability errors.
    
    Raised when HA operations fail.
    """
    pass


class HAInitializationError(HAError):
    """Raised when HA cluster fails to initialize."""
    
    def __init__(self, reason: str):
        super().__init__(
            "Failed to initialize HA cluster",
            details=reason
        )
        self.reason = reason


class HAPeerCommunicationError(HAError):
    """Raised when communication with peer fails."""
    
    def __init__(self, peer_host: str, peer_port: int, error: str):
        super().__init__(
            f"Cannot communicate with HA peer",
            details=f"{peer_host}:{peer_port} - {error}"
        )
        self.peer_host = peer_host
        self.peer_port = peer_port
        self.error = error


class HASplitBrainError(HAError):
    """Raised when split-brain condition is detected."""
    
    def __init__(self, local_state: str, peer_state: str):
        super().__init__(
            "Split-brain condition detected",
            details=f"local={local_state}, peer={peer_state}"
        )
        self.local_state = local_state
        self.peer_state = peer_state


class HAStateTransitionError(HAError):
    """Raised when state transition is invalid."""
    
    def __init__(self, current_state: str, target_state: str, reason: str):
        super().__init__(
            f"Invalid HA state transition: {current_state} -> {target_state}",
            details=reason
        )
        self.current_state = current_state
        self.target_state = target_state
        self.reason = reason


# =============================================================================
# SECURITY EXCEPTIONS
# =============================================================================

class SecurityError(TrapNinjaError):
    """
    Exception for security-related errors.
    
    Raised when security operations fail or violations occur.
    """
    pass


class SNMPv3DecryptionError(SecurityError):
    """Raised when SNMPv3 decryption fails."""
    
    def __init__(self, reason: str, engine_id: Optional[str] = None):
        message = "SNMPv3 decryption failed"
        details = reason
        if engine_id:
            details = f"engine_id={engine_id}, reason={reason}"
        super().__init__(message, details=details)
        self.reason = reason
        self.engine_id = engine_id


class CredentialNotFoundError(SecurityError):
    """Raised when SNMPv3 credentials are not found."""
    
    def __init__(self, username: str, engine_id: Optional[str] = None):
        message = f"Credentials not found for user '{username}'"
        if engine_id:
            message += f" (engine_id={engine_id})"
        super().__init__(message)
        self.username = username
        self.engine_id = engine_id


class AuthenticationError(SecurityError):
    """Raised when SNMPv3 authentication fails."""
    
    def __init__(self, reason: str):
        super().__init__(
            "SNMPv3 authentication failed",
            details=reason
        )
        self.reason = reason


class InvalidCredentialsError(SecurityError):
    """Raised when credentials are invalid."""
    
    def __init__(self, field: str, reason: str):
        super().__init__(
            f"Invalid credentials: {field}",
            details=reason
        )
        self.field = field
        self.reason = reason


# =============================================================================
# CAPTURE EXCEPTIONS
# =============================================================================

class CaptureError(TrapNinjaError):
    """
    Exception for packet capture errors.
    """
    pass


class InterfaceNotFoundError(CaptureError):
    """Raised when network interface is not found."""
    
    def __init__(self, interface: str, available: list):
        super().__init__(
            f"Network interface '{interface}' not found",
            details=f"Available interfaces: {available}"
        )
        self.interface = interface
        self.available = available


class CapturePermissionError(CaptureError):
    """Raised when capture permissions are insufficient."""
    
    def __init__(self, operation: str):
        super().__init__(
            f"Insufficient permissions for {operation}",
            details="Try running as root or with CAP_NET_RAW capability"
        )
        self.operation = operation


class EBPFError(CaptureError):
    """Raised when eBPF operations fail."""
    
    def __init__(self, operation: str, error: str):
        super().__init__(
            f"eBPF {operation} failed",
            details=error
        )
        self.operation = operation
        self.error = error
