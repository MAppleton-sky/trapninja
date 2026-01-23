#!/usr/bin/env python3
"""
TrapNinja Security Utilities Module

Provides secure path handling, cryptographic utilities, and security validation
functions to address common vulnerability patterns.

Security Features:
- CWE-23: Path traversal prevention with canonicalization
- CWE-327: Secure algorithm selection with deprecation warnings
- CWE-916: Proper key derivation parameters
"""

import os
import re
import hashlib
import logging
import warnings
from typing import Optional, Tuple, Set
from functools import wraps

logger = logging.getLogger("trapninja")

# ============================================================================
# CWE-23: PATH TRAVERSAL PREVENTION
# ============================================================================

class PathTraversalError(Exception):
    """Raised when a path traversal attempt is detected."""
    pass


class SecurePath:
    """
    Secure path handling with traversal prevention.
    
    All path operations validate that the resulting path remains
    within the allowed base directory.
    """
    
    # Patterns that indicate potential path traversal
    TRAVERSAL_PATTERNS = [
        re.compile(r'\.\.'),           # Parent directory reference
        re.compile(r'^/'),             # Absolute path when relative expected
        re.compile(r'%2e%2e', re.I),   # URL-encoded ..
        re.compile(r'%252e', re.I),    # Double URL-encoded .
        re.compile(r'\x00'),           # Null byte injection
    ]
    
    def __init__(self, base_dir: str):
        """
        Initialize secure path handler.
        
        Args:
            base_dir: Base directory that all paths must remain within
        """
        # Resolve and normalize the base directory
        self.base_dir = os.path.realpath(os.path.abspath(base_dir))
        
        if not os.path.isdir(self.base_dir):
            raise ValueError(f"Base directory does not exist: {self.base_dir}")
    
    def _contains_traversal_pattern(self, path: str) -> bool:
        """Check if path contains suspicious traversal patterns."""
        for pattern in self.TRAVERSAL_PATTERNS:
            if pattern.search(path):
                return True
        return False
    
    def validate_filename(self, filename: str) -> str:
        """
        Validate a filename (no directory components allowed).
        
        Args:
            filename: Filename to validate
            
        Returns:
            Validated filename
            
        Raises:
            PathTraversalError: If filename contains path components
        """
        if not filename:
            raise PathTraversalError("Empty filename")
        
        # Check for traversal patterns
        if self._contains_traversal_pattern(filename):
            raise PathTraversalError(f"Suspicious pattern in filename: {filename}")
        
        # Ensure no directory separators
        if os.sep in filename or '/' in filename or '\\' in filename:
            raise PathTraversalError(f"Filename contains path separator: {filename}")
        
        # Basic sanity check on characters
        if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
            raise PathTraversalError(f"Invalid characters in filename: {filename}")
        
        return filename
    
    def safe_join(self, *path_components: str) -> str:
        """
        Safely join path components, ensuring result stays within base_dir.
        
        Args:
            *path_components: Path components to join
            
        Returns:
            Safe absolute path within base_dir
            
        Raises:
            PathTraversalError: If resulting path escapes base_dir
        """
        # Check each component for suspicious patterns
        for component in path_components:
            if self._contains_traversal_pattern(str(component)):
                raise PathTraversalError(
                    f"Suspicious pattern in path component: {component}"
                )
        
        # Join and resolve the path
        joined = os.path.join(self.base_dir, *path_components)
        resolved = os.path.realpath(os.path.abspath(joined))
        
        # Verify the resolved path is within base_dir
        if not self._is_within_base(resolved):
            raise PathTraversalError(
                f"Path escapes base directory: {resolved} not in {self.base_dir}"
            )
        
        return resolved
    
    def _is_within_base(self, path: str) -> bool:
        """Check if path is within the base directory."""
        # Normalize both paths
        normalized_path = os.path.realpath(os.path.abspath(path))
        normalized_base = self.base_dir
        
        # Check if the path starts with the base directory
        # Add trailing separator to prevent /base/dir matching /base/directory
        return normalized_path.startswith(normalized_base + os.sep) or \
               normalized_path == normalized_base
    
    def safe_open(self, filename: str, mode: str = 'r'):
        """
        Safely open a file within the base directory.
        
        Args:
            filename: Filename (not path) to open
            mode: File open mode
            
        Returns:
            Open file handle
            
        Raises:
            PathTraversalError: If filename would escape base_dir
        """
        # Validate filename first
        validated_filename = self.validate_filename(filename)
        safe_path = self.safe_join(validated_filename)
        
        return open(safe_path, mode)
    
    def exists(self, filename: str) -> bool:
        """
        Check if a file exists within the base directory.
        
        Args:
            filename: Filename to check
            
        Returns:
            True if file exists
        """
        try:
            validated_filename = self.validate_filename(filename)
            safe_path = self.safe_join(validated_filename)
            return os.path.exists(safe_path)
        except PathTraversalError:
            return False
    
    def get_mtime(self, filename: str) -> float:
        """
        Get file modification time safely.
        
        Args:
            filename: Filename to check
            
        Returns:
            Modification time as float
        """
        validated_filename = self.validate_filename(filename)
        safe_path = self.safe_join(validated_filename)
        return os.path.getmtime(safe_path)


def validate_config_path(config_dir: str, filename: str) -> str:
    """
    Convenience function to validate a config file path.
    
    Args:
        config_dir: Configuration directory
        filename: Configuration filename
        
    Returns:
        Safe absolute path
        
    Raises:
        PathTraversalError: If path would escape config_dir
    """
    secure = SecurePath(config_dir)
    return secure.safe_join(filename)


# ============================================================================
# CWE-327: CRYPTOGRAPHIC ALGORITHM SECURITY
# ============================================================================

class CryptoAlgorithmWarning(UserWarning):
    """Warning for deprecated or weak cryptographic algorithms."""
    pass


# Algorithms considered weak or deprecated
WEAK_ALGORITHMS = {
    'MD5': 'MD5 is cryptographically broken. Use SHA-256 or stronger.',
    'SHA1': 'SHA-1 is deprecated. Use SHA-256 or stronger.',
    'DES': 'DES is obsolete with only 56-bit keys. Use AES.',
    '3DES': '3DES is deprecated. Use AES.',
}

# Algorithms that are acceptable but should be used carefully
LEGACY_ALGORITHMS = {
    'SHA224': 'Consider using SHA-256 for better security margin.',
}

# Recommended algorithms
RECOMMENDED_ALGORITHMS = {'SHA256', 'SHA384', 'SHA512', 'AES128', 'AES192', 'AES256'}


def check_algorithm_security(
    algorithm: str, 
    context: str = "operation",
    allow_legacy: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Check if a cryptographic algorithm is secure.
    
    Args:
        algorithm: Algorithm name to check
        context: Context description for warnings
        allow_legacy: If True, allow legacy algorithms with warning
        
    Returns:
        Tuple of (is_acceptable, warning_message)
    """
    algo_upper = algorithm.upper()
    
    # Check if it's a weak algorithm
    if algo_upper in WEAK_ALGORITHMS:
        warning_msg = (
            f"Algorithm {algorithm} used for {context}: "
            f"{WEAK_ALGORITHMS[algo_upper]}"
        )
        
        if not allow_legacy:
            logger.warning(warning_msg)
            return False, warning_msg
        else:
            # Allow for protocol compatibility but warn
            warnings.warn(warning_msg, CryptoAlgorithmWarning, stacklevel=3)
            return True, warning_msg
    
    # Check if it's a legacy algorithm
    if algo_upper in LEGACY_ALGORITHMS:
        warning_msg = (
            f"Algorithm {algorithm} used for {context}: "
            f"{LEGACY_ALGORITHMS[algo_upper]}"
        )
        logger.info(warning_msg)
        return True, warning_msg
    
    # Check if it's recommended
    if algo_upper in RECOMMENDED_ALGORITHMS:
        return True, None
    
    # Unknown algorithm
    warning_msg = f"Unknown algorithm {algorithm} used for {context}"
    logger.warning(warning_msg)
    return True, warning_msg


def get_secure_hash(algorithm: str = 'SHA256'):
    """
    Get a secure hash function.
    
    Args:
        algorithm: Preferred algorithm (default: SHA256)
        
    Returns:
        hashlib hash object
    """
    algo_map = {
        'SHA256': hashlib.sha256,
        'SHA384': hashlib.sha384,
        'SHA512': hashlib.sha512,
        'SHA224': hashlib.sha224,
        # Legacy - only for protocol compatibility
        'SHA1': hashlib.sha1,
        'MD5': hashlib.md5,
    }
    
    algo_upper = algorithm.upper()
    
    if algo_upper not in algo_map:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    # Log warning for weak algorithms
    check_algorithm_security(algo_upper, "hashing", allow_legacy=True)
    
    return algo_map[algo_upper]()


def secure_checksum(data: bytes, algorithm: str = 'SHA256') -> str:
    """
    Calculate a secure checksum of data.
    
    Uses SHA-256 by default instead of MD5.
    
    Args:
        data: Data to checksum
        algorithm: Hash algorithm to use
        
    Returns:
        Hexadecimal checksum string
    """
    hasher = get_secure_hash(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def secure_checksum_file(filepath: str, algorithm: str = 'SHA256') -> str:
    """
    Calculate a secure checksum of a file.
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm to use
        
    Returns:
        Hexadecimal checksum string
    """
    hasher = get_secure_hash(algorithm)
    
    with open(filepath, 'rb') as f:
        # Read in chunks for large files
        for chunk in iter(lambda: f.read(8192), b''):
            hasher.update(chunk)
    
    return hasher.hexdigest()


# ============================================================================
# CWE-916: KEY DERIVATION SECURITY
# ============================================================================

# Minimum recommended PBKDF2 iterations (OWASP 2023)
MIN_PBKDF2_ITERATIONS = 600000  # OWASP recommendation for PBKDF2-SHA256
MIN_PBKDF2_ITERATIONS_LEGACY = 100000  # Acceptable minimum

# Salt requirements
MIN_SALT_LENGTH = 16  # bytes


def validate_kdf_parameters(
    iterations: int,
    salt_length: int = 0,
    algorithm: str = 'SHA256'
) -> Tuple[bool, Optional[str]]:
    """
    Validate key derivation function parameters.
    
    Args:
        iterations: Number of iterations
        salt_length: Length of salt in bytes
        algorithm: Hash algorithm used
        
    Returns:
        Tuple of (is_secure, warning_message)
    """
    warnings_list = []
    
    # Check iterations
    if iterations < MIN_PBKDF2_ITERATIONS_LEGACY:
        warnings_list.append(
            f"PBKDF2 iterations ({iterations}) below minimum ({MIN_PBKDF2_ITERATIONS_LEGACY}). "
            f"Recommended: {MIN_PBKDF2_ITERATIONS}"
        )
    elif iterations < MIN_PBKDF2_ITERATIONS:
        warnings_list.append(
            f"PBKDF2 iterations ({iterations}) below recommended ({MIN_PBKDF2_ITERATIONS}). "
            f"Consider increasing for better security."
        )
    
    # Check salt length
    if salt_length > 0 and salt_length < MIN_SALT_LENGTH:
        warnings_list.append(
            f"Salt length ({salt_length} bytes) below minimum ({MIN_SALT_LENGTH} bytes)"
        )
    
    # Check algorithm
    algo_ok, algo_warning = check_algorithm_security(algorithm, "key derivation")
    if algo_warning:
        warnings_list.append(algo_warning)
    
    if warnings_list:
        combined_warning = "; ".join(warnings_list)
        logger.warning(f"KDF security: {combined_warning}")
        return len(warnings_list) == 0 or all('recommended' in w.lower() for w in warnings_list), combined_warning
    
    return True, None


# ============================================================================
# SNMP-SPECIFIC SECURITY HELPERS
# ============================================================================

# SNMPv3 algorithms mandated by RFC 3414 (USM for SNMPv3)
SNMPV3_RFC_ALGORITHMS = {
    'auth': {'MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'},
    'priv': {'DES', '3DES', 'AES128', 'AES192', 'AES256'},
}


def validate_snmpv3_algorithm(
    algorithm: str,
    algorithm_type: str  # 'auth' or 'priv'
) -> Tuple[bool, Optional[str]]:
    """
    Validate SNMPv3 algorithm with security warnings.
    
    SNMPv3 requires support for legacy algorithms (MD5, DES) per RFC 3414.
    This function validates the algorithm is valid for SNMP and issues
    security warnings for weak algorithms.
    
    Args:
        algorithm: Algorithm name
        algorithm_type: 'auth' or 'priv'
        
    Returns:
        Tuple of (is_valid, warning_message)
    """
    algo_upper = algorithm.upper()
    
    # Map SHA to SHA1 for SNMP
    if algo_upper == 'SHA':
        algo_upper = 'SHA1'
    
    valid_algorithms = SNMPV3_RFC_ALGORITHMS.get(algorithm_type, set())
    
    # Check if algorithm is valid for SNMP
    if algo_upper not in valid_algorithms and algorithm.upper() not in valid_algorithms:
        return False, f"Invalid SNMPv3 {algorithm_type} algorithm: {algorithm}"
    
    # Check security level with SNMP context
    is_ok, warning = check_algorithm_security(
        algo_upper, 
        f"SNMPv3 {algorithm_type}", 
        allow_legacy=True  # SNMP requires legacy support
    )
    
    # Add SNMP-specific recommendation
    if algo_upper in WEAK_ALGORITHMS:
        snmp_recommendation = (
            f"SNMPv3 {algorithm_type} algorithm '{algorithm}' is weak but required "
            f"by RFC 3414 for interoperability. "
        )
        if algorithm_type == 'auth':
            snmp_recommendation += "Consider SHA-256 or stronger where device supports it."
        else:
            snmp_recommendation += "Consider AES-128 or stronger where device supports it."
        
        return True, snmp_recommendation
    
    return True, warning


def log_snmpv3_security_assessment(auth_protocol: str, priv_protocol: str):
    """
    Log a security assessment of SNMPv3 credential configuration.
    
    Args:
        auth_protocol: Authentication protocol
        priv_protocol: Privacy protocol
    """
    assessments = []
    
    # Check auth protocol
    auth_valid, auth_warning = validate_snmpv3_algorithm(auth_protocol, 'auth')
    if auth_warning:
        assessments.append(f"Auth: {auth_warning}")
    
    # Check priv protocol
    priv_valid, priv_warning = validate_snmpv3_algorithm(priv_protocol, 'priv')
    if priv_warning:
        assessments.append(f"Priv: {priv_warning}")
    
    # Determine overall security level
    auth_upper = auth_protocol.upper()
    priv_upper = priv_protocol.upper()
    
    if auth_upper in {'SHA256', 'SHA384', 'SHA512'} and priv_upper in {'AES128', 'AES192', 'AES256'}:
        level = "STRONG"
        logger.info(f"SNMPv3 security level: {level}")
    elif auth_upper in {'MD5', 'SHA', 'SHA1'} or priv_upper in {'DES', '3DES'}:
        level = "LEGACY (weak algorithms for protocol compatibility)"
        logger.warning(f"SNMPv3 security level: {level}")
        for assessment in assessments:
            logger.warning(f"  {assessment}")
    else:
        level = "MODERATE"
        logger.info(f"SNMPv3 security level: {level}")


# ============================================================================
# UTILITY DECORATORS
# ============================================================================

def requires_secure_path(base_dir_param: str = 'config_dir'):
    """
    Decorator to ensure path parameters are validated.
    
    Args:
        base_dir_param: Name of the parameter containing the base directory
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            base_dir = kwargs.get(base_dir_param)
            if base_dir:
                # Create SecurePath to validate base_dir exists
                SecurePath(base_dir)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def log_crypto_usage(algorithm_param: str = 'algorithm', context: str = 'operation'):
    """
    Decorator to log cryptographic algorithm usage.
    
    Args:
        algorithm_param: Name of the parameter containing the algorithm
        context: Description of the cryptographic operation
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            algorithm = kwargs.get(algorithm_param, 'unknown')
            check_algorithm_security(algorithm, context, allow_legacy=True)
            return func(*args, **kwargs)
        return wrapper
    return decorator
