"""
Security-related modules for TrueFA

This package provides security features for the TrueFA application, including:
- Secure string handling to prevent sensitive data exposure
- Secure storage for vault and secrets
- File integrity verification using HMAC
- Security event tracking and response
"""

from .secure_memory import SecureString
from .secure_storage import SecureStorage
from .file_integrity import (
    FileIntegrityVerifier, 
    add_hmac_to_file, 
    verify_file_integrity
)
from .security_events import (
    SecurityEventTracker,
    record_security_event,
    get_security_event_count,
    reset_security_counters
)

__all__ = [
    'SecureString', 
    'SecureStorage',
    'FileIntegrityVerifier',
    'add_hmac_to_file',
    'verify_file_integrity',
    'SecurityEventTracker',
    'record_security_event',
    'get_security_event_count',
    'reset_security_counters'
] 