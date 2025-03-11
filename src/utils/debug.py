"""
Debug Utility Module

Provides simple debug printing that can be globally enabled or disabled.
This allows debug statements to remain in the code but be silent in production.
"""

import os
import datetime
import sys

# Debug state - can be enabled via environment variable or set_debug()
_debug_enabled = os.environ.get('TRUEFA_DEBUG', '').lower() in ('1', 'true', 'yes')

# Simple logging capability
_logging_enabled = os.environ.get('TRUEFA_LOG', '').lower() in ('1', 'true', 'yes')
_log_file = None

def set_debug(enabled=True):
    """
    Enable or disable debug output.
    
    Args:
        enabled (bool): Whether to enable debug output
    """
    global _debug_enabled
    _debug_enabled = enabled

def is_debug_enabled():
    """
    Check if debug mode is enabled.
    
    Returns:
        bool: True if debug is enabled, False otherwise
    """
    return _debug_enabled

def debug_print(*args, **kwargs):
    """
    Print debug messages if debug mode is enabled.
    
    Args:
        *args: Arguments to pass to print()
        **kwargs: Keyword arguments to pass to print()
    """
    if not _debug_enabled:
        return
    
    # Add DEBUG prefix for clarity
    if args and isinstance(args[0], str):
        args = (f"DEBUG: {args[0]}",) + args[1:]
    else:
        args = ("DEBUG:",) + args
    
    # Use standard print function with our args
    print(*args, **kwargs)
    
    # Also log to file if enabled
    if _logging_enabled:
        _log_to_file(*args)

def _log_to_file(*args):
    """
    Log message to a file.
    
    Args:
        *args: Arguments to log
    """
    global _log_file
    
    try:
        # Create log file if it doesn't exist
        if _log_file is None:
            log_dir = os.path.join(os.path.expanduser('~'), '.truefa', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = os.path.join(log_dir, f"truefa_{timestamp}.log")
            
            _log_file = open(log_path, 'a', encoding='utf-8')
            _log_file.write(f"=== TrueFA-Py Log Started at {datetime.datetime.now().isoformat()} ===\n\n")
        
        # Log the message with timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = " ".join(str(arg) for arg in args)
        _log_file.write(f"[{timestamp}] {message}\n")
        _log_file.flush()
        
    except Exception:
        # Silently fail if logging fails - don't interrupt the program
        pass

def close_logging():
    """Close the log file if it's open."""
    global _log_file
    
    if _log_file is not None:
        try:
            _log_file.write(f"\n=== TrueFA-Py Log Closed at {datetime.datetime.now().isoformat()} ===\n")
            _log_file.close()
        except Exception:
            pass  # Ignore errors when closing
        _log_file = None

# Convenience alias
debug = debug_print 