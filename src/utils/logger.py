"""
Logger Module

Provides standardized logging functionality using Python's built-in logging module.
This makes it easy to log messages to both console and file with different severity levels.
"""

import os
import sys
import logging
import datetime
from pathlib import Path

# Try to import build-time environment settings
try:
    # This file is generated during the build process
    from _build_env import LOGGING_ENABLED, DEBUG_ENABLED
    # Use build-time settings
    DEFAULT_LOG_TO_FILE = LOGGING_ENABLED
    DEFAULT_DEBUG_MODE = DEBUG_ENABLED
except ImportError:
    # If not running from a built executable, use environment variables or defaults
    DEFAULT_LOG_TO_FILE = os.environ.get('TRUEFA_LOG', '').lower() in ('1', 'true', 'yes')
    DEFAULT_DEBUG_MODE = os.environ.get('TRUEFA_DEBUG', '').lower() in ('1', 'true', 'yes')

# Default log levels
DEFAULT_CONSOLE_LEVEL = logging.DEBUG if DEFAULT_DEBUG_MODE else logging.WARNING
DEFAULT_FILE_LEVEL = logging.DEBUG      # File always logs everything (when enabled)

# Global logger instance
logger = None
log_file_path = None

# List of module loggers to configure with the same settings
MODULE_LOGGERS = [
    'src.security.vault_interfaces',
    'src.security.vault_crypto',
    'src.security.secure_storage',
    'src.security.vault',
    'truefa_crypto',
    'truefa_crypto.loader'
]

def configure_root_logger(console_level):
    """
    Configure the root logger to respect our console level settings.
    This affects all loggers that don't override their level explicitly.
    
    Args:
        console_level (int): Logging level for console output
    """
    # Configure the root logger
    root_logger = logging.getLogger()
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add a console handler with our level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    formatter = logging.Formatter('%(levelname)s [%(filename)s:%(lineno)d]: %(message)s')
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Configure all module loggers to respect our console level
    for module_name in MODULE_LOGGERS:
        module_logger = logging.getLogger(module_name)
        module_logger.setLevel(logging.DEBUG)  # Let handlers control the output
        
        # Remove any existing handlers
        for handler in module_logger.handlers[:]:
            module_logger.removeHandler(handler)
            
        # Add a console handler with our level
        module_handler = logging.StreamHandler()
        module_handler.setLevel(console_level)
        module_handler.setFormatter(formatter)
        module_logger.addHandler(module_handler)
        
        # Don't propagate to avoid duplicate messages
        module_logger.propagate = False

def setup_logger(name='truefa', 
                 console_level=None, 
                 file_level=None,
                 log_to_file=DEFAULT_LOG_TO_FILE,
                 log_dir=None):
    """
    Set up the logger with handlers for console and file output.
    
    Args:
        name (str): Logger name
        console_level (int): Logging level for console output (e.g., logging.DEBUG)
        file_level (int): Logging level for file output
        log_to_file (bool): Whether to log to a file
        log_dir (str): Directory for log files, defaults to ~/.truefa/logs
        
    Returns:
        logging.Logger: Configured logger instance
    """
    global logger, log_file_path
    
    # Use default levels if not specified
    if console_level is None:
        console_level = DEFAULT_CONSOLE_LEVEL
        
        # If debug mode is enabled via environment variable, lower console level to DEBUG
        if os.environ.get('TRUEFA_DEBUG', '').lower() in ('1', 'true', 'yes'):
            console_level = logging.DEBUG
            
    if file_level is None:
        file_level = DEFAULT_FILE_LEVEL
    
    # Configure the root logger first to establish baseline behavior
    configure_root_logger(console_level)
    
    # Create our application logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Set to lowest level to catch everything
    
    # Remove any existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    
    # Create formatter with source file and line number
    console_formatter = logging.Formatter(
        '%(levelname)s [%(filename)s:%(lineno)d]: %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Don't propagate to root logger to avoid duplicate messages
    logger.propagate = False
    
    # Set up file logging if enabled
    if log_to_file:
        try:
            if log_dir is None:
                log_dir = os.path.join(os.path.expanduser('~'), '.truefa', 'logs')
            
            # Create log directory if it doesn't exist
            os.makedirs(log_dir, exist_ok=True)
            
            # Create log file with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file_path = os.path.join(log_dir, f"truefa_{timestamp}.log")
            
            # Print a message to confirm the log file path
            if not getattr(setup_logger, 'log_file_created', False):
                print(f"Creating log file at: {log_file_path}")
                setup_logger.log_file_created = True
            
            # Create file handler with explicit encoding
            file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')
            file_handler.setLevel(file_level)
            
            # Create a detailed formatter for the file
            file_formatter = logging.Formatter(
                '[%(asctime)s] %(levelname)s [%(filename)s:%(lineno)d]: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
            # Log the startup message
            logger.info(f"=== TrueFA-Py Log Started at {datetime.datetime.now().isoformat()} ===")
            logger.info(f"Log file created at: {log_file_path}")
            
            # Force a flush to ensure the file is written
            for handler in logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    handler.flush()
                    
        except Exception as e:
            # Log any errors setting up file logging to console
            print(f"Error setting up file logging: {e}")
            # Fall back to console-only logging
    else:
        # Log file is disabled
        log_file_path = None
        print("File logging disabled")
    
    return logger

def get_logger():
    """
    Get the configured logger instance or set up a new one if not configured.
    
    Returns:
        logging.Logger: Logger instance
    """
    global logger
    if logger is None:
        return setup_logger()
    return logger

def set_console_level(level):
    """
    Set the console output log level.
    
    Args:
        level (int): Logging level (e.g., logging.DEBUG, logging.INFO)
    """
    for handler in get_logger().handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(level)

def get_log_file_path():
    """
    Get the path to the current log file.
    
    Returns:
        str: Path to the log file or None if file logging is disabled
    """
    return log_file_path

# Convenience functions that map to logging methods
def debug(msg, *args, **kwargs):
    """Log a debug message"""
    get_logger().debug(msg, *args, **kwargs)

def info(msg, *args, **kwargs):
    """Log an info message"""
    get_logger().info(msg, *args, **kwargs)

def warning(msg, *args, **kwargs):
    """Log a warning message"""
    get_logger().warning(msg, *args, **kwargs)

def error(msg, *args, **kwargs):
    """Log an error message"""
    get_logger().error(msg, *args, **kwargs)

def critical(msg, *args, **kwargs):
    """Log a critical message"""
    get_logger().critical(msg, *args, **kwargs)

# For compatibility with old debug_print
def debug_print(msg, *args, **kwargs):
    """
    Compatibility function for the old debug_print interface.
    Converts the message and args to a string and logs at debug level.
    """
    if args:
        full_msg = f"{msg} {' '.join(str(arg) for arg in args)}"
    else:
        full_msg = msg
    debug(full_msg)

# No automatic initialization - let main.py control when the logger is created 