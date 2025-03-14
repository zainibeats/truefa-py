"""
Vault Directory Module for TrueFA-Py

Handles secure directory operations for the vault system,
ensuring proper permissions and access controls for sensitive files.
"""

import os
import sys
import platform
import tempfile
import shutil
from pathlib import Path
import logging

from src.utils.colorprint import print_warning, print_info

logger = logging.getLogger(__name__)

def is_running_in_docker():
    """
    Check if the application is running inside a Docker container.
    
    Returns:
        bool: True if running in Docker, False otherwise
    """
    # Check for .dockerenv file
    if os.path.exists('/.dockerenv'):
        return True
    
    # Check for Docker-specific entries in /proc/1/cgroup
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return 'docker' in f.read()
    except:
        pass
        
    return False

def create_secure_directory(path, fallback_path=None):
    """
    Create a secure directory with proper permissions.
    Falls back to alternate location if primary location is not writable.
    
    Args:
        path: Primary path to create
        fallback_path: Fallback path if primary fails
        
    Returns:
        str: The path of the created directory
        
    Raises:
        OSError: If neither primary nor fallback paths can be created securely
    """
    # Normalize the path
    path = os.path.abspath(os.path.expanduser(path))
    
    # Check if we're running in Docker with a Windows host volume mount
    running_in_docker = is_running_in_docker()
    docker_with_windows_mount = running_in_docker and platform.system() != "Windows"
    
    # First, attempt to create and secure the primary directory
    try:
        # Create the directory if it doesn't exist
        if not os.path.exists(path):
            os.makedirs(path, mode=0o700, exist_ok=True)
        
        # On POSIX systems, verify and set proper permissions
        if platform.system() != "Windows":
            try:
                current_mode = os.stat(path).st_mode & 0o777
                if current_mode != 0o700:
                    os.chmod(path, 0o700)
            except PermissionError:
                # Can't set permissions, but directory might still be usable
                logger.warning(f"Cannot set secure permissions on {path}")
        
        # Test if the directory is writable by creating and removing a test file
        test_file = os.path.join(path, '.test')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            logger.info(f"Successfully created secure directory: {path}")
            return path
        except (PermissionError, OSError) as e:
            # This is a user-facing warning, print it directly to console
            error_msg = f"Cannot write to {path}: {str(e)}"
            print_warning(error_msg)  # Print with color
            logger.warning(error_msg)  # Also log it
            # Fall through to fallback logic
    except Exception as e:
        logger.warning(f"Failed to create primary secure directory {path}: {str(e)}")
        # Fall through to fallback logic
    
    # If we get here, the primary path failed
    
    # If no fallback was provided, create one based on HOME directory
    if not fallback_path:
        home_dir = os.path.expanduser("~")
        
        # Create platform-specific fallback paths
        if platform.system() == "Windows":
            fallback_path = os.path.join(home_dir, ".truefa", ".secure")
        else:
            # On Unix-like systems, use ~/.local/share/truefa/secure
            fallback_path = os.path.join(home_dir, ".local", "share", "truefa", ".secure")
            
            # If running as root, use a safer location
            if os.getuid() == 0:  # Root user
                fallback_path = os.path.join("/var", "lib", "truefa", ".secure")
    
    # Try the fallback path
    try:
        # Create the fallback directory if it doesn't exist
        if not os.path.exists(fallback_path):
            os.makedirs(fallback_path, mode=0o700, exist_ok=True)
        
        # On POSIX systems, verify and set proper permissions
        if platform.system() != "Windows":
            try:
                current_mode = os.stat(fallback_path).st_mode & 0o777
                if current_mode != 0o700:
                    os.chmod(fallback_path, 0o700)
            except PermissionError:
                logger.warning(f"Cannot set secure permissions on fallback path {fallback_path}")
        
        # Test if the directory is writable
        test_file = os.path.join(fallback_path, '.test')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            
            # This is a user-facing warning, print it directly to console
            fallback_msg = f"Using fallback secure directory: {fallback_path}"
            print_warning(fallback_msg)  # Print with color
            logger.info(fallback_msg)  # Also log it
            
            return fallback_path
        except (PermissionError, OSError) as e:
            error_msg = f"Cannot write to fallback path {fallback_path}: {str(e)}"
            print_warning(error_msg)  # Print error message in yellow
            logger.error(error_msg)  # Also log it
            raise OSError(f"Cannot create a secure directory: {str(e)}")
    except Exception as e:
        error_msg = f"Failed to create fallback secure directory {fallback_path}: {str(e)}"
        print_warning(error_msg)  # Print error message in yellow
        logger.error(error_msg)  # Also log it
        raise OSError(f"Cannot create a secure directory: {str(e)}")

def secure_file_permissions(file_path):
    """
    Apply secure permissions to a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # On POSIX systems, set proper permissions (owner read/write only)
        if platform.system() != "Windows":
            try:
                os.chmod(file_path, 0o600)
            except PermissionError:
                if is_running_in_docker():
                    logger.warning(f"Could not set permissions on {file_path} - this is expected when mounting from Windows to Docker")
                    return True
                else:
                    raise
        return True
    except Exception as e:
        error_msg = f"Error setting secure permissions on {file_path}: {e}"
        print_warning(error_msg)  # Print with color
        logger.error(error_msg)  # Also log it
        return False

def secure_directory_permissions(dir_path):
    """
    Apply secure permissions to a directory.
    
    Args:
        dir_path: Path to the directory
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # On POSIX systems, set proper permissions (owner read/write/execute only)
        if platform.system() != "Windows":
            try:
                os.chmod(dir_path, 0o700)
            except PermissionError:
                if is_running_in_docker():
                    logger.warning(f"Could not set permissions on directory {dir_path} - this is expected when mounting from Windows to Docker")
                    return True
                else:
                    raise
        return True
    except Exception as e:
        print(f"Error setting secure permissions on directory {dir_path}: {e}")
        return False

def verify_directory_permissions(dir_path):
    """
    Verify that a directory has secure permissions.
    
    Args:
        dir_path: Path to the directory
        
    Returns:
        bool: True if permissions are secure, False otherwise
    """
    # Skip verification if running in Docker with Windows mounts
    if is_running_in_docker() and platform.system() != "Windows":
        print(f"Skipping permission verification for {dir_path} in Docker environment")
        return True
        
    try:
        # Skip checks on Windows
        if platform.system() == "Windows":
            return True
            
        # Check that directory exists
        if not os.path.isdir(dir_path):
            print(f"Directory does not exist: {dir_path}")
            return False
            
        # Check directory permissions
        stat_info = os.stat(dir_path)
        mode = stat_info.st_mode & 0o777
        
        if mode != 0o700:
            print(f"Directory has insecure permissions: {dir_path} (mode: {mode:o}, expected: 700)")
            return False
            
        return True
    except Exception as e:
        print(f"Error verifying directory permissions: {e}")
        return False

def secure_atomic_write(file_path, content, mode="w"):
    """
    Write content to a file atomically and securely.
    Uses a temporary file and rename to ensure data integrity.
    
    Args:
        file_path: Target file path
        content: Content to write
        mode: File mode ('w' for text, 'wb' for binary)
        
    Returns:
        bool: True if successful, False otherwise
    """
    dir_path = os.path.dirname(file_path)
    
    try:
        # Ensure the directory exists
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, mode=0o700, exist_ok=True)
            except PermissionError:
                if is_running_in_docker() and platform.system() != "Windows":
                    logger.warning(f"Could not set permissions on directory {dir_path} when creating - this is expected when mounting from Windows to Docker")
                    os.makedirs(dir_path, exist_ok=True)
                else:
                    raise
        
        # Create a temporary file next to the target
        temp_file = file_path + ".tmp"
        
        # Write content to temporary file
        with open(temp_file, mode) as f:
            f.write(content)
        
        # Set secure permissions on the temp file
        secure_file_permissions(temp_file)
        
        # Atomically rename temp file to target
        shutil.move(temp_file, file_path)
        
        return True
    except Exception as e:
        print(f"Error during secure atomic write to {file_path}: {e}")
        # Clean up temp file if it exists
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass
        return False

def get_secure_vault_dir():
    """
    Get the path to the secure vault directory.
    
    This function determines the most appropriate location for storing
    vault files based on the platform and environment.
    
    Returns:
        str: Path to the secure vault directory
    """
    # First check environment variable override - this should take precedence over everything else
    env_data_dir = os.environ.get('TRUEFA_DATA_DIR')
    if env_data_dir:
        logger.info(f"Using vault directory from environment variable: {env_data_dir}")
        # Ensure directory exists
        os.makedirs(env_data_dir, exist_ok=True)
        return env_data_dir
    
    # Check if running in Docker
    running_in_docker = is_running_in_docker()
    
    # Get the user's home directory
    home_dir = os.path.expanduser("~")
    
    if running_in_docker:
        # Use a dedicated Docker vault location
        if "ContainerAdministrator" in home_dir or platform.system() == "Windows":
            # Windows container
            return "C:\\test_vault"
        else:
            # Linux container
            return os.path.join(home_dir, "truefa_vault") 
    
    # Standard locations based on platform
    if platform.system() == "Windows":
        # On Windows, use AppData/Roaming
        appdata = os.environ.get('APPDATA') or os.path.join(home_dir, "AppData", "Roaming")
        return os.path.join(appdata, "TrueFA-Py", "vault")
    elif platform.system() == "Darwin":
        # On macOS, use Library/Application Support
        return os.path.join(home_dir, "Library", "Application Support", "TrueFA-Py", "vault")
    else:
        # On Linux/Unix, use XDG_DATA_HOME or ~/.local/share
        xdg_data_home = os.environ.get('XDG_DATA_HOME') or os.path.join(home_dir, ".local", "share")
        return os.path.join(xdg_data_home, "TrueFA-Py", "vault") 