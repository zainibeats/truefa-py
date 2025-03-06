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
    
    try:
        # Create the directory if it doesn't exist
        if not os.path.exists(path):
            os.makedirs(path, mode=0o700, exist_ok=True)
        
        # On POSIX systems, verify and set proper permissions
        if platform.system() != "Windows":
            current_mode = os.stat(path).st_mode & 0o777
            if current_mode != 0o700:
                os.chmod(path, 0o700)
        
        # Test if we can write to the directory
        test_file = os.path.join(path, ".test_write")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        
        return path
    
    except (OSError, PermissionError) as e:
        print(f"Error creating secure directory at {path}: {e}")
        
        # Try fallback location if provided
        if fallback_path:
            try:
                print(f"Trying fallback location: {fallback_path}")
                fallback_path = os.path.abspath(os.path.expanduser(fallback_path))
                
                if not os.path.exists(fallback_path):
                    os.makedirs(fallback_path, mode=0o700, exist_ok=True)
                
                # On POSIX systems, verify and set proper permissions
                if platform.system() != "Windows":
                    current_mode = os.stat(fallback_path).st_mode & 0o777
                    if current_mode != 0o700:
                        os.chmod(fallback_path, 0o700)
                
                # Test if we can write to the directory
                test_file = os.path.join(fallback_path, ".test_write")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                
                return fallback_path
            
            except (OSError, PermissionError) as fallback_error:
                print(f"Error creating fallback directory: {fallback_error}")
                raise OSError(f"Cannot create a secure directory at either {path} or {fallback_path}")
        else:
            raise OSError(f"Cannot create secure directory at {path} and no fallback provided")

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
            os.chmod(file_path, 0o600)
        return True
    except Exception as e:
        print(f"Error setting secure permissions on {file_path}: {e}")
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
            os.chmod(dir_path, 0o700)
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
    # On Windows, can't easily verify permissions in the same way
    if platform.system() == "Windows":
        return True
    
    try:
        # Check directory permissions (should be 0o700)
        mode = os.stat(dir_path).st_mode & 0o777
        return mode == 0o700
    except Exception as e:
        print(f"Error verifying directory permissions for {dir_path}: {e}")
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
            os.makedirs(dir_path, mode=0o700, exist_ok=True)
        
        # Create a temporary file in the same directory
        fd, temp_path = tempfile.mkstemp(dir=dir_path)
        os.close(fd)
        
        # Write content to the temporary file
        with open(temp_path, mode) as f:
            f.write(content)
        
        # Set secure permissions
        secure_file_permissions(temp_path)
        
        # Rename to target (atomic on most systems)
        if os.path.exists(file_path):
            os.remove(file_path)
        os.rename(temp_path, file_path)
        
        return True
    except Exception as e:
        print(f"Error writing securely to {file_path}: {e}")
        # Clean up temp file if it exists
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return False 