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
            except PermissionError as e:
                if docker_with_windows_mount:
                    print(f"Warning: Could not set permissions on {path} - this is expected when mounting from Windows to Docker")
                else:
                    raise
        
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
                    try:
                        current_mode = os.stat(fallback_path).st_mode & 0o777
                        if current_mode != 0o700:
                            os.chmod(fallback_path, 0o700)
                    except PermissionError as e:
                        if docker_with_windows_mount:
                            print(f"Warning: Could not set permissions on {fallback_path} - this is expected when mounting from Windows to Docker")
                        else:
                            raise
                
                # Test if we can write to the directory
                test_file = os.path.join(fallback_path, ".test_write")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                
                return fallback_path
            
            except (OSError, PermissionError) as fallback_error:
                print(f"Error creating fallback directory: {fallback_error}")
                
                # If running in Docker with a Windows mount, create a temporary directory as last resort
                if docker_with_windows_mount:
                    print("Running in Docker with Windows host mount, creating temporary directory inside container")
                    temp_dir = os.path.join(tempfile.gettempdir(), "truefa_temp_vault")
                    os.makedirs(temp_dir, mode=0o700, exist_ok=True)
                    return temp_dir
                
                raise OSError(f"Cannot create a secure directory at either {path} or {fallback_path}")
        else:
            # If running in Docker with a Windows mount, create a temporary directory as last resort
            if docker_with_windows_mount:
                print("Running in Docker with Windows host mount, creating temporary directory inside container")
                temp_dir = os.path.join(tempfile.gettempdir(), "truefa_temp_vault")
                os.makedirs(temp_dir, mode=0o700, exist_ok=True)
                return temp_dir
                
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
            try:
                os.chmod(file_path, 0o600)
            except PermissionError:
                if is_running_in_docker():
                    print(f"Warning: Could not set permissions on {file_path} - this is expected when mounting from Windows to Docker")
                    return True
                else:
                    raise
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
            try:
                os.chmod(dir_path, 0o700)
            except PermissionError:
                if is_running_in_docker():
                    print(f"Warning: Could not set permissions on directory {dir_path} - this is expected when mounting from Windows to Docker")
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
                    print(f"Warning: Could not set permissions on directory {dir_path} when creating - this is expected when mounting from Windows to Docker")
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