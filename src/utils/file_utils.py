"""
File Utilities

Provides utility functions for file operations.
"""

import os
import shutil
import tempfile
from pathlib import Path
import logging
from .logger import debug, info, warning, error

# Configure logging
logger = logging.getLogger(__name__)

def safe_delete(path):
    """
    Safely delete a file or directory.
    
    Args:
        path: Path to the file or directory to delete
        
    Returns:
        bool: True if deleted successfully, False otherwise
    """
    try:
        if os.path.isfile(path):
            os.remove(path)
            return True
        elif os.path.isdir(path):
            shutil.rmtree(path)
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting {path}: {e}")
        return False

def delete_truefa_vault(confirm=False):
    """
    Completely delete the TrueFA vault and all its contents, including any fallback locations.
    
    This utility ensures that all vault data is removed from both the primary location
    and any fallback locations that might contain vault data, addressing issues with
    fallback mode where deleted vaults might reappear.
    
    Args:
        confirm (bool): Must be True to confirm deletion
        
    Returns:
        tuple: (success, message) where success is a boolean indicating success/failure
               and message is a descriptive message about what was deleted or why it failed
    """
    if not confirm:
        return False, "Vault deletion requires explicit confirmation"
    
    # Force disable fallback for clean deletion
    os.environ["TRUEFA_USE_FALLBACK"] = "0"
        
    try:
        deleted_locations = []
        failed_locations = []
        
        # First, try to delete primary vault location
        primary_vault_dir = os.path.join(os.environ.get('APPDATA') or 
                            os.path.join(os.path.expanduser("~"), "AppData", "Roaming"),
                            "TrueFA-Py", "vault")
        
        if os.path.exists(primary_vault_dir):
            try:
                # Delete all files in the primary vault directory
                for filename in os.listdir(primary_vault_dir):
                    file_path = os.path.join(primary_vault_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                
                # Try to remove the directory itself
                os.rmdir(primary_vault_dir)
                deleted_locations.append(primary_vault_dir)
                debug(f"Deleted primary vault at {primary_vault_dir}")
            except Exception as e:
                failed_locations.append(f"{primary_vault_dir} ({str(e)})")
                debug(f"Failed to delete primary vault: {str(e)}")
        
        # Also handle truefa-py related files in AppData
        try:
            truefa_dir = os.path.join(os.environ.get('APPDATA') or 
                        os.path.join(os.path.expanduser("~"), "AppData", "Roaming"),
                        "TrueFA-Py")
            
            if os.path.exists(truefa_dir) and os.path.isdir(truefa_dir):
                # We don't want to delete the entire TrueFA-Py directory, just its contents
                for item in os.listdir(truefa_dir):
                    item_path = os.path.join(truefa_dir, item)
                    if item != "vault":  # Skip vault dir as we already handled it
                        try:
                            if os.path.isfile(item_path):
                                os.remove(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path)
                        except Exception as e:
                            debug(f"Failed to clean TrueFA-Py app directory item {item}: {str(e)}")
        except Exception as e:
            debug(f"Failed to clean TrueFA-Py app directory: {str(e)}")
            
        # Next, try to delete fallback locations
        fallback_paths = [
            os.path.join(os.path.expanduser("~"), ".truefa", ".secure", "crypto"),
            os.path.join(os.path.expanduser("~"), ".truefa", ".secure"),
            os.path.join(os.path.expanduser("~"), ".local", "share", "truefa", ".secure"),
            os.path.join(tempfile.gettempdir(), "truefa_secure")
        ]
        
        for fallback_path in fallback_paths:
            if os.path.exists(fallback_path):
                try:
                    if os.path.isdir(fallback_path):
                        shutil.rmtree(fallback_path)
                        deleted_locations.append(fallback_path)
                        debug(f"Deleted fallback location at {fallback_path}")
                except Exception as e:
                    failed_locations.append(f"{fallback_path} ({str(e)})")
                    debug(f"Failed to delete fallback location {fallback_path}: {str(e)}")
        
        # Also clean up logs directory
        logs_dir = os.path.join(os.path.expanduser("~"), ".truefa", "logs")
        if os.path.exists(logs_dir):
            try:
                shutil.rmtree(logs_dir)
                deleted_locations.append(logs_dir)
                debug(f"Deleted logs directory at {logs_dir}")
            except Exception as e:
                debug(f"Failed to delete logs directory: {str(e)}")
                
        # Prepare result message
        if deleted_locations:
            message = f"Successfully deleted vault from: {', '.join(deleted_locations)}"
            if failed_locations:
                message += f"\nFailed to delete from: {', '.join(failed_locations)}"
            return True, message
        elif failed_locations:
            return False, f"Failed to delete vault from: {', '.join(failed_locations)}"
        else:
            return False, "No vault directories found to delete"
            
    except Exception as e:
        error_msg = f"Error deleting vault: {str(e)}"
        error(error_msg)
        return False, error_msg 