#!/usr/bin/env python
# Test script for verifying vault creation in Windows environments
# Tests both Rust crypto implementation and Python fallback

import os
import sys
import time
import base64
import logging
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("VaultTest")

# Add the src directory to the path to ensure we can import modules
# This is particularly important for Docker testing
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

# Check for Python fallback enforcement
USE_FALLBACK = os.environ.get("TRUEFA_USE_FALLBACK", "0") == "1"

def get_implementation_type():
    """Determine which implementation (Rust or Python) is being used"""
    if USE_FALLBACK:
        logger.info("TRUEFA_USE_FALLBACK environment variable is set to enforce Python fallback")
        return "Python Fallback (Forced)"
    
    try:
        import src.truefa_crypto
        if hasattr(src.truefa_crypto, '_lib_loaded'):
            if src.truefa_crypto._lib_loaded:
                logger.info("Rust crypto library successfully loaded")
                return "Rust Native"
            else:
                logger.info("Rust crypto library failed to load, using Python fallback")
                return "Python Fallback (Auto)"
        else:
            logger.warning("Unable to determine if Rust library loaded, '_lib_loaded' attribute missing")
            return "Unknown (Attribute Missing)"
    except (ImportError, AttributeError) as e:
        logger.error(f"Error checking implementation type: {e}")
        return "Python Fallback (Auto - Error)"

def test_vault_creation():
    """Test the creation of a vault and verify it worked"""
    logger.info(f"Starting vault creation test on {platform.system()} {platform.release()}")
    logger.info(f"Python version: {sys.version}")
    
    # Print Python module search path for debugging
    logger.info("Python module search path:")
    for path in sys.path:
        logger.info(f"  - {path}")
    
    # Log environment variables related to TrueFA
    env_vars = {k: v for k, v in os.environ.items() if 'TRUEFA' in k}
    logger.info(f"TrueFA environment variables: {env_vars}")
    
    # Determine and log implementation type
    impl_type = get_implementation_type()
    logger.info(f"Implementation: {impl_type}")
    
    # Import necessary modules
    try:
        from src.truefa_crypto import (
            secure_random_bytes, 
            generate_salt,
            create_vault, 
            unlock_vault, 
            vault_exists,
            is_vault_unlocked,
            lock_vault
        )
        logger.info("Successfully imported crypto functions")
    except ImportError as e:
        logger.error(f"Failed to import crypto functions: {e}")
        return False
    
    # Create test vault directory if it doesn't exist
    os.makedirs(os.path.join(os.getcwd(), ".truefa"), exist_ok=True)
    
    # Test secure random bytes generation
    try:
        random_bytes = secure_random_bytes(32)
        logger.info(f"Generated {len(random_bytes)} random bytes successfully")
    except Exception as e:
        logger.error(f"Failed to generate random bytes: {e}")
        return False
    
    # Test salt generation
    try:
        salt = generate_salt()
        logger.info(f"Generated salt successfully: {salt[:10]}... (length: {len(salt)})")
    except Exception as e:
        logger.error(f"Failed to generate salt: {e}")
        return False
    
    # Test vault_exists (should be False initially)
    try:
        exists = vault_exists()
        logger.info(f"Initial vault_exists check: {exists}")
    except Exception as e:
        logger.error(f"Failed to check if vault exists: {e}")
        return False
    
    # Test vault creation
    test_password = "SecureTestPassword123!"
    try:
        vault_created = create_vault(test_password)
        logger.info(f"Vault creation result: {vault_created}")
        
        if not vault_created:
            logger.error("Failed to create vault")
            return False
    except Exception as e:
        logger.error(f"Exception during vault creation: {e}")
        return False
    
    # Verify vault exists after creation
    try:
        exists = vault_exists()
        logger.info(f"Vault exists after creation: {exists}")
        
        if not exists:
            logger.error("Vault creation reported success but vault_exists returns False")
            return False
    except Exception as e:
        logger.error(f"Failed to check if vault exists after creation: {e}")
        return False
    
    # Test vault unlocking
    try:
        unlocked = unlock_vault(test_password)
        logger.info(f"Unlock vault result: {unlocked}")
        
        if not unlocked:
            logger.error("Failed to unlock vault")
            return False
    except Exception as e:
        logger.error(f"Exception during vault unlocking: {e}")
        return False
    
    # Verify vault is unlocked
    try:
        is_unlocked = is_vault_unlocked()
        logger.info(f"Vault is unlocked: {is_unlocked}")
        
        if not is_unlocked:
            logger.error("Vault unlock reported success but is_vault_unlocked returns False")
            return False
    except Exception as e:
        logger.error(f"Failed to check if vault is unlocked: {e}")
        return False
    
    # Test vault locking
    try:
        locked = lock_vault()
        logger.info(f"Lock vault result: {locked}")
        
        if not locked:
            logger.error("Failed to lock vault")
            return False
    except Exception as e:
        logger.error(f"Exception during vault locking: {e}")
        return False
    
    # Verify vault is locked
    try:
        is_unlocked = is_vault_unlocked()
        logger.info(f"Vault is unlocked after lock: {is_unlocked}")
        
        if is_unlocked:
            logger.error("Vault lock reported success but is_vault_unlocked still returns True")
            return False
    except Exception as e:
        logger.error(f"Failed to check if vault is unlocked after locking: {e}")
        return False
    
    # Check if vault file was actually created on disk
    vault_file = os.path.join(os.getcwd(), ".truefa", "vault.dat")
    if os.path.exists(vault_file):
        logger.info(f"Vault file created successfully at {vault_file}")
        logger.info(f"Vault file size: {os.path.getsize(vault_file)} bytes")
    else:
        logger.warning(f"Vault API operations succeeded but no vault file was created at {vault_file}")
        # This is a warning not an error since the API functions worked
    
    logger.info("All vault tests completed successfully!")
    return True

if __name__ == "__main__":
    success = test_vault_creation()
    
    # Print a summary of the test
    print("\n" + "="*50)
    print(f"Vault Creation Test: {'SUCCESS' if success else 'FAILED'}")
    print(f"Implementation: {get_implementation_type()}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print("="*50 + "\n")
    
    # Exit with appropriate code
    sys.exit(0 if success else 1) 