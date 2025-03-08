"""
Secure String Module

This module provides secure string handling with memory protection.
It automatically zeros out sensitive data when the objects are no longer needed.
"""

import secrets

class SecureString:
    """A string that is securely wiped from memory when no longer needed."""
    def __init__(self, data):
        """
        Initialize a new secure string.
        
        Args:
            data (str or bytes): The sensitive data to protect
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.data = bytearray(data)
        self.created_at = __import__('time').time()
    
    def __str__(self):
        """
        Return a string representation for display purposes.
        
        This will show a masked version like "****" rather than the actual value.
        """
        return "****" if self.data else ""
    
    def __repr__(self):
        """Return a secure representation that doesn't expose the data."""
        return f"<SecureString of length {len(self.data)}>"
    
    def get(self):
        """
        Retrieve the actual sensitive string value.
        
        This method provides controlled access to the underlying sensitive data.
        It should only be called when the value is immediately needed for
        cryptographic operations and should never be stored in regular variables.
        
        Returns:
            str: The actual sensitive string value
            
        Security Notes:
            - Use this method sparingly and only when absolutely necessary
            - Never store the returned value in regular variables
            - Clear any variables containing this value as soon as possible
        """
        # Decode the bytes
        return self.data.decode('utf-8', errors='replace')
    
    def get_raw_value(self):
        """
        Get the raw string value (alias for get).
        
        This method is maintained for compatibility with older code.
        
        Returns:
            str: The actual sensitive string value
        """
        return self.get()
    
    def clear(self):
        """Securely wipe the data."""
        for i in range(len(self.data)):
            self.data[i] = 0
    
    def __del__(self):
        """Automatically clear data when the object is garbage collected."""
        self.clear()

def create_secure_string(data):
    """
    Create a secure string that will be automatically zeroed when no longer needed.
    
    Args:
        data (str or bytes): The sensitive data to protect
        
    Returns:
        SecureString: A secure string object
    """
    return SecureString(data)

def secure_random_bytes(size):
    """
    Generate secure random bytes using Python's secrets module.
    
    Args:
        size (int): Number of random bytes to generate
        
    Returns:
        bytes: Secure random bytes
    """
    return secrets.token_bytes(size) 