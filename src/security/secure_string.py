from datetime import datetime
from .secure_memory import SecureString as BaseSecureString

class SecureString:
    """Secure string storage with automatic cleanup"""
    
    def __init__(self, string):
        self._secure_string = None
        self._creation_time = datetime.now()
        try:
            self._secure_string = BaseSecureString(string)
        except Exception:
            self._secure_string = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.clear()
            
    def __del__(self):
        try:
            self.clear()
        except Exception:
            pass  # Ignore cleanup errors in destructor
        
    def clear(self):
        if self._secure_string is not None:
            try:
                self._secure_string.clear()
            except Exception:
                pass  # Handle wiping errors gracefully
            finally:
                self._secure_string = None
                self._creation_time = None
            
    def get(self):
        if self._secure_string is None:
            return None
        try:
            return str(self._secure_string)
        except Exception:
            return None

    def age(self):
        """Get age of secret in seconds"""
        if self._creation_time is None:
            return float('inf')
        return (datetime.now() - self._creation_time).total_seconds() 