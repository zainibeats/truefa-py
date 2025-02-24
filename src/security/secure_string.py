from datetime import datetime
from .secure_memory import SecureMemory

class SecureString:
    """Secure string storage with automatic cleanup"""
    
    def __init__(self, string):
        self._memory = None
        self._size = len(string)
        self._creation_time = datetime.now()
        try:
            self._memory = SecureMemory()
            if self._memory.mm is not None:
                # Store the string in secured memory
                self._memory.mm.seek(0)
                self._memory.mm.write(string.encode())
        except Exception:
            self._memory = None

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
        if self._memory is not None:
            try:
                self._memory.secure_wipe()
            except Exception:
                pass  # Handle wiping errors gracefully
            finally:
                self._memory = None
                self._size = 0
                self._creation_time = None
            
    def get(self):
        if self._memory is None or self._memory.mm is None:
            return None
        try:
            self._memory.mm.seek(0)
            return self._memory.mm.read(self._size).decode()
        except Exception:
            return None

    def age(self):
        """Get age of secret in seconds"""
        if self._creation_time is None:
            return float('inf')
        return (datetime.now() - self._creation_time).total_seconds() 