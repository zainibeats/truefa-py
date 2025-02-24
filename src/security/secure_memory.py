import mmap
import platform
import ctypes
from datetime import datetime

class SecureMemory:
    """Secure memory handler with page locking and secure wiping"""
    
    def __init__(self, size=4096):
        self.size = size
        self.mm = None
        try:
            # Create a memory map with read/write access
            self.mm = mmap.mmap(-1, self.size, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE)
            if platform.system() != 'Windows':
                # Lock memory to prevent swapping (Unix-like systems only)
                try:
                    import resource
                    resource.mlock(self.mm)
                except Exception:
                    pass  # If mlock isn't available, continue without it
            else:
                try:
                    kernel32 = ctypes.windll.kernel32
                    # Create a ctypes char buffer from the mmap object
                    address = ctypes.addressof(ctypes.c_char.from_buffer(self.mm))
                    if not kernel32.VirtualLock(address, ctypes.c_size_t(self.size)):
                        print("Warning: Failed to lock memory on Windows")
                except Exception as e:
                    print("Warning: Windows memory locking failed:", e)
        except Exception:
            pass  # Handle initialization failures gracefully

    def __del__(self):
        try:
            self.secure_wipe()
        except Exception:
            pass  # Ignore cleanup errors in destructor

    def secure_wipe(self):
        """Securely wipe memory multiple times"""
        if self.mm is not None and hasattr(self.mm, 'write'):
            try:
                for _ in range(3):
                    self.mm.seek(0)
                    # Using ctypes.memset on the buffer for more secure wiping
                    buf = (ctypes.c_char * self.size).from_buffer(self.mm)
                    ctypes.memset(ctypes.addressof(buf), 0, self.size)
                self.mm.close()
            except Exception:
                pass  # Handle wiping errors gracefully
            finally:
                self.mm = None 