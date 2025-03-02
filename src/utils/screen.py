"""
Terminal Display Utilities for TrueFA-Py

Provides platform-independent utilities for controlling the terminal
display. These functions help maintain a clean and secure user interface
by implementing proper screen clearing and cursor control.
"""

import os
import platform

def clear_screen():
    """
    Clear the terminal screen securely across platforms.
    
    Executes the appropriate screen clearing command based on the
    operating system:
    - Windows: Uses 'cls' command
    - Unix/Linux/macOS: Uses 'clear' command
    
    This ensures no sensitive data remains visible in the terminal
    after operations involving passwords or secrets.
    """
    if platform.system().lower() == "windows":
        os.system('cls')
    else:
        os.system('clear') 