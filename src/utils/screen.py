import os
import platform

def clear_screen():
    """Clear the terminal screen securely"""
    if platform.system().lower() == "windows":
        os.system('cls')
    else:
        os.system('clear') 