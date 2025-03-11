"""
Color Print Utilities

Provides functions for printing colorful text to the console.
This is used for user-facing messages and does not affect logging.
"""

import platform

# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_color(text, color=Colors.RESET, bold=False):
    """
    Print text in the specified color.
    
    Args:
        text: The text to print
        color: The color to use (from Colors class)
        bold: Whether to make the text bold
    """
    # Check if we're on Windows
    if platform.system() == "Windows":
        # Enable ANSI colors on Windows
        import os
        os.system("")  # This enables ANSI escape sequences in Windows terminal
    
    # Apply bold if requested
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.RESET}")
    else:
        print(f"{color}{text}{Colors.RESET}")

def print_info(text):
    """Print an informational message in cyan."""
    print_color(text, Colors.CYAN)

def print_success(text):
    """Print a success message in green."""
    print_color(text, Colors.GREEN)

def print_warning(text):
    """Print a warning message in yellow."""
    print_color(text, Colors.YELLOW)

def print_error(text):
    """Print an error message in red."""
    print_color(text, Colors.RED) 