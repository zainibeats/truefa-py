#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TrueFA-Py GUI Launcher

This script launches the TrueFA-Py GUI application with proper path setup
and command-line argument handling.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Ensure src directory is in the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(script_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def debug(msg): logging.debug(msg)
def info(msg): logging.info(msg)
def warning(msg): logging.warning(msg)
def error(msg): logging.error(msg)

# Initialize environment without importing config
def initialize_env(vault_dir=None):
    """Initialize environment variables for the application"""
    # Set environment variable to disable fallback crypto implementation
    os.environ["TRUEFA_USE_FALLBACK"] = "0"
    
    # Set vault directory if specified
    if vault_dir:
        os.environ["TRUEFA_DATA_DIR"] = vault_dir
    
    # Get data directory
    if os.environ.get('TRUEFA_DATA_DIR'):
        data_dir = os.environ.get('TRUEFA_DATA_DIR')
    elif os.environ.get('TRUEFA_PORTABLE', '').lower() in ('1', 'true', 'yes'):
        data_dir = os.path.join(os.getcwd(), '.truefa')
    else:
        # Use platform-specific app data directory
        if sys.platform == 'win32':
            base_dir = os.environ.get('APPDATA')
            if not base_dir:
                base_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
            data_dir = os.path.join(base_dir, "TrueFA-Py")
        elif sys.platform == 'darwin':
            data_dir = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', "TrueFA-Py")
        else:
            data_dir = os.path.join(os.path.expanduser('~'), '.truefa')
    
    # Create necessary directories
    os.makedirs(data_dir, exist_ok=True)
    secure_dir = os.path.join(data_dir, "Secure")
    os.makedirs(secure_dir, exist_ok=True)
    
    return data_dir, secure_dir


def parse_args():
    """Parse command-line arguments for the GUI application."""
    parser = argparse.ArgumentParser(description="TrueFA-Py GUI - Secure TOTP Authenticator")
    
    # Debug and logging options
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-log", action="store_true", help="Disable file logging")
    
    # Vault options
    parser.add_argument("--vault-dir", type=str, help="Custom vault directory location")
    parser.add_argument("--create-vault", action="store_true", help="Create a new vault")
    
    # GUI-specific options
    parser.add_argument("--style", choices=["light", "dark"], help="UI style (light or dark)")
    
    return parser.parse_args()


def main():
    """Main entry point for the TrueFA-Py GUI application."""
    # Parse command-line arguments
    args = parse_args()
    
    # Configure logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize environment
    data_dir, secure_dir = initialize_env(args.vault_dir)
    
    # Log startup information
    info("Starting TrueFA-Py GUI")
    debug(f"Python version: {sys.version}")
    debug(f"Python executable: {sys.executable}")
    debug(f"Script directory: {script_dir}")
    debug(f"Data directory: {data_dir}")
    debug(f"Secure directory: {secure_dir}")
    
    # Only import PyQt after everything else is set up
    try:
        from PyQt6.QtWidgets import QApplication
        from src.gui.main_window import MainWindow
    except ImportError as e:
        error(f"Error importing PyQt6: {str(e)}")
        print(f"Error: PyQt6 is required but not installed. Please install it with 'pip install PyQt6'.")
        return 1
    
    # Create and run the application
    try:
        app = QApplication(sys.argv)
        app.setApplicationName("TrueFA-Py")
        app.setOrganizationName("TrueFA")
        
        # Create main window
        window = MainWindow()
        
        # Set window style if specified
        if args.style:
            window.dark_mode = args.style == "dark"
            window.apply_style()
        
        # Show the window
        window.show()
        
        # Run the application
        return app.exec()
    
    except Exception as e:
        error(f"Error starting GUI application: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 