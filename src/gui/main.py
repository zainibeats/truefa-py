import sys
import os
import argparse
from PyQt6.QtWidgets import QApplication

from src.utils.logger import setup_logger, debug, info, warning, error, critical
from src.gui.main_window import MainWindow

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="TrueFA-Py - Secure TOTP Authenticator (GUI)")
    
    # Add command line options
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--no-log', action='store_true', help='Disable file logging')
    parser.add_argument('--version', action='store_true', help='Show version information')
    parser.add_argument('--vault-dir', type=str, help='Specify custom vault directory')
    
    return parser.parse_args()

def main():
    """Main entry point for the GUI application"""
    # Parse command line arguments
    args = parse_args()
    
    # Setup logger based on arguments
    if args.debug:
        os.environ['TRUEFA_DEBUG'] = 'true'
    setup_logger(log_to_file=not args.no_log)
    
    # Process special flags
    if args.version:
        print("TrueFA-Py GUI v0.1.0")
        print("Secure TOTP Authenticator")
        return
    
    # Set vault directory if specified
    if args.vault_dir:
        os.environ["TRUEFA_DATA_DIR"] = args.vault_dir
        info(f"Using custom vault directory: {args.vault_dir}")
    
    # Initialize Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("TrueFA-Py")
    app.setApplicationDisplayName("TrueFA-Py - Secure TOTP Authenticator")
    
    # Log application startup
    info("Starting TrueFA-Py GUI")
    debug(f"PyQt6 version: {app.applicationVersion()}")
    
    # Create and show main window
    main_window = MainWindow()
    main_window.show()
    
    # Start event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 