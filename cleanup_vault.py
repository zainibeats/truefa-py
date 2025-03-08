#!/usr/bin/env python
"""
Clean up all vault-related files before testing.
"""
import os
import shutil
import sys

def cleanup_paths():
    # Define paths to clean
    paths = [
        os.path.join(os.environ.get('APPDATA', ''), 'TrueFA-Py'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'TrueFA-Py'),
        os.path.join(os.path.expanduser('~'), '.truefa'),
        os.path.join(os.path.expanduser('~'), '.truefa_secure'),
        os.path.join('C:\\', 'test_vault')
    ]
    
    # Try to remove each path
    for path in paths:
        if not path:
            continue
            
        try:
            if os.path.exists(path):
                print(f"Removing directory: {path}")
                shutil.rmtree(path)
                print(f"Successfully removed: {path}")
            else:
                print(f"Path does not exist: {path}")
        except Exception as e:
            print(f"Error removing {path}: {e}")
            
    print("Cleanup completed.")

if __name__ == "__main__":
    cleanup_paths() 