#!/usr/bin/env python
"""
TrueFA Data Cleanup Script

This script removes all TrueFA data directories to provide a clean slate
for testing or when uninstalling the application. Use with caution as it
will delete all saved secrets and configuration data.
"""

import os
import shutil
import time

print('Removing TrueFA data directories...')

# List all possible data directories
data_dirs = [
    os.path.expanduser('~/.truefa'),
    os.path.expanduser('~/.truefa_secure'),
    os.path.join(os.environ.get('APPDATA', ''), 'TrueFA-Py'),
    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'TrueFA-Py')
]

# Print directories to be checked
print(f'Checking directories:')
for d in data_dirs:
    print(f'  - {d}')

# Remove directories that exist
for d in data_dirs:
    if os.path.exists(d):
        print(f'Removing {d}...')
        try:
            # Handle permission error by trying to remove files first
            for root, dirs, files in os.walk(d, topdown=False):
                for name in files:
                    try:
                        file_path = os.path.join(root, name)
                        print(f'  Removing file: {file_path}')
                        # Try to make file writable before removing
                        os.chmod(file_path, 0o666)
                        os.remove(file_path)
                    except Exception as e:
                        print(f'  Error removing file {file_path}: {e}')
                
                # Then try to remove directories
                for name in dirs:
                    try:
                        dir_path = os.path.join(root, name)
                        print(f'  Removing directory: {dir_path}')
                        os.rmdir(dir_path)
                    except Exception as e:
                        print(f'  Error removing directory {dir_path}: {e}')
            
            # Finally try to remove the main directory
            os.rmdir(d)
            print(f'  Success!')
        except Exception as e:
            print(f'  Error: {e}')

print('Data directories removal attempted. Waiting 2 seconds to complete...')
time.sleep(2)  # Give OS time to complete operations
print('Done.') 