# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Get the current directory
current_dir = os.path.abspath(os.getcwd())

# Paths to Rust DLL and PYD files
dll_path = os.path.join(current_dir, 'rust_crypto', 'target', 'release', 'truefa_crypto.dll')

# Path to icon file
icon_path = os.path.join(current_dir, 'assets', 'truefa2.ico')

# Check if the DLL exists
if not os.path.exists(dll_path):
    raise Exception(f"DLL not found at {dll_path}")
else:
    print(f"DLL found at {dll_path}")

# Check if the icon exists
if not os.path.exists(icon_path):
    print(f"Warning: Icon not found at {icon_path}")
else:
    print(f"Icon found at {icon_path}")

# Include the truefa_crypto module and other dependencies
binaries = [
    (dll_path, '.'),
    (dll_path, 'truefa_crypto'),
    (os.path.join(os.environ['WINDIR'], 'System32', 'vcruntime140.dll'), '.'),
    (os.path.join(os.environ['WINDIR'], 'System32', 'msvcp140.dll'), '.'),
]

# Images directory for QR codes
image_dir = os.path.join(current_dir, 'images')
if not os.path.exists(image_dir):
    os.makedirs(image_dir)

# Create the Analysis object
a = Analysis(
    ['src/main_opencv.py'],
    pathex=[current_dir],
    binaries=binaries,
    datas=[
        (os.path.join(current_dir, 'truefa_crypto', '__init__.py'), 'truefa_crypto'),
        (os.path.join(current_dir, 'images'), 'images'),  # Include images directory
        (os.path.join(current_dir, 'assets'), 'assets'),  # Include assets directory
    ],
    hiddenimports=['truefa_crypto', 'cv2', 'PIL', 'pyotp'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pyzbar'],  # Explicitly exclude pyzbar since we're using OpenCV
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Create the PYZ archive
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Create the console executable
exe_console = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='TrueFA_Console',
    debug=False,  # Set to False for final release
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # Use console mode for CLI app
    icon=icon_path,  # Include icon
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Create the windowed executable (no console)
exe_window = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='TrueFA',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # No console window
    icon=icon_path,  # Include icon
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Create the COLLECT object to bundle everything for console version
coll_console = COLLECT(
    exe_console,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='TrueFA_Console',
)

# Create the COLLECT object to bundle everything for windowed version
coll_window = COLLECT(
    exe_window,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='TrueFA',
)
