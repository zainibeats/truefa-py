#!/usr/bin/env python
"""
TrueFA Comprehensive Build Script

This script builds TrueFA in multiple formats:
1. Portable executable (single file)
2. Setup installer (using NSIS)

It also ensures proper icon integration and DLL validation.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
import ctypes
import platform
import importlib.util
import time
import stat
import argparse

# Configuration
APP_NAME = "TrueFA-Py"
APP_VERSION = "0.1.0"
AUTHOR = "Cheyenne Z"
COPYRIGHT = "Copyright © 2025 Cheyenne Zaini"
DESCRIPTION = "Secure Two-Factor Authentication Tool"
WEBSITE = "https://github.com/zainibeats/truefa-py"

# Icon path - this should point to the icon file in assets directory
ICON_PATH = os.path.join("assets", "truefa2.ico")

def setup_parser():
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(description="Build TrueFA application")
    parser.add_argument("--portable", action="store_true", 
                        help="Build portable version only")
    parser.add_argument("--installer", action="store_true", 
                        help="Build installer version only")
    parser.add_argument("--console", action="store_true", 
                        help="Include console window (for debugging)")
    parser.add_argument("--fallback", action="store_true", 
                        help="Force use of Python fallback implementation")
    return parser

def check_requirements():
    """Check if all required tools are installed."""
    print("Checking build requirements...")
    
    requirements = []
    
    # 1. Check for PyInstaller
    try:
        # Try to import PyInstaller directly
        import PyInstaller
        print(f"✓ PyInstaller found (version {PyInstaller.__version__})")
    except ImportError:
        # Fall back to spec check
        try:
            spec = importlib.util.find_spec("PyInstaller")
            if spec is None:
                requirements.append("PyInstaller (pip install pyinstaller)")
            else:
                print("✓ PyInstaller found")
        except Exception:
            requirements.append("PyInstaller (pip install pyinstaller)")
    
    # 2. Check for NSIS (for installer creation)
    nsis_found = False
    nsis_paths = [
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe"
    ]
    for path in nsis_paths:
        if os.path.exists(path):
            nsis_found = True
            print(f"✓ NSIS found at {path}")
            break
    
    if not nsis_found:
        requirements.append("NSIS (https://nsis.sourceforge.io/Download)")
    
    # Report any missing requirements
    if requirements:
        print("\nMissing requirements:")
        for req in requirements:
            print(f"  - {req}")
        print("\nPlease install the missing requirements and try again.")
        return False
    
    return True

def check_icon():
    """Check if the icon file exists and is valid."""
    if not os.path.exists(ICON_PATH):
        print(f"Warning: Icon file not found at {ICON_PATH}")
        return False
    
    print(f"✓ Using icon: {ICON_PATH}")
    return True

def check_dll():
    """Check if the Rust DLL exists and has the required functions."""
    print("Checking Rust cryptography DLL...")
    
    possible_dll_locations = [
        # Current directory
        os.path.join(os.getcwd(), "truefa_crypto.dll"),
        # Direct path
        os.path.join("truefa_crypto", "truefa_crypto.dll"), 
        # Source directory
        os.path.join("src", "truefa_crypto", "truefa_crypto.dll"),
        # Build directory
        os.path.join("rust_crypto", "target", "release", "truefa_crypto.dll"),
    ]
    
    for dll_path in possible_dll_locations:
        if os.path.exists(dll_path):
            print(f"Found DLL at {dll_path}")
            try:
                # Load the DLL
                lib = ctypes.CDLL(dll_path)
                
                # Define the list of required functions
                required_functions = [
                    'c_secure_random_bytes',
                    'c_is_vault_unlocked',
                    'c_vault_exists',
                    'c_create_vault',
                    'c_unlock_vault',
                    'c_lock_vault',
                    'c_generate_salt',
                    'c_derive_master_key',
                    'c_encrypt_master_key',
                    'c_decrypt_master_key',
                    'c_verify_signature',
                    'c_create_secure_string'
                ]
                
                # Check all required functions
                missing_functions = []
                for func_name in required_functions:
                    if not hasattr(lib, func_name):
                        missing_functions.append(func_name)
                
                if missing_functions:
                    print(f"Warning: Missing functions in the DLL: {', '.join(missing_functions)}")
                    return False, dll_path
                else:
                    print("✓ All required functions found in the DLL")
                    
                    # Ensure DLL is in both root truefa_crypto and src/truefa_crypto
                    src_dll_path = os.path.join("src", "truefa_crypto", "truefa_crypto.dll")
                    root_dll_path = os.path.join("truefa_crypto", "truefa_crypto.dll")
                    
                    # Create directories if they don't exist
                    os.makedirs(os.path.dirname(src_dll_path), exist_ok=True)
                    os.makedirs(os.path.dirname(root_dll_path), exist_ok=True)
                    
                    if os.path.abspath(dll_path) != os.path.abspath(src_dll_path):
                        print(f"Copying DLL to {src_dll_path}")
                        shutil.copy2(dll_path, src_dll_path)
                    
                    if os.path.abspath(dll_path) != os.path.abspath(root_dll_path):
                        print(f"Copying DLL to {root_dll_path}")
                        shutil.copy2(dll_path, root_dll_path)
                    
                    return True, dll_path
                    
            except Exception as e:
                print(f"Error loading DLL: {e}")
    
    print("No valid DLL found")
    return False, None

def create_spec_file(icon_path, use_console=True, one_file=True):
    """Create a PyInstaller spec file."""
    print("Creating PyInstaller spec file...")
    
    output_name = f"{APP_NAME}_console" if use_console else APP_NAME
    
    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[('truefa_crypto\\\\truefa_crypto.dll', '.')],
    datas=[
        ('assets/*', 'assets'),
        ('images/*', 'images'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    {'a.binaries + a.zipfiles + a.datas' if one_file else '[]'},
    exclude_binaries=not {one_file},
    name='{output_name}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console={use_console},
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['{icon_path.replace("\\", "\\\\")}'],
    version='file_version_info.txt',
)

{'' if one_file else f"""
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='{APP_NAME}',
)
"""}
"""
    
    # Write the spec file
    spec_file = f"{output_name}.spec"
    with open(spec_file, 'w') as f:
        f.write(spec_content)
    
    print(f"✓ Created spec file: {spec_file}")
    return spec_file

def create_version_file():
    """Create a version file for the Windows executable."""
    print("Creating version information file...")
    
    version_content = f"""
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({APP_VERSION.replace('.', ', ')}, 0),
    prodvers=({APP_VERSION.replace('.', ', ')}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [StringStruct(u'CompanyName', u'{AUTHOR}'),
           StringStruct(u'FileDescription', u'{DESCRIPTION}'),
           StringStruct(u'FileVersion', u'{APP_VERSION}'),
           StringStruct(u'InternalName', u'{APP_NAME}'),
           StringStruct(u'LegalCopyright', u'{COPYRIGHT}'),
           StringStruct(u'OriginalFilename', u'{APP_NAME}.exe'),
           StringStruct(u'ProductName', u'{APP_NAME}'),
           StringStruct(u'ProductVersion', u'{APP_VERSION}')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""
    
    with open('file_version_info.txt', 'w') as f:
        f.write(version_content)
    
    print("✓ Created version information file")

def setup_environment(use_fallback):
    """Set up environment variables for the build."""
    if use_fallback:
        print("Configuring build to use Python fallback implementation")
        os.environ["TRUEFA_USE_FALLBACK"] = "true"
    else:
        print("Configuring build to use Rust crypto implementation")
        os.environ["TRUEFA_USE_FALLBACK"] = "false"
    
    # Create or update .env file
    with open(".env", "w") as f:
        f.write(f"TRUEFA_USE_FALLBACK={'true' if use_fallback else 'false'}\n")
    
    print(f"✓ Updated .env file to use {'Python fallback' if use_fallback else 'Rust implementation'}")

def build_executable(spec_file):
    """Build the executable using PyInstaller."""
    print(f"Building executable from {spec_file}...")
    
    try:
        # Run PyInstaller
        result = subprocess.run(
            [sys.executable, "-m", "PyInstaller", spec_file, "--clean"],
            check=True,
            capture_output=True,
            text=True
        )
        
        print("✓ PyInstaller build completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error building executable: {e}")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return False

def create_nsis_script(icon_path, has_console=False):
    """Create an NSIS script for the installer."""
    print("Creating NSIS installer script...")
    
    # Determine EXE name based on console mode
    exe_name = f"{APP_NAME}_console.exe" if has_console else f"{APP_NAME}.exe"
    
    nsis_script = f"""
; TrueFA Installer Script
Unicode True

!include "MUI2.nsh"
!include "FileFunc.nsh"

; Application information
!define PRODUCT_NAME "{APP_NAME}"
!define PRODUCT_VERSION "{APP_VERSION}"
!define PRODUCT_PUBLISHER "{AUTHOR}"
!define PRODUCT_WEB_SITE "{WEBSITE}"
!define PRODUCT_DIR_REGKEY "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{exe_name}"
!define PRODUCT_UNINST_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{PRODUCT_NAME}}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "{icon_path.replace('/', '\\')}"
!define MUI_UNICON "{icon_path.replace('/', '\\')}"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; Installer Information
Name "${{PRODUCT_NAME}} ${{PRODUCT_VERSION}}"
OutFile "dist\\${{PRODUCT_NAME}}_Setup_${{PRODUCT_VERSION}}.exe"
InstallDir "$PROGRAMFILES\\${{PRODUCT_NAME}}"
InstallDirRegKey HKLM "${{PRODUCT_DIR_REGKEY}}" ""
ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  
  ; Add files (if one-file mode)
  File "dist\\{exe_name}"
  
  ; Create shortcuts
  CreateDirectory "$SMPROGRAMS\\${{PRODUCT_NAME}}"
  CreateShortCut "$SMPROGRAMS\\${{PRODUCT_NAME}}\\${{PRODUCT_NAME}}.lnk" "$INSTDIR\\{exe_name}"
  CreateShortCut "$DESKTOP\\${{PRODUCT_NAME}}.lnk" "$INSTDIR\\{exe_name}"
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\\uninstall.exe"
  
  ; Register application
  WriteRegStr HKLM "${{PRODUCT_DIR_REGKEY}}" "" "$INSTDIR\\{exe_name}"
  WriteRegStr ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}" "DisplayName" "$(^Name)"
  WriteRegStr ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}" "UninstallString" "$INSTDIR\\uninstall.exe"
  WriteRegStr ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}" "DisplayIcon" "$INSTDIR\\{exe_name}"
  WriteRegStr ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}" "DisplayVersion" "${{PRODUCT_VERSION}}"
  WriteRegStr ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}" "URLInfoAbout" "${{PRODUCT_WEB_SITE}}"
  WriteRegStr ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}" "Publisher" "${{PRODUCT_PUBLISHER}}"
  
  ; Get installed size
  ${{GetSize}} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}" "EstimatedSize" "$0"
SectionEnd

Section "Uninstall"
  ; Remove shortcuts
  Delete "$SMPROGRAMS\\${{PRODUCT_NAME}}\\${{PRODUCT_NAME}}.lnk"
  Delete "$DESKTOP\\${{PRODUCT_NAME}}.lnk"
  RMDir "$SMPROGRAMS\\${{PRODUCT_NAME}}"
  
  ; Remove files
  Delete "$INSTDIR\\{exe_name}"
  Delete "$INSTDIR\\uninstall.exe"
  
  ; Remove directories
  RMDir "$INSTDIR"
  
  ; Remove registry entries
  DeleteRegKey ${{PRODUCT_UNINST_ROOT_KEY}} "${{PRODUCT_UNINST_KEY}}"
  DeleteRegKey HKLM "${{PRODUCT_DIR_REGKEY}}"
SectionEnd
"""
    
    with open('installer.nsi', 'w') as f:
        f.write(nsis_script)
    
    print("✓ Created NSIS installer script")
    return 'installer.nsi'

def build_installer(nsis_script):
    """Build the installer using NSIS."""
    print("Building installer with NSIS...")
    
    nsis_paths = [
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe"
    ]
    
    nsis_exe = None
    for path in nsis_paths:
        if os.path.exists(path):
            nsis_exe = path
            break
    
    if not nsis_exe:
        print("Error: NSIS not found")
        return False
    
    try:
        # Run NSIS
        result = subprocess.run(
            [nsis_exe, nsis_script],
            check=True,
            capture_output=True,
            text=True
        )
        
        print("✓ NSIS installer build completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error building installer: {e}")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return False

def main():
    """Main function for building the application."""
    parser = setup_parser()
    args = parser.parse_args()
    
    print("=" * 60)
    print(f"TrueFA Build Tool v{APP_VERSION}")
    print("=" * 60)
    
    # Check requirements
    if not check_requirements():
        return 1
    
    # Check icon
    icon_exists = check_icon()
    icon_path = ICON_PATH if icon_exists else ""
    
    # Check DLL if not using fallback
    if args.fallback:
        use_fallback = True
        print("Using Python fallback implementation as requested")
    else:
        dll_valid, dll_path = check_dll()
        use_fallback = not dll_valid
        
        if use_fallback:
            print("Warning: Using Python fallback implementation due to DLL issues")
            response = input("Continue with fallback implementation? (y/n): ").lower()
            if response != 'y':
                print("Build aborted")
                return 1
    
    # Setup environment
    setup_environment(use_fallback)
    
    # Create version information file
    create_version_file()
    
    # Determine what to build
    build_portable = args.portable or not args.installer
    build_installer = args.installer or not args.portable
    
    # Build portable EXE if requested
    if build_portable:
        print("\n" + "=" * 40)
        print("Building Portable Executable")
        print("=" * 40)
        
        # Create spec file for console/windowed mode
        use_console = args.console
        spec_file = create_spec_file(icon_path, use_console=use_console, one_file=True)
        
        # Build the executable
        if not build_executable(spec_file):
            print("Failed to build portable executable")
            return 1
        
        print(f"Portable {'console ' if use_console else ''}executable created successfully!")
    
    # Build installer if requested
    if build_installer:
        print("\n" + "=" * 40)
        print("Building Installer")
        print("=" * 40)
        
        # Create spec file for windowed mode (installer should use windowed version)
        use_console = args.console
        spec_file = create_spec_file(icon_path, use_console=use_console, one_file=True)
        
        # Build the executable for installer
        if not build_executable(spec_file):
            print("Failed to build executable for installer")
            return 1
        
        # Create NSIS script
        nsis_script = create_nsis_script(icon_path, has_console=use_console)
        
        # Build the installer
        if not build_installer(nsis_script):
            print("Failed to build installer")
            return 1
        
        print("Installer created successfully!")
    
    print("\n" + "=" * 60)
    print("Build completed successfully!")
    print("=" * 60)
    
    if build_portable:
        portable_exe = f"dist\\{APP_NAME}_console.exe" if args.console else f"dist\\{APP_NAME}.exe"
        print(f"Portable Executable: {portable_exe}")
    
    if build_installer:
        print(f"Installer: dist\\{APP_NAME}_Setup_{APP_VERSION}.exe")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 