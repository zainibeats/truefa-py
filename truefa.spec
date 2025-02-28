# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[('truefa_crypto\\truefa_crypto.dll', 'truefa_crypto'), ('truefa_crypto\\truefa_crypto.dll', '.')],
    datas=[('truefa_crypto', 'truefa_crypto'), ('C:\\Users\\dontb\\Documents\\repos\\truefa-py\\images', 'images')],
    hiddenimports=['cryptography', 'pyotp', 'qrcode', 'PIL', 'PIL._tkinter_finder', 'PIL.ImageFilter', 'pillow', 'cv2', 'numpy', 'truefa_crypto'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='truefa',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
