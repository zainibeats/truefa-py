; TrueFA Installer Script
; NSIS (Nullsoft Scriptable Install System) configuration

!include "MUI2.nsh"
!include "FileFunc.nsh"

; General
Name "TrueFA"
OutFile "dist\TrueFA_Setup.exe"
InstallDir "$PROGRAMFILES\TrueFA"
InstallDirRegKey HKCU "Software\TrueFA" "Install_Dir"
RequestExecutionLevel admin

; Variables
Var StartMenuFolder

; Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "assets\truefa_icon.ico"
!define MUI_UNICON "assets\truefa_icon.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\installer_welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "assets\installer_header.bmp"
!define MUI_FINISHPAGE_RUN "$INSTDIR\TrueFA.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch TrueFA"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY

; Start Menu Folder Page Configuration
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKCU" 
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\TrueFA" 
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; Function to set secure permissions on a directory
Function SetSecurePermissions
    Pop $0 ; Directory to secure
    
    ; Set NTFS permissions using icacls to restrict access to the owner only
    nsExec::ExecToLog 'icacls "$0" /inheritance:r /grant:r "$USERNAME":(OI)(CI)F'
SectionEnd

; Installation Section
Section "Install"
    SetOutPath "$INSTDIR"
    
    ; Add files to install directory
    File "dist\TrueFA.exe"
    File "LICENSE"
    File "README.md"
    
    ; Create user data directories with appropriate structure
    ; 1. Regular data directory in %APPDATA%
    CreateDirectory "$APPDATA\TrueFA"
    CreateDirectory "$APPDATA\TrueFA\exports"
    CreateDirectory "$APPDATA\TrueFA\temp"
    CreateDirectory "$APPDATA\TrueFA\.vault"
    
    ; 2. Secure data directory in %LOCALAPPDATA% for sensitive cryptographic material
    CreateDirectory "$LOCALAPPDATA\TrueFA"
    CreateDirectory "$LOCALAPPDATA\TrueFA\Secure"
    CreateDirectory "$LOCALAPPDATA\TrueFA\Secure\crypto"
    
    ; Set secure permissions on the crypto directory
    Push "$LOCALAPPDATA\TrueFA\Secure"
    Call SetSecurePermissions
    
    ; Store installation folder in registry
    WriteRegStr HKCU "Software\TrueFA" "Install_Dir" $INSTDIR
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
    
    ; Add uninstaller to Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "DisplayName" "TrueFA - Two-Factor Authentication"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "DisplayIcon" "$\"$INSTDIR\TrueFA.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "Publisher" "TrueFA Project"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "DisplayVersion" "1.0.0"
    
    ; Get estimated size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "EstimatedSize" "$0"
    
    ; Create Start Menu shortcuts
    !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
        CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
        CreateShortcut "$SMPROGRAMS\$StartMenuFolder\TrueFA.lnk" "$INSTDIR\TrueFA.exe"
        CreateShortcut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninstall.exe"
    !insertmacro MUI_STARTMENU_WRITE_END
    
    ; Create desktop shortcut
    CreateShortcut "$DESKTOP\TrueFA.lnk" "$INSTDIR\TrueFA.exe"
SectionEnd

; Uninstaller Section
Section "Uninstall"
    ; Remove files and uninstaller
    Delete "$INSTDIR\TrueFA.exe"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\uninstall.exe"
    
    ; Remove the installation directory
    RMDir "$INSTDIR"
    
    ; Remove Start Menu items
    !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
    Delete "$SMPROGRAMS\$StartMenuFolder\TrueFA.lnk"
    Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
    RMDir "$SMPROGRAMS\$StartMenuFolder"
    
    ; Remove Desktop shortcut
    Delete "$DESKTOP\TrueFA.lnk"
    
    ; Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA"
    DeleteRegKey HKCU "Software\TrueFA"
    
    ; Note: We do NOT delete user data from %APPDATA% or %LOCALAPPDATA%
    ; Uncomment the following lines ONLY if you want to remove user data during uninstall
    ; RMDir /r "$APPDATA\TrueFA"
    ; RMDir /r "$LOCALAPPDATA\TrueFA"
SectionEnd

; Display a message about enhanced security model
Function .onInstSuccess
    MessageBox MB_OK "TrueFA has been installed successfully with enhanced security.$\r$\n$\r$\nYour authentication data is split between two locations:$\r$\n- General application data in your AppData folder$\r$\n- Critical encryption keys in a protected secure folder$\r$\n$\r$\nThis provides better protection against malware and unauthorized access."
FunctionEnd 