; TrueFA - NSIS Installer Script
!include "MUI2.nsh"

; General
Name "TrueFA"
OutFile "dist\TrueFA_Setup.exe"
Unicode True
InstallDir "$PROGRAMFILES\TrueFA"
InstallDirRegKey HKCU "Software\TrueFA" ""
RequestExecutionLevel admin

; Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "assets\truefa2.ico"
!define MUI_UNICON "assets\truefa2.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  
  ; Copy application files
  File "dist\TrueFA.exe"
  
  ; Create Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\TrueFA"
  CreateShortCut "$SMPROGRAMS\TrueFA\TrueFA.lnk" "$INSTDIR\TrueFA.exe"
  CreateShortCut "$SMPROGRAMS\TrueFA\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
  
  ; Create desktop shortcut
  CreateShortCut "$DESKTOP\TrueFA.lnk" "$INSTDIR\TrueFA.exe"
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  ; Write registry keys for uninstaller
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "DisplayName" "TrueFA"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "DisplayIcon" "$\"$INSTDIR\TrueFA.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "Publisher" "TrueFA Team"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA" "DisplayVersion" "1.0.0"
SectionEnd

Section "Uninstall"
  ; Remove application files
  Delete "$INSTDIR\TrueFA.exe"
  Delete "$INSTDIR\Uninstall.exe"
  
  ; Remove Start Menu shortcuts
  Delete "$SMPROGRAMS\TrueFA\TrueFA.lnk"
  Delete "$SMPROGRAMS\TrueFA\Uninstall.lnk"
  RMDir "$SMPROGRAMS\TrueFA"
  
  ; Remove desktop shortcut
  Delete "$DESKTOP\TrueFA.lnk"
  
  ; Remove installation directory if empty
  RMDir "$INSTDIR"
  
  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueFA"
  DeleteRegKey HKCU "Software\TrueFA"
SectionEnd 