; Inno Setup definition for the per-user PRAMAN Windows appliance.
; The PyInstaller one-folder output is produced by build-windows.ps1.

#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif

[Setup]
AppId={{9B4A2CB7-AC5B-4E7A-9BF9-000000000001}
AppName=PRAMAN
AppVersion={#MyAppVersion}
AppPublisher=PRAMAN
AppPublisherURL=https://github.com/RonitMehta08/praman
DefaultDirName={localappdata}\Programs\PRAMAN
DefaultGroupName=PRAMAN
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist\installer
OutputBaseFilename=PRAMAN-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\PRAMAN.exe
DisableProgramGroupPage=yes
SetupLogging=yes

[Files]
Source: "..\dist\PRAMAN\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\PRAMAN"; Filename: "{app}\PRAMAN.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\PRAMAN"; Filename: "{app}\PRAMAN.exe"; WorkingDir: "{app}"
Name: "{autoprograms}\PRAMAN Optional Components"; Filename: "{app}\PRAMAN-components.exe"; WorkingDir: "{app}"

[Run]
Filename: "{app}\PRAMAN.exe"; Description: "Launch PRAMAN"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; User audit data and signing keys intentionally survive uninstall.
Type: filesandordirs; Name: "{app}"
