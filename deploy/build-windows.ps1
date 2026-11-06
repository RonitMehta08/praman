<#
Build the PRAMAN Windows installer.

Run this on Windows from a normal PowerShell prompt.  The script deliberately
creates a separate build environment and calls the pinned PyInstaller spec; it
never includes local databases, private keys, Qwen weights, checkpoints, or
publisher source archives.
#>
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$BuildVenv = Join-Path $ProjectRoot ".venv-packaging"
$Python = Join-Path $BuildVenv "Scripts\python.exe"
$DistDir = Join-Path $ProjectRoot "dist"
$InstallerDir = Join-Path $DistDir "installer"
$PipCache = Join-Path $ProjectRoot ".pip-cache"

Push-Location $ProjectRoot
try {
    # py.exe selects a real CPython installation instead of inheriting the
    # active Conda interpreter. PRAMAN supports Python 3.10 and 3.11 only;
    # Python 3.14 can make pip silently choose a different dependency set.
    $PyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if (-not $PyLauncher) {
        throw "Python Launcher (py.exe) was not found. Install CPython 3.11 x64 and retry."
    }
    $SupportedPython = (& $PyLauncher.Source -3.11 -c "import sys; print(sys.executable)" 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $SupportedPython) {
        throw "CPython 3.11 was not found. Install Python 3.11 x64 from python.org and retry."
    }

    $ExistingVersion = $null
    if (Test-Path $Python) {
        $ExistingVersion = (& $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null)
    }
    if ($ExistingVersion -ne "3.11") {
        if (Test-Path $BuildVenv) {
            Remove-Item -Recurse -Force $BuildVenv
        }
        & $PyLauncher.Source -3.11 -m venv $BuildVenv
        if ($LASTEXITCODE -ne 0) { throw "Could not create the Python 3.11 packaging environment." }
    }

    $env:PIP_CACHE_DIR = $PipCache
    New-Item -ItemType Directory -Force -Path $PipCache | Out-Null

    & $Python -m pip install --upgrade pip --cache-dir $PipCache
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
    & $Python -m pip install -r requirements.lock.txt --cache-dir $PipCache
    if ($LASTEXITCODE -ne 0) { throw "Base dependency installation failed." }
    & $Python -m pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements-ai.txt --cache-dir $PipCache
    if ($LASTEXITCODE -ne 0) { throw "AI dependency installation failed." }
    & $Python -m pip install "pyinstaller>=6.10,<7" --cache-dir $PipCache
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller installation failed." }

    $RuntimeVersion = & $Python --version
    Write-Host "Packaging with $RuntimeVersion"

    & $Python deploy/check_windows_package.py
    if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
    & $Python -m PyInstaller --noconfirm --clean deploy/praman.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
    & $Python deploy/check_windows_package.py --dist (Join-Path $DistDir "PRAMAN")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller output validation failed." }

    $RegistryInstallRoots = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $RegistryCandidates = foreach ($RegistryRoot in $RegistryInstallRoots) {
        Get-ItemProperty $RegistryRoot -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -like "*Inno Setup*" -and $_.InstallLocation
            } |
            ForEach-Object { Join-Path $_.InstallLocation "ISCC.exe" }
    }
    $IsccCandidates = @(
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source,
        "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        $RegistryCandidates
    ) | Where-Object { $_ -and (Test-Path $_) }
    if (-not $IsccCandidates) {
        throw "Inno Setup 6 was not found. Install it, then rerun this script."
    }

    if (Test-Path $InstallerDir) { Remove-Item -Recurse -Force $InstallerDir }
    New-Item -ItemType Directory -Force -Path $InstallerDir | Out-Null
    & $IsccCandidates[0] "/DMyAppVersion=0.1.0" deploy/praman.iss
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup build failed." }
    $Installer = Join-Path $InstallerDir "PRAMAN-Setup-0.1.0.exe"
    if (-not (Test-Path $Installer)) {
        throw "Inno Setup completed but did not create $Installer"
    }
    $Hash = Get-FileHash -Algorithm SHA256 $Installer
    "$($Hash.Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($Installer))" |
        Set-Content -Encoding ascii (Join-Path $InstallerDir "PRAMAN-Setup-0.1.0.exe.sha256")
    Write-Host "Installer created: $Installer"
    Write-Host "Installer size: $((Get-Item $Installer).Length) bytes"
    Write-Host "SHA-256: $($Hash.Hash.ToLowerInvariant())"
} finally {
    Pop-Location
}
