# Local Windows startup. The public HTTPS deployment uses start-online.sh on Render.
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Python = if (Test-Path $VenvPython) { $VenvPython } else { "python" }
$env:PYTHONUTF8 = "1"

Push-Location $ProjectRoot
try {
    & $Python scripts/bootstrap_user.py
    if ($LASTEXITCODE -ne 0) { throw "PRAMAN account bootstrap failed." }
    & $Python scripts/serve.py
    if ($LASTEXITCODE -ne 0) { throw "PRAMAN server exited with an error." }
} finally {
    Pop-Location
}
