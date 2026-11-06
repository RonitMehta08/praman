# Windows installer

PRAMAN can be distributed as a normal Windows installer without requiring the
user to install Python, Node, Docker, or a database server.

## Build requirements

Build the installer on a Windows x64 machine with:

- CPython 3.11 x64 installed through the official Windows installer, including
  the Python Launcher (`py.exe`)
- Inno Setup 6
- Internet access for Python dependencies during the build

The build script deliberately selects CPython 3.11 with `py -3.11`; it does not
use an active Conda environment. Python 3.12+ is outside PRAMAN's supported
runtime range. Inno Setup can be installed from its official website; the build
script searches the normal per-user and system installation locations.

From the repository root, run in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/build-windows.ps1
```

Run this from the repository root, or use the equivalent full path from another
directory:

```powershell
powershell -ExecutionPolicy Bypass -File D:\TEST1\praman\deploy\build-windows.ps1
```

The output is:

```text
dist/installer/PRAMAN-Setup-0.1.0.exe
```

The build includes the deterministic audit engine, frontend, rules, shipped
framework catalogs, Tier 1, and the repository's Tier 2 classifier files. It
does not select `data/praman.db`, `data/private/`, Qwen GGUF weights, LoRA
checkpoints, complete STIG library archives, CIS source PDFs, or real corpora.

## Excluded artifact inventory

| Path or class | Treatment | Reason |
|---|---|---|
| `data/praman.db` and `data/praman.db-*` | Generated on first run | Contains users, audit history, and device data |
| `data/private/` | Generated on first run | Signing keys belong to the installation owner |
| `data/models/Qwen_*.gguf` | Optional verified download | About 2.4 GB; Tier 3 is not required for verdicts |
| `data/models/lora/` | Omitted | Training checkpoints are not runtime dependencies |
| `data/frameworks/attack/ent.json` | Optional verified download | About 51 MB; threat enrichment does not affect verdicts |
| `data/frameworks/stig/U_SRG-STIG_Library_*.zip` | Omitted | Full publisher bundles are large; supported extracted data is selected separately |
| `data/frameworks/cis/_source/` | Omitted | Source PDFs are not needed by the runtime |
| `data/index/` | Generated or omitted | Optional template index is build output, not core audit input |
| `data/schemas/` | Omitted | Export conformance fixtures are for development verification |
| `data/corpus/` and private corpora | Omitted | May contain non-redistributable or customer configurations |
| `reports/metrics/`, `tests/`, `docs/`, research, and build caches | Omitted | Development, benchmark, and documentation material |
| `llama-server.exe` and CUDA/LLM runtimes | Optional separate component | Only needed when the Qwen Tier 3 server is enabled |

The selected PyInstaller data roots are explicit in `deploy/praman.spec`; the
build does not recursively package the whole repository. `deploy/check_windows_package.py`
fails the build if a private key, database, GGUF, checkpoint, source archive, or
other forbidden artifact enters the selected package.

## Installed data boundaries

Read-only application resources are installed under the selected application
directory. Writable state is stored under:

```text
%LOCALAPPDATA%\PRAMAN\
```

The launcher creates the SQLite database and a new Ed25519 ledger key pair on
first run. The installer never contains an account, customer configuration, or
signing identity from the build machine.

## Optional components

The frozen executable exposes a verified component manager:

```powershell
PRAMAN.exe --components list
PRAMAN.exe --components status
PRAMAN.exe --components install attack --url <approved-url> --sha256 <64-hex-digest>
```

The installer also places a visible console shortcut named **PRAMAN Optional
Components**. It runs `PRAMAN-components.exe` and is preferable to launching the
windowed main executable from a terminal when download output needs to be seen.

`deploy/windows_components.json` is a release manifest template. Its URLs and
digests are deliberately blank until a release owner has reviewed the exact
publisher artifact and recorded its SHA-256. The downloader refuses an
unhashed or over-sized download, writes to a temporary file, verifies it, and
only then moves it into the user data directory. It never executes a downloaded
file.

The core application does not require any optional component. Qwen also needs a
compatible `llama-server.exe`; downloading model weights alone does not enable
Tier 3 inference.
