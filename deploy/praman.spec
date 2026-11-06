"""PyInstaller one-folder build for the offline Windows appliance.

Only runtime resources are selected here.  In particular, this spec does not
walk all of ``data/``: doing that would accidentally ship the local database,
private signing keys, Qwen's multi-gigabyte GGUF, training checkpoints, and
publisher source bundles.
"""

from pathlib import Path

from PyInstaller.building.build_main import Analysis, COLLECT, EXE, PYZ
from PyInstaller.utils.hooks import collect_data_files, collect_submodules


ROOT = Path(SPEC).resolve().parent.parent


def add_tree(source: str, destination: str, *, extensions: set[str] | None = None) -> list[tuple[str, str]]:
    """Return PyInstaller data tuples for a deliberately selected resource tree."""
    source_path = ROOT / source
    result: list[tuple[str, str]] = []
    if not source_path.is_dir():
        raise SystemExit(f"required packaging resource is missing: {source_path}")
    for path in sorted(source_path.rglob("*")):
        if not path.is_file():
            continue
        if extensions and path.suffix.lower() not in extensions:
            continue
        relative = path.relative_to(source_path)
        result.append((str(path), str(Path(destination) / relative.parent)))
    return result


datas: list[tuple[str, str]] = []
datas += add_tree("frontend", "frontend")
datas += add_tree("rules", "rules")
datas += add_tree("schemas", "schemas")
datas += add_tree("test_configs", "test_configs")
datas += add_tree("data/ingest", "data/ingest")
datas += add_tree("data/labels", "data/labels")
datas += add_tree("data/models/classifier", "data/models/classifier")
datas += add_tree("data/frameworks/catalog", "data/frameworks/catalog")
datas += add_tree("data/frameworks/crosswalk", "data/frameworks/crosswalk")
datas += add_tree("data/frameworks/cis", "data/frameworks/cis", extensions={".json"})
datas += add_tree("data/frameworks/iso", "data/frameworks/iso", extensions={".json", ".xlsx"})
datas += add_tree("data/frameworks/oscal", "data/frameworks/oscal", extensions={".json"})
datas.append((str(ROOT / "data/frameworks/attack/canonical_map.yaml"), "data/frameworks/attack"))
datas += add_tree("data/frameworks/stig/_extracted", "data/frameworks/stig/_extracted", extensions={".xml"})
datas += add_tree(
    "data/frameworks/stig/U_CCI_List",
    "data/frameworks/stig/U_CCI_List",
    extensions={".xml", ".xsl", ".html", ".txt"},
)
datas.append((str(ROOT / "deploy" / "windows_components.json"), "deploy"))

# These package data files are needed by the network-config parsers and by the
# optional SetFit classifier.  No user database or model checkpoint is picked
# up by collect_data_files.
for package in ("ntc_templates", "ttp_templates"):
    datas += collect_data_files(package)

hiddenimports = ["tkinter"]
for package in ("backend", "uvicorn", "setfit", "sentence_transformers"):
    hiddenimports += collect_submodules(package)

a = Analysis(
    [str(ROOT / "deploy" / "windows_launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "pytest_cov", "ruff"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PRAMAN",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
component_a = Analysis(
    [str(ROOT / "deploy" / "windows_components_entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(ROOT / "deploy" / "windows_components.json"), "deploy")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
component_pyz = PYZ(component_a.pure)
component_exe = EXE(
    component_pyz,
    component_a.scripts,
    [],
    exclude_binaries=True,
    name="PRAMAN-components",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    a.zipfiles,
    component_exe,
    component_a.binaries,
    component_a.zipfiles,
    name="PRAMAN",
)
