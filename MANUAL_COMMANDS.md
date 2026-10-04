# MANUAL_COMMANDS.md — heavy commands, run by the human (Windows / PowerShell)

**Project:** PRAMAN — AI-Driven Multi-Vendor Network Security Compliance Auditor
**Local setup, optional AI models, and reproducible project artifacts**

---

## How to use this file

Every command in this file is run **by you, in your own terminal** — never by a build agent. A command lands here if it does any of:

- downloads more than **200 MB**
- **trains** a model or touches the **GPU** for more than 90 seconds
- requires a **login, registration, or licence acceptance** a script cannot perform
- takes longer than **90 seconds**

This split is enforced by `GLOBAL_RULESET.md` §2 (R2.1–R2.4). The build agents are forbidden from running these, and they must never silently substitute a smaller model or a fake artifact.

### Shell: PowerShell

**Every command below is PowerShell**, which is what Windows Terminal opens by default on Windows 11. Open it as a **normal user** (not Administrator) unless a step says otherwise — Step 9 is the only one that needs elevation.

```powershell
$PSVersionTable.PSVersion
```

PowerShell **7.x** is recommended. **5.1 works**, but four of the traps below apply only to 5.1 — read them before you start. If you have 7.x, `pwsh` is the executable; if 5.1, it's `powershell`.

> **cmd.exe users:** the venv activation line differs (`.\.venv\Scripts\activate.bat` instead of the `.ps1`) and none of the `Get-*`/`Select-String` verification commands work. Everything else — `python`, `pip`, `git`, `curl.exe`, `conda` — is identical. I recommend PowerShell; the verify steps depend on it.

### The `ArtifactMissingError` contract

Until a step below has been run, the code path that needs its artifact raises `ArtifactMissingError` with a message that *names the step*. This is deliberate: a missing model must produce a precise instruction, never a crash and never a silent fallback.

```python
raise ArtifactMissingError(
    "Embedding index not found at data/index/templates.sqlite3. "
    "Run Step 7 in MANUAL_COMMANDS.md, then re-run this command."
)
```

### Rules for this file

- Steps are **independently re-runnable**. Re-running a completed step is safe and idempotent.
- Steps **0–5 and 11** are enough for a fully green `pytest` and a working deterministic audit. The AI/LLM steps (6, 7, 8, 8c) are only needed for the *training GUI suggestions* and *prose drafting* — the compliance verdicts never depend on them.
- **Do the steps in order.** Where a step is optional it says so in its Purpose.
- Paths are relative to the repository root unless absolute.
- `TODO(verify):` marks a value I could not confirm from the research corpus. **Resolve it before relying on it** — do not let a guessed filename into a build. Research proved that guessed DISA filenames return `404`.

### Two kinds of command in this file — read this before you hit a `ModuleNotFoundError`

The commands here fall into two groups, and confusing them produces a confusing error:

**Group A — acquisition. Runnable right now, in any order.** Creating venvs, `pip install`, `curl.exe` downloads, `git clone`, `Copy-Item`, browser downloads. These touch nothing but the filesystem and the network. Steps 0, 1, 2, 2b, 3, 4a, 4b *(the download half)*, 4c, 4d, 5, 6, 9, 10, 14 *(the download half)*.

**Group B — project code. Only runnable after the build agents have written that module.** Any command of the form `python -m backend.…`, `python -m scripts.…`, or `pytest`. These live in this file because they are *heavy* (they train, index, or parse a large corpus), but they invoke code that does not exist in a fresh checkout.

If you run a Group B command too early you get exactly this:

```text
python.exe: Error while finding module specification for 'backend.frameworks.cis.extract'
(ModuleNotFoundError: No module named 'backend.frameworks.cis')
```

**That is not a bug and nothing is misconfigured.** It means the build has not reached that module yet. Check whether the file exists, and re-run when it does:

```powershell
Test-Path backend\frameworks\cis\extract.py
```

The Group B commands, and what must exist first:

| Command | Needs this file to exist |
|---|---|
| Step 4b verify — `python -m backend.frameworks.cis.extract` | `backend\frameworks\cis\extract.py` |
| Step 7 — `python -m scripts.build_template_index` | `scripts\build_template_index.py` |
| Step 8a — `python -m scripts.train_classifier` | `scripts\train_classifier.py` |
| Step 8b — `python -m scripts.finetune_qlora` | `scripts\finetune_qlora.py` |
| Step 8c — `python -m scripts.train_setfit` | `scripts\train_setfit.py` |
| Step 11 — `pytest`, `python -m backend.cli audit` | `tests\`, `backend\cli.py` |
| Step 14 verify — `python scripts\check_export_conformance.py` | `scripts\check_export_conformance.py`, `backend\export\` |

Do the Group A half of every step first. The corpora, venvs and models are what the build agents cannot produce for you; the Group B commands are just the moment you take delivery.

> **Distinguish this from `ArtifactMissingError`.** `ModuleNotFoundError` = the *code* is not written yet (wait for the build). `ArtifactMissingError` = the code is written and is correctly telling you a *step in this file* has not been run yet (run that step). If you ever see `ArtifactMissingError` for a step you have already completed, that is a genuine bug — report it.

---

## PowerShell traps that will bite this project specifically

Read these once. Each one caused a real, silent failure mode in a project whose entire premise is UTF-8 correctness and honest provenance.

### Trap 1 — `curl` is not curl (PowerShell 5.1)

In PowerShell 5.1, `curl` is an **alias for `Invoke-WebRequest`**, so `curl -fLO <url>` fails with a bizarre parameter error rather than downloading. Windows 10 1803+ ships the real curl as `curl.exe`.

**Always write `curl.exe`, never bare `curl`.** Every download below does. Verify yours exists:

```powershell
curl.exe --version
```

### Trap 2 — `>` redirection writes UTF-16LE (PowerShell 5.1)

This is the worst one for this project. In 5.1, `pip freeze > requirements.lock.txt` produces a **UTF-16LE** file, not UTF-8. Python then reads it as mojibake, and a project whose §0 rule is "explicit UTF-8 everywhere" ships a UTF-16 lockfile.

**Never use bare `>` for a file you intend to be UTF-8.** Use:

```powershell
pip freeze | Out-File -FilePath requirements.lock.txt -Encoding utf8
```

In PowerShell **5.1**, `-Encoding utf8` writes a **BOM**. In **7.x** it writes no BOM (`utf8BOM` is opt-in). If a downstream reader chokes on the BOM, open with `encoding="utf-8-sig"` — the same fix Step 4c needs for `U_CCI_List.xml`.

### Trap 3 — `Activate.ps1` is blocked by execution policy

A fresh Windows install often has `Restricted` policy, and venv activation fails with *"running scripts is disabled on this system."* Check and fix once:

```powershell
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

`RemoteSigned` allows local scripts and is the normal developer setting — it does not require Administrator for `-Scope CurrentUser`. If your organisation's policy blocks this, use `.\.venv\Scripts\activate.bat` from cmd.exe instead.

### Trap 4 — `Invoke-WebRequest` is very slow on large files (PowerShell 5.1)

5.1 renders a progress bar per chunk, which can slow a large download by an order of magnitude. This matters for the 369 MB STIG library in Step 4c. Two mitigations — I use `curl.exe` throughout, which sidesteps it, but if you do use `Invoke-WebRequest`:

```powershell
$ProgressPreference = 'SilentlyContinue'
```

`Expand-Archive` in 5.1 is likewise slow on large ZIPs. It is correct, just slow — let it finish rather than interrupting a partial extract.

### A note on multi-line Python

Several verify steps run a short Python script. In PowerShell, use a **here-string** piped to `python -`:

```powershell
@'
print("hello")
'@ | python -
```

PowerShell requires `@'` to be the **last thing on its line** and `'@` to be at the **very start of its line** (column 0, no indentation). If you indent the closing `'@`, you get a parse error. Paste these blocks as-is.

### Time and disk at a glance

| Step | What | Est. time | Est. disk | Needed for green `pytest`? |
|---|---|---|---|---|
| 0 | Prerequisites & UTF-8 | 5 min | 0 | Yes |
| 1 | Backend venv + pins | 5–10 min | ~1.2 GB | Yes |
| 2 | Remediation venv (`hier-config`) | 2 min | ~150 MB | Yes |
| 2b | Dev-only venv (`ciscoconfparse2`) | 2 min | ~150 MB | No (optional) |
| 3 | Training env (conda, py3.12 + torch) | 20–40 min | ~8 GB | No |
| 4 | Framework corpora (CIS/STIG/CCI) | 30–60 min (manual) | ~1–2 GB | Partly |
| 5 | Real config corpora | 5 min | ~50 MB | Yes (fixtures) |
| 6 | llama.cpp + Qwen3-4B GGUF | 20–30 min | ~3.5 GB | No |
| 7 | Embedding / template index | 5–15 min | ~200 MB | No |
| 8 | Classifier training (+ optional QLoRA) | 10 min / 1–3 h | ~1–6 GB | No |
| 8c | SetFit Tier 2 fine-tune (CPU) | ~45 min | ~850 MB | No |
| 9 | MSYS2 Pango (WeasyPrint archival path) | 15 min | ~1.5 GB | No (optional) |
| 10 | STIG Viewer 3.x oracle | 10 min | ~400 MB | No |
| 11 | Smoke test — green with no models | 5 min | 0 | **Yes — the gate** |

Total if you run everything: roughly **17–22 GB**. You have ~66 GB free, so this fits with headroom. Skipping steps 3, 8-QLoRA and 9 brings it closer to **8 GB**.

---

## Step 0 — Prerequisites and UTF-8

**Purpose.** Confirm the toolchain and force UTF-8 for the whole project. Not optional: the research corpus recorded three real Windows encoding crashes on exactly this material — `UnicodeEncodeError: 'charmap' codec can't encode character '\u2193'`, `'charmap' codec can't decode byte 0x9d` from `cp1252.py`, and a UTF-8 BOM (`\ufeff`) crash while reading `U_CCI_List.xml`. The OSCAL catalog also contains real em dashes (control `sc-7.5` is titled `Deny by Default — Allow by Exception`), which mojibake under `cp1252`.

**Command**

```powershell
# Persist UTF-8 for all future shells (run once)
[Environment]::SetEnvironmentVariable("PYTHONUTF8", "1", "User")

# ...and set it for the current session
$env:PYTHONUTF8 = "1"

# Execution policy, so venv activation works later (Trap 3)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Toolchain check
$PSVersionTable.PSVersion
python --version
node --version
git --version
curl.exe --version
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv

# Disk headroom
Get-PSDrive C | Select-Object Used, Free, @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}}
```

**Est. time** 5 minutes.
**Est. disk** 0.

**Verify.** Every command prints a version, and:
- `python --version` reports **3.10.11** (the backend runtime).
- `nvidia-smi` reports an **RTX 4050 Laptop** with roughly **6141 MiB** total memory. If it reports 8192 MiB you are on a different machine and the `-ngl` values in Step 6 must be re-tuned.
- `FreeGB` is at least **25**.
- `$env:PYTHONUTF8` prints `1`. **Open a new terminal and check again** — that proves the persistent variable took, not just the session one.

```powershell
$env:PYTHONUTF8
[Environment]::GetEnvironmentVariable("PYTHONUTF8", "User")
```

Both must print `1`.

**Undo.**

```powershell
[Environment]::SetEnvironmentVariable("PYTHONUTF8", $null, "User")
```

Reopen the terminal. Nothing else was installed.

> **There is no Docker on this machine and the project must never require it.** If any instruction anywhere in the build tells you to run `docker`, that is a defect: report it. The backend is deliberately zero-infra (FastAPI + SQLite in-process).

---

## Step 1 — Backend virtual environment and pinned dependencies

**Purpose.** Create the main backend environment. Pins come from `.build/SPINE.md`, resolved **2026-08-24**; the installer resolves transitive dependencies itself.

**Critical:** `ciscoconfparse2` is **not** installed here. It is GPL-3.0-only (a copyleft risk for distribution) *and* it hard-pins `hier-config==2.3.1`, which is incompatible with the `hier-config 3.7.0` API this project requires. It gets its own throwaway venv in Step 2b, dev-only.

**Command**

```powershell
# --- CRITICAL: no conda env may be active when you create this venv ---
# If your prompt shows (base) or (unsloth_env), run `conda deactivate` until it does not.
# `python -m venv` inherits whichever python is FIRST on PATH, and an active conda env
# puts miniconda's python there. You would silently get a conda-based venv on the wrong
# Python version. Confirm the interpreter you are about to clone:
conda deactivate   # repeat until no (env) prefix remains; harmless if conda is not active
Get-Command python | Select-Object -ExpandProperty Source
python --version   # must be 3.10.11, NOT a miniconda path

Set-Location C:\Users\ronit\Desktop\TEST1\praman

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip wheel

# --- core web / data ---
pip install fastapi "uvicorn[standard]" pydantic==2.13.4 python-multipart jinja2 pyyaml

# --- config parsing (vendor adapters) ---
pip install netutils==1.18.0 ntc-templates==9.2.0 textfsm==2.1.0 `
            ttp==0.10.1 ttp-templates==0.5.11 netmiko==4.7.0

# --- rule DSL evaluation ---
pip install cel-python==0.5.0 jsonschema

# --- reporting pipeline: ReportLab -> pikepdf -> pyHanko ---
pip install reportlab==5.0.1 pikepdf pyhanko pyhanko-certvalidator

# --- crypto / tamper-evident ledger ---
pip install cryptography==50.0.0 pymerkle==6.1.0 cvss==3.6

# --- AI (CPU-only here; no CUDA torch in this venv) ---
pip install drain3==0.9.11 scikit-learn numpy

# --- framework corpora parsing ---
pip install openpyxl==3.1.5 ijson

# --- vector search over templates ---
pip install sqlite-vec

# --- test / dev ---
pip install pytest pytest-cov httpx pdfplumber==0.11.10 ruff

# UTF-8, not UTF-16 (Trap 2)
pip freeze | Out-File -FilePath requirements.lock.txt -Encoding utf8
```

> The backtick `` ` `` is PowerShell's line-continuation character (bash's `\`). Keep the trailing space before it off — a backtick must be the last character on the line.

**Est. time** 5–10 minutes.
**Est. disk** ~1.2 GB.

**Verify.**

```powershell
.\.venv\Scripts\Activate.ps1

# The venv must be built on the RIGHT interpreter. Check this FIRST.
python --version
Get-Content .venv\pyvenv.cfg
```

`python --version` must report **3.10.11**, and `pyvenv.cfg` must show a `home` pointing at your system Python — **not** `C:\Users\ronit\miniconda3`. If it shows miniconda, a conda env was active when you created the venv; see the *wrong interpreter* note below.

```powershell
@'
import importlib
mods = ["fastapi","pydantic","netutils","ntc_templates","textfsm","ttp","netmiko",
        "celpy","reportlab","pikepdf","pyhanko","cryptography","pymerkle","cvss",
        "drain3","sklearn","openpyxl","jsonschema"]
bad = []
for m in mods:
    try: importlib.import_module(m)
    except Exception as e: bad.append((m, type(e).__name__, str(e)[:60]))
print("FAILED:", bad if bad else "none")
'@ | python -
```

Expect `FAILED: none`. Then confirm the lockfile is genuinely UTF-8 and not UTF-16:

```powershell
Get-Content requirements.lock.txt -TotalCount 3
(Get-Item requirements.lock.txt).Length
```

If the first command prints characters separated by blank space or gibberish, you hit Trap 2 — regenerate with `Out-File -Encoding utf8`.

**Undo.**

```powershell
deactivate
Remove-Item -Recurse -Force .venv
```

> **If the venv was built on the wrong interpreter.** Every pin in this step was resolved against **Python 3.10.11**, and `requirements.lock.txt` is only reproducible on the version that produced it. A conda-based venv on a different Python (e.g. 3.14) is a real divergence even when every package installs cleanly, because a later `pip install` may resolve differently and the lockfile will not reproduce on another machine.
>
> You have two honest options — pick one and write it down in `docs/GAPS.md` either way:
> 1. **Rebuild on 3.10.11** (recommended for reproducibility): `deactivate`, `Remove-Item -Recurse -Force .venv`, `conda deactivate` until no prefix remains, then re-run this step from the top. ~10 minutes.
> 2. **Keep the newer Python** if all pins installed at their exact pinned versions: verify with the snippet below, then **update the version stated in Step 0 and here** so the document matches reality. Do not leave the file claiming 3.10.11 while the venv is something else — a doc that disagrees with the machine misleads the operator.
>
> ```powershell
> @'
> import importlib.metadata as m
> want = {"reportlab":"5.0.1","cryptography":"50.0.0","netutils":"1.18.0",
>         "ntc-templates":"9.2.0","textfsm":"2.1.0","pydantic":"2.13.4",
>         "pymerkle":"6.1.0","cvss":"3.6","drain3":"0.9.11","openpyxl":"3.1.5",
>         "cel-python":"0.5.0"}
> for p, v in want.items():
>     try:
>         got = m.version(p)
>         print(f"  {p:16} {got:10} {'OK' if got == v else '*** DRIFT, want ' + v}")
>     except Exception:
>         print(f"  {p:16} *** MISSING ***")
> '@ | python -
> ```
>
> **Never stack a conda env and a venv at once** (a prompt reading `(.venv) (unsloth_env)`). Which `python` and `pip` win is order-dependent, so installs can land in the wrong environment. Use the Step 1 venv for backend work and `conda activate unsloth_env` for Step 3/8b training work — never both.

> **Known Windows risk — `textfsm`.** A Windows `ImportError` in `textfsm` is a documented possibility (upstream `google/textfsm` PR #82). If the import check fails on `textfsm`, that PR is the reference; record it in `docs/GAPS.md` and re-check after the next release. `ntc-templates` parsing was executed successfully on this exact Windows 11 / Python 3.10.11 box during research, so a failure here is an environment regression, not an expected state.

---

## Step 2 — Remediation virtual environment (`hier-config` alone)

**Purpose.** `hier-config 3.7.0` (MIT) computes the remediation delta CLI. It lives alone because of the pin conflict described in Step 1. Every API the project needs — `Platform`, `get_hconfig`, `WorkflowRemediation`, `get_hconfig_view`, `TagRule` — exists **only in 3.x**; version 2.3.1 exports just `HConfig`, `HConfigBase`, `HConfigChild`, `Host` and friends.

You may already have this: research used an existing `hc3venv` under `research_probe\`. Reuse it if you prefer, but the canonical location is below.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman

python -m venv .venv-remediation
.\.venv-remediation\Scripts\Activate.ps1
python -m pip install --upgrade pip wheel
pip install hier-config==3.7.0 jinja2
pip freeze | Out-File -FilePath requirements-remediation.lock.txt -Encoding utf8
deactivate
```

**Est. time** 2 minutes.
**Est. disk** ~150 MB.

**Verify.**

```powershell
.\.venv-remediation\Scripts\Activate.ps1
@'
from hier_config import WorkflowRemediation, get_hconfig, Platform
running  = get_hconfig(Platform.CISCO_IOS, "line con 0\n exec-timeout 30 0\n")
intended = get_hconfig(Platform.CISCO_IOS, "line con 0\n exec-timeout 5 0\n")
wr = WorkflowRemediation(running, intended)
print([c.cisco_style_text() for c in wr.remediation_config.all_children_sorted()])
'@ | python -
deactivate
```

Expect a non-empty list containing the `line con 0` context and the `exec-timeout 5 0` change. If you see `ImportError: cannot import name 'WorkflowRemediation'`, you have 2.3.1 installed — the pin was ignored.

**Undo.**

```powershell
Remove-Item -Recurse -Force .venv-remediation
```

---

## Step 2b — Dev-only venv for `ciscoconfparse2` (OPTIONAL)

**Purpose.** Optional. `ciscoconfparse2 0.9.18` is useful for exploratory parsing during development only. It is **GPL-3.0-only** — nothing it touches may be linked into or distributed with the shipped deliverable, and it must never be imported from `backend\`. Skip this step entirely unless you are doing parser exploration.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
python -m venv .venv-dev-ccp2
.\.venv-dev-ccp2\Scripts\Activate.ps1
pip install ciscoconfparse2==0.9.18
deactivate
```

**Est. time** 2 minutes.
**Est. disk** ~150 MB.

**Verify.**

```powershell
.\.venv-dev-ccp2\Scripts\Activate.ps1
python -c "from importlib.metadata import version; print(version('ciscoconfparse2'))"
deactivate

# The isolation must hold — no GPL import anywhere in backend
$hits = Get-ChildItem -Path backend -Filter *.py -Recurse | Select-String -Pattern "ciscoconfparse" -ErrorAction SilentlyContinue
if ($hits) { $hits } else { "CLEAN - no GPL import in backend" }
```

Expect `0.9.18` then `CLEAN`.

**Undo.**

```powershell
Remove-Item -Recurse -Force .venv-dev-ccp2
```

---

## Step 3 — Training environment (conda, Python 3.12 + CUDA torch) — OPTIONAL

**Purpose.** Only needed for Step 8's optional QLoRA fine-tune. The backend runtime is Python **3.10.11**, which is **below the floor** the training stack requires, so training gets a separate conda environment at **3.12**. Skip if you are not fine-tuning — the TF-IDF classifier (Step 8a) and the SetFit fine-tune (Step 8c) both train fine on CPU in the Step 1 venv.

**Command**

```powershell
# One-time: teach conda to work inside PowerShell, then RESTART the terminal
conda init powershell

# After restarting:
conda create --name unsloth_env python==3.12 -y
conda activate unsloth_env

# CUDA build of torch — the index URL is the CUDA 13.0 wheel channel
pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu130

pip install transformers datasets accelerate peft trl bitsandbytes
pip install sentence-transformers==6.0.0 setfit==1.1.3
```

**Est. time** 20–40 minutes (torch + CUDA wheels are large).
**Est. disk** ~8 GB.

**Verify.**

```powershell
conda activate unsloth_env
python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'NO CUDA')"
```

Expect `True` and a device name containing `4050`. If `False`, the CPU wheel was installed — `pip uninstall torch -y` and re-run with the `--index-url` above.

> If `conda activate` errors with *"Run 'conda init' before 'conda activate'"*, you skipped `conda init powershell` or did not restart the terminal afterwards.

**Undo.**

```powershell
conda deactivate
conda env remove --name unsloth_env -y
```

> **Do not install FlashAttention.** It is not available for this Windows configuration. Do not install `uvloop` either — it is Unix-only, and `uvicorn[standard]` correctly skips it on Windows.

---

## Step 4 — Framework corpora

**Purpose.** Acquire the real compliance content. Every control ID in the product must trace to a file produced by this step (`GLOBAL_RULESET.md` R1.1, R1.6). This is the step that separates a real auditor from a demo with invented IDs.

### 4a — ALREADY ON DISK — do NOT re-download

These are already in `C:\Users\ronit\Desktop\TEST1\`. Verify and copy them into the repo; **do not** spend bandwidth or risk pulling a different version.

| File | Verified size (bytes) | What it is |
|---|---|---|
| `sp80053.json` | 10,442,037 | OSCAL catalog, "Electronic (OSCAL) Version of NIST SP 800-53 Rev 5.2.0 Controls and SP 800-53A Rev 5.2.0 Assessment Procedures", version 5.2.0, oscal-version 1.2.2, uuid `ea7c7688-79c5-463b-a91b-0650f2d98623` |
| `iso27001_2022_map.xlsx` | 155,745 | NIST OLIR reference 155 — 800-53 Rev 5 ↔ ISO/IEC 27001:2022 crosswalk |
| `ent.json` | 53,835,637 | MITRE ATT&CK Enterprise STIX bundle, `x_mitre_version` **19.2**, spec 3.3.0 |
| `olir155.html` | 37,616 | OLIR 155 landing page (metadata/provenance) |
| `_research\ndm.json`, `ndm.xml`, `ndm.html` | — | Cisco IOS-XE Router **NDM** STIG artifacts (the 42-rule V3R7 set) |
| `research_probe\backup.cfg`, `forti.conf`, `intended.cfg`, `junos.conf` | — | Real vendor config samples for fixtures |
| `_research\wash.conf` | 381,799 | Real production Junos config, 13,621 lines (see licence warning in Step 5) |

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1

foreach ($d in "oscal","iso","attack","stig","cis") {
    New-Item -ItemType Directory -Force -Path "praman\data\frameworks\$d" | Out-Null
}

Copy-Item sp80053.json           praman\data\frameworks\oscal\
Copy-Item iso27001_2022_map.xlsx praman\data\frameworks\iso\
Copy-Item ent.json               praman\data\frameworks\attack\
Copy-Item _research\ndm.json     praman\data\frameworks\stig\
Copy-Item _research\ndm.xml      praman\data\frameworks\stig\

# Confirm the bytes match what research verified
Get-ChildItem praman\data\frameworks\oscal\sp80053.json,
              praman\data\frameworks\iso\iso27001_2022_map.xlsx,
              praman\data\frameworks\attack\ent.json |
    Select-Object Name, Length
```

**Est. time** 1 minute. **Est. disk** ~65 MB (a local copy).

**Verify.** The three lengths are exactly `10442037`, `155745`, `53835637`. Then confirm the OSCAL catalog parses and has the expected shape:

```powershell
.\praman\.venv\Scripts\Activate.ps1
@'
import json
d = json.load(open("praman/data/frameworks/oscal/sp80053.json", encoding="utf-8"))
c = d["catalog"] if "catalog" in d else d
print("keys:", list(c.keys()))
print("families:", len(c["groups"]))
'@ | python -
```

Expect **20** families. (Research recorded the counts: AC 25, AT 6, AU 16, CA 9, CM 14, CP 13, IA 13, IR 10, MA 7, MP 8, PE 23, PL 11, PM 32, PS 9, PT 8, RA 10, SA 24, SC 51, SI 23, SR 12 — 1196 control objects total, of which **182 are withdrawn** and must be filtered at ingest.)

**Undo.**

```powershell
Remove-Item -Recurse -Force praman\data\frameworks
```

The originals in `TEST1\` are untouched.

### 4b — CIS Benchmarks (MANUAL, registration-gated)

**Purpose.** CIS Benchmark PDFs and the `.audit` content are behind **CIS WorkBench** registration. There is **no static URL** and no scriptable download; `GLOBAL_RULESET.md` §1 lists this as a known-hostile source. A scraper here would be both broken and a ToS violation.

**Command** — this one happens in a browser, by you:

```text
1. Create a free account at CIS WorkBench (registration required).
2. Download the benchmarks for the platforms in scope. The versions research
   identified as current are:
     - CIS Cisco IOS 15           v4.1.1
     - CIS Cisco IOS XE 17.x      v2.2.1
     - CIS Cisco NX-OS            v1.2.0
     - CIS Juniper OS             v2.1.0
     - CIS Palo Alto Firewall 11  v1.2.0
     - CIS Cisco ASA 9.x Firewall v1.1.0
     - CIS FortiGate 7.4.x        v1.0.1
   Per-level item counts are deliberately NOT quoted here. The figures this
   step used to carry came from a search endpoint that ignores its own
   audit_file filter, and 4 of 7 disagreed with the PDFs once the extractor
   measured them. Measured counts are under Verify Half 2 below; those are
   derived from the PDFs themselves and are the ones to trust.
3. Save the PDFs into:  praman\data\frameworks\cis\_source\
4. Do NOT commit them. .gitignore already excludes _source\.
   CIS content is not redistributable.
```

Create the folder first:

```powershell
New-Item -ItemType Directory -Force -Path C:\Users\ronit\Desktop\TEST1\praman\data\frameworks\cis\_source
Invoke-Item C:\Users\ronit\Desktop\TEST1\praman\data\frameworks\cis\_source
```

**Est. time** 30–45 minutes of manual clicking.
**Est. disk** ~200 MB.

**Verify.** Two halves — do the first now, the second when the build has written the extractor (see *Two kinds of command* above).

**Half 1 — acquisition (now).**

```powershell
(Get-ChildItem praman\data\frameworks\cis\_source\*.pdf).Count
Get-ChildItem praman\data\frameworks\cis\_source\*.pdf | Select-Object Name, Length
```

At least **2** PDFs (you need a minimum of two platforms to demonstrate the vendor-agnostic claim). Note that CIS reissues benchmarks and renames files — an `ARCHIVE` suffix or a version that differs from the list above is fine, but **record the exact filename and version you downloaded**, because `(benchmark, benchmark_version, section)` is the rule key and a version mismatch silently changes which control a section number refers to.

**Half 2 — extraction (after `backend\frameworks\cis\extract.py` exists).**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1

if (-not (Test-Path backend\frameworks\cis\extract.py)) {
    "NOT BUILT YET - skip this half and re-run later"
} else {
    python -m backend.frameworks.cis.extract --source data\frameworks\cis\_source --out data\frameworks\cis\
    Get-ChildItem data\frameworks\cis\*.json | Select-Object Name, Length
}
```

One JSON per benchmark PDF. Every emitted control must carry `source_document`, `source_version`, `retrieved_at`, `source_url` (R1.6) — spot-check one:

```powershell
@'
import json, glob
f = sorted(glob.glob("data/frameworks/cis/*.json"))[0]
d = json.load(open(f, encoding="utf-8"))
items = d if isinstance(d, list) else d.get("controls", d.get("items", []))
print(f, "->", len(items), "controls")
print("first keys:", sorted(items[0].keys()) if items else "EMPTY")
'@ | python -
```

An **empty** control list is a failure, not a pass — a PDF that yielded zero controls means the extractor did not understand that benchmark's layout, and R1.7 requires that be reported rather than shipped as "nothing to audit."

**Measured counts for the seven PDFs currently in `_source\`.** These come from running the extractor and were cross-checked against the number of `Profile Applicability:` occurrences in each PDF — every CIS recommendation has exactly one, so that count is ground truth for how many controls a benchmark contains. All seven match exactly. Treat this table as the regression baseline: if a re-run disagrees, the extractor changed behaviour, not the PDFs.

| Benchmark (version **on disk**) | Controls | L1 | L2 | Designation |
|---|---:|---:|---:|---|
| Cisco ASA 9.x v1.1.0 | 78 | 65 | 13 | Automated 73 / Manual 5 |
| Cisco IOS 15 v4.1.1 | 90 | 53 | 37 | Automated 87 / Manual 3 |
| Cisco IOS XE 17.x v2.2.1 | 84 | 75 | 9 | Automated 51 / Manual 33 |
| Cisco NX-OS v1.2.0 | 62 | 41 | 21 | Automated 24 / Manual 38 |
| FortiGate 7.4.x v1.0.1 | 64 | 39 | 25 | Automated 48 / Manual 16 |
| Juniper OS **v2.0.0** | 172 | 118 | 54 | Scored 147 / Not Scored 25 |
| Palo Alto Firewall 11 v1.2.0 | 79 | 69 | 10 | Automated 62 / Manual 17 |
| **Total** | **629** | | | |

Four things in that table are load-bearing and easy to get wrong:

1. **The Juniper PDF on disk is v2.0.0 (dated 02-28-2019), not the v2.1.0 named in the download list.** The file is `CIS_Juniper_OS_Benchmark_v2.0.0 ARCHIVE.pdf`. Because `(benchmark, benchmark_version, section)` is the rule key, every Juniper rule must record **2.0.0** — a rule pack that claims 2.1.0 while citing 2.0.0 section numbers is silently wrong. Either keep 2.0.0 and label it so, or download 2.1.0 and re-extract; do not mix.
2. **Juniper uses the `(Scored)` / `(Not Scored)` vocabulary, not `(Automated)` / `(Manual)`.** These are different axes — Automated/Manual describes whether *assessment* can be automated, Scored/Not Scored describes whether an item counts toward the *score*. They are not interchangeable and must never be mapped onto each other. The extractor records `designation_vocabulary` per control and leaves `automated` as `null` on Scored/Not Scored benchmarks rather than inventing an automation claim.
3. **7 Juniper controls have an empty `audit` field, and that is faithful to the PDF** — they are physical/procedural recommendations (1.3 physical security, 1.4–1.6 backups and RAM, 1.7 log monitoring, 1.8 secure disposal, 6.6.14 MFA with external AAA) whose `Audit:` heading is followed immediately by `Remediation:`. Control 6.6.14 says so in its own rationale: *"it is not possible to include an audit action or include this as a scored recommendation."* The rules engine must classify these as **not machine-checkable**, not as FAIL — an empty audit is not evidence of non-compliance.
4. **Palo Alto section 5.3 is reconstructed, not read.** pdfplumber drops the leading glyph of that heading, so it extracts as `.3 Ensure forwarding of decrypted content to WildFire is enabled` in both the heading and the table of contents — the `5` is absent from the PDF text layer entirely. The extractor rebuilds it from document order (it follows 5.2, precedes 5.4), validates the sequence, and prints a `NOTE:` naming what it did. That NOTE appearing in the output is expected, not an error.

**Undo.**

```powershell
Remove-Item -Recurse -Force praman\data\frameworks\cis\_source
```

> **Two traps recorded in research, both of which silently corrupt rule packs if ignored.**
> 1. **CIS section numbers are NOT stable identifiers across benchmarks or versions.** `1.1.4` is *"line con 0"* in IOS 15 v4.1.1 L1 but *"line vty"* in IOS XE 17.x v2.2.1 L1. `2.1.5` is *"no ip identd"* in one and *"service tcp-keepalives-in"* in another. **Always key on the tuple `(benchmark, benchmark_version, section)`** — never on the section number alone.
> 2. CIS cross-references use a pipe token syntax to preserve verbatim: `800-53|AC-2(1)`, `800-53|SC-7(11)`, `CSCv7|16.2`, `CAT|II`, `CCI|CCI-002403`, `Rule-ID|SV-237764r856665_rule`, `STIG-ID|CISC-RT-000393`, `Vuln-ID|V-237764`.

### 4c — DISA STIGs (pinned filenames — never guess one)

**Purpose.** STIG content gives you real `V-`/`SV-`/`STIG-ID`/`CCI` identifiers and, critically, **verbatim remediation CLI** in the Fix text.

**Every filename below was probed and returned HTTP 200 with the byte size shown.** Filenames use a `Y<year>M<month>` scheme — DISA moved *away* from `V<major>R<minor>` in filenames. Guessed names 404: research confirmed `U_SRG-STIG_Library_2025_07.zip`, `U_Cisco_IOS-XE_Router_V3R3_STIG.zip` and `U_STIGViewer-win32_x64-3-5-2.zip` all return 404. **Do not construct a filename by pattern.**

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman\data\frameworks\stig
$BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip"

# --- Per-technology STIGs (small, start here). Expected sizes in the comments. ---
$files = @(
    "U_Cisco_IOS-XE_Router_Y26M01_STIG.zip",   #  2,181,995
    "U_Cisco_IOS-XE_Router_Y26M04_STIG.zip",   #  2,208,477
    "U_Juniper_SRX_SG_Y25M01_STIG.zip",        #  1,502,611
    "U_Cisco_ASA_Y25M07_STIG.zip",             #  1,405,181
    "U_Arista_MLS_EOS_4-X_Y25M07_STIG.zip",    #  2,961,725
    "U_F5_BIG-IP_Y25M01_STIG.zip",             #  1,583,695
    "U_CCI_List.zip"                           #    417,323
)
foreach ($f in $files) { curl.exe -fLO "$BASE/$f" }

# --- OPTIONAL: the full SRG/STIG library. LARGE. Only if you want every SRG. ---
curl.exe -fLO "$BASE/U_SRG-STIG_Library_July_2026.zip"     # 368,971,055 (~369 MB)
curl.exe -fLO "$BASE/U_SRG-STIG_Library_April_2026.zip"    # 210,647,056
curl.exe -fLO "$BASE/U_SRG-STIG_Library_January_2026.zip"  # 281,671,920

# Extract each into its own folder
Get-ChildItem *.zip | ForEach-Object {
    Expand-Archive -Path $_.FullName -DestinationPath $_.BaseName -Force
}
```

**Est. time** 5 minutes for the per-technology set; 15–25 minutes if you add a full library ZIP.
**Est. disk** ~35 MB extracted for the per-technology set; ~1.5 GB if you add `July_2026`.

**Verify.** Sizes match the comments exactly:

```powershell
Get-ChildItem *.zip | Select-Object Name, Length
```

Then confirm the Cisco NDM rule count — the single best sanity check that you have real content:

```powershell
..\..\..\.venv\Scripts\Activate.ps1
@'
import glob, re
xml = glob.glob("U_Cisco_IOS-XE_Router_Y26M01_STIG/**/*Manual*xccdf.xml", recursive=True)
print("xccdf files:", xml)
if xml:
    t = open(xml[0], encoding="utf-8").read()
    print("Group ids:", len(set(re.findall(r'<Group id="(V-\d+)"', t))))
'@ | python -
```

For the **Cisco IOS XE Router NDM V3R7 (2026-02-11)** content, research verified **42 rules — 8 CAT I and 34 CAT II**. The 8 CAT I V-IDs are exactly: `V-215823`, `V-215832`, `V-215833`, `V-215844`, `V-215845`, `V-215854`, `V-220139`, `V-220140`. V-IDs are **non-contiguous** (the set skips V-215816, V-215825, V-215835, V-215839/40, V-215846/47, V-215851–853) — **never interpolate a V-ID.**

**Undo.**

```powershell
Remove-Item *.zip -Force
Remove-Item -Recurse -Force U_*
```

> **`U_CCI_List.xml` has a UTF-8 BOM.** Open it with `encoding="utf-8-sig"`, not `"utf-8"` — research recorded a real `UnicodeEncodeError: ... '\ufeff' in position 0` on this exact file. It contains 5,138 `cci_item` entries (3,836 with a Rev 5 reference), version/publishdate 2025-01-23, namespace `http://iase.disa.mil/cci`.
>
> **Severity mapping is fixed:** `high` = **CAT I**, `medium` = **CAT II**, `low` = **CAT III**.
>
> **PAN-OS has no remediation CLI in STIG fix text.** Palo Alto STIG Fix content is GUI-navigation prose only (e.g. *"Device >> Setup >> Management"*, *"Network >> Network Profiles >> Zone Protection"*). The "device-specific remediation CLI" promise **cannot** be met from STIG content for PAN-OS. The build must render ordered GUI steps plus a `manual_verification_required` flag for that vendor — see `MASTER_PROMPT.md` §16.

### 4d — OLIR 800-53 ↔ ISO 27001 crosswalk (optional refresh)

**Purpose.** You already have `iso27001_2022_map.xlsx` from 4a. Only re-fetch if you need to confirm provenance.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman\data\frameworks\iso
curl.exe -fLO "https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx"
```

**Est. time** 1 minute. **Est. disk** ~160 KB.

**Verify.** The workbook opens and yields 643 mapping rows across 121 distinct ISO elements:

```powershell
@'
import warnings, openpyxl
warnings.filterwarnings("ignore", message="Data Validation extension is not supported")
wb = openpyxl.load_workbook("sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx")
print("sheets:", len(wb.sheetnames))
'@ | python -
```

Expect 21 sheets. **Suppress the `UserWarning: Data Validation extension is not supported` explicitly** — openpyxl emits it on this exact workbook.

**Undo.** Delete the file; 4a's copy remains.

> **Present the crosswalk as advisory, never as equivalence.** NIST explicitly warns against reading OLIR mappings as equivalence. Always display the OLIR `Relationship` value — one of `subset of`, `intersects with`, `equal`, `superset of`, `not related to` — beside any ISO↔800-53 claim in the UI and the PDF. Note also a documented version skew: OLIR 155 declares its focal document as *SP 800-53 Rev 5.1.1* while the catalog you loaded in 4a is **5.2.0**.

---

## Step 5 — Real configuration corpora (test fixtures)

**Purpose.** Real multi-vendor configs to test parsers against. Synthetic configs here would invalidate the published parse-coverage claims.

**Command**

```powershell
New-Item -ItemType Directory -Force -Path C:\Users\ronit\Desktop\TEST1\praman\data\corpus
Set-Location C:\Users\ronit\Desktop\TEST1\praman\data\corpus

# --- Batfish test configs: broad multi-vendor coverage (no JVM, no Batfish run) ---
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/batfish/batfish.git _batfish
Set-Location _batfish
git sparse-checkout init --cone
git sparse-checkout set tests/parsing-tests
git checkout
Set-Location ..

# --- hier_config fixtures: golden running/intended/remediation triples ---
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/netdevops/hier_config.git _hierconfig
Set-Location _hierconfig
git sparse-checkout init --cone
git sparse-checkout set tests/fixtures
git checkout
Set-Location ..

# --- config2spec: 10 real production Juniper configs (see LICENCE WARNING) ---
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/nsg-ethz/config2spec.git _config2spec
Set-Location _config2spec
git sparse-checkout init --cone
git sparse-checkout set scenarios/internet2
git checkout
Set-Location ..
```

> Note the sparse-checkout paths keep **forward slashes** — those are git-internal paths, not Windows paths, and git wants `/` on every platform.

**Est. time** 5 minutes.
**Est. disk** ~50 MB.

**Verify.**

```powershell
(Get-ChildItem _batfish -Recurse -Include *.cfg,*.conf -ErrorAction SilentlyContinue).Count
Get-ChildItem _hierconfig\tests\fixtures | Select-Object -First 5 Name
(Get-ChildItem _config2spec\scenarios\internet2).Count
(Get-Content _config2spec\scenarios\internet2\wash.conf).Count
```

Expect a few thousand config blobs, the fixture listing, **10** Juniper configs, and **13,621** lines in `wash.conf`.

Research recorded the Batfish per-vendor blob distribution as juniper 338, cisco 169, palo_alto 161, cisco_nxos 148, arista 121, cisco_xr 82, a10 61, cisco_asa 60, fortios 56, f5_bigip_structured 43, sros 33, check_point_gateway 26 — about 2,511 blobs totalling ~3.5 MB.

**Undo.**

```powershell
Remove-Item -Recurse -Force _batfish, _hierconfig, _config2spec
```

> **LICENCE WARNINGS — read before you commit anything.**
> - **`config2spec` has no licence file** (`licence: None`) and its README states configuration lines were **removed**. Use it for **local testing only**. Never redistribute it, never commit it, never ship it in the repo or the demo video.
> - **Batfish test configs** are third-party fixtures — keep them under `data\corpus\_batfish\`, which `.gitignore` excludes, and reference them by path in tests.
> - **Never commit a real device config, credential, `.env`, or model weight** (`GLOBAL_RULESET.md` §8).
> - **Do not install or run Batfish itself.** It needs a JVM and is not a dependency — you are using its *fixtures*, not its engine.
> - `ntc-templates` is a **show-command** corpus, not a config corpus (only ~3 config-ish `.raw` files, ~1.6 KB total). Use it for device-identity parsing, not config fixtures.
> - On PyPI, the name `batfish` is an unrelated 2014 DigitalOcean CLI. The real client is `pybatfish` — which you do not need.

---

## Step 6 — llama.cpp (CUDA) and the Qwen3-4B model — OPTIONAL

**Purpose.** Local LLM for training-GUI suggestions, prose drafting, and natural-language search. **Nothing in the compliance verdict path depends on this** — the deterministic rules engine issues every `pass`/`fail`. Skipping this step must leave `pytest` green and the audit fully functional, with the AI ladder degrading to its deterministic and TF-IDF tiers.

Grammar-constrained decoding via `llama-server --json-schema` is what makes the model's output safe to consume: it can only emit a field path from an enum generated from the Canonical Model schema at build time. It cannot invent a field.

**Command**

```powershell
New-Item -ItemType Directory -Force -Path C:\Users\ronit\Desktop\TEST1\praman\vendor
Set-Location C:\Users\ronit\Desktop\TEST1\praman\vendor

# --- 6a: llama.cpp CUDA binaries, build b10610 ---
# Open the releases page and download the Windows CUDA binary for build b10610,
# PLUS the SEPARATE cudart archive (~391.4 MB) — the binary alone will not run.
Start-Process "https://github.com/ggml-org/llama.cpp/releases"
# TODO(verify): exact asset filenames for build b10610 (the Windows CUDA zip and the
#   cudart zip). Research confirmed the build number and that cudart ships separately
#   (391.4 MB), but not the literal asset names. Read them off the releases page —
#   do NOT construct them by pattern.

# Once downloaded into this folder (adjust the wildcards to the real names):
Get-ChildItem llama-b10610-*-win-cuda-*.zip | ForEach-Object {
    Expand-Archive -Path $_.FullName -DestinationPath llama-cpp -Force
}
Get-ChildItem cudart-*.zip | ForEach-Object {
    Expand-Archive -Path $_.FullName -DestinationPath llama-cpp -Force   # must land beside the .exe files
}

# --- 6b: the model, Qwen3-4B-Instruct-2507 in Q4_K_M ---
New-Item -ItemType Directory -Force -Path ..\data\models
# TODO(verify): exact HuggingFace repo id and GGUF filename for
#   Qwen3-4B-Instruct-2507 Q4_K_M. Confirm on the model page, then:
#   curl.exe -fL -o ..\data\models\<EXACT_FILENAME>.gguf "<EXACT_URL>"

# --- 6c: OPTIONAL Python binding, only if you need in-process inference ---
# PyPI does NOT ship a Windows CUDA wheel. Use the abetlen prebuilt wheel index.
# pip install llama-cpp-python==0.3.35 --extra-index-url <abetlen wheel index>
# TODO(verify): the abetlen wheel index URL for llama_cpp_python-0.3.35-py3-none-win_amd64.whl.
```

**Launch the server** (the command the backend expects; keep it in its own terminal):

```powershell
.\llama-server.exe `
  -m ..\..\data\models\Qwen_Qwen3-4B-Instruct-2507-Q4_K_M.gguf `
  -c 4096 `
  -ngl 99 `
  --cache-type-k q8_0 `
  --cache-type-v q8_0 `
  --host 127.0.0.1 `
  --port 8080

```

**Flag rationale — do not change these casually.**
- `-c 4096` — **pin the context explicitly.** KV cache grows with context; an unpinned or oversized context is the most likely cause of a VRAM OOM on a 6 GB card.
- `-ngl 99` — offload all layers. A 4B model at Q4_K_M fits comfortably in ~6141 MiB *with* the settings below. On an OOM, lower `-ngl` (try 28, then 20) before touching anything else.
- `--cache-type-k/v q8_0` — quantised KV cache, the main VRAM saving.
- `--json-schema` is passed **per request** by the backend, not on the server line.

**Est. time** 20–30 minutes (mostly the ~3 GB model download).
**Est. disk** ~3.5 GB (model ~2.5 GB + binaries and cudart ~1 GB).

**Verify.**

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/health

# Prove grammar-constrained decoding actually constrains the output
$body = @{
    prompt      = "Map this Cisco line to a canonical field path: transport input ssh"
    n_predict   = 64
    json_schema = @{
        type       = "object"
        required   = @("path")
        properties = @{
            path = @{
                type = "string"
                enum = @("mgmt.ssh.version", "line.vty.transport_input", "logging.remote_syslog")
            }
        }
    }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri http://127.0.0.1:8080/completion -Method Post `
    -ContentType "application/json" -Body $body | Select-Object -ExpandProperty content
```

The returned `path` **must** be one of the three enum values. If it returns anything else, grammar constraint is not active and the AI ladder must stay disabled — an unconstrained model can invent a field name, which violates the core boundary.

While it runs, watch VRAM in a second terminal:

```powershell
while ($true) { nvidia-smi --query-gpu=memory.used --format=csv,noheader; Start-Sleep 2 }
```

It must stay below ~5800 MiB.

**Undo.** Stop the server (Ctrl-C), then:

```powershell
Remove-Item -Recurse -Force C:\Users\ronit\Desktop\TEST1\praman\vendor\llama-cpp
Remove-Item C:\Users\ronit\Desktop\TEST1\praman\data\models\*.gguf -Force
```

The code returns to raising `ArtifactMissingError` naming Step 6, which is the correct state.

---

## Step 7 — Build the embedding / template index — OPTIONAL

**Purpose.** A `sqlite-vec` index over mined Drain3 templates, powering nearest-neighbour suggestions in the training GUI and natural-language search. Needs Step 5 (corpus). Does not need Step 6.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

python -m scripts.build_template_index `
  --corpus data\corpus `
  --out data\index\templates.sqlite3
```

**Est. time** 5–15 minutes (CPU embedding over the corpus).
**Est. disk** ~200 MB.

**Verify.**

```powershell
Get-Item data\index\templates.sqlite3 | Select-Object Name, Length
python -m scripts.build_template_index --verify --out data\index\templates.sqlite3
```

Expect a non-zero template count and a successful nearest-neighbour probe. Before this step runs, any code path needing the index must raise `ArtifactMissingError` naming **Step 7** — the behaviour asserted by the test in Step 11.

**Undo.**

```powershell
Remove-Item data\index\templates.sqlite3 -Force
```

> Drain3 mode separation is a hard invariant, enforced in code review: `add_log_message()` may be called **only** from the training-GUI path (it mutates the template tree), and `match()` **only** from the audit path (read-only). Mixing them makes audits non-reproducible — the same config would parse differently depending on what was ingested before it.

---

## Step 8 — Train the syntax classifier (and optional QLoRA)

**Purpose.** Tier 1 of the AI escalation ladder: a calibrated TF-IDF classifier mapping unknown config lines to canonical field paths. CPU is sufficient. The optional QLoRA fine-tune is a stretch goal and is **not** needed for the demo.

> **This step does not train Tier 2.** The name reads as if it covers the whole ladder and it does not: `scripts\train_classifier.py` writes `data\models\classifier\tfidf_pipeline.joblib`, and the SetFit model that `backend\ai\setfit_clf.py` loads is written by **Step 8c**.

**Command**

```powershell
# --- 8a: TF-IDF / SetFit classifier (CPU, in the backend venv) ---
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

python -m scripts.train_classifier `
  --labels data\labels\line_to_path.jsonl `
  --out data\models\classifier\ `
  --group-by device `
  --calibrate sigmoid `
  --report reports\metrics\classifier.json

# --- 8b: OPTIONAL QLoRA fine-tune (GPU, in the conda env from Step 3) ---
# conda activate unsloth_env
# python -m scripts.finetune_qlora --config configs\qlora.yaml --out data\models\lora\
```

**Est. time** ~10 minutes for 8a; 1–3 hours for 8b.
**Est. disk** ~1 GB for 8a; up to ~6 GB for 8b.

**Verify.**

```powershell
Get-Content reports\metrics\classifier.json
```

It must contain measured metrics with the split described. Two non-negotiables:

1. **Grouping must be by device**, using `StratifiedGroupKFold`. Splitting by *line* leaks: the same device's lines appear in train and test, and the score becomes meaningless. The report must state the grouping it used.
2. **Every published number comes from this file.** `GLOBAL_RULESET.md` R1.3 forbids any accuracy/F1/coverage/latency figure that a script in `scripts\bench\` did not regenerate into `reports\metrics\*.json`. Docs and slides read *from* these files. Never type a number into a slide by hand.

**Undo.**

```powershell
Remove-Item -Recurse -Force data\models\classifier, data\models\lora -ErrorAction SilentlyContinue
Remove-Item reports\metrics\classifier.json -Force -ErrorAction SilentlyContinue
```

---

## Step 8c — Train the SetFit few-shot classifier (ladder Tier 2) — OPTIONAL

**Purpose.** Write the artifact `backend\ai\setfit_clf.py` loads. **Step 8a does not train Tier 2** — `scripts\train_classifier.py` fits the TF-IDF pipeline only, despite a name that reads as covering both, so `data\models\classifier\setfit_model` had no producer and `SetFitClassifier.is_available()` returned `False` on every machine, forever. The escalation ladder ran two tiers and nothing failed, because a tier with no artifact is indistinguishable from a tier deliberately switched off. This step is what makes the third rung real.

Optional in the same sense as Steps 6–8: the compliance verdicts never depend on it (`GLOBAL_RULESET.md` R3.2 — AI is never in the verdict path). It affects training-GUI suggestions only.

**Needs Step 8a first.** The trainer reads the same `data\labels\line_to_path.jsonl` that `scripts\train_classifier.py` generates, deliberately — two tiers trained on two different label sets produce confidence scores the ladder cannot compare, and it compares them directly when deciding whether to escalate.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

# Tier 2's dependencies are NOT in requirements.lock.txt and Step 1 does not
# install them. These are the exact versions that produced the shipped artifact.
pip install torch==2.13.0 setfit==1.1.3 sentence-transformers==5.7.0

python -m scripts.train_setfit `
  --labels data\labels\line_to_path.jsonl `
  --out data\models\classifier\setfit_model `
  --report reports\metrics\setfit.json
```

> **Do not add Step 3's `--index-url .../cu130` here.** The default PyPI `torch` wheel on Windows is CPU-only and that is what this step wants: the base model is 22.7M parameters, the fine-tune is minutes on CPU, and the CUDA wheel is several gigabytes of download for no gain. Do not stack the conda env either — `conda deactivate` first if Step 3 is active.

> **Version note.** Step 3 pins `sentence-transformers==6.0.0` for the QLoRA environment; this machine's `.venv` has **5.7.0**, and 5.7.0 is what trained `reports\metrics\setfit.json`. Pinned to the measured version rather than harmonised upward, because a model fine-tuned under one sentence-transformers version and loaded under another loads without complaint and scores differently.

**Est. time** ~5–10 minutes for the wheels; **~34 minutes measured** for the fine-tune (`train_seconds: 2013.8` in `reports\metrics\setfit.json`, CPU, 1,443 training lines). Budget ~45 minutes.
**Est. disk** ~635 MB of wheels into `.venv` (measured: `torch` alone is 509 MB), ~88 MB for the base model in `%USERPROFILE%\.cache\huggingface\hub`, ~90 MB for the output model. Roughly **~850 MB** total.

**Verify.**

```powershell
Get-ChildItem data\models\classifier\setfit_model
Get-Content reports\metrics\setfit.json | Select-String '"accuracy"|"caveat"|"n_classes_measured"'
```

Three things must be true, and the third is the one people miss:

1. **`neighbour_index.npz` exists inside the model directory.** It is the out-of-distribution guard's reference set. Without it `SetFitClassifier` abstains on *everything* and logs a warning — deliberately fail-closed, because Tier 2 answers nonsense at 0.92 confidence when unguarded (the measured table is in `backend\ai\setfit_clf.py`, `OOD_SIMILARITY_FLOOR`).
2. **The report carries its own correction.** `accuracy` is `1.0` and that number is nearly empty: 94.1% of the 493 held-out lines are one class, and 7 of the 14 trained classes appear in the holdout at all. `tests\test_metrics_are_current.py::test_the_setfit_record_cannot_publish_a_perfect_score_bare` fails if the `caveat` field goes missing. **Never put the 1.00 on a slide without it.**
3. **`praman\checkpoints\` must NOT appear.** SetFit's `TrainingArguments.output_dir` defaults to the relative string `"checkpoints"`, which resolves against the working directory; `scripts\train_setfit.py` now pins it to `data\models\classifier\setfit_checkpoints` (gitignored). If a 260 MB `checkpoints\` shows up in `git status` at the repo root, that pin was lost — report it rather than gitignoring it.

**Undo.**

```powershell
Remove-Item -Recurse -Force data\models\classifier\setfit_model, data\models\classifier\setfit_checkpoints -ErrorAction SilentlyContinue
Remove-Item reports\metrics\setfit.json -Force -ErrorAction SilentlyContinue

# One-off: reclaim the 260 MB left by the pre-fix default output_dir. Safe —
# these are mid-training optimizer/scheduler states, superseded by the saved
# model above. Nothing reads them.
Remove-Item -Recurse -Force checkpoints -ErrorAction SilentlyContinue

# Optional — reclaims ~635 MB, and reverts Tier 2 to ArtifactMissingError:
# pip uninstall -y setfit sentence-transformers torch
```

Removing the model is safe at any time. `is_available()` goes back to `False`, the ladder stops at Tier 1, and audits are byte-identical — Tier 2 only ever fed suggestions to the training GUI.

---

## Step 9 — MSYS2 + Pango for the WeasyPrint archival path — OPTIONAL, SKIP BY DEFAULT

**Purpose.** The shipped PDF pipeline is **ReportLab → pikepdf → pyHanko** and needs none of this. WeasyPrint is only an optional HTML-to-PDF *archival* path, and on Windows it needs GTK/Pango native libraries via MSYS2. **Skip unless you specifically need the archival path.**

**Command**

```powershell
# Install MSYS2 (this is the one step that may prompt for elevation)
Start-Process "https://www.msys2.org/"

# Then, in the MSYS2 UCRT64 shell (NOT PowerShell):
#   pacman -S mingw-w64-x86_64-pango mingw-w64-x86_64-gdk-pixbuf2

# Back in PowerShell — add the DLL folder to PATH for the session:
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

# ...or persist it for your user:
# [Environment]::SetEnvironmentVariable("PATH", "C:\msys64\mingw64\bin;" + [Environment]::GetEnvironmentVariable("PATH","User"), "User")

Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
pip install weasyprint==69.0
```

**Est. time** 15 minutes. **Est. disk** ~1.5 GB.

**Verify.**

```powershell
# The DLLs must actually be there before the import can work
Test-Path C:\msys64\mingw64\bin\libpango-1.0-0.dll
python -c "import weasyprint; print(weasyprint.__version__)"
```

Expect `True` then `69.0`, with no `OSError` about `libpango`.

**Undo.** Uninstall MSYS2 via Windows Settings, then:

```powershell
pip uninstall weasyprint -y
```

The primary pipeline is unaffected.

> **The report font must include U+2014 (em dash).** Real OSCAL control titles contain it — `sc-7.5` is *"Deny by Default — Allow by Exception"*. A font lacking the glyph renders a black box or mojibake in the PDF. Test with that exact string.

---

## Step 10 — STIG Viewer 3.x as an independent oracle — OPTIONAL but recommended

**Purpose.** DISA's own desktop STIG Viewer gives you a **ground-truth second opinion**. Load the same STIG and compare its rule list and CAT counts against what your parser produced. This is an independent check of the parser's output, and it needs no Docker.

**Command**

```text
Download U_STIGViewer-win32_x64-3-5-1.zip (or the -3-5-1 MSI) from DISA's
STIG Viewer download page and install it.

NOTE: U_STIGViewer-win32_x64-3-5-2.zip returned 404 in research — the -3-5-1
asset is the one verified to exist. Do not guess a newer patch number.
```

**Est. time** 10 minutes. **Est. disk** ~400 MB.

**Verify.** Open the Cisco IOS XE Router NDM STIG from Step 4c in STIG Viewer. It must show **42 rules with 8 CAT I**, matching your parser's output exactly. A mismatch means your XCCDF parsing is wrong — fix it before it reaches a report.

**Undo.** Uninstall via Windows Settings.

---

## Step 11 — Smoke test: prove `pytest` is GREEN with no models and no index

**Purpose.** **This is the gate.** It proves the heavy-command split is real: a clean checkout with zero downloaded models, zero indexes and zero AI artifacts must still pass its entire test suite and produce a full deterministic audit. If this fails, the project has a hidden dependency on a heavy artifact and `GLOBAL_RULESET.md` R2.4 is violated.

Run this **after** Steps 0–5 and **before** trusting anything from 6–8. Then run it again with the AI artifacts present, to confirm they are genuinely additive.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

# 1. Hide any AI artifacts so we test the true cold-start state
if (Test-Path data\models) { Move-Item data\models data\_models.bak -Force }
if (Test-Path data\index)  { Move-Item data\index  data\_index.bak  -Force }

# 2. Full suite must be green
pytest -q

# 3. The ArtifactMissingError contract must hold, and name the right step
pytest -q tests\test_artifact_missing.py -v

# 4. An end-to-end deterministic audit must still work with no AI at all
python -m backend.cli audit `
  --config data\corpus\_hierconfig\tests\fixtures\running_config.conf `
  --framework STIG `
  --out out\smoke\

# 5. Restore
if (Test-Path data\_models.bak) { Move-Item data\_models.bak data\models -Force }
if (Test-Path data\_index.bak)  { Move-Item data\_index.bak  data\index  -Force }
```

**Est. time** 5 minutes. **Est. disk** 0.

**Verify.** All four must hold:

1. `pytest -q` exits **0**. Check it explicitly — PowerShell does not print exit codes:
   ```powershell
   pytest -q; "exit code: $LASTEXITCODE"
   ```
   No skips that hide a missing artifact — a skipped test is not a passing test.
2. `tests\test_artifact_missing.py` confirms each AI entry point raises `ArtifactMissingError` whose message **names the correct step number** in this file.
3. Step 4's audit writes a real PDF to `out\smoke\` containing findings with `result` values drawn only from the 9-value XCCDF enum, and **no finding is silently a pass**: any control whose inputs were unavailable must appear as `unknown` or `notchecked`, never as `pass`.
4. The audit **never reports "0 findings"** for a config it could not parse. "The tool found nothing" and "the tool did not look" must render differently (R1.7). Confirm by feeding it deliberate garbage:
   ```powershell
   "this is not a network config`n@@@@" | Out-File -FilePath "$env:TEMP\garbage.cfg" -Encoding utf8
   python -m backend.cli audit --config "$env:TEMP\garbage.cfg" --framework STIG --out out\garbage\
   ```
   This must report an explicit parse failure or `error`/`unknown` findings — **not** a clean pass and not an empty report.

**Undo.** Nothing to undo. If you interrupted between commands 1 and 5, restore manually:

```powershell
Move-Item data\_models.bak data\models -Force -ErrorAction SilentlyContinue
Move-Item data\_index.bak  data\index  -Force -ErrorAction SilentlyContinue
```

---

## Step 12 — Seed the ledger (and re-seed it after a hash-definition change) — RUN ONCE, then only when the verifier says to

**Purpose.** Unlike every other step in this file, this one is **not heavy** — it takes seconds and downloads nothing. It is here because it **writes `data\praman.db`**, and that is your call, not the build's.

**Run it once after cloning.** `data\praman.db` is **not in git**, so a fresh checkout has no database and this step is the only thing that makes one. Untracking it was deliberate on two counts: a 17 MB binary that changes on every ingest diffs as unreviewable noise, and on a real deployment it would put whatever devices the last operator audited — customer configurations — into a repository. `pytest` does not need it (the suite uses `conftest.py`'s `isolated_database` fixture), but the UI, the report route and `/audit/verify` all read it, so run this before the demo.

**Run it again** when `python -m backend.ledger.verify data\praman.db` reports records as failing. That is the honest output of a verifier whose definitions have moved: the ledger is hash-chained, so changing what a record hash or a Merkle root *means* invalidates every record written under the old meaning. Three such changes have landed:

* **`config_hash` now covers the config as written**, not the redacted text. The more correct definition — rotating a secret *is* a configuration change, and the old one hid that — but it changes the hash of every device.
* **The Merkle root is now defined in-repo with RFC 6962 domain-separation tags.** The old code tried `from pymerkle import MerkleTree` and fell back on `ImportError`; pymerkle 6.1.0 has no such symbol, so the fallback was the only branch that ever ran, and it padded odd levels by *duplicating* the last leaf — which made `[a,b,c]` and `[a,b,c,c]` hash identically. A duplicate of the final finding could be appended to a committed audit undetected.
* **Redaction runs after the parse.** Redacting first shifted every whitespace-delimited field after a secret, so `enable secret 5 <hash>` parsed to the wrong hash type — and those wrong facts were stored as truth.

A ledger that fails on healthy data cannot report unhealthy data: the operator learns to ignore the red crosses. Re-seeding is what makes the verifier's output mean something again.

**The database this used to ship with held nothing you need.** Its 6,512 rows all predated `tests\conftest.py`'s `isolated_database` fixture — they were residue from test runs against the real ledger, from twelve probe devices (`demo.conf`, `cv.conf`, `cft.conf`, `lc.conf`, two path-traversal probes). Twenty-two of those rows still carried `*** REDACTED ***`, the pre-fix three-token replacement string, including **twelve stored facts whose values were read out of mangled lines** and **five "approved" taught mappings** that can never match again. None of the shipped fixtures had ever been ingested through the persisting path. That is the file that is no longer tracked; the script backs up whatever it finds anyway.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

# 1. Look first. This writes nothing. On a fresh clone it reports that there is
#    no database and how many fixtures it would seed from; on an existing one it
#    inventories the tables, names why each is going, and prints the rows still
#    carrying the old token.
python scripts\reset_ledger.py

# 2. Do it: create-or-back-up, purge, re-ingest every fixture under
#    test_configs\ through the real /ingest and /audit/commit routes, then verify.
python scripts\reset_ledger.py --yes
```

**Est. time** under 30 seconds. **Est. disk** ~9 MB on a fresh seed; ~18 MB when resetting (a backup beside the reseeded database).

**Verify.** The script ends by running the standalone verifier itself, so the check is its last line:

1. It prints **`VERIFIED: 16 record(s), all five checks, no gaps.`** — one per fixture under `test_configs\`, so the count tracks the corpus rather than being fixed. Anything else is a real bug in the commit path — restore the backup and report it. In particular `INCOMPLETE` means a check went *unchecked*, which is not a pass:
   ```powershell
   python -m backend.ledger.verify data\praman.db; "exit code: $LASTEXITCODE"
   ```
   Exit **0** verified, **1** a broken link, **2** not everything was checked, **3** unreadable. These are distinct so that CI cannot mistake "we did not look" for "we looked and it was fine".
2. Every row reads `merkle=y hash=y chain=y sig=y actor=y`. A `?` means unchecked, and the two that go `?` for environmental reasons are worth telling apart: `sig=?` means no public key beside the database (the verifier looks for `private\ed25519_verify.pub` **next to the ledger file**, so a copy of the database moved elsewhere verifies four checks out of five), and `actor=?` means the deployment has no operator roster yet — Step 13. Neither is a pass; both make the run `INCOMPLETE` and exit **2**.
3. No row carries the old token any more, and the hash type survives redaction:
   ```powershell
@'
import sqlite3
c = sqlite3.connect("file:data/praman.db?mode=ro", uri=True)
n = c.execute("SELECT COUNT(*) FROM canonical_facts "
              "WHERE raw_text LIKE '%*** REDACTED ***%'").fetchone()[0]
print("rows still carrying the old token:", n)
for row in c.execute("SELECT value, raw_text FROM canonical_facts "
                     "WHERE path='mgmt.enable_secret.hash_type' LIMIT 2"):
    print(row)
'@ | python -
   ```
   Expect `0`, then rows like `('5', 'enable secret 5 ***REDACTED***')` — the secret gone, the hash type intact. A `value` of `None` or `'***REDACTED***'` means the parse-then-redact order regressed.
4. `pytest -q` still exits **0**. The count grows with every commit, so the exit code is the assertion, not the number — `tests/test_published_counts.py` is what keeps the figure in `praman/README.md` current. The suite uses an isolated database, so re-seeding must not move it either way; if it does, a test is reaching the real ledger.
5. `mapping_store` is **empty** and `training_queue` holds **40** rows. That is the correct starting state for a C2 training demo: nothing taught yet, and forty genuinely unparsed lines from the fixtures waiting to be taught.
6. The append-only triggers are back on afterwards, and they bite:
   ```powershell
   sqlite3 data\praman.db "UPDATE audit_records SET created_at = '1999-01-01T00:00:00Z';"
   ```
   Must fail with *"audit_records is append-only: a committed audit record cannot be modified."* If you have no `sqlite3.exe`, any `UPDATE` or `DELETE` through Python raises `sqlite3.IntegrityError` with the same text. `init_database` installs them, so a fresh deployment gets them without anyone remembering to ask, and a dropped trigger is reinstalled by the next request.

> **Two layers, and they fail in different circumstances — that is the point of having both.** The triggers stop the *casual* corruption: a migration script with a stray `UPDATE`, an operator correcting a timestamp by hand, an ORM helpfully re-saving a row. Those abort at the statement with a message saying why, instead of surfacing weeks later as an unexplained verification failure nobody can attribute. They are **not** a defence against an attacker holding the database file, because anyone who can write to it can also `DROP TRIGGER` — that attacker is the hash chain's job, and the chain still catches them. `tests/test_ledger_chain.py::TestAppendOnlyEnforcement` drops the triggers on purpose to prove the second layer works without the first.

**Undo.** Fully reversible when resetting — the backup is a byte copy taken before the first `DELETE`:

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman\data
Get-ChildItem praman.db.bak-* | Sort-Object Name   # newest last
Move-Item -Force praman.db.bak-<TIMESTAMP> praman.db
```

Restoring brings back the old records — which will fail verification again, because they were written under the old definitions. That is the point of the step, not a fault in the restore.

On a **fresh seed** there is nothing to restore to, because there was no database. The undo is `Remove-Item data\praman.db*`, and re-running the step rebuilds it from the fixtures.

> **Do not add `--keep-mappings` on this first run.** It exists for later, once you have taught mappings worth keeping. The five that ship carry the mangled token and all claim the same canonical path; keeping them preserves a fixed bug's output as institutional knowledge.

---

## Step 13 — Create the first operator account — RUN ONCE per deployment, then on every staff change

**Purpose.** Not heavy either: no download, no model, nothing on the GPU. It is in this file because it is the one thing the software deliberately refuses to do for itself. **There is no default account, no `admin/admin`, and no HTTP route that creates the first operator.** Until you run this, every protected route answers `401` and `/auth/login` answers `503`, and both replies name this step and this script.

That refusal is the design, not a gap, and the two alternatives are worse:

* A **shipped default credential** is the exact finding this tool fails devices for. `rules/` marks a default enable secret as high severity; an auditor that ships one has no standing to report it.
* An **open bootstrap route** — "whoever posts first becomes an approver" — is the same mistake wearing a convenience. On an assessment laptop, "first" often means somebody else on the hotel wifi.
* Running this script requires **filesystem access to the deployment**, which authenticates the act of taking privilege more strongly than any password an endpoint could check.

Passwords are never taken as an argument, so there is no `--password` flag to look for. `--password` lands in `Get-History`, in `ps` output on Linux, and in PowerShell's transcript log if the operator has one on. The script prompts without echoing; a provisioning pipeline that has the value in a secret store passes `--password-stdin` and feeds it as one line.

**Roles are three, ordered, and only the last one can sign.** `viewer` reads devices, findings and reports. `auditor` also uploads configs and runs simulations. `approver` also commits an audit to the ledger and teaches the parser. `actor` is one of the nine fields inside the record hash, so *which approver committed it* is covered by the same Ed25519 signature as the verdicts — see Step 12. Give people the lowest role that lets them work; a viewer who needs to commit will tell you within a day, whereas an over-privileged account tells you nothing until it matters.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

# 1. Look first. On a fresh deployment this prints "no operators yet" and the
#    exact command to fix it. It writes nothing.
python scripts\manage_users.py list

# 2. Create yourself as an approver. This prompts twice for a password, without
#    echoing. Minimum 12 characters; stored as PBKDF2-HMAC-SHA256, 600,000
#    iterations, per-user salt, and it cannot be read back out.
python scripts\manage_users.py add --username your.name --role approver

# 3. Create the rest of the team at the role each one actually needs.
python scripts\manage_users.py add --username asha.n   --role auditor
python scripts\manage_users.py add --username review.b --role viewer

# 4. Confirm. 'login: no' rows are service principals — they hold a row so the
#    ledger verifier recognises their records, and no password so nothing can
#    authenticate as them over HTTP.
python scripts\manage_users.py list
```

The other four subcommands are for later, and none of them needs the server stopped — the gate reads the `users` table on every request, so a role change or a lockout takes effect on the next one:

```powershell
python scripts\manage_users.py passwd  --username asha.n            # revokes live sessions
python scripts\manage_users.py role    --username asha.n --role approver
python scripts\manage_users.py disable --username departed.staff    # ends access, keeps history
python scripts\manage_users.py enable  --username departed.staff    # old tokens stay revoked
```

Names are lowercase letters, digits, dot, underscore and hyphen, 3–56 characters. `add --db <path>` targets a database other than `data\praman.db`, and it runs the schema migrations first, so creating the first operator works on a checkout that has not run Step 12 yet.

Unattended provisioning takes the password from stdin instead of a prompt — one line, no confirmation, nothing in `Get-History`:

```powershell
Get-Content C:\secrets\asha.txt | python scripts\manage_users.py add `
  --username asha.n --role auditor --password-stdin
```

> **Do not rely on redirecting `NUL` to suppress the prompt.** On Windows both `NUL` and MSYS's `/dev/null` are *character* devices, so `isatty()` answers **true** for them and an inferred prompt would block on a console read forever. `--password-stdin` is the declared form precisely because that inference is unreliable here; without the flag, an interactive prompt is what you get.

> **There is no `delete`, on purpose.** The ledger's `actor` field names the row and `/audit/verify`'s fifth check resolves it against this table. Delete a departed assessor and every audit they ever committed starts reporting an unknown actor — you would have destroyed the accountability record, not the access. `disable` ends the access in the same second and keeps the history: the account cannot authenticate, live tokens are revoked immediately, and the name still resolves for the verifier.

**Est. time** under 5 seconds per command, of which 0.21 s is the deliberate PBKDF2 cost. **Est. disk** a few hundred bytes per operator inside `data\praman.db`. Nothing is downloaded.

**Verify.** Five checks. The first two need the server *not* running; the rest do.

1. **Before you create anything**, the refusal is actionable rather than blank. With `data\praman.db` present but no operators in it:
   ```powershell
   python -m uvicorn backend.app.main:app --port 8000    # in a second terminal
   curl.exe -s -i http://127.0.0.1:8000/devices | Select-Object -First 12
   curl.exe -s -X POST http://127.0.0.1:8000/auth/login `
     -H "Content-Type: application/json" -d '{\"username\":\"x\",\"password\":\"y\"}'
   ```
   Expect `401` from `/devices` with `WWW-Authenticate: Bearer` and a detail naming `manage_users.py` and *Step 13*, and `503` from `/auth/login` whose detail contains *"no bootstrap route"*. A `200` from `/devices` on an empty roster is the failure this whole step exists to prevent — report it. `/health` must still answer `200`, because a monitor that needs a credential is a monitor that reports the credential expiring as an outage.
2. **`list` shows what you created**, with the role you meant and `login: yes` for every human. A human row reading `login: no` cannot log in and is a mistake; `passwd` fixes it.
3. **The password is not recoverable from the database.** Prefix only — do not print the whole column into a terminal you are screen-sharing:
   ```powershell
   sqlite3 data\praman.db "SELECT username, role, substr(password_hash,1,22) FROM users;"
   ```
   Every human row must start `pbkdf2_sha256$600000$`. A row where that column contains anything resembling the password you typed means the hashing path was bypassed. Service rows are empty there, which is what makes them unable to log in.
4. **A login returns a token and a role, and the token authorises a read.** `Get-Credential` prompts rather than putting the password on a command line:
   ```powershell
   $cred = Get-Credential -UserName your.name -Message "PRAMAN"
   $body = @{ username = $cred.UserName
              password = $cred.GetNetworkCredential().Password } | ConvertTo-Json
   $res  = Invoke-RestMethod http://127.0.0.1:8000/auth/login -Method Post `
             -ContentType 'application/json' -Body $body
   "role=$($res.role)  expires=$($res.expires_at)  token length=$($res.token.Length)"
   Invoke-RestMethod http://127.0.0.1:8000/auth/whoami `
     -Headers @{ Authorization = "Bearer $($res.token)" }
   ```
   Expect `role=approver`, an `expires_at` roughly 12 hours out, a token of 43 characters, and a `whoami` reading `may_ingest: True`, `may_commit: True`. For a `viewer` both must be `False` — and confirm the *server* enforces that rather than the UI: a `POST /audit/commit` on a viewer's token must return `403`, not `404`.
5. **The role you gave is the role the ledger records.** Commit one audit as the account you just made — through the UI, or Step 12's script — then:
   ```powershell
   python -m backend.ledger.verify data\praman.db; "exit code: $LASTEXITCODE"
   ```
   The record must name that operator and the verifier must resolve it. An `actor` the verifier cannot resolve reports as *unresolved*, not as valid — absence of a roster is never a pass (R3.2).

> **Ten wrong passwords locks that username for 15 minutes**, and during the lockout the *correct* password is refused too — otherwise the lockout would be a free oracle for confirming a guess. It is per-username and in-process, so restarting the server clears it, and `passwd` is the deliberate reset. This is not the per-request rate limiter `docs/SECURITY.md` still lists as missing; do not read it as one.

**Undo.** `disable` is the answer 99 times out of 100 — it ends the access immediately, revokes live tokens, and keeps the name resolvable for the ledger:

```powershell
python scripts\manage_users.py disable --username the.account
```

A genuinely wrong row — a typo'd name, created minutes ago, that has never committed anything — can be removed by hand, but check first that the ledger does not name it, because that check is the whole reason `delete` is not a subcommand:

```powershell
sqlite3 data\praman.db "SELECT COUNT(*) FROM audit_records WHERE actor = 'typo.name';"
# only if that prints 0:
sqlite3 data\praman.db "DELETE FROM users WHERE username = 'typo.name';"
```

Beyond that there is nothing to undo: this step downloads nothing and writes only rows into `data\praman.db`, which Step 12's timestamped backup already covers as a file.

---

## Step 14 — Validate the OSCAL and SARIF exports against the publishers' own schemas — RUN ONCE, then after any change to `backend\export\`

**Purpose.** Like Steps 12 and 13, this one is **not heavy** — two small GETs and 18.5 s of CPU. It is here because it pulls **third-party content this repository deliberately does not vendor**, and that download is your call.

PRAMAN emits two machine-readable documents besides the PDF: an **OSCAL v1.2.3 Assessment Results** file for a GRC platform (`GET /devices/{id}/oscal.json`) and a **SARIF v2.1.0** log for a CI gate (`POST /simulate/sarif`). Both are consumed by software that will reject them wholesale if a single field is wrong, so "we believe it conforms" is not a claim worth shipping. This step downloads the two publishers' JSON Schemas and validates real exports against every keyword in them.

**Why the schemas are not vendored.** They are 152 KB from NIST and 116 KB from OASIS, redistributed under their publishers' terms, and a copy committed here would be a claim about their content that nobody ever re-checks. `pytest` therefore cannot depend on them, and it doesn't — `tests\test_export_oscal.py` and `tests\test_export_sarif.py` assert structure against the `required` lists *transcribed* out of these files, which is 131 tests of real value and one specific blind spot. <!-- scoped: tests/test_export_oscal.py tests/test_export_sarif.py -->

**That blind spot is the whole point of this step.** A transcription catches a missing field. It cannot catch a field whose *value* violates a `pattern`, an `enum` or a `minimum` the transcriber left behind — and the one bug this exporter pair was most likely to have was exactly that shape. SARIF's `region.startLine` carries `minimum: 1`; `backend\ingest\generic.py:614` gives every never-configured fact `line_start=0`, which on a hardened config is **1,311 of 1,462 findings**. A schema-derived assertion list written by hand would have reported those documents as fine. The publisher's own file does not.

**Nothing here touches the GPU, the network beyond two small GETs, or `data\praman.db`.** The check builds its exports in-process from four shipped fixtures and a synthetic ledger record; it commits nothing and reads no operator rows, so it works on a checkout that has never run Step 12 or Step 13.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

New-Item -ItemType Directory -Force -Path data\schemas | Out-Null

# 1. OASIS SARIF 2.1.0 (OS = OASIS Standard, the final one, not a CSPRD draft).
curl.exe -fL -o data\schemas\sarif-2.1.0.json `
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json

# 2. NIST OSCAL 1.2.3 Assessment Results. This is a GitHub *release asset*, so it
#    answers with a redirect to an object store — -L is required, not optional.
curl.exe -fL -o data\schemas\oscal-ar-1.2.3.json `
  https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_assessment-results_schema.json

# 3. Validate. Exports four fixtures both ways and runs every schema keyword.
python scripts\check_export_conformance.py
"exit code: $LASTEXITCODE"
```

Both files are saved under a **version-bearing local name** rather than the publisher's filename. `oscal_assessment-results_schema.json` says nothing about which OSCAL release it came from, and two releases of that name are indistinguishable on disk — which is how a conformance check quietly starts validating against the wrong specification. The digests pinned in `SCHEMAS` at the top of `scripts\check_export_conformance.py` are what actually identify them; the filename is there so a human reading `dir` can see it too.

`-o` writes the response body as bytes. Do **not** substitute `> file` — in PowerShell 5.1 that produces UTF-16LE and the schema reads back as gibberish (Trap 2).

**Est. time** under 5 seconds for both downloads on any usable link; **18.5 s measured** for the validation itself, almost all of it rule evaluation rather than schema work — the script evaluates 1,462 findings per fixture, four times, and does it twice per fixture to prove re-export is byte-identical.

**Est. disk** **267,846 bytes** — `sarif-2.1.0.json` is 115,632 and `oscal-ar-1.2.3.json` is 152,214. `data\schemas\` is gitignored. Nothing else is written.

**Verify.** Four checks, and the last two matter more than they look.

1. **Exit code 0, and the two documents account for every finding.** Expect exactly this shape, one block per fixture:
   ```
   test_configs\compliance_extremes\fully_hardened.conf
     SARIF ok   findings=1462 results= 151 rules= 151 omitted=1311
     OSCAL ok   results=   8 observations=1462 findings= 151 risks=   2
   ```
   followed by `Both documents validate against the publishers' schemas for all 4 config(s), and both re-export byte-identically.` The four fixtures should report `omitted=` 1311, 1311, 1325 and 1328, and `risks=` 2, 151, 55 and 111 — a hardened config carrying 151 risks, or a fully non-compliant one carrying 2, means the projection inverted.
2. **`results + omitted == findings`, on every line above.** The script asserts it, but read it yourself once: SARIF drops the 1,311 absent-fact findings *because* they have no `startLine` to point at, and a document that dropped them without counting them would be a compliance log that silently under-reports. That arithmetic is the difference between an omission and a loss.
3. **Break the schema on purpose and confirm the script refuses rather than passes.** A conformance check that cannot tell "valid" from "did not run" is worse than none:
   ```powershell
   python scripts\check_export_conformance.py --schema-dir data\nope
   "exit code: $LASTEXITCODE"      # expect 2, and a message naming Step 14

   Copy-Item data\schemas\oscal-ar-1.2.3.json data\schemas\oscal-ar-1.2.3.json.bak
   '{"$id":"http://csrc.nist.gov/ns/oscal/1.2.3/oscal-ar-schema.json"}' `
     | Out-File -Encoding utf8 -NoNewline data\schemas\oscal-ar-1.2.3.json
   python scripts\check_export_conformance.py
   "exit code: $LASTEXITCODE"      # expect 3 — the pin, not the exporter
   Move-Item -Force data\schemas\oscal-ar-1.2.3.json.bak data\schemas\oscal-ar-1.2.3.json
   ```
   The stub above is a schema that *everything* validates against. If it reports success, the digest pin is not being enforced and every past green run means nothing. **Exit 1 is reserved for "the exporter is wrong"**; 2 and 3 both mean "nothing was checked", and keeping them apart is the point.
4. **The byte sizes above match what you downloaded.** `(Get-Item data\schemas\*.json).Length` must print 115632 and 152214. A different size means the publisher re-released the file — which can silently change what conformance means — so investigate the upstream change before updating the digests. The script will already have told you this as exit 3.

> **A schema URL that 404s is not a filename to guess at.** Both URLs above were fetched, and both files' digests recorded, on 2026-09-09. OASIS's path segment `os` marks the final OASIS Standard; `cs01`, `csprd01` and friends are earlier drafts of the same version number with different content. If NIST moves the v1.2.3 asset, take the URL off the release page rather than editing the version in the path — the same rule as Step 4c's STIG ZIPs, for the same reason.

**Undo.** Delete the directory. Nothing else in the project reads it, and every test keeps passing without it:

```powershell
Remove-Item -Recurse -Force data\schemas
```

---

## Step 15 — Build the presentation and demo recording — RUN ONCE before presenting, then after any edit to `docs\PRESENTATION.md` or `docs\SCRIPT.md`

**Purpose.** `GLOBAL_RULESET.md` R10.3 names five deliverables: source link, README, **architecture document (max 2 pages)**, **demo video (max 2 minutes)**, **technical presentation (max 5 slides)**. Three of them are already produced and gated by this repository. Two are not, and this step exists because *nothing in the codebase can honestly produce them*.

The architecture PDF **is** built by code — `python scripts\build_architecture_pdf.py` renders `docs\ARCHITECTURE.md` to `docs\ARCHITECTURE.pdf` at exactly two pages, and it is committed. You do not need this step for it. It is mentioned here only so the accounting is complete, and because the verify block below re-checks it for free.

**Why the deck is not scripted.** `docs\PRESENTATION.md` carries the finished slide content for a person to lay out and export as PDF. The slide *count* is gated where the count actually lives (`scripts\check_deliverable_limits.py` reads the `## Slide N —` headings in the Markdown), and the export stays a human act so the visual layout can be reviewed.

**Why the video is not scripted either.** Same shape, less arguable: `docs\SCRIPT.md` holds the words and the shot list, `docs\DEMO.md` holds the sequence, and `check_script()` re-derives the duration from the document's own word count so the two-minute claim keeps following from the script underneath it. Recording is yours.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

# 1. The architecture PDF — this part IS automated. Rebuild it if ARCHITECTURE.md changed.
python scripts\build_architecture_pdf.py
"exit code: $LASTEXITCODE"

# 2. Read the deck content and the slide-by-slide notes, then build it by hand.
#    Not a command to run — a document to follow, in a PowerPoint window.
#      docs\PRESENTATION.md   the six slides, content ready to paste
#      ..\slides_content.md   the same deck with layout and speaker notes
#    Template: SIT_SIH2026-IDEA-Presentation-Format.pptx
#    Keep its images and footers, delete slide 7, File > Export > PDF,
#    save as: docs\PRESENTATION.pdf
Invoke-Item docs\PRESENTATION.md

# 3. Record the demo. docs\SCRIPT.md is the words, docs\DEMO.md is the shot list.
#    Two minutes is a hard ceiling, not a target.
Invoke-Item docs\SCRIPT.md

# 4. Re-check every deliverable limit that is machine-checkable.
python scripts\check_deliverable_limits.py --check
"exit code: $LASTEXITCODE"
python scripts\build_architecture_pdf.py --check
"exit code: $LASTEXITCODE"
```

**Est. time** under 2 seconds for the architecture PDF and both checks. **30–60 minutes** for the deck if you have not opened the template before, most of it spent on slide 3's diagram. **1–2 hours** for the video, because a two-minute take that lands inside two minutes is roughly the fifth attempt.

**Est. disk** the architecture PDF is **9 KB** and is committed. `docs\PRESENTATION.pdf` will be a few hundred KB depending on the template's images. The recording is the only real cost: budget **~200 MB** for a 1080p screen capture of two minutes plus takes, and keep it out of the repository — `.gitignore` excludes `reports\*.pdf` but **not** video, so put the file somewhere else and link it.

**Verify.**

1. **Both machine checks exit 0.** `check_deliverable_limits.py --check` prints `0 violations.` and a debt line; `build_architecture_pdf.py --check` prints `2 pages, page 2 NN% full.` If the fill percentage is climbing toward 100, `docs\ARCHITECTURE.md` is about to spill onto a third page — trim the prose, **not** the font size, because the limit is on the document.
2. **`docs\PRESENTATION.pdf` has six pages** — five content slides plus the title. Seven means slide 7 was not deleted. Confirm the template's own footer is still on every page; if it is missing, the deck was rebuilt rather than filled in, which is the failure this step exists to prevent.
3. **The video is at or under 2:00.** Read the duration off the file, not off the plan. R10.3 gives a ceiling and §247 lists overrunning a stated limit as the cheapest possible way to lose points.
4. **`pytest -q tests\test_deliverable_limits.py`** passes — seven tests, two of which are about the architecture PDF specifically. One counts its pages; the other re-renders and diffs the extracted text against the committed file, because a committed binary is the one artefact here that can go stale in silence.

> **The page count and the content are checked separately, on purpose.** A PDF rebuilt from a rewritten `ARCHITECTURE.md` can land on two pages while saying something else entirely, and a page-count gate would pass it. The text diff never compares bytes — a PDF embeds its creation timestamp, so two runs are never byte-identical and a byte comparison would report drift on every single invocation.

**Undo.** Delete the generated artefacts. Nothing in the runtime path reads any of them, and `pytest` stays green except for the two architecture-PDF tests, which will fail *loudly* and name the builder — which is the intended behaviour, not a regression:

```powershell
Remove-Item -Force docs\ARCHITECTURE.pdf, docs\PRESENTATION.pdf -ErrorAction SilentlyContinue
python scripts\build_architecture_pdf.py     # put ARCHITECTURE.pdf back
```

---

## Step 16 — Fetch the SP 800-53B baseline allocation so coverage has an honest denominator — OPTIONAL, run once

**Purpose.** Like Steps 12–15 this is **not heavy** — three small GETs and under a second of CPU. It is here for the same reason Step 14 is: it pulls **third-party content this repository deliberately does not vendor**, and that download is your call.

PRAMAN publishes its control coverage honestly, which currently means publishing it against the wrong denominator. `reports\metrics\rule_latency.json` reports that the crosswalk reaches a verdict on **43 of 1,014** NIST 800-53 controls — 4.2% — and that figure is true and close to meaningless. Of those 1,014, **714 are enhancements** and the majority of the 300 base controls are organisational: a router audit is not failing to check `PS-03` *Personnel Screening*, it is being measured against a control no configuration file could ever satisfy.

The denominator an auditor actually uses is a **baseline**: the subset of SP 800-53 that applies to a system at a given impact level. Scope to MODERATE and the same 43 verdicts are measured against the controls that were in scope to begin with.

**Why this is not already done.** `docs\PRODUCTION-ROADMAP.md` §3.4 assumed the baselines were in "the OSCAL catalog already on disk". They are not, and this was checked rather than assumed. `data\frameworks\oscal\sp80053.json` uses exactly ten `prop` names — `label`, `method`, `sort-id`, `implementation-level`, `alt-identifier`, `contributes-to-assurance`, `aggregates`, `status`, `alt-label`, `keywords` — and none of them is a baseline or an impact level (`implementation-level` is organization/system/mixed). The normalised catalog agrees: `impact` is `''` and `profile` is `null` for all 1,014 controls. **The allocation is in SP 800-53B, a different publication**, released as three OSCAL profiles. `tests\test_framework_baseline.py::test_baseline_allocation_is_genuinely_not_in_the_catalog` pins that finding, so if a future catalog build ever does carry it, you are told and this step can be deleted.

**Nothing in the audit path changes.** No verdict, no rule, no `Finding`. The baseline is a *reporting* scope: it changes which denominator a percentage is printed against and nothing else. With the files absent, `backend\frameworks\baseline.py` returns `{}` and the metric prints the full-catalog figure plus a sentence saying why the scoped one is missing — never a scoped-looking number computed from an unscoped set.

**Command**

```powershell
Set-Location C:\Users\ronit\Desktop\TEST1\praman
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"

New-Item -ItemType Directory -Force -Path data\frameworks\oscal\_b | Out-Null

# 1. The three SP 800-53B baseline profiles. These are *profiles*, not catalogs:
#    each is a list of the control ids its baseline selects, a few tens of KB.
#    The `-resolved-profile_catalog` files in the same directory are the same
#    selection with every control's full text inlined — several MB, and the text
#    is already on disk in sp80053.json. -L is required: /raw/ redirects.
foreach ($b in "LOW", "MODERATE", "HIGH") {
  curl.exe -fL -o "data\frameworks\oscal\_b\$b.json" `
    "https://github.com/usnistgov/oscal-content/raw/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_$b-baseline_profile.json"
}

# 2. Extract the ids into PRAMAN's own artefact. The extractor is library code
#    under test, not a snippet pasted into a runbook — see the note below.
python -c @"
import json, sys
sys.path.insert(0, '.')
from pathlib import Path
from backend.frameworks.baseline import write_baselines
src = Path('data/frameworks/oscal/_b')
profiles = {b: json.loads((src / f'{b.upper()}.json').read_text(encoding='utf-8'))
            for b in ('low', 'moderate', 'high')}
out = write_baselines(profiles, source='NIST SP 800-53 Rev 5 OSCAL baseline profiles, usnistgov/oscal-content')
print(out)
for name, ids in sorted(json.loads(out.read_text(encoding='utf-8'))['baselines'].items()):
    print(f'{name:9s} {len(ids)}')
"@

# 3. Re-measure. The scoped denominator appears the moment the artefact exists.
python scripts\bench\bench_rule_latency.py
"exit code: $LASTEXITCODE"
```

> **The extraction runs through `backend\frameworks\baseline.py`, not through a script written inside this file.** A runbook snippet that parses a publisher's JSON is untested code in a document nobody runs a linter over. `extract_profile_ids` walks the parsed profile for `with-ids` keys at any depth rather than assuming the `imports` → `include-controls` nesting, because the key name is the stable part of the OSCAL profile model and the nesting is not — and an unrecognised shape yields **zero ids**, which step 2 above prints and the Verify block below rejects. A snippet that guessed the nesting would have failed by finding a *subset*.

**Est. time** under 5 seconds for all three downloads on any usable link; under 1 second for the extraction; **~7 s** for the re-measure, which re-evaluates every fixture.

**Est. disk** under 1 MB total. The three profiles land in `data\frameworks\oscal\_b\` (gitignored, delete after) and the extracted `data\frameworks\oscal\baselines.json` is a few tens of KB of control ids.

**Verify.**

1. **Step 2 prints three non-zero counts.** `TODO(verify):` `MASTER_PROMPT.md` §10.1 states the allocation as **LOW 149 / MODERATE 287 / HIGH 370**. That figure has *not* been measured on this machine — the profiles were never downloaded here — so treat step 2's output as the measurement and §10.1 as the expectation. If they disagree, NIST's publication wins and §10.1 is what needs correcting. **A count of 0 for any baseline means the profile's JSON shape is not what the extractor expects — do not proceed, and do not "fix" it by loosening the extractor until you have looked at the file.**
2. **The three are strictly nested.** LOW ⊂ MODERATE ⊂ HIGH is a property of SP 800-53B, so it is a free correctness check on the extraction:
   ```powershell
   python -c @"
import json
b = json.load(open('data/frameworks/oscal/baselines.json', encoding='utf-8'))['baselines']
low, mod, high = (set(b[k]) for k in ('low', 'moderate', 'high'))
print('low subset of moderate :', low <= mod)
print('moderate subset of high:', mod <= high)
"@
   ```
   Both must print `True`. A `False` means ids were dropped or mangled — most likely an enhancement folded into its base control, which is the specific bug `tests\test_framework_baseline.py::test_oscal_dotted_enhancement_is_not_folded_into_its_base` exists to prevent.
3. **`reports\metrics\rule_latency.json` gains the scoped figure.** Under `results.governance_reach.NIST_800_53.moderate_baseline`, the long "not on disk" sentence is replaced by an object with `source`, `controls_in_baseline`, `controls_decided` and `reach_of_baseline`. `controls_decided` there must be **≤ 43** — the baseline can only ever remove controls from the numerator, never add any. A larger number means the scoping is being applied to the wrong set.
4. **`pytest -q tests\test_framework_baseline.py`** passes both before and after this step. Every test either monkeypatches the path to a temporary file or asserts the absent-case contract, so running Step 16 must not change a single test outcome — a suite that goes green only after an optional download is a suite that was not testing the absent case.

> **Do not commit `baselines.json`.** It is derived from a NIST publication under that publication's terms, and a copy in the repository is a claim about its content — specifically, about *which revision's* baselines a coverage figure was scoped against — that nobody re-checks. The same reasoning as Step 14's schemas. Both paths were added to `praman\.gitignore` when this step was written; confirm with `git check-ignore -v data\frameworks\oscal\baselines.json` before any commit.

**Undo.** Delete both, and the metric returns to the unscoped figure with its stated reason:

```powershell
Remove-Item -Recurse -Force data\frameworks\oscal\_b -ErrorAction SilentlyContinue
Remove-Item -Force data\frameworks\oscal\baselines.json -ErrorAction SilentlyContinue
python scripts\bench\bench_rule_latency.py
```

---

## Step 17 — Hosted CPU classifiers and self-service signup

**Purpose.** Enable the shipped CPU classifiers and visitor-owned demo accounts.
The GitHub repository includes both classifier weights. The earlier hosted
Blueprint disabled all AI with `SENTINEL_AI_BACKEND=none` and installed only the
base requirements, which contain no SetFit runtime. No retraining is needed.

**Command** — run on the hosting service, or manually in an activated Linux Python 3.10
environment. This installs a large CPU PyTorch wheel and is not an agent-run
command. The pins match the shipped SetFit model metadata.

```bash
sh deploy/build-online.sh
```

The build runs these commands in order:

```bash
python -m pip install -r requirements.lock.txt
python -m pip install torch==2.13.0+cpu --index-url https://download.pytorch.org/whl/cpu
python -m pip install -r requirements-ai.txt
SENTINEL_AI_BACKEND=classifiers HF_HUB_OFFLINE=1 python scripts/check_ai_runtime.py
```

**Est. time** — allow several minutes for dependency installation.
**Est. disk** — allow roughly 1–2 GB of installed dependency space as a planning
estimate, plus temporary pip cache space. This uses CPU only, no VRAM, and no model
download. Runtime memory must
accommodate CPU PyTorch, the encoder and the app. These are capacity estimates,
not new project benchmarks.

**Render settings:** Build Command `sh deploy/build-online.sh`, Start Command
`sh deploy/start-online.sh`, `SENTINEL_AI_BACKEND=classifiers`,
`PRAMAN_SIGNUP_ENABLED=true`, `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`,
`OMP_NUM_THREADS=1`, `TOKENIZERS_PARALLELISM=false`. A service configured manually
in Render must have its existing `none` value changed in the dashboard.

**Verify.** The build log reports successful load and inference for TF-IDF and
SetFit. `/health` reports both classifier tiers ready. Open the URL, create an
account with a username, chosen role and a password of at least 12 characters,
then try the workflow. Choose Approver to commit audits and teach mappings.

**Undo.** Set `SENTINEL_AI_BACKEND=none` and restore the base-only build command
to run deterministic auditing. Set `PRAMAN_SIGNUP_ENABLED=false` to stop new
registrations. Existing accounts remain usable and can be managed with
`scripts/manage_users.py`. Do not delete a database to reverse these settings.

## Artifact → step → failure mode

The contract in one table. If an artifact is absent, the named code path raises `ArtifactMissingError` pointing at its step — it never crashes, never guesses, and never degrades silently.

| Artifact | Produced by | Code path that needs it | Behaviour when absent |
|---|---|---|---|
| `.venv\` + pins | Step 1 | everything | `ModuleNotFoundError` at import |
| `.venv-remediation\` | Step 2 | `backend\remediation\` delta CLI | `ArtifactMissingError` → Step 2 |
| `data\frameworks\oscal\sp80053.json` | Step 4a (already on disk) | NIST 800-53 rule packs, ID normaliser | `ArtifactMissingError` → Step 4a |
| `data\frameworks\attack\ent.json` | Step 4a (already on disk) | ATT&CK threat appendix in `findings.json`, `scripts\attack_coverage.py` | the `threat_appendix` key is **omitted entirely**, not written hollow — every readable field of a technique (name, URL, the ATT&CK release that defined it) comes from this bundle, and a bare `T1602.001` is not a citation. Verdicts, findings, Merkle root and signature are byte-identical either way |
| `data\frameworks\iso\*.xlsx` | Step 4a (already on disk) | ISO 27001 advisory crosswalk | crosswalk column hidden |
| `data\frameworks\cis\_source\*.pdf` | Step 4b (manual) | CIS rule packs | `ArtifactMissingError` → Step 4b |
| `data\frameworks\stig\U_*\` | Step 4c | STIG rule packs, CCI resolution | `ArtifactMissingError` → Step 4c |
| `data\corpus\_*\` | Step 5 | parser tests, bench harness | tests fail loudly (not skipped) |
| `data\models\*.gguf` + `llama-server` | Step 6 | AI ladder tier 3, prose drafting | ladder stops at tier 2; audit unaffected |
| `data\index\templates.sqlite3` | Step 7 | training-GUI suggestions, NL search | `ArtifactMissingError` → Step 7 |
| `data\models\classifier\tfidf_pipeline.joblib` | Step 8a | AI ladder tier 1 | ladder stops at tier 0; audit unaffected |
| `data\models\classifier\setfit_model\` | Step 8c | AI ladder tier 2 (SetFit) | `ArtifactMissingError` → Step 8c; ladder stops at tier 1 |
| `…\setfit_model\neighbour_index.npz` | Step 8c | tier 2 out-of-distribution guard | tier 2 abstains on **everything** and warns — fail-closed, never unguarded |
| `reports\metrics\*.json` | Step 8a, Step 8c, `scripts\bench\*` | any metric in docs/slides/PDF | metric renders as `UNVERIFIED`; CI fails release |
| `data\praman.db` | Step 12 | UI, report route, `/audit/verify` | **absent on a fresh clone** — it is gitignored; `/devices` is empty until Step 12 runs. `pytest` is unaffected (isolated fixture DB) |
| `data\praman.db` ledger rows | Step 12 | `/audit/verify`, `python -m backend.ledger.verify` | every record reports `FAIL`; the verifier is right and the rows are stale |
| `data\praman.db` operator rows | Step 13 | every route except `/health`, `/auth/login` and the static assets | `401` naming this script and Step 13; `/auth/login` answers `503`. **There is no default account** — absence is the intended state of a deployment nobody has provisioned |
| `data\schemas\*.json` | Step 14 | `scripts\check_export_conformance.py`, and nothing else | the script exits **2** naming Step 14 and validates nothing. No runtime path reads these files: the exporters never load a schema, so `/devices/{id}/oscal.json`, `/simulate/sarif` and all 1,798 tests are unaffected. A schema present but not the pinned one exits **3**, never a pass |
| `docs\ARCHITECTURE.pdf` | Step 15 (`scripts\build_architecture_pdf.py`) | `scripts\check_deliverable_limits.py`; no runtime path | **committed, so normally present.** Deleted, `check_architecture()` returns a violation naming the builder and `tests\test_deliverable_limits.py` fails — R10.3 lists it as a deliverable and "not built" is not a pass. Present but stale against `ARCHITECTURE.md`, a *second* test fails on the text diff |
| `docs\PRESENTATION.pdf` | Step 15 (**by hand**, from the slide content) | nothing — it is a presentation artifact, not an input | absent by default and **not** gated: the slide limit is checked against `docs\PRESENTATION.md`, where the count actually lives. The visual layout and final export are reviewed by a person |
| `data\frameworks\oscal\baselines.json` | Step 16 (optional) | `scripts\bench\bench_rule_latency.py` governance reach; no runtime path | **absent by default.** `load_baselines()` returns `{}` and the metric prints the full-catalog reach plus a sentence naming this step. No verdict, rule or `Finding` changes either way — the baseline scopes a denominator, not an audit |

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'backend.…'` / `'scripts.…'` | the build has not written that module yet — **not** a bug | see *Two kinds of command*; `Test-Path` the file and re-run when it exists |
| `ArtifactMissingError` for a step you already ran | genuine bug | report it — the code is looking in the wrong place |
| The ledger verifier reports **every** record as `FAIL` | the rows predate the current record-hash / Merkle / `config_hash` definitions | Step 12 — re-seed. The verifier is not broken; a verifier that fails on healthy data is worse than none, because you learn to ignore it |
| The verifier prints `INCOMPLETE`, or a link shows `?` | a link went **unchecked** — usually no `data\private\ed25519_verify.pub` | Step 12's Verify note 2. Unchecked is not valid; exit code 2 exists to keep the two apart |
| `check_export_conformance.py` exits `2` | `data\schemas\` has no schemas in it — they are downloaded, never vendored | Step 14. Exit 2 means **nothing was validated**; do not read it as a pass |
| `check_export_conformance.py` exits `3` | a schema on disk is not the pinned file — normally an upstream re-release | read the publisher's changelog first, *then* update `SCHEMAS` in that script. Deleting the pin to make it green destroys the only thing that identifies what "valid" meant |
| `check_export_conformance.py` exits `1` | a real conformance bug in `backend\export\` | read the printed `INVALID at /path` — it is the JSON pointer to the offending field. This is the one exit code that blames PRAMAN |
| Every route answers `401 "no operator accounts exist"`, `/auth/login` answers `503` | the deployment has no operators — there is no default account by design | Step 13 — `python scripts\manage_users.py add --username <name> --role approver` |
| `401 invalid credentials` for a password you are sure of | one message covers unknown user, wrong password **and** disabled account, on purpose — three answers would enumerate users | `manage_users.py list`; if the row reads `disabled`, `enable` it, then `passwd` |
| `429 too many failed attempts … try again in N seconds` | ten consecutive failures locked that username for 15 minutes; the correct password is refused too, so the lockout is not a guess oracle | wait it out, restart the server, or `manage_users.py passwd` |
| `manage_users.py` hangs with no prompt | stdin was redirected from `NUL` or `/dev/null`, which Windows reports as a tty, so it is waiting on a console read | pass `--password-stdin` and feed the password as one line, or run it interactively |
| A `viewer`'s commit returns `404`, not `403` | the gate leaked: the route reached the database before checking the role | genuine bug — report it; `tests\test_auth.py` asserts `403` on a nonexistent device id for exactly this reason |
| A ledger record shows an unresolved actor | the `users` row was deleted rather than disabled | restore it under the same name; then use `disable`, never `DELETE` (Step 13's Undo) |
| `python --version` is not 3.10.11 inside `.venv` | a conda env was active during `python -m venv` | check `.venv\pyvenv.cfg`'s `home`; rebuild after `conda deactivate`, or accept it and update the version in Steps 0/1 |
| `pip install` lands in the wrong environment | conda env and venv both active | never stack them; `conda deactivate` before venv work |
| `curl: The term '-fLO' is not recognized` / weird parameter error | `curl` is aliased to `Invoke-WebRequest` in PS 5.1 | use `curl.exe`, never bare `curl` (Trap 1) |
| Lockfile or JSON reads as gibberish / spaced-out characters | `>` wrote UTF-16LE in PS 5.1 | `\| Out-File -Encoding utf8` (Trap 2) |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | ExecutionPolicy `Restricted` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (Trap 3) |
| A 369 MB download crawls | PS 5.1 progress-bar overhead | use `curl.exe`, or `$ProgressPreference = 'SilentlyContinue'` (Trap 4) |
| `The term 'conda' is not recognized` / *"Run conda init"* | conda not wired into PowerShell | `conda init powershell`, then restart the terminal (Step 3) |
| `UnicodeEncodeError: 'charmap' codec ...` | `PYTHONUTF8` unset, or an implicit `open()` | Step 0; add explicit `encoding="utf-8"` |
| `UnicodeEncodeError: ... '\ufeff' in position 0` | UTF-8 BOM file (`U_CCI_List.xml`) | open with `encoding="utf-8-sig"` |
| Em dash renders as `â€"` or a box | wrong codec, or a font missing U+2014 | Step 9 note; test with `Deny by Default — Allow by Exception` |
| `ImportError: cannot import name 'WorkflowRemediation'` | `hier-config 2.3.1` installed | Step 2 — it needs its own venv, isolated from `ciscoconfparse2` |
| Here-string parse error on a verify block | `'@` was indented | `'@` must start at column 0, no leading spaces |
| CUDA OOM on `llama-server` | context too large / too many layers | lower `-c`, then `-ngl`; keep `q8_0` KV cache (Step 6) |
| `torch.cuda.is_available()` is `False` | CPU wheel installed | reinstall with the `cu130` `--index-url` (Step 3) |
| A STIG URL returns `404` | filename guessed, not pinned | use only the verified filenames in Step 4c; never construct one |
| A baseline count prints `0` in Step 16 | the OSCAL profile's shape is not what `extract_profile_ids` walks — **not** an empty baseline | read the downloaded JSON before touching the extractor. Loosening it to match whatever is on disk is how a subset gets mistaken for a baseline |
| `moderate_baseline` in `rule_latency.json` is a sentence, not an object | Step 16 has not been run — this is the default and correct state | run Step 16, or quote `reach_of_emitted` and say it is unscoped. Never print the unscoped ratio under a MODERATE label |
| `UserWarning: Data Validation extension is not supported` | openpyxl on the OLIR workbook | suppress that specific warning (Step 4d) |
| `netutils` reports `cannot_parse: True` everywhere | known unreliable flag | never surface it as "we could not audit this"; research saw it returned for all four sample features |
| Phantom config diffs | inconsistent indent widths across the stack | normalise indentation before comparing (hier_config fixtures use 1-space, its remediation emits 2-space) |
| `stigviewer.com` API returns `401` | it requires auth | use the pinned `dl.dod.cyber.mil` ZIPs (Step 4c) |

---

## Where the numbers in this file came from

Every byte size, filename, version and count above was probed or parsed during the research phase and recorded under `.research\synth\`, with one exception noted below. Nothing here is estimated except the fields explicitly labelled **Est.**, and nothing is guessed except the **three `TODO(verify):` markers in Step 6** and **one in Step 16**. Step 6's cover four unresolved names: the llama.cpp Windows CUDA asset filename and the cudart asset filename (one marker), the Qwen GGUF repo id and filename, and the abetlen wheel index URL. Resolve all four by reading the source pages before you rely on them.

**Step 16's marker is a different and narrower kind.** The three filenames in its download loop were read off the publisher's own directory listing on 2026-09-11, so they are not guesses; what is unverified is the **control counts** those files contain. LOW 149 / MODERATE 287 / HIGH 370 is `MASTER_PROMPT.md` §10.1's figure, not a measurement — the profiles have never been downloaded on this machine, which is the entire reason Step 16 exists. Step 16's own step 2 prints the real counts, and its Verify block says explicitly that NIST's publication wins if the two disagree. This is the one number in this file that a reader must not quote before running the step that produces it.

**Step 14's figures are measured, not researched, and are the stronger kind.** Both schema URLs were fetched on 2026-09-09 and the two files' byte sizes and sha256 digests were taken from the downloaded bytes, not from a release page. The 18.5 s runtime and every per-fixture count in its Verify block were read off an actual run on this machine. The digests are pinned in `scripts\check_export_conformance.py` rather than only written here, so a stale number in this file cannot outlive a schema change quietly — the script exits 3 and says so.

**The exception is the CIS control-count table in Step 4b.** Those numbers were not taken from research — they were measured by running the extractor over the PDFs in `_source\` and cross-checked against each PDF's count of `Profile Applicability:` occurrences. That makes them stronger than the research figures they replaced, but they describe *the seven files currently on this machine*, not CIS's catalogue in general. Download a different version and the table no longer applies: re-measure rather than assume.

If you hit a discrepancy between a size printed here and what you actually download, **stop and investigate** rather than proceeding: a changed byte size means the upstream content changed, which can silently change control IDs.
