"""Exercise VM launchers without installing or starting a model runtime."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(os.name == "nt", reason="Linux VM shell launchers")


def _checkout(tmp_path: Path, launcher: str) -> Path:
    root = tmp_path / "checkout with spaces"
    (root / "deploy").mkdir(parents=True)
    shutil.copyfile(PROJECT_ROOT / "deploy" / launcher, root / "deploy" / launcher)
    return root


def _executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)


@pytest.mark.parametrize("profile", ["classifiers", "none", "full"])
def test_app_launcher_keeps_loopback_and_preserves_ai_profile(
    tmp_path: Path,
    profile: str,
) -> None:
    root = _checkout(tmp_path, "start-vm.sh")
    _executable(
        root / ".venv" / "bin" / "python",
        'printf "%s|%s|%s|%s|%s\\n" "$PWD" "$HOST" "$PORT" "$SENTINEL_AI_BACKEND" "$1"\n',
    )
    result = subprocess.run(
        ["sh", str(root / "deploy" / "start-vm.sh")],
        cwd=tmp_path,
        env={**os.environ, "HOST": "0.0.0.0", "PORT": "9000", "SENTINEL_AI_BACKEND": profile},
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    assert result.stdout.splitlines() == [
        f"{root}|127.0.0.1|8012|{profile}|scripts/bootstrap_user.py",
        f"{root}|127.0.0.1|8012|{profile}|scripts/serve.py",
    ]


def test_app_launcher_missing_venv_names_install_step(tmp_path: Path) -> None:
    root = _checkout(tmp_path, "start-vm.sh")
    result = subprocess.run(
        ["sh", str(root / "deploy" / "start-vm.sh")],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 1
    assert "Step 18 in MANUAL_COMMANDS.md" in result.stderr


def test_qwen_launcher_is_local_cpu_only_and_single_slot(tmp_path: Path) -> None:
    root = _checkout(tmp_path, "start-qwen-cpu.sh")
    server = root / "native server"
    model = root / "model weights.gguf"
    model.write_bytes(b"test artifact, not a model")
    _executable(server, 'printf "%s\\n" "$@"\n')
    result = subprocess.run(
        ["sh", str(root / "deploy" / "start-qwen-cpu.sh")],
        env={
            **os.environ,
            "PRAMAN_LLAMA_SERVER": str(server),
            "PRAMAN_QWEN_MODEL": str(model),
            "PRAMAN_QWEN_THREADS": "2",
        },
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    args = result.stdout.splitlines()
    assert args[args.index("--model") + 1] == str(model)
    for flag, expected in {
        "--host": "127.0.0.1",
        "--port": "8080",
        "--device": "none",
        "--n-gpu-layers": "0",
        "--parallel": "1",
        "--ctx-size": "4096",
        "--cache-ram": "0",
    }.items():
        assert args[args.index(flag) + 1] == expected


@pytest.mark.parametrize("server_present", [False, True])
def test_qwen_launcher_missing_artifacts_names_install_step(
    tmp_path: Path,
    server_present: bool,
) -> None:
    root = _checkout(tmp_path, "start-qwen-cpu.sh")
    server = root / "server"
    if server_present:
        _executable(server, 'printf "must not run\\n"\n')
    result = subprocess.run(
        ["sh", str(root / "deploy" / "start-qwen-cpu.sh")],
        env={
            **os.environ,
            "PRAMAN_LLAMA_SERVER": str(server),
            "PRAMAN_QWEN_MODEL": str(root / "absent.gguf"),
        },
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 1
    assert "Step 18c in MANUAL_COMMANDS.md" in result.stderr
    assert "must not run" not in result.stdout
