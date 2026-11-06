"""Launch the packaged PRAMAN local appliance on Windows."""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


def _repo_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    if getattr(sys, "frozen", False):
        root = Path(getattr(sys, "_MEIPASS", root))
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


def initialize_installation() -> None:
    """Create per-user storage, the SQLite schema, and a fresh ledger identity."""
    _repo_root()
    from backend.app.config import PRIVATE_DIR, USER_DATA_DIR
    from backend.db.connection import get_connection, init_database
    from backend.ledger.chain import (
        SIGNING_KEY_PATH,
        VERIFY_KEY_PATH,
        generate_signing_keys,
    )

    USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
    for directory in (PRIVATE_DIR, USER_DATA_DIR / "reports", USER_DATA_DIR / "downloads"):
        directory.mkdir(parents=True, exist_ok=True)

    if SIGNING_KEY_PATH.exists() != VERIFY_KEY_PATH.exists():
        raise RuntimeError(
            "PRAMAN has only one ledger key file. Restore the matching key pair "
            "from backup before starting the application."
        )
    if not SIGNING_KEY_PATH.exists():
        generate_signing_keys()

    connection = get_connection()
    try:
        init_database(connection)
    finally:
        connection.close()


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _healthy(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def _run_server(port: int, holder: dict[str, object]) -> None:
    import uvicorn

    config = uvicorn.Config(
        "backend.app.main:app",
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    holder["server"] = server
    server.run()


def _wait_for_server(url: str, thread: threading.Thread) -> bool:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and thread.is_alive():
        if _healthy(url):
            return True
        time.sleep(0.25)
    return False


def _run_window(url: str, holder: dict[str, object], thread: threading.Thread) -> None:
    try:
        import tkinter as tk
    except ImportError:
        webbrowser.open(url)
        thread.join()
        return

    root = tk.Tk()
    root.title("PRAMAN")
    root.geometry("360x160")
    root.resizable(False, False)

    tk.Label(root, text="PRAMAN is running locally", font=("Segoe UI", 13, "bold")).pack(
        pady=(18, 4)
    )
    tk.Label(root, text=url, foreground="#555555").pack()
    buttons = tk.Frame(root)
    buttons.pack(pady=18)
    tk.Button(buttons, text="Open PRAMAN", command=lambda: webbrowser.open(url)).pack(
        side="left", padx=5
    )

    def stop() -> None:
        server = holder.get("server")
        if server is not None:
            server.should_exit = True
        root.destroy()

    tk.Button(buttons, text="Stop", command=stop).pack(side="left", padx=5)
    root.protocol("WM_DELETE_WINDOW", stop)
    root.after(100, lambda: None)
    root.mainloop()
    thread.join(timeout=10)


def run_application(open_browser: bool = True) -> int:
    os.environ.setdefault("SENTINEL_AI_BACKEND", "classifiers")
    os.environ.setdefault("PRAMAN_SIGNUP_ENABLED", "true")
    initialize_installation()

    port = _available_port()
    url = f"http://127.0.0.1:{port}"
    holder: dict[str, object] = {}
    thread = threading.Thread(target=_run_server, args=(port, holder), daemon=True)
    thread.start()
    if not _wait_for_server(f"{url}/health", thread):
        server = holder.get("server")
        if server is not None:
            server.should_exit = True
        raise RuntimeError("PRAMAN did not become healthy within 30 seconds")

    if open_browser:
        webbrowser.open(url)
    _run_window(url, holder, thread)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start the PRAMAN Windows appliance")
    parser.add_argument("--initialize", action="store_true", help="prepare user storage and exit")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser")
    parser.add_argument("--components", nargs=argparse.REMAINDER, help="manage optional components")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.components is not None:
        _repo_root()
        from deploy.windows_components import main as components_main

        return components_main(args.components)
    if args.initialize:
        initialize_installation()
        print("PRAMAN user storage is ready.")
        return 0
    return run_application(open_browser=not args.no_browser)


if __name__ == "__main__":
    raise SystemExit(main())
