"""Run the PRAMAN API server.

    python scripts/serve.py                 # 127.0.0.1:8012
    PORT=9000 python scripts/serve.py       # 127.0.0.1:9000
    HOST=0.0.0.0 python scripts/serve.py    # all interfaces

Exists because ``uvicorn`` reads its port from the command line, and every
process manager that hands a port to a child — a PaaS, a supervisor, a preview
harness — hands it over in ``$PORT``. Wiring that in one place beats teaching
each caller to interpolate a flag, and it is the difference between a launch
config that survives a port collision and one that binds 8000 and looks fine.

Defaults bind loopback rather than ``0.0.0.0``. The API authenticates every
route except ``/health``, ``/auth/login`` and the static frontend, but it speaks
plain HTTP — so on any interface other than loopback the bearer token crosses the
network in clear text. Terminate TLS at a reverse proxy (``deploy/nginx/praman.conf``)
and let that proxy be the only thing listening publicly; binding every interface
directly should be a decision somebody typed, not the default they inherited.
See docs/SECURITY.md §2.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8012"))
    reload = os.environ.get("RELOAD", "").lower() in {"1", "true", "yes"}

    if host == "0.0.0.0":
        print(
            "WARNING: binding 0.0.0.0 serves the API over plain HTTP on every "
            "interface. Routes are authenticated, but the bearer token and every "
            "finding cross the network in clear text. Put a TLS-terminating "
            "reverse proxy in front of it (deploy/nginx/praman.conf) before doing "
            "this outside a lab. See docs/SECURITY.md §2.",
            file=sys.stderr,
        )

    uvicorn.run(
        "backend.app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=os.environ.get("LOG_LEVEL", "info"),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
