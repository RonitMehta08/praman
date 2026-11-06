"""Console entry point for the optional PRAMAN component manager."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deploy.windows_components import main

if __name__ == "__main__":
    raise SystemExit(main())
