"""PRAMAN application configuration.

APP_NAME is the single place where the product name lives.
Everything else imports it.
"""

from __future__ import annotations

import os
from pathlib import Path

# ─── Identity ──────────────────────────────────────────────────────────
APP_NAME = "PRAMAN"
APP_VERSION = "0.1.0"
PS_ID = "26155"
PS_TOKEN = "SIH26155"
PS_ORG = "NTRO"
PS_THEME = "Blockchain & Cybersecurity"
PS_TITLE = "AI-Driven Multi-Vendor Network Security Compliance Auditor"

# ─── Paths ─────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = DATA_DIR / "models"
INDEX_DIR = DATA_DIR / "index"
CORPUS_DIR = DATA_DIR / "corpus"
FRAMEWORKS_DIR = DATA_DIR / "frameworks"
LABELS_DIR = DATA_DIR / "labels"
REPORTS_DIR = PROJECT_ROOT / "reports"
METRICS_DIR = REPORTS_DIR / "metrics"
RULES_DIR = PROJECT_ROOT / "rules"

# ─── Database ──────────────────────────────────────────────────────────
DATABASE_PATH = DATA_DIR / "praman.db"

# ─── Encoding ──────────────────────────────────────────────────────────
FILE_ENCODING = "utf-8"
FILE_ENCODING_BOM = "utf-8-sig"

# ─── AI Escalation Thresholds (config knobs — SPINE §18.1) ────────────
TAU_TFIDF: float = 0.85  # below this → escalate to SetFit (Tier 2)
TAU_SETFIT: float = 0.80  # below this → escalate to LLM (Tier 3)
TAU_LLM: float = 0.70  # below this → ABSTAIN, queue for admin

# ─── LLM Server ───────────────────────────────────────────────────────
LLM_HOST = "127.0.0.1"
LLM_PORT = 8080
LLM_TIMEOUT_S = 30

# ─── Feature Flags ────────────────────────────────────────────────────
FEATURE_WEASYPRINT_ARCHIVAL = False  # off by default — needs MSYS2 Pango
FEATURE_THREAT_ENRICHMENT = True
FEATURE_LIVE_NAPALM = False  # napalm is optional/live-only (SPINE §14.2)

# ─── Sentinel ──────────────────────────────────────────────────────────
# Set SENTINEL_AI_BACKEND=none to disable all AI tiers.
# In that mode, only Tier 0 (deterministic parse) runs.

SENTINEL_AI_BACKEND = os.environ.get("SENTINEL_AI_BACKEND", "full")

# ─── Report signing ───────────────────────────────────────────────────
# Where the organisation's PDF signing identity lives. Left unset, reports are
# signed by an ephemeral self-signed demo key and say so on their face: the
# signature then proves the bytes are unaltered and nothing about who issued
# them. Configuration, not code, because the identity differs per deployment and
# a key path baked into a source file is a key path that ends up in a git remote.
_pfx = os.environ.get("PRAMAN_SIGNING_PFX", "").strip()
SIGNING_PFX_PATH: Path | None = Path(_pfx) if _pfx else None
SIGNING_PFX_PASSPHRASE: bytes = os.environ.get(
    "PRAMAN_SIGNING_PFX_PASSPHRASE", ""
).encode("utf-8")
#: RFC 3161 Time Stamp Authority. Set it to raise signatures from PAdES-B-B to
#: B-LT; unset, the signature carries only the signing host's own clock.
SIGNING_TSA_URL: str | None = os.environ.get("PRAMAN_TSA_URL", "").strip() or None

# ─── Upload limits (bulk ingest hardening) ────────────────────────────
# A compliance tool is handed archives by people who did not build it, so the
# archive reader assumes nothing. These are the ceilings /ingest/bulk enforces:
# a 400-device estate at ~40 KB a config is under 20 MB, so the limits are
# generous for real work and hostile to a zip bomb.
MAX_UPLOAD_BYTES = 64 * 1024 * 1024  # compressed size accepted from the client
MAX_ARCHIVE_MEMBERS = 2000  # entries in one archive
MAX_MEMBER_BYTES = 8 * 1024 * 1024  # one config, uncompressed
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024  # whole archive, uncompressed
