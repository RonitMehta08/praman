"""PRAMAN application configuration.

APP_NAME is the single place where the product name lives.
Everything else imports it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ─── Identity ──────────────────────────────────────────────────────────
APP_NAME = "PRAMAN"
APP_VERSION = "0.1.0"
APP_DESCRIPTION = "AI-Driven Multi-Vendor Network Security Compliance Auditor"

# ─── Paths ─────────────────────────────────────────────────────────────
#
# In a source checkout, PROJECT_ROOT is the repository root and the historical
# paths remain unchanged.  In a PyInstaller build, __file__ points into the
# read-only application bundle.  Keep shipped rules/catalogues there, but put
# databases, keys, reports, and optional downloads in the user's profile.
_FROZEN = bool(getattr(sys, "frozen", False))
if _FROZEN:
    PROJECT_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent.parent))
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

_local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
_default_user_data = (
    Path(_local_appdata) / "PRAMAN"
    if _local_appdata
    else Path.home() / "AppData" / "Local" / "PRAMAN"
)
USER_DATA_DIR = Path(os.environ.get("PRAMAN_USER_DATA_DIR", "")).expanduser() if os.environ.get(
    "PRAMAN_USER_DATA_DIR", "").strip() else _default_user_data
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = DATA_DIR / "models"
OPTIONAL_MODELS_DIR = USER_DATA_DIR / "models" if _FROZEN else MODELS_DIR
INDEX_DIR = DATA_DIR / "index"
CORPUS_DIR = DATA_DIR / "corpus"
FRAMEWORKS_DIR = DATA_DIR / "frameworks"
OPTIONAL_FRAMEWORKS_DIR = USER_DATA_DIR / "frameworks" if _FROZEN else FRAMEWORKS_DIR
LABELS_DIR = DATA_DIR / "labels"
REPORTS_DIR = PROJECT_ROOT / "reports"
METRICS_DIR = REPORTS_DIR / "metrics"
RULES_DIR = PROJECT_ROOT / "rules"
WRITABLE_DATA_DIR = USER_DATA_DIR if _FROZEN else DATA_DIR
PRIVATE_DIR = WRITABLE_DATA_DIR / "private"

# ─── Database ──────────────────────────────────────────────────────────
#
# Local/offline runs keep the database beside the project data. Hosted services
# can point this at their mounted persistent disk without moving the read-only
# framework packs or changing application code. The override is deliberately a
# file path rather than a second database backend: SQLite remains the same
# zero-infrastructure store in both deployment profiles.
_database_path = os.environ.get("PRAMAN_DATABASE_PATH", "").strip()
DATABASE_PATH = (
    Path(_database_path).expanduser()
    if _database_path
    else WRITABLE_DATA_DIR / "praman.db"
)


def optional_path(relative: str, *, bundled: Path | None = None) -> Path:
    """Resolve an optional artifact, preferring a downloaded user copy.

    Source-mode callers retain the repository path.  Frozen installations may
    add large optional artifacts below ``%LOCALAPPDATA%\\PRAMAN`` without
    modifying the read-only PyInstaller bundle.
    """
    downloaded = WRITABLE_DATA_DIR / relative
    if downloaded.is_file():
        return downloaded
    return bundled or DATA_DIR / relative

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

# "classifiers" enables the shipped CPU models without probing a local LLM.
SENTINEL_AI_BACKEND = os.environ.get("SENTINEL_AI_BACKEND", "full")

# Self-service registration lets evaluators use their own identity. Managed
# appliances can disable it and provision operators with manage_users.py.
SIGNUP_ENABLED = os.environ.get("PRAMAN_SIGNUP_ENABLED", "true").lower() in {
    "1", "true", "yes",
}

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
