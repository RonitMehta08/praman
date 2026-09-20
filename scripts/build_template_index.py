"""Build the Drain3 template embedding index for nearest-neighbour search.

Mines templates from the network config corpus using Drain3, embeds them
with TF-IDF character n-grams + TruncatedSVD, and stores the result in a
sqlite-vec database for the training GUI's suggestion engine and NL search.

Usage:
    python -m scripts.build_template_index --corpus data\\corpus --out data\\index\\templates.sqlite3
    python -m scripts.build_template_index --verify --out data\\index\\templates.sqlite3

MANUAL_COMMANDS.md Step 7 (OPTIONAL — needed for training-GUI suggestions).

Drain3 invariant: this script calls add_log_message() (mutation/training path).
The audit path must use match() only (read-only). Never mix them.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import sqlite_vec
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer

# ─── Constants ─────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Config file extensions to scan in the corpus
CONFIG_EXTENSIONS = frozenset({".cfg", ".conf"})

# Files with these extensions are never config files
SKIP_EXTENSIONS = frozenset({
    ".py", ".md", ".yml", ".yaml", ".json", ".toml", ".txt", ".lock",
    ".xml", ".html", ".css", ".js", ".ts", ".java", ".bazel", ".bzl",
    ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".zip", ".gz", ".tar", ".jar", ".war", ".class",
    ".gitignore", ".gitattributes",
})

# Drain3 tuning for network config (not syslog)
DRAIN_DEPTH = 4
DRAIN_SIMILARITY_THRESHOLD = 0.4
DRAIN_MAX_CLUSTERS = 2048

# Embedding dimensions after SVD truncation
EMBEDDING_DIM = 256

# Max sample lines stored per template
MAX_SAMPLE_LINES = 5

# Min lines a file must have to be considered a config file
MIN_CONFIG_LINES = 3


def _build_drain_config() -> TemplateMinerConfig:
    """Build Drain3 config tuned for network device configuration lines."""
    config = TemplateMinerConfig()
    config.drain_depth = DRAIN_DEPTH
    config.drain_sim_th = DRAIN_SIMILARITY_THRESHOLD
    config.drain_max_clusters = DRAIN_MAX_CLUSTERS
    # Don't persist Drain3 state — we rebuild from scratch each time
    config.profiling_enabled = False
    config.snapshot_interval_minutes = 0
    return config


def _is_config_file(path: Path) -> bool:
    """Heuristic: return True if the file looks like a network config."""
    suffix = path.suffix.lower()

    # Explicit config extensions
    if suffix in CONFIG_EXTENSIONS:
        return True

    # Skip known non-config extensions
    if suffix in SKIP_EXTENSIONS:
        return False

    # Skip dotfiles and known non-config basenames
    if path.name.startswith("."):
        return False

    # Extensionless or unknown-extension files: probe the content
    # (Batfish test configs are .cfg, but some may lack extensions)
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    except (OSError, UnicodeDecodeError):
        return False

    # Network config heuristics: look for common CLI patterns
    config_markers = (
        "hostname ", "set system ", "set interfaces ", "set protocols ",
        "interface ", "ip address ", "router ", "no service ",
        "service ", "access-list ", "snmp-server ", "logging ",
        "set firewall ", "set security ", "set routing-options ",
        "boot-start-marker", "version ", "aaa ", "line con ",
    )
    marker_count = sum(1 for m in config_markers if m in head)
    return marker_count >= 2


def _clean_line(line: str) -> str | None:
    """Clean a config line for template mining. Returns None if skip."""
    stripped = line.strip()

    # Skip empty, comments-only, section markers
    if not stripped:
        return None
    if stripped.startswith(("!", "#", "/*", "*/", "//", "---")):
        return None
    # Skip bare braces / end markers
    if stripped in ("{", "}", ";", "end", "exit"):
        return None

    return stripped


def collect_corpus_lines(corpus_dir: Path) -> list[str]:
    """Walk the corpus directory and collect cleaned config lines.

    Returns:
        Deduplicated list of cleaned config lines.
    """
    if not corpus_dir.exists():
        print(f"[ERROR] Corpus directory does not exist: {corpus_dir}", file=sys.stderr)
        sys.exit(1)

    seen_lines: set[str] = set()
    config_files_found = 0

    for filepath in sorted(corpus_dir.rglob("*")):
        if not filepath.is_file():
            continue
        # Skip git internals
        if ".git" in filepath.parts:
            continue
        if not _is_config_file(filepath):
            continue

        config_files_found += 1
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"[WARN] Cannot read {filepath}: {e}", file=sys.stderr)
            continue

        lines = text.splitlines()
        if len(lines) < MIN_CONFIG_LINES:
            continue

        for raw_line in lines:
            cleaned = _clean_line(raw_line)
            if cleaned and cleaned not in seen_lines:
                seen_lines.add(cleaned)

    print(f"[collect] Scanned {config_files_found} config files")
    print(f"[collect] {len(seen_lines):,} unique config lines collected")
    return sorted(seen_lines)


def mine_templates(lines: list[str]) -> list[dict[str, Any]]:
    """Run Drain3 over all config lines to mine templates.

    Returns:
        List of dicts: {template_id, template, cluster_size, sample_lines}
    """
    config = _build_drain_config()
    miner = TemplateMiner(config=config)

    # Track sample lines per cluster
    cluster_samples: dict[int, list[str]] = {}

    for line in lines:
        result = miner.add_log_message(line)
        cid = result["cluster_id"]
        if cid not in cluster_samples:
            cluster_samples[cid] = []
        if len(cluster_samples[cid]) < MAX_SAMPLE_LINES:
            cluster_samples[cid].append(line)

    templates: list[dict[str, Any]] = []
    for cluster in miner.drain.clusters:
        templates.append({
            "template_id": cluster.cluster_id,
            "template": cluster.get_template(),
            "cluster_size": cluster.size,
            "sample_lines": cluster_samples.get(cluster.cluster_id, []),
        })

    print(f"[drain3] Mined {len(templates):,} templates from {len(lines):,} lines")
    return templates


def embed_templates(templates: list[dict[str, Any]]) -> np.ndarray:
    """Embed template strings with TF-IDF char n-grams + TruncatedSVD.

    Returns:
        Float32 matrix of shape (n_templates, EMBEDDING_DIM).
    """
    template_texts = [t["template"] for t in templates]
    n_templates = len(template_texts)

    # TF-IDF on character n-grams (3-6 chars) — good for structured CLI text
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 6),
        max_features=8192,
        sublinear_tf=True,
    )
    tfidf_matrix = vectorizer.fit_transform(template_texts)

    # Truncate to EMBEDDING_DIM via SVD (Latent Semantic Analysis)
    actual_dim = min(EMBEDDING_DIM, tfidf_matrix.shape[1] - 1, n_templates - 1)
    if actual_dim < 1:
        # Fallback: if very few templates, pad with zeros
        actual_dim = 1

    svd = TruncatedSVD(n_components=actual_dim, random_state=42)
    reduced = svd.fit_transform(tfidf_matrix)

    # Pad to EMBEDDING_DIM if needed (when corpus is very small)
    if reduced.shape[1] < EMBEDDING_DIM:
        padding = np.zeros((n_templates, EMBEDDING_DIM - reduced.shape[1]), dtype=np.float32)
        reduced = np.hstack([reduced, padding])

    # L2-normalize for cosine similarity via dot product
    norms = np.linalg.norm(reduced, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)
    normalized = (reduced / norms).astype(np.float32)

    explained = svd.explained_variance_ratio_.sum() * 100
    print(f"[embed] TF-IDF -> {tfidf_matrix.shape[1]} features -> SVD({actual_dim}d)")
    print(f"[embed] Explained variance: {explained:.1f}%")
    print(f"[embed] Output shape: {normalized.shape}")

    return normalized


def store_index(
    out_path: Path,
    templates: list[dict[str, Any]],
    embeddings: np.ndarray,
    corpus_dir: Path,
) -> None:
    """Write templates and embeddings to a sqlite-vec database."""
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove existing file for clean rebuild
    if out_path.exists():
        out_path.unlink()

    conn = sqlite3.connect(str(out_path))
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)

    # Metadata table
    conn.execute("""
        CREATE TABLE metadata (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # Templates table (relational data)
    conn.execute("""
        CREATE TABLE templates (
            template_id  INTEGER PRIMARY KEY,
            template     TEXT NOT NULL UNIQUE,
            cluster_size INTEGER NOT NULL,
            sample_lines TEXT NOT NULL DEFAULT '[]'
        )
    """)

    # sqlite-vec virtual table for nearest-neighbour search
    conn.execute(f"""
        CREATE VIRTUAL TABLE vec_templates USING vec0(
            embedding float[{EMBEDDING_DIM}]
        )
    """)

    # Insert templates and vectors
    # strict: one embedding per template is an invariant of the build, and a
    # silent truncation here would ship an index missing its tail.
    for tmpl, vec in zip(templates, embeddings, strict=True):
        conn.execute(
            "INSERT INTO templates (template_id, template, cluster_size, sample_lines) "
            "VALUES (?, ?, ?, ?)",
            (
                tmpl["template_id"],
                tmpl["template"],
                tmpl["cluster_size"],
                json.dumps(tmpl["sample_lines"], ensure_ascii=False),
            ),
        )
        conn.execute(
            "INSERT INTO vec_templates (rowid, embedding) VALUES (?, ?)",
            (tmpl["template_id"], vec.tobytes()),
        )

    # Insert metadata
    build_meta = {
        "corpus_dir": str(corpus_dir),
        "template_count": len(templates),
        "embedding_dim": EMBEDDING_DIM,
        "drain_depth": DRAIN_DEPTH,
        "drain_sim_th": DRAIN_SIMILARITY_THRESHOLD,
        "build_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "total_cluster_lines": sum(t["cluster_size"] for t in templates),
    }
    for k, v in build_meta.items():
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            (k, json.dumps(v) if not isinstance(v, str) else v),
        )

    conn.commit()

    # Create index on template text for exact lookups
    conn.execute("CREATE INDEX idx_template_text ON templates(template)")
    conn.commit()
    conn.close()

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"[store] Wrote {out_path} ({size_mb:.1f} MB)")
    print(f"[store] {len(templates):,} templates, {EMBEDDING_DIM}-dim embeddings")


def verify_index(out_path: Path) -> None:
    """Read the database and run a nearest-neighbour probe to verify it works."""
    if not out_path.exists():
        print(f"[FAIL] Index file does not exist: {out_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(out_path))
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.row_factory = sqlite3.Row

    # Read metadata
    print("=" * 60)
    print("PRAMAN Template Index — Verification")
    print("=" * 60)
    print()

    rows = conn.execute("SELECT key, value FROM metadata ORDER BY key").fetchall()
    for row in rows:
        print(f"  {row['key']}: {row['value']}")
    print()

    # Count templates
    count = conn.execute("SELECT COUNT(*) as n FROM templates").fetchone()["n"]
    print(f"[verify] Template count: {count}")

    if count == 0:
        print("[FAIL] Zero templates in index — corpus may be empty", file=sys.stderr)
        conn.close()
        sys.exit(1)

    # Pick a random template and run NN search
    sample = conn.execute(
        "SELECT template_id, template FROM templates ORDER BY cluster_size DESC LIMIT 1"
    ).fetchone()
    print(f"[verify] Probe template: [{sample['template_id']}] {sample['template'][:80]}...")

    # Get its embedding
    vec_row = conn.execute(
        "SELECT embedding FROM vec_templates WHERE rowid = ?",
        (sample["template_id"],),
    ).fetchone()

    if vec_row is None:
        print("[FAIL] Embedding not found for probe template", file=sys.stderr)
        conn.close()
        sys.exit(1)

    probe_vec = vec_row["embedding"]

    # NN query (top 5)
    neighbors = conn.execute(
        "SELECT rowid, distance FROM vec_templates "
        "WHERE embedding MATCH ? AND k = 5",
        (probe_vec,),
    ).fetchall()

    print(f"[verify] Nearest neighbours ({len(neighbors)} returned):")
    for nb in neighbors:
        tmpl = conn.execute(
            "SELECT template FROM templates WHERE template_id = ?",
            (nb["rowid"],),
        ).fetchone()
        tmpl_text = tmpl["template"][:60] if tmpl else "???"
        print(f"    [{nb['rowid']}] dist={nb['distance']:.4f}  {tmpl_text}")

    conn.close()
    print()
    print("[PASS] Template index verification successful")


def main() -> None:
    """Entry point for python -m scripts.build_template_index."""
    parser = argparse.ArgumentParser(
        description="Build the Drain3 template embedding index (MANUAL_COMMANDS.md Step 7)",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=PROJECT_ROOT / "data" / "corpus",
        help="Path to the corpus directory (default: data/corpus)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "index" / "templates.sqlite3",
        help="Output path for the sqlite-vec database (default: data/index/templates.sqlite3)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify an existing index instead of building one",
    )
    args = parser.parse_args()

    # Resolve relative paths against project root
    corpus_path = args.corpus if args.corpus.is_absolute() else PROJECT_ROOT / args.corpus
    out_path = args.out if args.out.is_absolute() else PROJECT_ROOT / args.out

    if args.verify:
        verify_index(out_path)
        return

    print("=" * 60)
    print("PRAMAN — Build Template Index (Step 7)")
    print("=" * 60)
    print(f"  corpus: {corpus_path}")
    print(f"  output: {out_path}")
    print()

    t0 = time.time()

    # 1. Collect config lines from corpus
    lines = collect_corpus_lines(corpus_path)
    if not lines:
        print("[ERROR] No config lines found in corpus. Check --corpus path.", file=sys.stderr)
        sys.exit(1)

    # 2. Mine Drain3 templates
    templates = mine_templates(lines)
    if not templates:
        print("[ERROR] Drain3 produced zero templates.", file=sys.stderr)
        sys.exit(1)

    # 3. Embed templates
    embeddings = embed_templates(templates)

    # 4. Store in sqlite-vec
    store_index(out_path, templates, embeddings, corpus_path)

    elapsed = time.time() - t0
    print()
    print(f"[done] Completed in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
