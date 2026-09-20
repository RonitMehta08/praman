"""Train the TF-IDF syntax classifier (AI Escalation Ladder Tier 1).

Maps unrecognised config lines to canonical field paths using a supervised
TF-IDF char-ngram + LogisticRegression pipeline.

Usage:
    python -m scripts.train_classifier \
      --labels data\\labels\\line_to_path.jsonl \
      --out data\\models\\classifier\\ \
      --group-by device \
      --calibrate sigmoid \
      --report reports\\metrics\\classifier.json

MANUAL_COMMANDS.md Step 8a.

If no labeled data exists yet, the script auto-generates labels by running the
deterministic parsers over the corpus — these are the ground-truth mappings
with confidence=1.0.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ─── Label generation ──────────────────────────────────────────────────

def _generate_labels_from_corpus(corpus_dir: Path, labels_path: Path) -> Path:
    """Auto-generate labeled data by running deterministic parsers over the corpus.

    Each parser produces CanonicalFacts with confidence=1.0. We extract
    (raw_text, path, source_file) triples as training labels.
    """
    from backend.ingest.cisco_ios import CiscoIOSAdapter
    from backend.ingest.junos import JunosAdapter

    adapters = [CiscoIOSAdapter(), JunosAdapter()]
    labels: list[dict[str, str]] = []
    files_parsed = 0

    config_extensions = {".cfg", ".conf"}

    for filepath in sorted(corpus_dir.rglob("*")):
        if not filepath.is_file():
            continue
        if ".git" in filepath.parts:
            continue

        suffix = filepath.suffix.lower()
        # An extensionless file is kept and sniffed by content below; a file
        # with some other extension is not a configuration.
        if suffix not in config_extensions and suffix and suffix not in {"", ".txt"}:
            continue

        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if len(text.strip()) < 50:
            continue

        # Find matching adapter
        for adapter in adapters:
            if not adapter.can_parse(text, filepath.name):
                continue

            try:
                result = adapter.parse(text, str(filepath.relative_to(corpus_dir)))
            except Exception:
                continue

            files_parsed += 1
            device_id = result.device.device_id if result.device else filepath.stem

            for fact in result.facts:
                if fact.confidence >= 1.0 and fact.raw_text.strip():
                    labels.append({
                        "line": fact.raw_text.strip(),
                        "path": fact.path,
                        "device": device_id,
                        "source_file": fact.source_file,
                    })
            break  # First matching adapter wins

    if not labels:
        print("[ERROR] No labeled data generated from corpus.", file=sys.stderr)
        print("  Ensure the corpus contains parseable config files.", file=sys.stderr)
        sys.exit(1)

    # Write JSONL
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    with labels_path.open("w", encoding="utf-8") as f:
        for label in labels:
            f.write(json.dumps(label, ensure_ascii=False) + "\n")

    print(f"[labels] Generated {len(labels):,} labels from {files_parsed} config files")
    print(f"[labels] Wrote {labels_path}")
    return labels_path


def _load_labels(labels_path: Path) -> tuple[list[str], list[str], list[str]]:
    """Load JSONL labels into parallel lists.

    Returns:
        (lines, paths, device_ids)
    """
    lines: list[str] = []
    paths: list[str] = []
    devices: list[str] = []

    with labels_path.open("r", encoding="utf-8") as f:
        for line_num, raw_line in enumerate(f, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping malformed line {line_num}: {e}", file=sys.stderr)
                continue

            text = record.get("line", "").strip()
            path = record.get("path", "").strip()
            device = record.get("device", "unknown")

            if text and path:
                lines.append(text)
                paths.append(path)
                devices.append(device)

    return lines, paths, devices


# ─── Training ──────────────────────────────────────────────────────────

def train_classifier(
    lines: list[str],
    paths: list[str],
    devices: list[str],
    out_dir: Path,
    calibrate: str,
    report_path: Path,
) -> dict[str, Any]:
    """Train a TF-IDF + LogisticRegression pipeline with cross-validation.

    Args:
        lines: Config line texts.
        paths: Canonical path labels.
        devices: Device IDs for group-based splitting.
        out_dir: Directory to save model artifacts.
        calibrate: Calibration method ('sigmoid' or 'isotonic').
        report_path: Path for the metrics JSON report.

    Returns:
        Metrics dictionary.
    """
    import joblib
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        f1_score,
    )
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.pipeline import Pipeline

    X = np.array(lines)
    y = np.array(paths)
    groups = np.array(devices)

    unique_labels = sorted(set(y))
    n_classes = len(unique_labels)
    n_samples = len(X)
    unique_devices = len(set(groups))

    print(f"[train] {n_samples:,} samples, {n_classes} classes, {unique_devices} devices")

    # Filter out classes with too few samples for stratified CV
    # Need at least n_splits samples per class
    n_splits = min(5, unique_devices)
    if n_splits < 2:
        print("[WARN] Only 1 device group — falling back to 2-fold split", file=sys.stderr)
        n_splits = 2

    # Build the pipeline
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 6),
        max_features=8192,
        sublinear_tf=True,
    )
    lr = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        n_jobs=-1,
    )
    pipeline = Pipeline([
        ("tfidf", tfidf),
        ("clf", lr),
    ])

    # ── Cross-validation with StratifiedGroupKFold ──────────────────
    # Groups by device so the same device's lines never appear in both
    # train and test — prevents information leakage.
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)

    fold_metrics: list[dict[str, Any]] = []
    all_y_true: list[str] = []
    all_y_pred: list[str] = []

    print(f"[train] {n_splits}-fold StratifiedGroupKFold cross-validation")

    for fold_idx, (train_idx, test_idx) in enumerate(sgkf.split(X, y, groups)):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
        f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

        fold_metrics.append({
            "fold": fold_idx + 1,
            "accuracy": round(float(acc), 4),
            "f1_macro": round(float(f1_macro), 4),
            "f1_weighted": round(float(f1_weighted), 4),
            "train_size": len(train_idx),
            "test_size": len(test_idx),
            "train_devices": len(set(groups[train_idx])),
            "test_devices": len(set(groups[test_idx])),
        })

        all_y_true.extend(y_test.tolist())
        all_y_pred.extend(y_pred.tolist())

        print(f"  Fold {fold_idx + 1}: acc={acc:.4f}  F1(macro)={f1_macro:.4f}  "
              f"F1(weighted)={f1_weighted:.4f}")

    # Aggregate CV metrics
    mean_acc = np.mean([f["accuracy"] for f in fold_metrics])
    mean_f1_macro = np.mean([f["f1_macro"] for f in fold_metrics])
    mean_f1_weighted = np.mean([f["f1_weighted"] for f in fold_metrics])

    print(f"\n[train] Mean: acc={mean_acc:.4f}  F1(macro)={mean_f1_macro:.4f}  "
          f"F1(weighted)={mean_f1_weighted:.4f}")

    # ── Train final model on ALL data ──────────────────────────────
    print("[train] Training final model on all data...")
    pipeline.fit(X, y)

    # Calibrate probabilities
    if calibrate in ("sigmoid", "isotonic"):
        print(f"[train] Calibrating with method='{calibrate}'...")
        calibrated = CalibratedClassifierCV(
            pipeline,
            cv=min(3, n_splits),
            method=calibrate,
        )
        calibrated.fit(X, y)
        final_model = calibrated
    else:
        final_model = pipeline

    # ── Save artifacts ─────────────────────────────────────────────
    out_dir.mkdir(parents=True, exist_ok=True)

    model_path = out_dir / "tfidf_pipeline.joblib"
    joblib.dump(final_model, str(model_path), compress=3)
    model_size_mb = model_path.stat().st_size / (1024 * 1024)
    print(f"[save] Wrote {model_path} ({model_size_mb:.1f} MB)")

    # Save label map
    label_map_path = out_dir / "label_map.json"
    label_map_path.write_text(
        json.dumps({"classes": unique_labels}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # ── Build metrics report ───────────────────────────────────────
    overall_report = classification_report(
        all_y_true, all_y_pred, zero_division=0, output_dict=True,
    )

    metrics: dict[str, Any] = {
        "model": "TF-IDF char-ngram + LogisticRegression",
        "calibration": calibrate,
        "split_strategy": "StratifiedGroupKFold",
        "split_group_by": "device",
        "n_splits": n_splits,
        "n_samples": n_samples,
        "n_classes": n_classes,
        "n_devices": unique_devices,
        "classes": unique_labels,
        "fold_metrics": fold_metrics,
        "mean_accuracy": round(float(mean_acc), 4),
        "mean_f1_macro": round(float(mean_f1_macro), 4),
        "mean_f1_weighted": round(float(mean_f1_weighted), 4),
        "per_class": {
            k: v for k, v in overall_report.items()
            if isinstance(v, dict)
        },
        "model_artifact": str(model_path),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[report] Wrote {report_path}")

    return metrics


# ─── CLI ───────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point for python -m scripts.train_classifier."""
    parser = argparse.ArgumentParser(
        description="Train the TF-IDF syntax classifier (MANUAL_COMMANDS.md Step 8a)",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=PROJECT_ROOT / "data" / "labels" / "line_to_path.jsonl",
        help="Path to labeled JSONL data (default: data/labels/line_to_path.jsonl)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "models" / "classifier",
        help="Output directory for model artifacts (default: data/models/classifier/)",
    )
    parser.add_argument(
        "--group-by",
        dest="group_by",
        choices=["device"],
        default="device",
        help="CV grouping strategy (default: device)",
    )
    parser.add_argument(
        "--calibrate",
        choices=["sigmoid", "isotonic", "none"],
        default="sigmoid",
        help="Probability calibration method (default: sigmoid)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=PROJECT_ROOT / "reports" / "metrics" / "classifier.json",
        help="Output path for the metrics JSON report",
    )
    args = parser.parse_args()

    # Resolve relative paths against project root
    labels_path = args.labels if args.labels.is_absolute() else PROJECT_ROOT / args.labels
    out_dir = args.out if args.out.is_absolute() else PROJECT_ROOT / args.out
    report_path = args.report if args.report.is_absolute() else PROJECT_ROOT / args.report

    print("=" * 60)
    print("PRAMAN -- Train Syntax Classifier (Step 8a)")
    print("=" * 60)

    t0 = time.time()

    # Auto-generate labels if they don't exist
    if not labels_path.exists():
        print(f"[labels] {labels_path} not found -- auto-generating from corpus...")
        corpus_dir = PROJECT_ROOT / "data" / "corpus"
        labels_path = _generate_labels_from_corpus(corpus_dir, labels_path)

    # Load labels
    lines, paths, devices = _load_labels(labels_path)
    if not lines:
        print("[ERROR] No valid labeled data found.", file=sys.stderr)
        sys.exit(1)

    unique_paths = sorted(set(paths))
    print(f"[data] Loaded {len(lines):,} samples, {len(unique_paths)} unique paths")
    print(f"[data] Devices: {len(set(devices))}")
    print(f"[data] Top paths: {unique_paths[:5]}...")
    print()

    # Filter classes with too few samples (need at least 2 for stratification)
    from collections import Counter
    path_counts = Counter(paths)
    min_samples = 2
    rare_paths = {p for p, c in path_counts.items() if c < min_samples}
    if rare_paths:
        print(f"[data] Filtering {len(rare_paths)} rare paths (< {min_samples} samples)")
        filtered = [
            (line, path, device)
            for line, path, device in zip(lines, paths, devices, strict=True)
            if path not in rare_paths
        ]
        lines = [x[0] for x in filtered]
        paths = [x[1] for x in filtered]
        devices = [x[2] for x in filtered]
        print(f"[data] After filtering: {len(lines):,} samples, "
              f"{len(set(paths))} paths")
        print()

    if len(lines) < 10:
        print("[ERROR] Too few labeled samples to train a classifier.", file=sys.stderr)
        sys.exit(1)

    # Train
    metrics = train_classifier(
        lines=lines,
        paths=paths,
        devices=devices,
        out_dir=out_dir,
        calibrate=args.calibrate,
        report_path=report_path,
    )

    elapsed = time.time() - t0
    print()
    print(f"[done] Completed in {elapsed:.1f}s")
    print(f"[done] Mean accuracy: {metrics['mean_accuracy']:.4f}")
    print(f"[done] Mean F1 (weighted): {metrics['mean_f1_weighted']:.4f}")


if __name__ == "__main__":
    main()
