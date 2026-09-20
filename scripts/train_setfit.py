"""Train the SetFit few-shot classifier (AI Escalation Ladder Tier 2).

Tier 2 sits between the TF-IDF pipeline (Tier 1, cheap and literal) and the local
LLM (Tier 3, expensive and general). It exists because the two neighbours fail in
opposite ways on the same input: TF-IDF matches character n-grams, so it cannot
generalise from ``ip prefix-list`` to ``ipv6 prefix-list`` unless it saw both,
while the LLM generalises freely and costs three orders of magnitude more per
line. A sentence-transformer fine-tuned on the same labels bridges that gap.

Why this script exists at all: ``backend/ai/setfit_clf.py`` loads a model from
``data/models/classifier/setfit_model``, and until now **nothing in this project
wrote that directory**. ``scripts/train_classifier.py`` trains only the TF-IDF
pipeline despite its name being read as covering both, so Tier 2 reported
``is_available() == False`` on every machine, forever, and the escalation ladder
silently ran two tiers instead of three. A tier whose artefact no script produces
is not a degraded tier, it is an absent feature with a loader attached.

Usage:
    python -m scripts.train_setfit \\
      --labels data\\labels\\line_to_path.jsonl \\
      --out data\\models\\classifier\\setfit_model \\
      --report reports\\metrics\\setfit.json

MANUAL_COMMANDS.md Step 8c. Requires ``setfit`` and ``sentence-transformers``,
which the Step 1 venv does not install — see that step for the exact command.

The heavy imports (``torch``, ``setfit``) are deliberately deferred into
``train_setfit`` so this module can be imported, linted and unit-tested on a
machine with none of them installed. That mirrors ``setfit_clf.py``, which does
the same thing for the same reason.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

#: Base sentence-transformer. 22.7M params, 384-dim, and small enough that the
#: fine-tune fits well inside a 6 GB card — the constraint on this machine is the
#: download, not the VRAM. Pinned rather than configurable because
#: ``backend/ai/setfit_clf.py`` documents this exact model in its header, and a
#: model trained from a different base would load fine and score differently.
BASE_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

#: A class needs enough examples for the contrastive pairs to mean anything.
#: SetFit's own guidance is 8–16 per class; below that the pair sampling degenerates
#: to comparing a sample against itself. Rarer classes are *reported*, not silently
#: dropped — see ``_partition_by_support``.
MIN_SUPPORT = 8

#: Where SetFit's ``Trainer`` may write its intermediate checkpoints.
#:
#: Named because ``TrainingArguments.output_dir`` defaults to the relative string
#: ``"checkpoints"``, which resolves against the *current working directory* — so
#: running this script from the repository root silently created a 260 MB
#: ``praman/checkpoints/`` that no ``.gitignore`` covered and that looked, to
#: anyone reading ``git status``, like a directory the project meant to have. It
#: is pinned under ``data/models/classifier/`` instead, which is already
#: gitignored alongside the artefact these checkpoints are intermediate steps
#: towards, and is derived from ``--out`` so redirecting the model redirects them
#: with it rather than leaving them behind in the old place.
CHECKPOINT_DIR_NAME = "setfit_checkpoints"

#: Filename of the nearest-neighbour index written beside the model.
#:
#: The head alone cannot tell a line it understands from a line that merely looks
#: like its training data, and on this corpus that failure is severe rather than
#: theoretical. Measured on the shipped artefact:
#:
#:     "no passive-interface GigabitEthernet0/0" -> interface.admin_state  0.9935
#:     "passive-interface default"               -> interface.admin_state  0.9927
#:     "switchport trunk encapsulation dot1q"    -> interface.admin_state  0.9455
#:     '{"framework": "CIS", "result": "pass"}'  -> interface.admin_state  0.9249
#:     "shutdown"                                -> interface.admin_state  0.1552
#:
#: The first four are wrong and confident; the last is right and unconfident. No
#: threshold on that column separates them, so the tier needs a second signal that
#: is not the head's probability. This index is that signal: the embeddings of the
#: training lines, so inference can ask "how close is this to anything I was
#: actually taught?" rather than only "which of my 14 labels fits best?".
#:
#: It is written at training time rather than rebuilt at load because encoding the
#: corpus costs seconds, and paying that on every backend start would turn a
#: safety guard into a startup regression.
NEIGHBOUR_INDEX_NAME = "neighbour_index.npz"


def build_neighbour_index(model: object, records: list[dict[str, str]], out_dir: Path) -> Path:
    """Encode the training lines and save them as the OOD reference set.

    Stored normalised so inference is a single matrix product and the cosine
    similarity needs no per-query division. float32 keeps 1,443 x 384 at ~2.2 MB,
    which is small next to the 90 MB model it sits beside.
    """
    import numpy as np

    body = model.model_body  # type: ignore[attr-defined]
    lines = [r["line"] for r in records]
    embeddings = np.asarray(
        body.encode(lines, normalize_embeddings=True, show_progress_bar=False),
        dtype="float32",
    )
    path = out_dir / NEIGHBOUR_INDEX_NAME
    np.savez_compressed(
        path,
        embeddings=embeddings,
        labels=np.asarray([r["path"] for r in records], dtype=object),
    )
    return path


def _load_labels(labels_path: Path) -> list[dict[str, str]]:
    """Read the JSONL label file written by ``scripts/train_classifier.py``.

    Same file, same schema (``line`` / ``path`` / ``device``), on purpose: two
    tiers trained on two different label sets would make their confidence scores
    incomparable, and the escalation ladder compares them directly when it decides
    whether to escalate.
    """
    records: list[dict[str, str]] = []
    with labels_path.open("r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError as err:
                print(f"[warn] {labels_path}:{number}: {err}", file=sys.stderr)
                continue
            text = str(record.get("line", "")).strip()
            path = str(record.get("path", "")).strip()
            if not text or not path:
                continue
            records.append(
                {"line": text, "path": path, "device": str(record.get("device", "unknown"))}
            )
    return records


def _partition_by_support(
    records: list[dict[str, str]], min_support: int
) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Split records into trainable classes and a census of the ones held back.

    Returns ``(kept, excluded)`` where ``excluded`` maps a class to its support.

    The excluded census is returned rather than logged and forgotten because it is
    the honest ceiling on this tier: a path with three examples in the corpus is a
    path Tier 2 will never predict, and a reader of ``reports/metrics/setfit.json``
    should be able to see which ones those are without re-deriving them.
    """
    support = Counter(r["path"] for r in records)
    excluded = {p: n for p, n in sorted(support.items()) if n < min_support}
    kept = [r for r in records if support[r["path"]] >= min_support]
    return kept, excluded


def _grouped_split(
    records: list[dict[str, str]], holdout_fraction: float = 0.25
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Hold out whole devices, never individual lines.

    Splitting by line leaks badly here and the leak flatters the result: the same
    device contributes near-identical ``interface`` stanzas dozens of times, so a
    line-wise split puts textual near-duplicates on both sides and the test score
    measures memorisation. ``train_classifier.py`` uses ``StratifiedGroupKFold``
    grouped by device for exactly this reason; this is the same discipline in the
    cheaper single-split form, because a SetFit fine-tune is minutes rather than
    seconds and five folds of it is not worth the wall clock.

    Devices are assigned by sorted order rather than at random so the split is
    reproducible without seeding a global RNG.
    """
    by_device: dict[str, list[dict[str, str]]] = {}
    for record in records:
        by_device.setdefault(record["device"], []).append(record)

    devices = sorted(by_device)
    if len(devices) < 2:
        raise SystemExit(
            f"only {len(devices)} device group in the labels, so no honest "
            "held-out split exists. Add configs from more devices before trusting "
            "any number this script prints."
        )

    # Largest-first so the holdout is not accidentally all tiny devices.
    devices.sort(key=lambda d: (-len(by_device[d]), d))
    target = max(1, round(len(records) * holdout_fraction))
    test: list[dict[str, str]] = []
    test_devices: set[str] = set()
    # Fill the holdout from the *second* largest downwards: the largest device is
    # usually the one carrying the dominant class, and moving it wholesale into the
    # holdout leaves the training set unable to learn that class at all.
    for device in devices[1:]:
        if len(test) >= target:
            break
        test.extend(by_device[device])
        test_devices.add(device)

    train = [r for r in records if r["device"] not in test_devices]
    if not train or not test:
        raise SystemExit("device split produced an empty side; check the label file")
    return train, test


def train_setfit(
    records: list[dict[str, str]],
    out_dir: Path,
    report_path: Path,
    min_support: int = MIN_SUPPORT,
    base_model: str = BASE_MODEL,
) -> dict[str, Any]:
    """Fine-tune, evaluate on held-out devices, save, and write the metrics report.

    Every figure in the report is measured here. Nothing is copied from the TF-IDF
    report, even where the two would plausibly be similar, because
    ``GLOBAL_RULESET.md`` R1.3 requires each published number to trace to the
    script that produced it.
    """
    # Deferred: see the module docstring. Import failure is a message about the
    # environment, not a traceback about a missing wheel.
    try:
        from setfit import SetFitModel, Trainer, TrainingArguments
    except ImportError as err:  # pragma: no cover - depends on the environment
        raise SystemExit(
            "setfit is not installed in this interpreter. Tier 2 needs "
            "'setfit' and 'sentence-transformers', which the Step 1 venv does "
            "not install — run MANUAL_COMMANDS.md Step 8c first.\n"
            f"  interpreter: {sys.executable}\n"
            f"  import error: {err}"
        ) from err
    from datasets import Dataset
    from sklearn.metrics import accuracy_score, classification_report, f1_score

    kept, excluded = _partition_by_support(records, min_support)
    if not kept:
        raise SystemExit(
            f"no class has {min_support} examples, so there is nothing to train. "
            "Label more lines, or lower --min-support and accept a weaker model."
        )

    train_rows, test_rows = _grouped_split(kept)
    classes = sorted({r["path"] for r in kept})
    print(
        f"[data] {len(kept):,} samples over {len(classes)} classes "
        f"({len(excluded)} classes held back below {min_support} examples)"
    )
    print(f"[data] train {len(train_rows):,} / holdout {len(test_rows):,} (split by device)")

    train_ds = Dataset.from_dict(
        {"text": [r["line"] for r in train_rows], "label": [r["path"] for r in train_rows]}
    )

    print(f"[train] fine-tuning {base_model} ...")
    started = time.perf_counter()
    checkpoint_dir = out_dir.parent / CHECKPOINT_DIR_NAME
    model = SetFitModel.from_pretrained(base_model, labels=classes)
    trainer = Trainer(
        model=model,
        train_dataset=train_ds,
        args=TrainingArguments(
            # Absolute, and beside the model rather than under the cwd. See
            # CHECKPOINT_DIR_NAME: the default is a *relative* "checkpoints".
            output_dir=str(checkpoint_dir),
            batch_size=16,
            num_epochs=1,
            # One epoch over the contrastive pairs is SetFit's own default and is
            # what keeps this a minutes-long job. num_iterations controls how many
            # pairs are sampled per example, which is the real knob.
            num_iterations=20,
            seed=42,
            report_to="none",
        ),
        metric="accuracy",
    )
    trainer.train()
    train_seconds = time.perf_counter() - started

    y_true = [r["path"] for r in test_rows]
    y_pred = [str(p) for p in model.predict([r["line"] for r in test_rows])]

    accuracy = float(accuracy_score(y_true, y_pred))
    # `labels=` is deliberately NOT passed. Holding out whole devices means the
    # holdout carries only the classes those devices happen to use — 7 of 14 on the
    # shipped corpus — and forcing the other 7 into the average would score them 0
    # for having no support, understating the model for a property of the split
    # rather than of the model. The classes actually measured are published below
    # so the denominator of this average is never in doubt.
    f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    per_class = classification_report(y_true, y_pred, zero_division=0, output_dict=True)
    measured = sorted(set(y_true))

    # A device-grouped holdout inherits the corpus imbalance, and on this corpus it
    # inherits it badly: `interface.admin_state` is 81% of the labels, so whichever
    # devices land in the holdout, one class dominates it. That makes `accuracy`
    # true and nearly uninformative, and it is published together with the share
    # below so the headline can never be quoted without its denominator. A reader
    # who sees 1.00 and 94.1% at the same time draws the right conclusion; a reader
    # who sees only 1.00 does not.
    holdout_distribution = dict(Counter(y_true).most_common())
    majority_class, majority_count = next(iter(holdout_distribution.items()))
    majority_share = round(100.0 * majority_count / len(y_true), 1)

    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(out_dir))
    print(f"[save] wrote {out_dir}")

    # Built from the *training* rows only. Including the holdout would let a line
    # be judged in-distribution because it is near an example the model never saw,
    # which is the same leak the device-grouped split exists to prevent.
    index_path = build_neighbour_index(model, train_rows, out_dir)
    print(f"[save] wrote {index_path.name} ({index_path.stat().st_size / 1e6:.1f} MB)")

    metrics: dict[str, Any] = {
        "model": f"SetFit few-shot over {base_model}",
        "tier": 2,
        "base_model": base_model,
        "split_strategy": "held-out devices (single split)",
        "split_group_by": "device",
        "holdout_devices": sorted({r["device"] for r in test_rows}),
        "n_samples": len(kept),
        "n_train": len(train_rows),
        "n_holdout": len(test_rows),
        "n_classes": len(classes),
        "classes": classes,
        # The macro/weighted averages above are over these classes, not over all
        # `n_classes`. A device-grouped holdout cannot contain every class, and the
        # difference is large enough here (7 measured of 14 trained) that quoting
        # f1_macro without it would be a misleading number.
        "n_classes_measured": len(measured),
        "classes_measured": measured,
        "min_support": min_support,
        # The ceiling, stated rather than implied: these paths are in the canonical
        # vocabulary and in the label file, and Tier 2 still cannot predict them.
        "classes_below_min_support": excluded,
        "accuracy": round(accuracy, 4),
        "f1_macro": round(f1_macro, 4),
        "f1_weighted": round(f1_weighted, 4),
        "holdout_distribution": holdout_distribution,
        "majority_class": majority_class,
        "majority_class_share_pct": majority_share,
        "caveat": (
            f"{majority_share}% of the {len(y_true)} holdout lines are "
            f"'{majority_class}', and {len(measured)} of {len(classes)} trained "
            "classes appear in the holdout at all. Accuracy on this split is "
            "therefore dominated by one easy class and should not be read as a "
            "per-class capability figure — read 'per_class' supports instead. "
            "Tier 2's real job is the long tail, which this split barely samples."
        ),
        "per_class": {k: v for k, v in per_class.items() if isinstance(v, dict)},
        "train_seconds": round(train_seconds, 1),
        "model_artifact": str(out_dir),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[report] wrote {report_path}")
    print(
        f"[done] accuracy {accuracy:.3f}  f1_macro {f1_macro:.3f}  "
        f"in {train_seconds:.0f}s"
    )
    return metrics


def main() -> int:
    """Entry point for ``python -m scripts.train_setfit``."""
    from backend.ai.setfit_clf import SETFIT_MODEL_PATH

    parser = argparse.ArgumentParser(
        description="Train the SetFit few-shot classifier (MANUAL_COMMANDS.md Step 8c)",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=PROJECT_ROOT / "data" / "labels" / "line_to_path.jsonl",
        help="Labelled JSONL, same file and schema as the Tier 1 trainer",
    )
    parser.add_argument(
        "--out",
        type=Path,
        # Defaulted from the loader's constant rather than retyped, so the trainer
        # cannot write somewhere the loader does not look. That mismatch is the
        # whole reason Tier 2 was unavailable before this script existed.
        default=SETFIT_MODEL_PATH,
        help=f"Output directory for the model (default: {SETFIT_MODEL_PATH})",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=PROJECT_ROOT / "reports" / "metrics" / "setfit.json",
        help="Output path for the metrics JSON report",
    )
    parser.add_argument(
        "--min-support",
        type=int,
        default=MIN_SUPPORT,
        help=f"Minimum examples per class to train it (default: {MIN_SUPPORT})",
    )
    parser.add_argument(
        "--base-model",
        default=BASE_MODEL,
        help=f"Sentence-transformer to fine-tune (default: {BASE_MODEL})",
    )
    args = parser.parse_args()

    labels_path = (
        args.labels if args.labels.is_absolute() else PROJECT_ROOT / args.labels
    )
    out_dir = args.out if args.out.is_absolute() else PROJECT_ROOT / args.out
    report_path = args.report if args.report.is_absolute() else PROJECT_ROOT / args.report

    if not labels_path.exists():
        print(
            f"[error] {labels_path} not found. Run Step 8a first — "
            "scripts/train_classifier.py generates this file from the corpus.",
            file=sys.stderr,
        )
        return 1

    records = _load_labels(labels_path)
    if not records:
        print(f"[error] {labels_path} contained no usable records", file=sys.stderr)
        return 1

    train_setfit(
        records,
        out_dir=out_dir,
        report_path=report_path,
        min_support=args.min_support,
        base_model=args.base_model,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
