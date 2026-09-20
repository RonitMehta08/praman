"""QLoRA fine-tune of Qwen3-4B for config-line classification.

Fine-tunes a 4-bit quantised Qwen3-4B-Instruct model with LoRA adapters
to classify network config lines into canonical field paths (AI Escalation
Ladder Tier 3 upgrade).

Usage:
    conda activate unsloth_env
    python -m scripts.finetune_qlora --config configs\\qlora.yaml --out data\\models\\lora\\

MANUAL_COMMANDS.md Step 8b (OPTIONAL).

IMPORTANT: This script runs in the unsloth_env conda environment (Python 3.12),
NOT in the project's .venv (Python 3.10). It does NOT import from backend.*.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ─── Prompt template ──────────────────────────────────────────────────
# Kept short — config lines are ~50 tokens, paths are ~5 tokens.
SYSTEM_PROMPT = (
    "You are a network configuration classifier. "
    "Given a config line, output ONLY the canonical field path it belongs to."
)

PROMPT_TEMPLATE = (
    "<|im_start|>system\n{system}<|im_end|>\n"
    "<|im_start|>user\nClassify: {line}<|im_end|>\n"
    "<|im_start|>assistant\n{path}<|im_end|>"
)

INFERENCE_TEMPLATE = (
    "<|im_start|>system\n{system}<|im_end|>\n"
    "<|im_start|>user\nClassify: {line}<|im_end|>\n"
    "<|im_start|>assistant\n"
)


def load_config(config_path: Path) -> dict[str, Any]:
    """Load and validate the QLoRA YAML config."""
    if not config_path.exists():
        print(f"[ERROR] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_labels(labels_path: Path) -> list[dict[str, str]]:
    """Load JSONL labels into a list of records."""
    if not labels_path.exists():
        print(f"[ERROR] Labels not found: {labels_path}", file=sys.stderr)
        print("  Run Step 8a first to generate labels.", file=sys.stderr)
        sys.exit(1)

    records: list[dict[str, str]] = []
    with labels_path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                record = json.loads(raw_line)
                if record.get("line") and record.get("path"):
                    records.append(record)
            except json.JSONDecodeError:
                continue
    return records


def split_by_device(
    records: list[dict[str, str]],
    test_size: float = 0.15,
    seed: int = 42,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Split records by device to prevent data leakage.

    All lines from a given device go entirely into train or test.
    """
    import random

    rng = random.Random(seed)
    devices = sorted(set(r["device"] for r in records))
    rng.shuffle(devices)

    n_test_devices = max(1, int(len(devices) * test_size))
    test_devices = set(devices[:n_test_devices])

    train = [r for r in records if r["device"] not in test_devices]
    test = [r for r in records if r["device"] in test_devices]

    return train, test


def format_for_sft(records: list[dict[str, str]]) -> list[dict[str, str]]:
    """Format records into prompt-completion pairs for SFT."""
    formatted = []
    for r in records:
        text = PROMPT_TEMPLATE.format(
            system=SYSTEM_PROMPT,
            line=r["line"],
            path=r["path"],
        )
        formatted.append({"text": text})
    return formatted


def main() -> None:
    """Entry point for python -m scripts.finetune_qlora."""
    parser = argparse.ArgumentParser(
        description="QLoRA fine-tune Qwen3-4B for config classification (Step 8b)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "configs" / "qlora.yaml",
        help="Path to QLoRA YAML config",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "models" / "lora",
        help="Output directory for LoRA adapter",
    )
    args = parser.parse_args()

    config_path = args.config if args.config.is_absolute() else PROJECT_ROOT / args.config
    out_dir = args.out if args.out.is_absolute() else PROJECT_ROOT / args.out

    print("=" * 60)
    print("PRAMAN -- QLoRA Fine-Tune (Step 8b)")
    print("=" * 60)

    t0 = time.time()

    # ── Load config ────────────────────────────────────────────────
    cfg = load_config(config_path)
    model_cfg = cfg["model"]
    lora_cfg = cfg["lora"]
    train_cfg = cfg["training"]
    data_cfg = cfg["data"]
    output_cfg = cfg.get("output", {})

    print(f"  Model: {model_cfg['name']}")
    print(f"  Quantisation: {model_cfg['quantization']}")
    print(f"  LoRA rank: {lora_cfg['r']}, alpha: {lora_cfg['lora_alpha']}")
    print(f"  Epochs: {train_cfg['num_epochs']}, batch: {train_cfg['batch_size']}")
    print()

    # ── Load and split data ────────────────────────────────────────
    labels_path = Path(data_cfg["labels_path"])
    if not labels_path.is_absolute():
        labels_path = PROJECT_ROOT / labels_path

    records = load_labels(labels_path)
    max_samples = data_cfg.get("max_samples")
    if max_samples and len(records) > max_samples:
        import random
        random.Random(train_cfg["seed"]).shuffle(records)
        records = records[:max_samples]

    # Filter rare classes (need at least 2 samples)
    path_counts = Counter(r["path"] for r in records)
    records = [r for r in records if path_counts[r["path"]] >= 2]

    train_records, eval_records = split_by_device(
        records,
        test_size=data_cfg.get("test_size", 0.15),
        seed=train_cfg["seed"],
    )

    unique_paths = sorted(set(r["path"] for r in records))
    print(f"[data] Total: {len(records)} samples, {len(unique_paths)} classes")
    print(f"[data] Train: {len(train_records)}, Eval: {len(eval_records)}")
    print(f"[data] Devices: {len(set(r['device'] for r in records))}")
    print()

    # ── Format for SFT ─────────────────────────────────────────────
    train_formatted = format_for_sft(train_records)
    eval_formatted = format_for_sft(eval_records)

    # ── Import heavy dependencies (after basic validation) ─────────
    print("[model] Loading torch and transformers...")
    import torch
    from datasets import Dataset
    from peft import LoraConfig, TaskType, get_peft_model
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )
    from trl import SFTConfig, SFTTrainer

    device_name = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU"
    print(f"[model] Device: {device_name}")
    print(f"[model] CUDA available: {torch.cuda.is_available()}")

    if not torch.cuda.is_available():
        print("[WARN] No CUDA GPU detected. Training will be very slow on CPU.",
              file=sys.stderr)

    # ── Quantisation config ────────────────────────────────────────
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=getattr(torch, model_cfg.get("bnb_4bit_compute_dtype", "float16")),
        bnb_4bit_quant_type=model_cfg.get("bnb_4bit_quant_type", "nf4"),
        bnb_4bit_use_double_quant=model_cfg.get("use_double_quant", True),
    )

    # ── Load model + tokenizer ─────────────────────────────────────
    model_name = model_cfg["name"]
    print(f"[model] Loading {model_name} (4-bit quantised)...")
    print("  This will download ~2.5 GB on first run.")

    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=True,
        padding_side="right",
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    use_bf16 = train_cfg.get("bf16", False)
    model_dtype = torch.bfloat16 if use_bf16 else torch.float16

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=model_dtype,
    )
    model.config.use_cache = False  # Required for gradient checkpointing

    print(f"[model] Loaded. Parameters: {model.num_parameters():,}")

    # ── Apply LoRA ─────────────────────────────────────────────────
    peft_config = LoraConfig(
        r=lora_cfg["r"],
        lora_alpha=lora_cfg["lora_alpha"],
        lora_dropout=lora_cfg.get("lora_dropout", 0.05),
        target_modules=lora_cfg["target_modules"],
        bias=lora_cfg.get("bias", "none"),
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, peft_config)

    trainable, total = model.get_nb_trainable_parameters()
    print(f"[lora] Trainable: {trainable:,} / {total:,} "
          f"({100 * trainable / total:.2f}%)")
    print()

    # ── Prepare datasets ───────────────────────────────────────────
    train_dataset = Dataset.from_list(train_formatted)
    eval_dataset = Dataset.from_list(eval_formatted)

    # ── Training config (trl 1.10+ uses SFTConfig) ─────────────────
    out_dir.mkdir(parents=True, exist_ok=True)
    training_dir = out_dir / "checkpoints"

    # Compute warmup_steps from warmup_ratio (transformers 5.x uses warmup_steps)
    effective_batch = train_cfg["batch_size"] * train_cfg["gradient_accumulation_steps"]
    total_steps = (len(train_formatted) // effective_batch) * train_cfg["num_epochs"]
    warmup_ratio = train_cfg.get("warmup_ratio", 0.1)
    warmup_steps = max(1, int(total_steps * warmup_ratio))

    sft_config = SFTConfig(
        output_dir=str(training_dir),
        num_train_epochs=train_cfg["num_epochs"],
        per_device_train_batch_size=train_cfg["batch_size"],
        per_device_eval_batch_size=train_cfg["batch_size"],
        gradient_accumulation_steps=train_cfg["gradient_accumulation_steps"],
        learning_rate=train_cfg["learning_rate"],
        lr_scheduler_type=train_cfg.get("lr_scheduler", "cosine"),
        warmup_steps=warmup_steps,
        weight_decay=train_cfg.get("weight_decay", 0.01),
        fp16=train_cfg.get("fp16", False),
        bf16=train_cfg.get("bf16", False),
        gradient_checkpointing=train_cfg.get("gradient_checkpointing", True),
        logging_steps=train_cfg.get("logging_steps", 10),
        save_strategy=train_cfg.get("save_strategy", "epoch"),
        eval_strategy=train_cfg.get("evaluation_strategy", "epoch"),
        seed=train_cfg["seed"],
        report_to="none",
        remove_unused_columns=False,
        optim="paged_adamw_8bit",
        max_length=train_cfg.get("max_seq_length", 128),
        dataset_text_field="text",
    )

    # ── Trainer ────────────────────────────────────────────────────
    print("[train] Starting QLoRA fine-tuning...")
    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        processing_class=tokenizer,
    )

    # Train
    train_result = trainer.train()

    # ── Save adapter ───────────────────────────────────────────────
    adapter_path = out_dir / "adapter"
    model.save_pretrained(str(adapter_path))
    tokenizer.save_pretrained(str(adapter_path))
    print(f"[save] LoRA adapter saved to {adapter_path}")

    # Save inference prompt template
    template_path = out_dir / "prompt_template.json"
    template_path.write_text(
        json.dumps({
            "system": SYSTEM_PROMPT,
            "inference_template": INFERENCE_TEMPLATE,
            "canonical_paths": unique_paths,
        }, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # ── Metrics ────────────────────────────────────────────────────
    eval_result = trainer.evaluate()

    metrics: dict[str, Any] = {
        "model": model_name,
        "method": "QLoRA 4-bit NF4",
        "lora_rank": lora_cfg["r"],
        "lora_alpha": lora_cfg["lora_alpha"],
        "target_modules": lora_cfg["target_modules"],
        "trainable_params": trainable,
        "total_params": total,
        "trainable_pct": round(100 * trainable / total, 4),
        "epochs": train_cfg["num_epochs"],
        "effective_batch_size": (
            train_cfg["batch_size"] * train_cfg["gradient_accumulation_steps"]
        ),
        "learning_rate": train_cfg["learning_rate"],
        "n_train": len(train_records),
        "n_eval": len(eval_records),
        "n_classes": len(unique_paths),
        "classes": unique_paths,
        "split_group_by": "device",
        "train_loss": round(train_result.training_loss, 4),
        "eval_loss": round(eval_result.get("eval_loss", 0.0), 4),
        "train_runtime_s": round(train_result.metrics.get("train_runtime", 0), 1),
        "gpu": device_name,
        "adapter_path": str(adapter_path),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }

    metrics_path = Path(output_cfg.get("metrics_path", "reports/metrics/qlora.json"))
    if not metrics_path.is_absolute():
        metrics_path = PROJECT_ROOT / metrics_path
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[report] Wrote {metrics_path}")

    elapsed = time.time() - t0
    print()
    print(f"[done] Completed in {elapsed / 60:.1f} minutes")
    print(f"[done] Train loss: {metrics['train_loss']}")
    print(f"[done] Eval loss: {metrics['eval_loss']}")


if __name__ == "__main__":
    main()
