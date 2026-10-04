"""Cheap classifier readiness checks: model files alone are not a runtime."""

from __future__ import annotations

from importlib.util import find_spec

from backend.ai.setfit_clf import SETFIT_MODEL_PATH
from backend.ai.tfidf_clf import TFIDF_MODEL_PATH


def classifier_readiness() -> dict[str, dict]:
    """Report packaging/dependency gaps without importing torch on health polls.

    Actual loading is checked by scripts/check_ai_runtime.py during hosted builds
    and remains lazy in the application, with the existing classifier cache.
    """
    definitions = {
        "tier1_tfidf": ([TFIDF_MODEL_PATH], ("joblib", "sklearn", "numpy")),
        "tier2_setfit": (
            [SETFIT_MODEL_PATH / name for name in (
                "config_setfit.json", "modules.json", "model.safetensors",
                "model_head.pkl", "tokenizer.json", "neighbour_index.npz",
                "1_Pooling/config.json",
            )],
            ("setfit", "sentence_transformers", "torch", "numpy", "sklearn"),
        ),
    }
    result = {}
    for tier, (files, dependencies) in definitions.items():
        missing_files = [str(path) for path in files if not path.is_file()]
        missing_dependencies = [name for name in dependencies if find_spec(name) is None]
        result[tier] = {
            "ready": not missing_files and not missing_dependencies,
            "missing_files": missing_files,
            "missing_dependencies": missing_dependencies,
        }
    return result
