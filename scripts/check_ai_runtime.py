"""Fail a hosted build if either shipped classifier cannot actually load.

No training or model downloads. The weights must already be in the checkout.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    from backend.ai.readiness import classifier_readiness
    from backend.ai.setfit_clf import SetFitClassifier
    from backend.ai.tfidf_clf import TfidfClassifier

    for tier, status in classifier_readiness().items():
        if not status["ready"]:
            print(f"{tier} is not ready: {status}", file=sys.stderr)
            return 1
    for name, classifier in (
        ("TF-IDF", TfidfClassifier()), ("SetFit", SetFitClassifier()),
    ):
        try:
            classifier.load()
            classifier.predict("ip ssh version 2")
        except Exception as exc:
            print(f"{name} load/inference check failed: {exc}", file=sys.stderr)
            return 1
        print(f"{name}: shipped model loaded and inference completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
