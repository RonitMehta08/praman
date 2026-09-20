"""Verdict-by-verdict for one fixture, so a pole pair is measured not guessed."""

import sys
from collections import Counter

sys.path.insert(0, ".")

from backend.app.config import FILE_ENCODING  # noqa: E402
from backend.canonical.findings import Result  # noqa: E402
from backend.ingest.generic import PatternAdapterRegistry  # noqa: E402
from backend.rules.evaluator import RulesEvaluator  # noqa: E402
from tests.test_rules_mapping import CONFIG_DIR, _evaluate  # noqa: E402

want = sys.argv[1]
config = next(p for p in CONFIG_DIR.rglob("*.conf") if p.name == want)

registry = PatternAdapterRegistry()
ev = RulesEvaluator()
text = config.read_text(encoding=FILE_ENCODING)
adapter = registry.detect(text, config.name)
print(f"{config.name}  vendor={adapter.pack.vendor if adapter else 'NONE DETECTED'}")

findings = [
    f
    for f in _evaluate(registry, ev, config)
    if f.result is not Result.NOTCHECKED
]
tally = Counter(f.result.value for f in findings)
print(f"automated findings: {len(findings)}  {dict(tally)}\n")
for f in sorted(findings, key=lambda f: f.control_id):
    mark = "OK " if f.result.value == "pass" else "!! "
    print(f"{mark}{f.control_id:<10} {f.result.value:<14} {f.title[:62]}")
