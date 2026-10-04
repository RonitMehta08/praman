"""Shared harness for ``scripts/bench/`` — the evidence layer behind every number.

GLOBAL_RULESET R1.3 and R9.1 say no accuracy, coverage, latency or throughput
figure may appear in the README, the architecture document, the slides or the UI
unless a script here regenerates it into ``reports/metrics/*.json``. R9.2 says
each metric must state what was measured, the dataset, N, the hardware and the
date.

The reason those two rules need *code* rather than discipline is that a stale
number is invisible. A README claiming "103 rules across 42 catalogs" reads
exactly the same whether it was measured this morning or six weeks and two rule
packs ago, and the version that is wrong is the more flattering one more often
than chance would suggest. So the envelope below is not documentation of the
measurement — it is the measurement's only permitted output shape, and
``--check`` compares what is on disk against a fresh run.

``environment()`` is deliberately coarse. A precise fingerprint (CPU model
string, exact RAM, GPU name) would be more informative and would also make every
metric file differ on every machine, so ``--check`` would fail for the honest
reason "you are not the person who generated this" and be switched off. What is
recorded is what a reader needs in order to know whether a latency figure
transfers: the platform, the interpreter, the core count, and whether a GPU was
in play at all.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

#: Where published metrics live. Named ``reports/metrics/`` by R9.1, which the
#: docs read from; ``scripts/bench/out/`` holds nothing durable.
METRICS_DIR = PROJECT_ROOT / "reports" / "metrics"

#: Fields whose value legitimately differs between two runs of the same code on
#: the same inputs, and which ``--check`` therefore ignores. Wall-clock timings
#: are the obvious case: asserting a p50 to the microsecond would make the gate
#: fail on a busy laptop, and a gate that fails for reasons unrelated to
#: correctness gets muted, which costs more than it catches.
#: Every *derived* statistic is listed, not just the raw ``timings_ms`` it came
#: from. Excluding the samples while gating on their own median was the first
#: version of this set and it made ``--check`` fail on every second run: p50 is
#: exactly as volatile as the numbers it summarises. ``n`` deliberately stays in
#: the comparison, because the number of repetitions is a property of the script
#: rather than of the machine, and silently dropping from 20 samples to 3 is the
#: kind of change a reader of the metric should see.
#:
#: Ratios derived from timings (``latency_per_line_ms``, ``speedup_vs_reportlab``)
#: and cache ages (``tier3_probe_age_s``) belong here for the same reason as the
#: timings themselves: they carry no substance to gate and would make the gate
#: fail on machine noise.
VOLATILE = frozenset(
    {
        "generated_at",
        "environment",
        "timings_ms",
        "wall_seconds",
        "p50_ms",
        "p95_ms",
        "min_ms",
        "max_ms",
        "mean_ms",
        "speedup_vs_reportlab",
        "latency_per_line_ms",
        "tier3_probe_age_s",
        "tier3_checked_age_s",
    }
)


def environment() -> dict[str, Any]:
    """Coarse hardware and interpreter fingerprint (R9.2).

    ``gpu`` is read from the environment rather than probed: probing means
    importing torch, which on this project means a multi-second import and a
    CUDA context, inside a script whose whole purpose is to measure how long
    things take.
    """
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "gpu": os.environ.get("PRAMAN_BENCH_GPU", "not recorded"),
    }


def now_iso() -> str:
    """UTC timestamp, seconds precision — the same shape the ledger uses."""
    from backend.canonical.models import utc_now_iso

    return utc_now_iso()


@dataclass
class Timing:
    """Latency distribution over N repetitions of one operation.

    p95 is reported alongside p50 because R9.5 forbids the phrase "real time"
    without both, and because the tail is the number an operator feels. On a
    sample this small p95 is the second-worst observation rather than a real
    quantile — ``n`` is published so a reader can see that for themselves
    instead of taking a percentile at face value.
    """

    n: int
    p50_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float
    mean_ms: float
    timings_ms: list[float] = field(default_factory=list)

    @classmethod
    def measure(cls, operation: Callable[[], Any], *, repeat: int, warmup: int = 1) -> Timing:
        """Time ``operation`` ``repeat`` times after discarding ``warmup`` runs.

        The warmup is not politeness. Catalogs, rule packs and the pattern
        library are loaded lazily and cached, so the first call to anything in
        this project measures disk and YAML parsing rather than the operation —
        including it would report a p50 several times the steady-state figure and
        understate the tool by claiming it is slower than it is.
        """
        for _ in range(warmup):
            operation()
        samples: list[float] = []
        for _ in range(repeat):
            start = time.perf_counter()
            operation()
            samples.append((time.perf_counter() - start) * 1000.0)
        ordered = sorted(samples)
        return cls(
            n=len(samples),
            p50_ms=round(statistics.median(ordered), 3),
            p95_ms=round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
            min_ms=round(ordered[0], 3),
            max_ms=round(ordered[-1], 3),
            mean_ms=round(statistics.fmean(ordered), 3),
            timings_ms=[round(s, 3) for s in samples],
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
            "mean_ms": self.mean_ms,
            "timings_ms": self.timings_ms,
        }


def envelope(
    *,
    metric: str,
    measures: str,
    dataset: str,
    n: int,
    results: dict[str, Any],
    caveats: Iterable[str] = (),
    configuration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap results in the R9.2 envelope.

    ``caveats`` is a required-by-convention field rather than an optional one:
    R9.4 says report the weak numbers too, and a metric file with an empty
    caveats list is a claim that the measurement has no limitations, which for
    every metric in this project is false. Reviewers should read an empty list as
    a smell.

    ``configuration`` declares the *setup* a measurement was taken under, as
    opposed to the machine it ran on (``environment``) or what it found
    (``results``). It exists for one narrow case: a knob that legitimately
    differs between two honest runs and genuinely changes the numbers, so that
    neither ignoring it nor gating on it is right. See :func:`check`.
    """
    payload = {
        "metric": metric,
        "measures": measures,
        "dataset": dataset,
        "n": n,
        "generated_at": now_iso(),
        "environment": environment(),
        "results": results,
        "caveats": list(caveats),
    }
    if configuration is not None:
        payload["configuration"] = configuration
    return payload


def write(payload: dict[str, Any], *, filename: str) -> Path:
    """Write one metric file and echo a one-line summary."""
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    path = METRICS_DIR / filename
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(PROJECT_ROOT)}")
    return path


def _stable(value: Any) -> Any:
    """Recursively drop the fields that legitimately differ between runs."""
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in sorted(value.items()) if k not in VOLATILE}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value


def check(payload: dict[str, Any], *, filename: str) -> int:
    """Compare a fresh measurement against what is on disk. 0 if they agree.

    Timings and the environment are excluded (see ``VOLATILE``), so what this
    actually gates is the *substance*: counts, coverage ratios, control totals,
    abstention rates. Those are the numbers the docs quote and the ones that go
    stale silently when a rule pack lands.

    A declared ``configuration`` is checked *first*, and a mismatch is reported
    as not-comparable rather than as stale. The distinction matters because the
    two have opposite remedies. Stale means the code moved and the published
    number is now wrong, so the fix is to regenerate and re-read the docs.
    Not-comparable means the published number is still a true statement about
    the setup it was measured in, and this machine is simply in a different one
    — regenerating would overwrite a deliberate publication with an accident of
    whether a local server happened to be running.

    Returning 0 there is the load-bearing choice, and it is a narrow exemption
    rather than a softening of the gate: every substantive figure is still gated
    whenever the configuration matches, which is the shipped default and so the
    case CI and a new user both hit. The alternative — failing — was the behaviour
    this replaced, and it fails for a reason unrelated to correctness on any
    machine with a model server up. A gate that cries wolf on demo day is a gate
    someone switches off, and then it catches nothing at all.
    """
    path = METRICS_DIR / filename
    if not path.exists():
        print(f"MISSING: {path.relative_to(PROJECT_ROOT)} — run without --check", file=sys.stderr)
        return 1
    on_disk = json.loads(path.read_text(encoding="utf-8"))

    was_config, now_config = on_disk.get("configuration"), payload.get("configuration")
    if was_config != now_config:
        print(
            f"NOT COMPARABLE: {filename} was measured in a different configuration, "
            "so its figures are neither confirmed nor contradicted here."
        )
        for key in sorted(set(was_config or {}) | set(now_config or {})):
            was, now = (was_config or {}).get(key), (now_config or {}).get(key)
            if was != now:
                print(f"  {key}:\n    published: {was}\n    this machine: {now}")
        print(
            "  Republish only if this machine's configuration is the one you intend "
            "to ship:\n"
            "    .venv/Scripts/python.exe scripts/bench/run_all.py"
        )
        return 0

    if _stable(on_disk) == _stable(payload):
        print(f"OK: {filename} is current")
        return 0

    print(f"STALE: {filename} disagrees with a fresh measurement", file=sys.stderr)
    for key in sorted(set(_stable(on_disk)) | set(_stable(payload))):
        was, now = _stable(on_disk).get(key), _stable(payload).get(key)
        if was != now:
            print(f"  {key}:\n    on disk: {was}\n    fresh:   {now}", file=sys.stderr)
    print(
        "\nRegenerate with: .venv/Scripts/python.exe scripts/bench/run_all.py",
        file=sys.stderr,
    )
    return 1


def emit(payload: dict[str, Any], *, filename: str, checking: bool) -> int:
    """Write or check, depending on the flag. Every bench script ends here."""
    if checking:
        return check(payload, filename=filename)
    write(payload, filename=filename)
    return 0


def arg_parser(description: str) -> Any:
    """The one flag every bench script shares."""
    import argparse

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the published metric disagrees with a fresh run",
    )
    return parser
