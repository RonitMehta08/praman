"""Regenerate (or verify) every published metric with one command.

    python scripts/bench/run_all.py            # regenerate reports/metrics/*.json
    python scripts/bench/run_all.py --check     # exit 1 if any published number is stale

GLOBAL_RULESET R9.1 requires that one command regenerate every figure quoted in
the README, the architecture document, the slides and the UI. This is that command.

``--check`` is the half that does the work. It is wired into the pytest suite
(``tests/test_metrics_are_current.py``), so a rule pack that changes control
coverage, or a pattern that changes parse coverage, turns a published number red
in the same run that would otherwise have quietly left the README describing last
month's build. Without that, R9.1 is a promise rather than a property: nothing
about a stale number looks wrong.

Each bench script runs in a **subprocess** rather than being imported and called.
Two reasons, and the second is the real one:

* they mutate global state on purpose — ``bench_pdf_gen`` replaces
  ``builtins.__import__`` to make ReportLab unimportable — and a crash between
  the swap and the ``finally`` would poison every script that ran afterwards in
  the same interpreter;
* a fresh process per script is also the *measurement* condition. Catalogs, rule
  packs and the pattern library are cached at module scope. Importing all five
  into one interpreter would hand the later scripts warm caches the earlier ones
  paid for, and the latency figures would then depend on alphabetical order.

The cost is about a second of interpreter start per script, which is not worth
optimising away in something a human runs occasionally.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BENCH_DIR.parent.parent

#: In dependency-free order, cheapest first, so a broken environment fails on the
#: 7-second script rather than after the 30-second one. Names only — the runner
#: derives paths, so adding a benchmark means adding one line here and nothing
#: else.
BENCHMARKS = [
    "bench_parse_coverage",
    "bench_rule_latency",
    "bench_llm_abstention",
    "bench_pdf_gen",
]


def _run(name: str, *, checking: bool) -> tuple[int, float, str]:
    """Run one benchmark in its own interpreter. Returns (code, seconds, output)."""
    cmd = [sys.executable, str(BENCH_DIR / f"{name}.py")]
    if checking:
        cmd.append("--check")
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    elapsed = time.perf_counter() - started
    return proc.returncode, elapsed, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify published metrics instead of overwriting them; exit 1 if any is stale",
    )
    parser.add_argument(
        "--only",
        metavar="NAME",
        help="run a single benchmark by module name (e.g. bench_rule_latency)",
    )
    args = parser.parse_args()

    selected = BENCHMARKS
    if args.only:
        if args.only not in BENCHMARKS:
            print(
                f"unknown benchmark {args.only!r}; known: {', '.join(BENCHMARKS)}",
                file=sys.stderr,
            )
            return 2
        selected = [args.only]

    verb = "checking" if args.check else "regenerating"
    print(f"{verb} {len(selected)} metric(s) into reports/metrics/\n")

    failures: list[str] = []
    for name in selected:
        code, elapsed, output = _run(name, checking=args.check)
        status = "OK  " if code == 0 else "FAIL"
        print(f"[{status}] {name:26s} {elapsed:6.1f}s")
        # Output is echoed only on failure. A passing --check prints one "OK" line
        # per script and nothing else, which is what makes it usable as a gate: a
        # command that prints 200 lines when it succeeds trains people to skip
        # reading it, and then the failure scrolls past too.
        if code != 0:
            failures.append(name)
            for line in output.strip().splitlines():
                print(f"         {line}")
        print()

    if failures:
        print(f"{len(failures)} of {len(selected)} failed: {', '.join(failures)}", file=sys.stderr)
        if args.check:
            print(
                "\nA stale metric means a number published in README.md, "
                "docs/ARCHITECTURE.md, the slides or the UI no longer matches the "
                "code. Regenerate with:\n"
                "    .venv/Scripts/python.exe scripts/bench/run_all.py\n"
                "then re-read the docs for figures that moved -- the diff above "
                "lists them by key.",
                file=sys.stderr,
            )
        return 1

    print(f"all {len(selected)} metric(s) {'current' if args.check else 'written'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
