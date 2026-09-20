"""Pin what each rule's target control *said*, so a renumbering cannot go quiet.

    python scripts/control_bindings.py            # summary
    python scripts/control_bindings.py --diff     # show every drifted binding
    python scripts/control_bindings.py --write    # re-pin to the current catalogs
    python scripts/control_bindings.py --check    # exit 1 on drift

The hazard this closes
----------------------
A rule names its target as ``{catalog_id, control_id}`` and nothing else.
`RulesEvaluator._validate_rule_targets` already rejects a control id that does
not exist, which catches a typo and catches porting a pack onto a benchmark that
renumbered *and* renamed — the DISA switch NDM benchmark reuses none of the
router NDM's V-numbers, so every mis-port there fails at load.

It cannot catch the opposite case, and that case is real. CIS renumbers decimal
control ids between adjacent benchmarks while keeping the numbering *shape*. Of
the 71 controls the CIS Cisco IOS 15 pack decides, 12 have a different id in CIS
Cisco IOS XE 17.x for the same control text:

    ios15 1.1.6  "login authentication for 'line vty'"  -> xe 1.1.4
    xe    1.1.6  "aaa accounting ... commands 15"       <- ios15 1.1.7

Both ids exist in both catalogs. A pack ported by changing `applies_to` and
pointing it at the XE catalog would load clean, validate clean, and then decide
`1.1.6` — "login authentication" — by running the check for a *different*
control. The output is not an error. It is a confident PASS or FAIL attributed
to a control that was never tested, which is the failure mode this project
treats as worse than a crash: the auditor has no way to see it from the report.

Why a lockfile and not a field on the rule
------------------------------------------
The title is the catalog's data. Copying it into all 454 rules would put the
same prose in two editable places, and the copy in the rule would be the one
that drifts — a rule is edited when its *condition* changes, which is exactly
when nobody re-reads the title. The lockfile is not a second source of truth; it
is a fingerprint of the first, regenerated wholesale and never hand-edited.

The title is stored verbatim rather than hashed on purpose. The diff is the
review artefact, and

    - "1.1.6": "Set 'login authentication for 'line vty'"
    + "1.1.6": "Set 'aaa accounting' to log all privileged use commands"

is alarming to a reader in a way that two changed hex digests are not.

What a failure means
--------------------
Drift is not automatically a bug. A publisher erratum that fixes a typo in a
control title is drift, and the right response is `--write` plus a glance at the
diff. A *swap* — two controls trading titles, or a title changing category — is
a mis-binding, and the right response is to fix the rule. This script cannot
tell those apart and does not try to. It makes the change visible and leaves the
judgement with the person reading the diff, which is the only place it can live.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import FILE_ENCODING
from backend.frameworks.catalog import load_catalogs
from backend.rules.loader import load_all_rules

ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "rules" / "control_bindings.lock.json"


def measure() -> dict[str, dict[str, str]]:
    """``catalog_id`` → ``control_id`` → the title that control carries today.

    Scoped to controls some enabled rule actually decides. Pinning every control
    in every catalog would turn a benchmark upgrade into a thousand-line diff in
    which the handful of bindings that matter are invisible.
    """
    catalogs = {c.catalog_id: c for c in load_catalogs()}
    out: dict[str, dict[str, str]] = {}
    for rule in load_all_rules():
        if not rule.enabled:
            continue
        catalog = catalogs.get(rule.catalog.catalog_id)
        if catalog is None:
            continue  # the evaluator reports this far better than we can
        for control in catalog.controls:
            if control.control_id == rule.catalog.control_id:
                out.setdefault(catalog.catalog_id, {})[control.control_id] = control.title
                break
    return out


def published() -> dict[str, dict[str, str]]:
    if not LOCK_PATH.exists():
        return {}
    data = json.loads(LOCK_PATH.read_text(encoding=FILE_ENCODING))
    return data.get("bindings", {})


def drift(now: dict, was: dict) -> list[str]:
    """Every binding that changed, appeared or vanished, as readable lines."""
    problems: list[str] = []
    for catalog_id in sorted(set(now) | set(was)):
        mine, theirs = now.get(catalog_id, {}), was.get(catalog_id, {})
        for control_id in sorted(set(mine) | set(theirs)):
            new, old = mine.get(control_id), theirs.get(control_id)
            if new == old:
                continue
            if old is None:
                problems.append(f"  + {catalog_id} {control_id}\n      now: {new}")
            elif new is None:
                problems.append(f"  - {catalog_id} {control_id}\n      was: {old}")
            else:
                problems.append(
                    f"  ~ {catalog_id} {control_id}\n      was: {old}\n      now: {new}"
                )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="re-pin to the current catalogs")
    parser.add_argument("--check", action="store_true", help="exit 1 on drift")
    parser.add_argument("--diff", action="store_true", help="show every drifted binding")
    args = parser.parse_args()

    now = measure()
    total = sum(len(v) for v in now.values())

    if args.write:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "_comment": (
                "Generated by scripts/control_bindings.py --write. Never hand-edit. "
                "This pins the title each rule's target control carried when the rule "
                "was authored, so a benchmark that renumbers its controls cannot "
                "silently re-point a rule at a different one. See the script header."
            ),
            "controls_pinned": total,
            "bindings": now,
        }
        LOCK_PATH.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding=FILE_ENCODING
        )
        print(f"wrote {LOCK_PATH} ({total} bindings)")
        return 0

    problems = drift(now, published())

    if args.check:
        if not LOCK_PATH.exists():
            print(f"STALE {LOCK_PATH.name} does not exist")
            print("Regenerate with: python scripts/control_bindings.py --write")
            return 1
        if problems:
            print(f"{len(problems)} binding(s) drifted from {LOCK_PATH.name}:")
            print("\n".join(problems))
            print(
                "\nA rule now decides a control whose text is not the one it was "
                "written against.\nIf the publisher corrected a title, re-pin with "
                "--write. If two controls swapped\nids, the rule is mis-bound and "
                "the rule must be fixed, not the lockfile."
            )
            return 1
        print(f"OK {total} rule → control bindings match {LOCK_PATH.name}.")
        return 0

    if args.diff:
        print("\n".join(problems) if problems else "no drift")
        return 0

    print(f"{total} rule → control bindings across {len(now)} catalogs")
    for catalog_id in sorted(now):
        print(f"  {len(now[catalog_id]):>4}  {catalog_id}")
    if problems:
        print(f"\n{len(problems)} drifted — run --diff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
