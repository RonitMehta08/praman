"""Verify STIG source document tuples (GLOBAL_RULESET §8).

Runs offline verification of STIG V-IDs against the known-good tuple:
  V-215814 / SV-215814r960843_rule / CISC-ND-000160 / CCI-000048 → AC-8 a

Usage:
    python -m scripts.verify_sources
"""

from __future__ import annotations

import sys
from pathlib import Path

# The ONE fully verified STIG tuple from SPINE
VERIFIED_TUPLE = {
    "vuln_id": "V-215814",
    "rule_id": "SV-215814r960843_rule",
    "stig_id": "CISC-ND-000160",
    "cci": "CCI-000048",
    "nist_control": "AC-8",
}


def verify_stig_tuple_in_rules(rules_dir: Path) -> list[str]:
    """Check that the verified STIG tuple appears correctly in our rule packs."""
    errors: list[str] = []

    if not rules_dir.exists():
        errors.append(f"Rules directory does not exist: {rules_dir}")
        return errors

    found_v215814 = False
    for yaml_file in rules_dir.rglob("*.yaml"):
        content = yaml_file.read_text(encoding="utf-8")

        if VERIFIED_TUPLE["vuln_id"] in content:
            found_v215814 = True

            # Verify the cross-references
            if VERIFIED_TUPLE["cci"] not in content:
                errors.append(
                    f"{yaml_file.name}: V-215814 found but CCI-000048 missing"
                )
            if "AC-8" not in content:
                errors.append(
                    f"{yaml_file.name}: V-215814 found but AC-8 NIST mapping missing"
                )

    if not found_v215814:
        errors.append(
            "CRITICAL: V-215814 (the ONE verified tuple) not found in any rule pack"
        )

    return errors


def main() -> None:
    """Run all source verification checks."""
    project_root = Path(__file__).resolve().parent.parent
    rules_dir = project_root / "rules"

    print("=" * 60)
    print("PRAMAN Source Verification — GLOBAL_RULESET §8")
    print("=" * 60)
    print()

    print(f"Verified STIG tuple: {VERIFIED_TUPLE}")
    print()

    errors = verify_stig_tuple_in_rules(rules_dir)

    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  [FAIL] {e}")
        sys.exit(1)
    else:
        print("[PASS] All source verification checks passed")
        print("[PASS] V-215814 tuple verified in rule packs")
        sys.exit(0)


if __name__ == "__main__":
    main()
