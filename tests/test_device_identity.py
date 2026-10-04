"""Test: Device identity — serial numbers and hardware.

C4 requires the per-device report to identify the device "including serial
numbers and hardware". Neither appears anywhere in a running-config, so both are
read from whatever ``show version`` / ``show inventory`` text the upload happened
to bundle alongside the config. That makes identity extraction the one part of
the pipeline whose input is not a configuration, and it fails in ways the rest of
the parser does not:

* **The same serial arrives under several headings.** IOS prints the chassis
  serial as ``System serial number`` *and* as ``Processor board ID``, and again
  as a ``show inventory`` SN. A report listing it three times reads like three
  devices, so ``_build_device`` deduplicates while preserving first-seen order.
* **A stack has more than one of everything.** ``serials`` and ``hardware`` are
  ``list[str]`` for exactly this reason. A single-chassis fixture would pass with
  a scalar field and never notice.
* **Component serials are not device serials.** The same block prints motherboard
  and power-supply serials. ``device.serials`` is unlabelled and its consumer is
  an auditor matching an asset register, which tracks chassis — so those lines
  are in the pack's ignore list, deliberately.
* **Config-only uploads must stay honest.** Most real uploads have no show
  output. Identity is then genuinely unknown, and the correct answer is an empty
  list that the report renders as "not captured" — never a fabricated value.

The two fixtures under ``test_configs/device_identity/`` cover the stack and the
single chassis. Their header comments state the same expectations asserted here;
if you change one, change both.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.config import PROJECT_ROOT
from backend.app.services import parse_config

FIXTURE_DIR = PROJECT_ROOT / "test_configs" / "device_identity"

STACK = "stacked_switch_with_inventory.conf"
ROUTER = "router_with_show_version.conf"


def _parse_fixture(name: str, directory: Path | None = None):
    """Parse a fixture through the real ingestion entry point.

    Deliberately ``parse_config`` and not a hand-built adapter: the dedup under
    test lives in ``generic._build_device``, and a test that assembled the
    Device itself would assert on its own arithmetic.
    """
    path = (directory or FIXTURE_DIR) / name
    assert path.exists(), f"missing fixture: {path}"
    return parse_config(path.read_text(encoding="utf-8"), path.name)


@pytest.fixture(scope="module")
def stack():
    return _parse_fixture(STACK)


@pytest.fixture(scope="module")
def router():
    return _parse_fixture(ROUTER)


class TestStackedSwitchIdentity:
    """A four-member stack: four chassis, four serials, no more and no less."""

    def test_serials_are_exactly_the_four_stack_members(self, stack) -> None:
        """Equality, not containment.

        ``>= 4`` would pass while the parser also swallowed the motherboard
        serial, and that is the failure this fixture was built to catch. The
        order is first-seen: member 1 arrives via ``Processor board ID`` near the
        top of ``show version``, the rest via ``show inventory`` in stack order.
        """
        assert stack.device.serials == [
            "FDO1732H0KL",  # member 1 — Processor board ID / System serial number
            "FDO1801J1AB",  # member 2 — show inventory
            "FDO1902K2CD",  # member 3
            "FDO1834M7QP",  # member 4
        ]

    def test_chassis_serial_printed_three_times_appears_once(self, stack) -> None:
        """The dedup is the point, so assert the count and not just membership."""
        assert stack.device.serials.count("FDO1732H0KL") == 1

    def test_component_serials_are_not_collected(self, stack) -> None:
        """FDO17320KLL is member 1's motherboard, not a chassis.

        It is printed two lines from the chassis serial and differs from it by
        three characters, which is precisely why capturing it is tempting and
        wrong: an auditor cannot tell the two apart by eye, and only one of them
        is in the asset register.
        """
        assert "FDO17320KLL" not in stack.device.serials

    def test_hardware_lists_the_member_models(self, stack) -> None:
        assert "WS-C3750X-48P-S" in stack.device.hardware
        assert "WS-C3750X-24P-S" in stack.device.hardware

    def test_hardware_is_deduplicated(self, stack) -> None:
        """Members 1 and 3 are the same PID; the stack reports it once."""
        assert len(stack.device.hardware) == len(set(stack.device.hardware))

    def test_hostname_and_version_from_show_output(self, stack) -> None:
        assert stack.device.hostname == "core-sw-01"
        assert stack.device.os_version == "15.2"


class TestRouterIdentity:
    """One chassis printed under two headings: one serial out."""

    def test_serials_is_exactly_the_chassis(self, router) -> None:
        assert router.device.serials == ["FTX1840ALBE"]

    def test_motherboard_and_psu_serials_excluded(self, router) -> None:
        """Here the motherboard serial *differs* from the chassis serial.

        On the stack they were near-identical; here FOC18396K2N shares no prefix
        with FTX1840ALBE. Both cases must be excluded, and a rule that only
        happened to work because the strings looked alike would pass one and fail
        the other.
        """
        assert "FOC18396K2N" not in router.device.serials  # motherboard
        assert "AZS183503LK" not in router.device.serials  # power supply

    def test_hardware_from_chassis_line(self, router) -> None:
        assert "CISCO2921/K9" in router.device.hardware

    def test_hostname_and_version(self, router) -> None:
        assert router.device.hostname == "branch-rtr-07"
        assert router.device.os_version == "15.7"


class TestConfigOnlyUploadStaysEmpty:
    """The honest-empty case, which is the common one.

    Every other fixture in the library is config-only. If a future pattern ever
    started inferring a serial from a config line — a hostname that looks like an
    asset tag, a description field — this is the test that catches it. An invented
    serial in a compliance report is worse than a missing one: it is traceable to
    nothing and an auditor cannot tell it was invented.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "realistic/secure_baseline.conf",
            "realistic/telnet_exposed.conf",
            "compliance_extremes/fully_hardened.conf",
        ],
    )
    def test_no_serial_or_hardware_without_show_output(self, name: str) -> None:
        result = _parse_fixture(name, PROJECT_ROOT / "test_configs")
        assert result.device.serials == [], (
            f"{name} is config-only but produced serials "
            f"{result.device.serials!r} — a fabricated identity"
        )
        assert result.device.hardware == [], (
            f"{name} is config-only but produced hardware "
            f"{result.device.hardware!r} — a fabricated identity"
        )


class TestShowVersionBoilerplateIsIgnored:
    """Bundled show output must not flood the C2 training queue.

    Both fixtures pair a config with ~30 lines of build metadata, copyright
    notices, reload reasons and inventory tables. Those lines carry no fact any
    rule reads, but they reach the training queue as unmapped templates — and the
    queue is ordered by ``occurrences DESC``, while this text appears once per
    device exactly like the genuinely unmapped config lines beside it. So
    busiest-first does not bury it, it interleaves, and an operator opening the
    training view finds the real work outnumbered six to one.

    The assertion is therefore about the *ratio*, not a count: everything left
    unparsed must be a configuration directive.
    """

    @pytest.mark.parametrize("name", [STACK, ROUTER])
    def test_only_configuration_lines_remain_unparsed(self, name: str) -> None:
        result = _parse_fixture(name)
        show_output_markers = (
            "Copyright",
            "Technical Support",
            "Compiled ",
            "ROM:",
            "BOOTLDR:",
            "System restarted",
            "System returned to ROM",
            "Last reload",
            "Last reset",
            "bytes of",
            "Motherboard",
            "Power supply",
            "Top Assembly",
            "CLEI",
            "Version ID",
            "Base ethernet MAC",
            "Technology",
            "revision number",
            "SW Image",
        )
        leaked = [
            entry["raw_text"]
            for entry in result.unparsed_lines
            if any(marker in entry["raw_text"] for marker in show_output_markers)
        ]
        assert not leaked, (
            f"{name}: show-version boilerplate reached the training queue:\n  "
            + "\n  ".join(leaked)
        )

    @pytest.mark.parametrize("name", [STACK, ROUTER])
    def test_unparsed_count_stays_small(self, name: str) -> None:
        """A ceiling, so a regression in the ignore list is loud.

        Before the ignore block these were 33 and 38. The remaining handful are
        real unmapped directives (``ip default-gateway``, OSPF ``network``
        statements) and belong in the queue — they are what the C2 demo teaches.
        """
        result = _parse_fixture(name)
        assert len(result.unparsed_lines) <= 8, (
            f"{name}: {len(result.unparsed_lines)} unparsed lines, expected <= 8:\n  "
            + "\n  ".join(e["raw_text"] for e in result.unparsed_lines)
        )


class TestPasswordRecoveryFact:
    """The one show-version line that is a security decision, not metadata.

    ``no service password-recovery`` stops an attacker with console access from
    resetting the enable password by interrupting the boot. IOS reports the
    resulting state in ``show version`` as a sentence, and in the config only when
    it has been turned off — two forms, one canonical path, so a rule reads one
    fact whichever the upload contained.
    """

    def test_switch_reports_recovery_enabled(self, stack) -> None:
        values = [f.value for f in stack.facts if f.path == "service.password_recovery"]
        assert values == [True]

    def test_fact_carries_full_provenance(self, stack) -> None:
        """Six-field provenance, same as any other fact.

        A fact sourced from show output rather than a config line is still
        evidence and still has to be traceable to a line number.
        """
        fact = next(
            f for f in stack.facts if f.path == "service.password_recovery"
        )
        assert fact.source_file == STACK
        assert fact.line_start > 0
        assert "password-recovery" in fact.raw_text
        assert fact.confidence == 1.0
        assert fact.parser_id

    def test_router_reports_nothing_rather_than_a_default(self, router) -> None:
        """Absence, not a guessed default.

        Password recovery is a Catalyst feature; the ISR's show version never
        mentions it. The pack deliberately has no ``defaults`` entry for this
        path, so a rule reading it on this device renders INDETERMINATE — which
        is true — instead of passing on an assumption.
        """
        values = [f.value for f in router.facts if f.path == "service.password_recovery"]
        assert values == []
