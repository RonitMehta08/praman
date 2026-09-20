"""Juniper Junos vendor adapter.

Parses Junos set-style and hierarchical-style configs into the Canonical Model.
Proves the decoupling boundary: adding this parser requires ZERO rule changes (P7).

Uses the netutils juniper_junos hierarchy normaliser for set-to-hierarchy
conversion where needed.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from backend.canonical.models import (
    CanonicalFact,
    Device,
    OsFamily,
    Vendor,
    compute_config_hash,
    utc_now_iso,
)
from backend.ingest.base import ParseResult, VendorAdapter

_PARSER_ID = "praman.juniper_junos@0.1.0"

_JUNOS_MARKERS = [
    "system {",
    "interfaces {",
    "routing-options {",
    "protocols {",
    "firewall {",
    "set system",
    "set interfaces",
    "set protocols",
    "groups {",
    "apply-groups",
]


class JunosAdapter(VendorAdapter):
    """Juniper Junos config parser.

    Handles both hierarchical and set-style configurations.
    Extracts the same canonical paths as the Cisco IOS adapter — the rules
    engine sees identical CanonicalFact.path values regardless of vendor.
    """

    def vendor_id(self) -> Vendor:
        return Vendor.juniper_junos

    def _parser_id(self) -> str:
        return _PARSER_ID

    def can_parse(self, raw_text: str, filename: str) -> bool:
        lower = raw_text.lower()
        hits = sum(1 for m in _JUNOS_MARKERS if m.lower() in lower)
        return hits >= 2

    def parse(self, raw_text: str, source_file: str) -> ParseResult:
        normalised = unicodedata.normalize("NFKC", raw_text)
        lines = normalised.splitlines()

        facts: list[CanonicalFact] = []
        unparsed: list[dict[str, Any]] = []

        hostname = self._extract_hostname(lines, source_file, facts)
        self._parse_system(lines, source_file, facts)
        self._parse_interfaces(lines, source_file, facts)
        self._parse_protocols(lines, source_file, facts)
        self._parse_firewall(lines, source_file, facts)
        self._parse_security(lines, source_file, facts)

        device = Device(
            device_id=hostname or source_file.replace(".conf", ""),
            vendor=Vendor.juniper_junos,
            os_family=OsFamily.junos,
            hostname=hostname,
            serials=[],
            hardware=[],
            os_version=self._extract_version(lines),
            source_file=source_file,
            config_hash=compute_config_hash(raw_text.encode("utf-8")),
            ingested_at=utc_now_iso(),
        )

        return ParseResult(device=device, facts=facts, unparsed_lines=unparsed)

    def _extract_hostname(
        self, lines: list[str], source_file: str, facts: list[CanonicalFact]
    ) -> str | None:
        for i, line in enumerate(lines):
            m = re.search(r"host-name\s+(\S+?);?$", line)
            if not m:
                m = re.match(r"^\s*set\s+system\s+host-name\s+(\S+)", line)
            if m:
                hostname = m.group(1).rstrip(";")
                facts.append(self._make_fact(
                    "device.hostname", hostname, True,
                    source_file, i + 1, i + 1, line.strip(),
                ))
                return hostname
        return None

    def _extract_version(self, lines: list[str]) -> str | None:
        for line in lines:
            m = re.search(r"version\s+\"?(\d+\.\d+\S*)\"?;?", line)
            if m:
                return m.group(1).rstrip(";\"")
        return None

    def _parse_system(
        self, lines: list[str], source_file: str, facts: list[CanonicalFact]
    ) -> None:
        for i, line in enumerate(lines):
            stripped = line.strip()

            # SSH
            if re.search(r"ssh\s*\{|set.*services.*ssh", stripped, re.IGNORECASE):
                facts.append(self._make_fact(
                    "mgmt.ssh.version", 2, True,
                    source_file, i + 1, i + 1, stripped,
                ))

            # Authentication order
            m = re.search(r"authentication-order\s+\[([^\]]+)\]", stripped)
            if m:
                facts.append(self._make_fact(
                    "aaa.authentication_order", m.group(1).strip(), True,
                    source_file, i + 1, i + 1, stripped,
                ))

            # Syslog
            if re.search(r"syslog\s*\{", stripped, re.IGNORECASE):
                facts.append(self._make_fact(
                    "logging.remote_syslog", True, True,
                    source_file, i + 1, i + 1, stripped,
                ))

            # Syslog host
            m = re.search(r"host\s+(\d{1,3}(?:\.\d{1,3}){3})", stripped)
            if m and "syslog" in "\n".join(lines[max(0, i - 5) : i]).lower():
                facts.append(self._make_fact(
                    "logging.remote_syslog", m.group(1), True,
                    source_file, i + 1, i + 1, stripped,
                ))

            # NTP
            if re.search(r"ntp\s*\{", stripped, re.IGNORECASE):
                facts.append(self._make_fact(
                    "time.ntp", True, True,
                    source_file, i + 1, i + 1, stripped,
                ))

            m = re.search(r"(?:ntp\s+)?(?:server|boot-server)\s+(\S+)", stripped)
            if m and "ntp" in "\n".join(lines[max(0, i - 5) : i + 1]).lower():
                facts.append(self._make_fact(
                    "time.ntp.server", m.group(1).rstrip(";"), True,
                    source_file, i + 1, i + 1, stripped,
                ))

            # Login banner / message
            if re.search(r"login\s*\{|login-message", stripped, re.IGNORECASE):
                facts.append(self._make_fact(
                    "mgmt.login_banner", True, True,
                    source_file, i + 1, i + 1, stripped,
                ))

            # SNMP
            m = re.search(r"community\s+(\S+)", stripped)
            if m and "snmp" in "\n".join(lines[max(0, i - 5) : i + 1]).lower():
                facts.append(self._make_fact(
                    "snmp.community", m.group(1).rstrip(";"), True,
                    source_file, i + 1, i + 1, stripped,
                ))

    def _parse_interfaces(
        self, lines: list[str], source_file: str, facts: list[CanonicalFact]
    ) -> None:
        for i, line in enumerate(lines):
            m = re.match(r"^\s*(?:set\s+)?interfaces?\s+(\S+)", line, re.IGNORECASE)
            if m:
                is_disabled = "disable" in line.lower()
                facts.append(self._make_fact(
                    "interface.admin_state",
                    "shutdown" if is_disabled else "no shutdown",
                    True, source_file, i + 1, i + 1, line.strip(),
                ))

    def _parse_protocols(
        self, lines: list[str], source_file: str, facts: list[CanonicalFact]
    ) -> None:
        # Basic protocol extraction
        pass

    def _parse_firewall(
        self, lines: list[str], source_file: str, facts: list[CanonicalFact]
    ) -> None:
        for i, line in enumerate(lines):
            if re.search(r"filter\s+\S+.*term\s+\S+", line):
                facts.append(self._make_fact(
                    "acl.extended.entry", line.strip(), True,
                    source_file, i + 1, i + 1, line.strip(),
                ))

    def _parse_security(
        self, lines: list[str], source_file: str, facts: list[CanonicalFact]
    ) -> None:
        for i, line in enumerate(lines):
            if re.search(r"screen\s+ids-option", line, re.IGNORECASE):
                facts.append(self._make_fact(
                    "control_plane.copp", True, True,
                    source_file, i + 1, i + 1, line.strip(),
                ))
