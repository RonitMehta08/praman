"""Cisco IOS vendor adapter.

Parses Cisco IOS running-config text into the Canonical Model using
netutils for hierarchy normalisation and ntc-templates for show-version
identity extraction.

This adapter writes ONLY to Device + list[CanonicalFact].
It never imports, references, or evaluates any framework control.
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

# Parser identity string carried on every CanonicalFact
_PARSER_ID = "praman.cisco_ios@0.1.0"

# Detection heuristics for Cisco IOS configs
_IOS_MARKERS = [
    "version 1",
    "hostname ",
    "boot-start-marker",
    "boot-end-marker",
    "enable secret",
    "enable password",
    "service timestamps",
    "line con 0",
    "line vty",
]


class CiscoIOSAdapter(VendorAdapter):
    """Cisco IOS running-config parser.

    Extracts CanonicalFacts from standard IOS configuration sections:
    - Management (SSH, enable secret, HTTP, banners)
    - AAA (authentication, authorisation, accounting)
    - Line (console, VTY, aux)
    - Logging (syslog, buffered, console)
    - SNMP (community, version, traps)
    - NTP / timekeeping
    - Interfaces (state, ACLs)
    - ACLs (extended, standard)
    - Service settings
    """

    def vendor_id(self) -> Vendor:
        return Vendor.cisco_ios

    def _parser_id(self) -> str:
        return _PARSER_ID

    def can_parse(self, raw_text: str, filename: str) -> bool:
        """Detect Cisco IOS by marker density."""
        lower = raw_text.lower()
        hits = sum(1 for m in _IOS_MARKERS if m.lower() in lower)
        return hits >= 3

    def parse(self, raw_text: str, source_file: str) -> ParseResult:
        """Parse a Cisco IOS config into Canonical Model entities."""
        normalised = unicodedata.normalize("NFKC", raw_text)
        lines = normalised.splitlines()

        facts: list[CanonicalFact] = []
        unparsed: list[dict[str, Any]] = []

        # Extract device identity from config (hostname, enable secret, version hints)
        hostname = self._extract_hostname(lines, source_file, facts)

        # Parse each section
        self._parse_enable_secret(lines, source_file, facts)
        self._parse_service_settings(lines, source_file, facts)
        self._parse_aaa(lines, source_file, facts)
        self._parse_logging(lines, source_file, facts)
        self._parse_snmp(lines, source_file, facts)
        self._parse_ntp(lines, source_file, facts)
        self._parse_ssh(lines, source_file, facts)
        self._parse_http(lines, source_file, facts)
        self._parse_banners(lines, source_file, facts)
        self._parse_lines(lines, source_file, facts)
        self._parse_interfaces(lines, source_file, facts)
        self._parse_acls(lines, source_file, facts)

        # Build device record
        device = Device(
            device_id=hostname or source_file.replace(".conf", "").replace(".cfg", ""),
            vendor=Vendor.cisco_ios,
            os_family=OsFamily.ios,
            hostname=hostname,
            serials=[],  # populated by ntc-templates show-version parse
            hardware=[],  # populated by ntc-templates show-version parse
            os_version=self._extract_version_hint(lines),
            source_file=source_file,
            config_hash=compute_config_hash(raw_text.encode("utf-8")),
            ingested_at=utc_now_iso(),
        )

        return ParseResult(device=device, facts=facts, unparsed_lines=unparsed)

    # ─── Section parsers ───────────────────────────────────────────────

    def _extract_hostname(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> str | None:
        """Extract hostname from 'hostname <name>' line."""
        for i, line in enumerate(lines):
            m = re.match(r"^\s*hostname\s+(\S+)", line, re.IGNORECASE)
            if m:
                hostname = m.group(1)
                facts.append(
                    self._make_fact(
                        path="device.hostname",
                        value=hostname,
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=line.strip(),
                    )
                )
                return hostname
        return None

    def _extract_version_hint(self, lines: list[str]) -> str | None:
        """Try to extract IOS version from 'version X.Y' line in config.

        Note: Real version comes from show-version parse (SPINE), not from config.
        This is a fallback for when show-version is unavailable.
        """
        for line in lines:
            m = re.match(r"^\s*version\s+(\S+)", line, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _parse_enable_secret(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse enable secret/password lines."""
        for i, line in enumerate(lines):
            m = re.match(
                r"^\s*enable\s+(secret|password)\s+(\d)?\s*(\S+)",
                line,
                re.IGNORECASE,
            )
            if m:
                secret_type = m.group(2) or "0"
                facts.append(
                    self._make_fact(
                        path="mgmt.enable_secret.hash_type",
                        value=int(secret_type),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=line.strip(),
                    )
                )

    def _parse_service_settings(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse service-level settings."""
        service_map = {
            r"service\s+password-encryption": "service.password_encryption",
            r"service\s+tcp-keepalives-in": "service.tcp_keepalives_in",
            r"service\s+tcp-keepalives-out": "service.tcp_keepalives_out",
            r"service\s+timestamps": "service.timestamps",
            r"no\s+service\s+pad": "service.pad",
            r"no\s+service\s+finger": "service.finger",
            r"no\s+service\s+config": "service.config",
            r"no\s+ip\s+source-route": "routing.source_routing",
        }

        for i, line in enumerate(lines):
            stripped = line.strip()
            for pattern, path in service_map.items():
                if re.match(rf"^\s*{pattern}", stripped, re.IGNORECASE):
                    is_negated = stripped.lower().startswith("no ")
                    facts.append(
                        self._make_fact(
                            path=path,
                            value=not is_negated,
                            present=True,
                            source_file=source_file,
                            line_start=i + 1,
                            line_end=i + 1,
                            raw_text=stripped,
                        )
                    )

    def _parse_aaa(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse AAA configuration."""
        for i, line in enumerate(lines):
            stripped = line.strip()

            if re.match(r"^\s*aaa\s+new-model", stripped, re.IGNORECASE):
                facts.append(
                    self._make_fact(
                        path="aaa.new_model",
                        value=True,
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*aaa\s+authentication\s+login\s+(\S+)\s+(.+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="aaa.authentication_login",
                        value=m.group(2).strip(),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*aaa\s+authentication\s+enable\s+(.+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="aaa.authentication_enable",
                        value=m.group(1).strip(),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*aaa\s+authorization\s+exec\s+(.+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="aaa.authorization_exec",
                        value=m.group(1).strip(),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*aaa\s+accounting\s+commands\s+(.+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="aaa.accounting_commands",
                        value=m.group(1).strip(),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

    def _parse_logging(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse logging configuration."""
        for i, line in enumerate(lines):
            stripped = line.strip()

            m = re.match(
                r"^\s*logging\s+host\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            if not m:
                m = re.match(
                    r"^\s*logging\s+(\d{1,3}(?:\.\d{1,3}){3})",
                    stripped,
                    re.IGNORECASE,
                )
            if m:
                facts.append(
                    self._make_fact(
                        path="logging.remote_syslog",
                        value=m.group(1),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*logging\s+buffered\s+(.+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="logging.buffered",
                        value=m.group(1).strip(),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*logging\s+trap\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="logging.trap_level",
                        value=m.group(1),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

    def _parse_snmp(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse SNMP configuration."""
        for i, line in enumerate(lines):
            stripped = line.strip()

            m = re.match(
                r"^\s*snmp-server\s+community\s+(\S+)\s*(RO|RW)?",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="snmp.community",
                        value=m.group(1),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*snmp-server\s+host\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="snmp.host",
                        value=m.group(1),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*snmp-server\s+enable\s+traps",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="snmp.traps",
                        value=True,
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

    def _parse_ntp(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse NTP configuration."""
        for i, line in enumerate(lines):
            stripped = line.strip()

            m = re.match(
                r"^\s*ntp\s+server\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="time.ntp.server",
                        value=m.group(1),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            if re.match(
                r"^\s*ntp\s+authenticate",
                stripped,
                re.IGNORECASE,
            ):
                facts.append(
                    self._make_fact(
                        path="time.ntp.authentication",
                        value=True,
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

    def _parse_ssh(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse SSH configuration."""
        for i, line in enumerate(lines):
            stripped = line.strip()

            m = re.match(
                r"^\s*ip\s+ssh\s+version\s+(\d+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="mgmt.ssh.version",
                        value=int(m.group(1)),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*ip\s+ssh\s+time-out\s+(\d+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="mgmt.ssh.timeout",
                        value=int(m.group(1)),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            m = re.match(
                r"^\s*ip\s+ssh\s+authentication-retries\s+(\d+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                facts.append(
                    self._make_fact(
                        path="mgmt.ssh.maxretries",
                        value=int(m.group(1)),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

    def _parse_http(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse HTTP/HTTPS server settings."""
        for i, line in enumerate(lines):
            stripped = line.strip()

            if re.match(r"^\s*(?:no\s+)?ip\s+http\s+server", stripped, re.IGNORECASE):
                is_negated = stripped.lower().startswith("no ")
                facts.append(
                    self._make_fact(
                        path="mgmt.http.server_enabled",
                        value=not is_negated,
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

            if re.match(
                r"^\s*(?:no\s+)?ip\s+http\s+secure-server",
                stripped,
                re.IGNORECASE,
            ):
                is_negated = stripped.lower().startswith("no ")
                facts.append(
                    self._make_fact(
                        path="mgmt.http.secure_server_enabled",
                        value=not is_negated,
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=stripped,
                    )
                )

    def _parse_banners(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse banner login/motd/exec."""
        banner_map = {
            "login": "mgmt.login_banner",
            "motd": "mgmt.motd_banner",
            "exec": "mgmt.exec_banner",
        }

        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            m = re.match(
                r"^\s*banner\s+(login|motd|exec)\s+(.)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                banner_type = m.group(1).lower()
                delimiter = m.group(2)
                start_line = i + 1
                banner_text = stripped
                # Find the end delimiter
                if delimiter in stripped[stripped.index(delimiter) + 1 :]:
                    # Single-line banner
                    pass
                else:
                    i += 1
                    while i < len(lines):
                        banner_text += "\n" + lines[i]
                        if delimiter in lines[i]:
                            break
                        i += 1

                path = banner_map.get(banner_type, f"mgmt.{banner_type}_banner")
                facts.append(
                    self._make_fact(
                        path=path,
                        value=True,
                        present=True,
                        source_file=source_file,
                        line_start=start_line,
                        line_end=i + 1,
                        raw_text=banner_text.strip(),
                    )
                )
            i += 1

    def _parse_lines(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse line console, vty, aux sections."""
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()

            m = re.match(
                r"^\s*line\s+(con|console|vty|aux)\s+(.+)",
                stripped,
                re.IGNORECASE,
            )
            if m:
                line_type = m.group(1).lower()
                if line_type in ("con", "console"):
                    line_type = "console"
                i += 1
                # Collect sub-commands
                while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t")):
                    sub = lines[i].strip()

                    # exec-timeout
                    tm = re.match(r"exec-timeout\s+(\d+)\s*(\d+)?", sub, re.IGNORECASE)
                    if tm:
                        minutes = int(tm.group(1))
                        seconds = int(tm.group(2)) if tm.group(2) else 0
                        facts.append(
                            self._make_fact(
                                path=f"line.{line_type}.exec_timeout",
                                value=minutes * 60 + seconds,
                                present=True,
                                source_file=source_file,
                                line_start=i + 1,
                                line_end=i + 1,
                                raw_text=sub,
                            )
                        )

                    # transport input
                    tm = re.match(r"transport\s+input\s+(.+)", sub, re.IGNORECASE)
                    if tm:
                        facts.append(
                            self._make_fact(
                                path=f"line.{line_type}.transport_input",
                                value=tm.group(1).strip(),
                                present=True,
                                source_file=source_file,
                                line_start=i + 1,
                                line_end=i + 1,
                                raw_text=sub,
                            )
                        )

                    # access-class
                    tm = re.match(r"access-class\s+(\S+)\s+in", sub, re.IGNORECASE)
                    if tm:
                        facts.append(
                            self._make_fact(
                                path=f"line.{line_type}.access_class",
                                value=tm.group(1),
                                present=True,
                                source_file=source_file,
                                line_start=i + 1,
                                line_end=i + 1,
                                raw_text=sub,
                            )
                        )

                    # login authentication
                    tm = re.match(r"login\s+authentication\s+(\S+)", sub, re.IGNORECASE)
                    if tm:
                        facts.append(
                            self._make_fact(
                                path=f"line.{line_type}.login_auth",
                                value=tm.group(1),
                                present=True,
                                source_file=source_file,
                                line_start=i + 1,
                                line_end=i + 1,
                                raw_text=sub,
                            )
                        )

                    i += 1
                continue
            i += 1

    def _parse_interfaces(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse interface sections."""
        i = 0
        while i < len(lines):
            m = re.match(r"^\s*interface\s+(\S+)", lines[i], re.IGNORECASE)
            if m:
                iface_name = m.group(1)
                start_line = i + 1
                i += 1
                is_shutdown = False
                while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t")):
                    sub = lines[i].strip()
                    if re.match(r"^\s*shutdown", sub, re.IGNORECASE):
                        is_shutdown = True
                    i += 1

                facts.append(
                    self._make_fact(
                        path="interface.admin_state",
                        value="shutdown" if is_shutdown else "no shutdown",
                        present=True,
                        source_file=source_file,
                        line_start=start_line,
                        line_end=i,
                        raw_text=f"interface {iface_name}",
                    )
                )
                continue
            i += 1

    def _parse_acls(
        self,
        lines: list[str],
        source_file: str,
        facts: list[CanonicalFact],
    ) -> None:
        """Parse access-list entries."""
        for i, line in enumerate(lines):
            m = re.match(
                r"^\s*(?:ip\s+)?access-list\s+(standard|extended)\s+(\S+)",
                line,
                re.IGNORECASE,
            )
            if m:
                acl_type = m.group(1).lower()
                facts.append(
                    self._make_fact(
                        path=f"acl.{acl_type}.entry",
                        value=m.group(2),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=line.strip(),
                    )
                )

            # Numbered ACL entries
            m = re.match(
                r"^\s*access-list\s+(\d+)\s+(permit|deny)\s+(.+)",
                line,
                re.IGNORECASE,
            )
            if m:
                acl_num = int(m.group(1))
                acl_type = "standard" if acl_num < 100 else "extended"
                facts.append(
                    self._make_fact(
                        path=f"acl.{acl_type}.entry",
                        value=line.strip(),
                        present=True,
                        source_file=source_file,
                        line_start=i + 1,
                        line_end=i + 1,
                        raw_text=line.strip(),
                    )
                )
